package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// 审查报告 G-6：ReplacePvf 的并发保护（replaceMu + <pvf>.lock）与自差分拒绝
//
// 钉死的三条静默失效路径：
//   · 跨进程并发上传 → 第二次 BackupFile 把刚写好的新版覆盖成 .bak
//     ⇒ rebuildDelta 产出 from == to 的**自差分**（09-30「全体旧版客户端进不去」
//       就是这个形态），且全程不报错；
//   · 锁文件残留（持锁进程被 kill/断电）→ PVF 从此再也换不了，没有任何出口；
//   · 正常替换后锁没释放 → 下一次上传会白白等满超时。
// ────────────────────────────────────────────────────────────────────────────

// withShortLockWait 把抢锁超时压到毫秒级，用例跑完自动恢复。
// ★ 必须恢复：pvfReplaceLockWait 是包级 var，漏恢复会污染同包其它用例。
func withShortLockWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := pvfReplaceLockWait
	pvfReplaceLockWait = d
	t.Cleanup(func() { pvfReplaceLockWait = old })
}

// ① 另一个进程持锁时，本次替换必须**明确失败**而不是硬上。
//
// ★ 区分力：把 ReplacePvf 里 acquirePvfReplaceLock 那三行摘掉，本用例立刻变红
// —— 替换会"成功"，锁形同虚设（跨进程那一层的保护没了）。
func TestReplacePvfRejectsWhenLockHeld(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)
	withShortLockWait(t, 300*time.Millisecond)

	if err := os.WriteFile(pvfPath, randBody(21, testPvfSize), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}
	oldHash := svc.GetPvfInfo().Hash

	// 模拟"另一个进程（admin）正在替换"：锁文件新鲜存在
	lock := pvfPath + ".lock"
	if err := os.WriteFile(lock, []byte("pid=999999 time=now\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := svc.ReplacePvf(bytes.NewReader(randBody(22, testPvfSize)), "并发上传", "Script.pvf")
	if err == nil {
		t.Fatal("有进程持锁时 ReplacePvf 竟然成功了 —— 跨进程锁没生效（审查 G-6）")
	}
	if !strings.Contains(err.Error(), "另一个进程正在替换") {
		t.Fatalf("报错信息应指向 %q，实得: %v", "另一个进程正在替换", err)
	}

	// 拒绝必须发生在**任何写盘动作之前**：PVF 内容与指纹都不能变
	if svc.GetPvfInfo().Hash != oldHash {
		t.Fatal("被拒绝的替换却改动了 PVF 指纹 —— 写盘发生在抢锁之前？")
	}
}

// ② 残留锁（持锁进程崩溃）必须能被接管，否则 PVF 永远换不了。
func TestReplacePvfTakesOverStaleLock(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)
	withShortLockWait(t, 300*time.Millisecond)

	if err := os.WriteFile(pvfPath, randBody(31, testPvfSize), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}
	oldHash := svc.GetPvfInfo().Hash

	// 残留锁：mtime 推到 stale 阈值之外（pid 早就没了）
	lock := pvfPath + ".lock"
	if err := os.WriteFile(lock, []byte("pid=999999 time=long-ago\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-pvfReplaceLockStale - time.Minute)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}

	newBody := randBody(32, testPvfSize)
	if _, err := svc.ReplacePvf(bytes.NewReader(newBody), "接管残留锁", "Script.pvf"); err != nil {
		t.Fatalf("残留锁应被强制接管，替换却失败: %v", err)
	}
	if svc.GetPvfInfo().Hash == oldHash {
		t.Fatal("替换报告成功但指纹没变 —— 内容其实没写进去")
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("替换成功后锁文件应被释放，实得 stat err=%v", err)
	}
}

// ③ 正常替换后不得留下锁文件（否则下一次上传白白等满超时）。
func TestReplacePvfReleasesLockOnSuccess(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	if err := os.WriteFile(pvfPath, randBody(41, testPvfSize), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.ReplacePvf(bytes.NewReader(randBody(42, testPvfSize)), "正常替换", "Script.pvf"); err != nil {
		t.Fatalf("替换失败: %v", err)
	}
	lock := pvfPath + ".lock"
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("替换成功后 <pvf>.lock 仍在 —— 下一次上传会被自己的锁挡住")
	}
}

// ④ 自差分（.bak 与当前文件内容相同）必须被拒绝落地。
//
// 造现场：直接构造 path 与 path.bak 内容一致，再调 rebuildDelta ——
// 这正是并发替换后 .bak 被覆盖的终局状态。
//
// ★ 区分力：把 rebuildDelta 里 `if strings.EqualFold(st.FromHash, st.ToHash)`
// 那段摘掉，本用例变红（current.delta 会被写出来）。
func TestRebuildDeltaRejectsSelfDiff(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	body := randBody(51, testPvfSize)
	if err := os.WriteFile(pvfPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	// .bak 内容与当前文件**逐字节相同**
	if err := os.WriteFile(pvfPath+".bak", body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}

	svc.rebuildDelta(pvfPath)

	final := filepath.Join(svc.DeltaDir(), deltaFileName)
	if _, err := os.Stat(final); err == nil {
		t.Fatal("自差分被落地成了 current.delta —— from == to 的包会下发给玩家（审查 G-6）")
	}
	if d := svc.GetDelta(); d != nil {
		t.Fatalf("自差分场景下 GetDelta 应为 nil，实得 %+v", d)
	}
	// 中间文件也不能留
	if _, err := os.Stat(final + ".tmp"); err == nil {
		t.Fatal("自差分被拒绝后残留了 .tmp 临时文件")
	}
}

// ⑤ 对照：内容确实不同的两版，增量包必须照常生成。
//   没有这条，④ 的"变红"可能只是因为 rebuildDelta 被整体改坏了。
func TestRebuildDeltaStillBuildsForRealDiff(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	old := randBody(61, testPvfSize)
	if err := os.WriteFile(pvfPath, old, 0o644); err != nil {
		t.Fatal(err)
	}
	newBody := append([]byte(nil), old...)
	newBody[testPvfSize/2] ^= 0xFF
	if err := os.WriteFile(pvfPath+".bak", old, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pvfPath, newBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}

	svc.rebuildDelta(pvfPath)

	d := svc.GetDelta()
	if d == nil {
		t.Fatal("真实差分却没能生成增量包 —— 自差分判据误伤了正常路径")
	}
	if strings.EqualFold(d.FromHash, d.ToHash) {
		t.Fatal("生成的增量包 from == to")
	}
}
