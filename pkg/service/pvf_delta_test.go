package service

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/pvfdiff"
)

// ────────────────────────────────────────────────────────────────────────
// PVF 增量更新（2026-09-30）
//
// 重点不是"能跑通"，而是把几条**静默失效**路径钉死：
//   · 增量包没生成      → 玩家只能全量更新，功能退化成"做了等于没做"，不报错；
//   · 增量包与当前 PVF 对不上却仍下发 → 玩家本地 PVF 被合成成错误内容；
//   · 首次替换（没有 .bak）却下发     → 同上。
// 这三条都不会崩、不会重启、日志也不显眼，只有断言拦得住。
// ────────────────────────────────────────────────────────────────────────

// 4 MiB：够产生真实的分块结构，又不拖慢测试。
const testPvfSize = 4 << 20

func randBody(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func newPvfDeltaService(t *testing.T) (*PvfService, string) {
	t.Helper()
	dir := t.TempDir()
	pvfPath := filepath.Join(dir, "Data", "Pvf", "Script.pvf")
	if err := os.MkdirAll(filepath.Dir(pvfPath), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Pvf.FilePath = pvfPath
	cfg.Pvf.DeltaDir = filepath.Join(dir, "pvf_delta")
	// ★ 历史目录必须同样钉进 TempDir —— 漏了会落到 CWD 的真实 ./pvf_history，
	//   用例间互相污染（计数对不上）且往仓库里丢垃圾文件。
	cfg.Pvf.HistoryDir = filepath.Join(dir, "pvf_history")
	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	// ★ 必须显式关掉：ConsoleLogger 持有 logs/error.log 的句柄，Windows 上不关会让
	// t.TempDir() 的清理失败（"The process cannot access the file ... being used by
	// another process"）⇒ 断言明明全过、用例却报 FAIL，极易误判成功能坏了。
	t.Cleanup(func() { lg.Close() })
	return NewPvfService(cfg, lg), pvfPath
}

// ① 替换 PVF 必须自动生成「上一版 → 当前版」的增量包，且**合成结果逐字节等于新版**。
func TestReplacePvfGeneratesUsableDelta(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	oldBody := randBody(1, testPvfSize)
	if err := os.WriteFile(pvfPath, oldBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}
	oldHash := svc.GetPvfInfo().Hash

	// 新版本：改中间一个字节（模拟"改了个数值"）
	newBody := append([]byte(nil), oldBody...)
	newBody[testPvfSize/2] ^= 0xFF

	if _, err := svc.ReplacePvf(bytes.NewReader(newBody), "", ""); err != nil {
		t.Fatalf("ReplacePvf 失败: %v", err)
	}

	d := svc.GetDelta()
	if d == nil {
		t.Fatal("替换 PVF 后应当生成增量包，实际没有")
	}
	if d.FromHash != oldHash {
		t.Fatalf("delta.from_hash 应当是旧版 %s，实得 %s", shortHash(oldHash), shortHash(d.FromHash))
	}
	newHash := svc.GetPvfInfo().Hash
	if d.ToHash != newHash {
		t.Fatalf("delta.to_hash 应当等于当前 PVF %s，实得 %s",
			shortHash(newHash), shortHash(d.ToHash))
	}
	if d.Size >= int64(len(newBody)) {
		t.Fatalf("delta %d 字节不该 >= 新文件 %d 字节（增量没有意义）", d.Size, len(newBody))
	}

	// ★ 端到端：用「磁盘上的旧版本（.bak）+ 下发的 delta」合成，必须逐字节等于新版本。
	//   这是唯一能证明"下发给玩家的包真的能用"的断言 —— 只断言 delta 存在是不够的。
	out := filepath.Join(t.TempDir(), "applied.pvf")
	if err := pvfdiff.Apply(pvfPath+".bak", d.Path, out); err != nil {
		t.Fatalf("用下发的 delta 合成失败: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBody) {
		t.Fatal("合成结果与新版本 PVF 不一致（下发的包不可用）")
	}
}

// ② 增量包过期时绝不能下发 —— 典型场景：运维直接 scp 覆盖了 Script.pvf，没走 upload-pvf。
func TestStaleDeltaIsNotServed(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(2, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()

	// 上传 v2 ⇒ 生成 v1→v2 的增量包
	v2 := append([]byte(nil), v1...)
	v2[100] ^= 0x33
	if _, err := svc.ReplacePvf(bytes.NewReader(v2), "", ""); err != nil {
		t.Fatal(err)
	}
	if svc.GetDelta() == nil {
		t.Fatal("前置条件不成立：v1→v2 的增量包应当可用")
	}

	// 手工换成 v3（不走 upload-pvf ⇒ 没有新的 .bak，也不会重新生成 delta）
	v3 := randBody(3, testPvfSize)
	if err := os.WriteFile(pvfPath, v3, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}

	if d := svc.GetDelta(); d != nil {
		t.Fatalf("PVF 已不是 delta 的目标版本（to=%s，当前=%s），不该下发",
			shortHash(d.ToHash), shortHash(svc.GetPvfInfo().Hash))
	}
}

// ③ 首次替换（没有 .bak）时没有增量，但**替换本身必须成功** ——
//    不能因为"出不了 delta"就把整个上传判失败。
func TestFirstReplaceHasNoDeltaButStillSucceeds(t *testing.T) {
	svc, _ := newPvfDeltaService(t)

	body := randBody(4, testPvfSize)
	if _, err := svc.ReplacePvf(bytes.NewReader(body), "", ""); err != nil {
		t.Fatalf("首次替换本身必须成功: %v", err)
	}
	if svc.GetDelta() != nil {
		t.Fatal("没有上一版时不该有增量包")
	}
	if svc.GetPvfInfo().Hash == "" {
		t.Fatal("替换后应当有 PVF 指纹")
	}
}

// ④ 网关重启后应当直接从磁盘装载已有的增量包，而不是"重启就没了"。
func TestDeltaLoadedAfterRestart(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(5, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()
	v2 := append([]byte(nil), v1...)
	v2[7] ^= 0x11
	if _, err := svc.ReplacePvf(bytes.NewReader(v2), "", ""); err != nil {
		t.Fatal(err)
	}
	want := svc.GetDelta()
	if want == nil {
		t.Fatal("前置条件不成立：应当已生成增量包")
	}

	// 模拟重启：同一份配置与目录，新建一个 service
	svc2 := NewPvfService(svc.config, svc.logger)
	if err := svc2.RefreshCache(); err != nil {
		t.Fatal(err)
	}
	got := svc2.GetDelta()
	if got == nil {
		t.Fatal("重启后应当能从 pvf_delta/current.delta 装载增量包")
	}
	if got.ToHash != want.ToHash || got.FromHash != want.FromHash {
		t.Fatalf("重启后装载的增量包对不上: %s→%s，期望 %s→%s",
			shortHash(got.FromHash), shortHash(got.ToHash),
			shortHash(want.FromHash), shortHash(want.ToHash))
	}
}
