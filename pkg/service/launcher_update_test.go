package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/pvfdiff"
)

// ────────────────────────────────────────────────────────────────────────
// 登录器自更新分发（2026-10-01）
//
// 钉死的静默失效路径：
//   · 版本号/PE 校验缺失        → 传错文件直接铺给全体玩家（最严重）；
//   · 两进程缓存不感知          → admin 上传后网关仍发旧清单，玩家更新完还提示更新；
//   · 按需增量 from/to 对不上   → 玩家本地 exe 被合成成错误内容；
//   · 换版后旧缓存没清          → 下发的包 to 过期；
//   · 历史超限把当前版删了      → 回退/按需终点丢失。
// ────────────────────────────────────────────────────────────────────────

const testLauncherSize = 1<<20 + 4096 // 略高于 minLauncherSize（1 MiB）

// randExe 造一个「像登录器 exe」的随机体（MZ 头 + 随机字节）。
func randExe(seed int64, n int) []byte {
	b := randBody(seed, n)
	b[0] = 'M'
	b[1] = 'Z'
	return b
}

func newLauncherUpdateService(t *testing.T) (*LauncherUpdateService, *config.GatewayConfig) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	cfg.Launcher.UpdateKeep = 4
	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })
	return NewLauncherUpdateService(cfg, lg), cfg
}

// ① 上传校验：版本号格式 / MZ 头 / 体积下限，任何一条不过都不能写盘。
func TestReplaceLauncherValidations(t *testing.T) {
	svc, _ := newLauncherUpdateService(t)
	good := randExe(1, testLauncherSize)

	// 版本号非法：全拒绝（这是强更判据的输入，宁可严）。
	// （" 2.4.0 " 不在此列：实现刻意 TrimSpace —— 表单输入常带空白，不因空白拒人。）
	for _, bad := range []string{"", "2.4", "v2.4.0", "2.4.0.1", "x.y.z"} {
		if _, err := svc.ReplaceLauncher(bytes.NewReader(good), bad, "", "a.exe"); err == nil {
			t.Fatalf("版本号 %q 应被拒绝", bad)
		}
	}
	// 非 PE（缺 MZ）
	notExe := randBody(2, testLauncherSize)
	if _, err := svc.ReplaceLauncher(bytes.NewReader(notExe), "2.4.0", "", "a.exe"); err == nil {
		t.Fatal("缺 MZ 头的文件应被拒绝")
	}
	// 太小
	tiny := randExe(3, 1024)
	if _, err := svc.ReplaceLauncher(bytes.NewReader(tiny), "2.4.0", "", "a.exe"); err == nil {
		t.Fatal("小文件应被拒绝")
	}
	// 全拒之后 current.exe 必须还不存在（没写半截）
	if fileExistsQuiet(svc.CurrentPath()) {
		t.Fatal("全部被拒后 current.exe 不应存在")
	}
	// 合法上传通过
	if _, err := svc.ReplaceLauncher(bytes.NewReader(good), "2.4.0", "首个版本", "a.exe"); err != nil {
		t.Fatalf("合法上传失败: %v", err)
	}
	if !fileExistsQuiet(svc.CurrentPath()) {
		t.Fatal("合法上传后 current.exe 应存在")
	}
}

// ② 上传入史：新旧两版都进历史、version/name/filename 记录、内容寻址去重。
func TestReplaceLauncherArchivesHistory(t *testing.T) {
	svc, _ := newLauncherUpdateService(t)

	v1 := randExe(11, testLauncherSize)
	uploadLauncherOK(t, svc, v1, "2.3.8", "旧版")
	v2 := randExe(12, testLauncherSize)
	uploadLauncherOK(t, svc, v2, "2.4.0", "新增自更新")

	entries := svc.GetHistory()
	if len(entries) != 2 {
		t.Fatalf("上传两版后历史应有 2 条，实得 %d", len(entries))
	}
	// GetHistory 新→旧
	if entries[0].Version != "2.4.0" || entries[1].Version != "2.3.8" {
		t.Fatalf("历史顺序应新→旧，实得 %s, %s", entries[0].Version, entries[1].Version)
	}
	if entries[0].Name != "新增自更新" {
		t.Fatalf("备注应入史，实得 %q", entries[0].Name)
	}
	if entries[0].Filename != "a.exe" {
		t.Fatalf("上传文件名应入史，实得 %q", entries[0].Filename)
	}

	// 同内容重复上传 ⇒ 去重
	uploadLauncherOK(t, svc, append([]byte(nil), v2...), "2.4.0", "重复上传不该新建记录")
	if entries := svc.GetHistory(); len(entries) != 2 {
		t.Fatalf("同内容重复上传不该新增历史，实得 %d 条", len(entries))
	}

	// 当前版描述
	cur := svc.Current()
	if cur.Version != "2.4.0" || cur.Hash == "" {
		t.Fatalf("当前版应是 v2.4.0，实得 %+v", cur)
	}
}

// uploadLauncherOK 上传并断言成功（返回当前版描述）。
func uploadLauncherOK(t *testing.T, svc *LauncherUpdateService, body []byte, version, name string) *models.LauncherBuildEntry {
	t.Helper()
	cur, err := svc.ReplaceLauncher(bytes.NewReader(body), version, name, "a.exe")
	if err != nil {
		t.Fatalf("上传 v%s 失败: %v", version, err)
	}
	return cur
}

// ③ ★ 跨进程缓存感知（currentStamp）：两个实例共用目录（= gateway/admin 两进程），
//    A 上传新 exe 后 B 的 Current() 必须自动拿到新 hash —— 不自动 = 网关永远发旧清单。
func TestLauncherCurrentStampCrossInstance(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	newSvc := func() *LauncherUpdateService {
		lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { lg.Close() })
		return NewLauncherUpdateService(cfg, lg)
	}

	// 模拟 admin 进程上传
	adminSide := newSvc()
	uploadLauncherOK(t, adminSide, randExe(21, testLauncherSize), "2.3.8", "")

	// 模拟网关进程（独立实例、同目录）此前已读过一次清单（缓存已建）
	gwSide := newSvc()
	if cur := gwSide.Current(); cur.Version != "2.3.8" {
		t.Fatalf("网关侧首次读取应是 v2.3.8，实得 %q", cur.Version)
	}

	// admin 又传了新版 —— 网关侧**没有收到任何通知**，
	// 只能靠 currentStamp（size+mtime）在下一次请求时自动感知。
	uploadLauncherOK(t, adminSide, randExe(22, testLauncherSize), "2.4.0", "")

	if cur := gwSide.Current(); cur.Version != "2.4.0" {
		t.Fatalf("★ 缓存失效机制失效：admin 上传新版后网关侧仍返回 %q（应 2.4.0）", cur.Version)
	}
}

// ④ 按需增量：落后多版的客户端合成结果必须逐字节等于当前版；缓存命中；拒绝路径。
func TestLauncherOnDemandDelta(t *testing.T) {
	svc, _ := newLauncherUpdateService(t)

	v1 := randExe(31, testLauncherSize)
	cur1 := uploadLauncherOK(t, svc, v1, "2.3.7", "")
	v2 := randExe(32, testLauncherSize)
	uploadLauncherOK(t, svc, v2, "2.3.8", "")
	v3 := randExe(33, testLauncherSize)
	uploadLauncherOK(t, svc, v3, "2.4.0", "")

	// v1 客户端（落后两版）按需
	d := svc.GetOnDemandDelta(cur1.Hash)
	if d == nil {
		t.Fatal("历史里有 v1，按需增量不该为 nil")
	}
	if d.ToHash != svc.Current().Hash {
		t.Fatalf("按需增量 to 应是当前版")
	}
	// 端到端合成：v1 + delta == v3
	out := filepath.Join(t.TempDir(), "composed.exe")
	if err := pvfdiff.Apply(filepath.Join(svc.historyDir(), cur1.Hash+".exe"), d.Path, out); err != nil {
		t.Fatalf("合成失败: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, v3) {
		t.Fatal("按需增量合成结果 != 当前版（下发的包不可用）")
	}

	// 二次请求命中缓存
	d2 := svc.GetOnDemandDelta(cur1.Hash)
	if d2 == nil || d2.Path != d.Path {
		t.Fatal("同 from 二次请求应命中缓存")
	}

	// 拒绝路径
	if d := svc.GetOnDemandDelta(svc.Current().Hash); d != nil {
		t.Fatal("from == 当前版应返回 nil")
	}
	if d := svc.GetOnDemandDelta(strings.Repeat("C", 64)); d != nil {
		t.Fatal("历史没有的版本应返回 nil")
	}
	for _, evil := range []string{"", "xyz", "../../etc/passwd", strings.Repeat("0", 63)} {
		if d := svc.GetOnDemandDelta(evil); d != nil {
			t.Fatalf("非法 from %q 应返回 nil", evil)
		}
	}
}

// ⑤ 换版清缓存：上传新版后 delta 目录不得有 from_* 残留，且旧 from 的新包指向新当前版。
func TestLauncherDeltaCacheInvalidatedOnReplace(t *testing.T) {
	svc, _ := newLauncherUpdateService(t)

	v1 := randExe(41, testLauncherSize)
	cur1 := uploadLauncherOK(t, svc, v1, "2.3.8", "")
	uploadLauncherOK(t, svc, randExe(42, testLauncherSize), "2.4.0", "")
	if d := svc.GetOnDemandDelta(cur1.Hash); d == nil {
		t.Fatal("前置条件不成立：v1 按需增量应可用")
	}

	v3Hash := uploadLauncherOK(t, svc, randExe(43, testLauncherSize), "2.4.1", "").Hash

	items, _ := os.ReadDir(svc.deltaDir())
	for _, it := range items {
		if strings.HasPrefix(it.Name(), "from_") {
			t.Fatalf("换版后按需缓存应被清除，残留 %s", it.Name())
		}
	}
	d := svc.GetOnDemandDelta(cur1.Hash)
	if d == nil || d.ToHash != v3Hash {
		t.Fatalf("换版后 v1 按需增量 to 应是新当前版")
	}
}

// ⑥ 回退：走完整链路、回退目标拒绝路径齐全。
func TestLauncherRollback(t *testing.T) {
	svc, _ := newLauncherUpdateService(t)

	v1 := randExe(51, testLauncherSize)
	cur1 := uploadLauncherOK(t, svc, v1, "2.3.8", "")
	cur2 := uploadLauncherOK(t, svc, randExe(52, testLauncherSize), "2.4.0", "")

	// 回退到 v1：版本号跟着历史索引走
	cur, err := svc.RollbackLauncher(cur1.Hash)
	if err != nil {
		t.Fatalf("回退失败: %v", err)
	}
	if cur.Hash != cur1.Hash || cur.Version != "2.3.8" {
		t.Fatalf("回退后当前版应是 v2.3.8（%s），实得 v%s", shortHash(cur1.Hash), cur.Version)
	}
	_ = cur2

	// 拒绝路径
	if _, err := svc.RollbackLauncher(cur1.Hash); err == nil {
		t.Fatal("回退到当前版应报错")
	}
	if _, err := svc.RollbackLauncher(strings.Repeat("D", 64)); err == nil {
		t.Fatal("回退到不存在的版本应报错")
	}
	for _, evil := range []string{"../../etc/passwd", "ab", ""} {
		if _, err := svc.RollbackLauncher(evil); err == nil {
			t.Fatalf("非法 hash %q 应被拒绝", evil)
		}
	}
}

// ⑦ 历史超限：UpdateKeep=2 下传 4 版，历史 ≤2 条且当前版必在。
func TestLauncherPruneKeep(t *testing.T) {
	svc, cfg := newLauncherUpdateService(t)
	cfg.Launcher.UpdateKeep = 2

	var lastHash string
	for i, ver := range []string{"2.4.0", "2.4.1", "2.4.2", "2.4.3"} {
		lastHash = uploadLauncherOK(t, svc, randExe(int64(60+i), testLauncherSize), ver, "").Hash
	}

	entries := svc.GetHistory()
	if len(entries) > 2 {
		t.Fatalf("UpdateKeep=2 时历史最多 2 条，实得 %d", len(entries))
	}
	found := false
	for _, e := range entries {
		if strings.EqualFold(e.Hash, lastHash) {
			found = true
		}
	}
	if !found {
		t.Fatal("历史超限清理绝不能删掉当前版")
	}
}

// ⑧ 惰性 seed：手动放 current.exe（从未走过上传流程的部署）→ 历史页有版可回退。
func TestLauncherHistorySeedsCurrent(t *testing.T) {
	svc, _ := newLauncherUpdateService(t)

	if err := os.MkdirAll(filepath.Dir(svc.CurrentPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.CurrentPath(), randExe(71, testLauncherSize), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := svc.GetHistory()
	if len(entries) != 1 {
		t.Fatalf("惰性 seed 后历史应有 1 条，实得 %d", len(entries))
	}
	if entries[0].Version != "" {
		t.Fatalf("seed 的版本号未知，应为空串，实得 %q", entries[0].Version)
	}
	// 无 current.exe 的全新部署：历史为空、Current 返回空 Hash（清单据此不发版本）。
	svc2, _ := newLauncherUpdateService(t)
	if cur := svc2.Current(); cur.Hash != "" {
		t.Fatalf("空部署 Current().Hash 应为空，实得 %s", shortHash(cur.Hash))
	}
	if entries := svc2.GetHistory(); len(entries) != 0 {
		t.Fatalf("空部署历史应为空，实得 %d 条", len(entries))
	}
}
