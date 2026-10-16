package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
)

// ────────────────────────────────────────────────────────────────────────
// PVF 路径解析（2026-09-27 修）
//
// 线上形态：Server.WorkDir = /opt/S4A21Server（**不带** publish），
// 而 PVF 真实位置是 /opt/S4A21Server/publish/Data/Pvf/Script.pvf。
// 旧代码只拼 WorkDir+"Data/Pvf/Script.pvf"，于是
//   上传 → "open /opt/S4A21Server/Data/Pvf/Script.pvf.tmp: no such file or directory"
//   备份 → PVF 静默跳过
//
// 本文件把"必须能找到 publish/ 下的那份"变成机器可判的断言。
// ────────────────────────────────────────────────────────────────────────

// newTestServerManager 造一个 WorkDir 带 publish/ 子目录的 ServerManager。
// 返回 (manager, WorkDir, PVF 真实路径)。
func newTestServerManager(t *testing.T) (*ServerManager, string, string) {
	t.Helper()
	dir := t.TempDir()
	workDir := filepath.Join(dir, "S4A21Server") // 模拟 /opt/S4A21Server
	pvfPath := filepath.Join(workDir, "publish", "Data", "Pvf", "Script.pvf")
	if err := os.MkdirAll(filepath.Dir(pvfPath), 0o755); err != nil {
		t.Fatalf("建 publish/Data/Pvf 失败: %v", err)
	}
	if err := os.WriteFile(pvfPath, []byte("old-pvf-body"), 0o644); err != nil {
		t.Fatalf("造 PVF 样本失败: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Server.WorkDir = workDir
	cfg.Server.PvfPath = "" // 线上没配这一项
	cfg.Pvf.FilePath = ""   // 清掉默认的相对路径 ./Data/Pvf/Script.pvf

	// ReplacePvf 落盘后会回读指纹并打日志（2026-09-30 双角色分离批）——
	// 夹具不配 logger 会 nil panic（2026-10-01 全量回归抓到）。
	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatalf("建 logger 失败: %v", err)
	}
	t.Cleanup(func() { lg.Close() })

	return &ServerManager{config: cfg, logger: lg}, workDir, pvfPath
}

// oldBrokenPath 复现修复前的拼接结果 —— 用它断言"旧路径确实不存在"，
// 让本文件的每条用例都自带区分力（换回旧逻辑必然变红）。
func oldBrokenPath(workDir string) string {
	return filepath.Join(workDir, "Data/Pvf/Script.pvf")
}

// 核心回归：WorkDir 不带 publish 时，必须回退到 publish/ 子目录。
func TestResolvePvfPathFallsBackToPublishSubdir(t *testing.T) {
	mgr, workDir, want := newTestServerManager(t)

	// 前置：确认这在复现线上场景，而不是碰巧也能命中旧路径。
	if _, err := os.Stat(filepath.Dir(oldBrokenPath(workDir))); !os.IsNotExist(err) {
		t.Fatalf("测试构造有问题：旧路径的父目录居然存在（%s），用例失去区分力", oldBrokenPath(workDir))
	}

	got, err := mgr.resolvePvfPath()
	if err != nil {
		t.Fatalf("不该解析失败: %v", err)
	}
	if got != want {
		t.Fatalf("应解析到 publish 下的 PVF\n期望 %s\n实际 %s", want, got)
	}
}

// 显式配置的 Server.PvfPath 优先于一切探测。
func TestResolvePvfPathPrefersExplicitPvfPath(t *testing.T) {
	mgr, _, _ := newTestServerManager(t)

	dir := t.TempDir()
	explicit := filepath.Join(dir, "custom", "MyPvf.pvf")
	if err := os.MkdirAll(filepath.Dir(explicit), 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	if err := os.WriteFile(explicit, []byte("x"), 0o644); err != nil {
		t.Fatalf("造样本失败: %v", err)
	}
	mgr.config.Server.PvfPath = explicit

	got, err := mgr.resolvePvfPath()
	if err != nil {
		t.Fatalf("不该解析失败: %v", err)
	}
	if got != explicit {
		t.Fatalf("显式 PvfPath 应优先，期望 %s，实际 %s", explicit, got)
	}
}

// Pvf.FilePath（网关自己的配置，线上配的是绝对路径）也要认。
func TestResolvePvfPathUsesPvfSectionAbsolutePath(t *testing.T) {
	mgr, _, want := newTestServerManager(t)
	mgr.config.Pvf.FilePath = want

	got, err := mgr.resolvePvfPath()
	if err != nil {
		t.Fatalf("不该解析失败: %v", err)
	}
	if got != want {
		t.Fatalf("期望 %s，实际 %s", want, got)
	}
}

// 相对路径的 Pvf.FilePath 不参与探测 —— 它是相对进程 cwd 的，
// 网关与后台进程 cwd 不同，拿它拼绝对路径等于掷骰子。
func TestResolvePvfPathIgnoresRelativePvfFilePath(t *testing.T) {
	mgr, _, want := newTestServerManager(t)
	mgr.config.Pvf.FilePath = "./Data/Pvf/Script.pvf" // 默认值形态

	got, err := mgr.resolvePvfPath()
	if err != nil {
		t.Fatalf("不该解析失败: %v", err)
	}
	if got != want {
		t.Fatalf("相对路径不该被采纳，期望回退到 %s，实际 %s", want, got)
	}
}

// 全都找不到时必须报错，且错误里带候选列表（后台弹窗要能照着查）。
func TestResolvePvfPathErrorsWithCandidates(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Server.WorkDir = filepath.Join(dir, "empty")
	cfg.Server.PvfPath = ""
	cfg.Pvf.FilePath = ""
	mgr := &ServerManager{config: cfg}

	got, err := mgr.resolvePvfPath()
	if err == nil {
		t.Fatalf("路径全都不可用时应报错，却返回 %s", got)
	}
	msg := err.Error()
	// 用 filepath.Join 拼期望片段：Windows 上是反斜杠，硬编码 "/" 会假红。
	for _, want := range []string{
		filepath.Join("Data", "Pvf", "Script.pvf"),
		"publish",
		"Server.WorkDir",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("报错信息里应提到 %q，实际：%s", want, msg)
		}
	}
}

// ★ 端到端回归：ReplacePvf 必须真的写到 publish 下那份，并留下 .bak。
//
// 修复前这里会返回 "open .../Data/Pvf/Script.pvf.tmp: no such file or directory"
// —— 与线上报障逐字同形。
func TestReplacePvfWritesToPublishSubdir(t *testing.T) {
	mgr, workDir, want := newTestServerManager(t)

	body := []byte("new-pvf-body-from-upload")
	res := mgr.ReplacePvf(bytes.NewReader(body))
	if !res.Ok {
		t.Fatalf("替换应成功，实际失败: %s", res.Error)
	}

	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("读替换后的 PVF 失败: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("PVF 内容不对：期望 %d 字节，实际 %d 字节", len(body), len(got))
	}

	// 旧内容应被备份成 .bak
	bak, err := os.ReadFile(want + ".bak")
	if err != nil {
		t.Fatalf("应生成 .bak 备份: %v", err)
	}
	if string(bak) != "old-pvf-body" {
		t.Fatalf(".bak 里应是旧内容，实际 %q", string(bak))
	}

	// 不该在任何地方留下临时文件
	if _, err := os.Stat(want + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("不该残留 .tmp 文件：%s", want+".tmp")
	}

	// 旧路径必须仍然不存在 —— 证明没有"另写一份假文件"
	if _, err := os.Stat(oldBrokenPath(workDir)); !os.IsNotExist(err) {
		t.Fatalf("不该在旧路径下产生文件：%s", oldBrokenPath(workDir))
	}
}

// ★ 端到端回归：备份必须**带上** publish 下的 PVF。
//
// 修复前 PVF 会被静默跳过（连日志都没有），运维以为备份齐了。
func TestBackupIncludesPvfFromPublishSubdir(t *testing.T) {
	mgr, _, pvfPath := newTestServerManager(t)
	backupDir := filepath.Join(t.TempDir(), "backups")
	mgr.config.Server.BackupDir = backupDir
	mgr.config.Database.GamePath = "" // 只留 PVF 一个备份目标
	mgr.config.Database.Path = ""

	res := mgr.Backup()
	if !res.Ok {
		t.Fatalf("备份应成功，实际失败: %s", res.Error)
	}

	// 2026-10-16 起 PVF 打进 pvf-<时间戳>.tar.gz，不再散装落盘。
	// 断言口径不变：**备份里必须有 PVF，且字节与源一致**。
	// 改成从包里取，而不是删掉这条 —— 删了它，"PVF 被静默跳过"就会重新变成
	// 一个没人发现的故障（这正是这条测试当年被加进来的原因）。
	dst := extractEntryBytes(t, backupDir, "pvf", "Script-")

	src, err := os.ReadFile(pvfPath)
	if err != nil {
		t.Fatalf("读源 PVF 失败: %v", err)
	}
	if !bytes.Equal(src, dst) {
		t.Fatalf("备份的 PVF 内容与源不一致")
	}
}
