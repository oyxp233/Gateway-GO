package service

import (
	"os"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/utils"
)

// TestGetPvfInfoNeverNilOnHashFailure 复现审查 G-2 的现场：
// PVF 路径**存在**（FileExists 为 true）但指纹算不出来。
//
// ★ 区分力：修复前 RefreshCache 在这一支直接 `return err`，s.info 保持 nil，
// 而 GetPvfInfo 会吞掉 error 返回 nil ⇒ /api/launcher/policy（免鉴权公开端点、
// 每个登录器启动必打）解引用 nil → 进程级 panic + 重启后崩溃循环。
// 把 services.go 里那段「留着旧 info / 落零值」的兜底注释掉，本用例立刻变红。
//
// 造现场的手法：拿一个**目录**当 FilePath —— utils.FileExists 走 os.Stat，
// 对目录返回 true；而 ComputeFileFingerprintPath 里 os.Open(目录) 成功、
// 读取必然失败（Windows ERROR_INVALID_HANDLE / Linux EISDIR）⇒ 返回 error。
func TestGetPvfInfoNeverNilOnHashFailure(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "not-a-file")
	if err := os.Mkdir(bogus, 0o755); err != nil {
		t.Fatalf("造目录失败: %v", err)
	}
	if !utils.FileExists(bogus) {
		t.Fatalf("前提不成立：FileExists(%q) 应为 true（否则测的不是哈希失败分支）", bogus)
	}

	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatalf("建 logger 失败: %v", err)
	}
	t.Cleanup(func() { lg.Close() })

	cfg := config.DefaultConfig()
	cfg.Pvf.FilePath = bogus
	svc := NewPvfService(cfg, lg)

	info := svc.GetPvfInfo()
	if info == nil {
		t.Fatal("GetPvfInfo 返回 nil —— /api/launcher/policy 会解引用它（审查 G-2）")
	}
	// 二次确认前提：指纹确实没算出来（否则本用例没有区分力）
	if info.Hash != "" {
		t.Fatalf("前提不成立：本应指纹失败，却拿到 hash=%q", info.Hash)
	}
}

// TestGetPvfInfoMissingFileIsNonNull 文件不存在时也必须是**非 nil** 的零值
// —— 这条在修复前就成立（RefreshCache 的 FileExists 分支），留作回归。
func TestGetPvfInfoMissingFileIsNonNull(t *testing.T) {
	dir := t.TempDir()

	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatalf("建 logger 失败: %v", err)
	}
	t.Cleanup(func() { lg.Close() })

	cfg := config.DefaultConfig()
	cfg.Pvf.FilePath = filepath.Join(dir, "does-not-exist.pvf")
	svc := NewPvfService(cfg, lg)

	info := svc.GetPvfInfo()
	if info == nil {
		t.Fatal("文件不存在时 GetPvfInfo 仍不得返回 nil")
	}
	if info.Hash != "" {
		t.Fatalf("文件不存在时 hash 应为空，实际 %q", info.Hash)
	}
}
