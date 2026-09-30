package service

import (
	"os"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/logger"
)

// TestBonusLoadConfigToleratesJSONC 钉住「生产那份带注释的 bonus.json 必须能读出来」。
//
// 2026-09-28 在 161 上用**生产配置**演练时实测到的故障：
//
//	泡点配置解析失败: invalid character '/' looking for beginning of value
//
// 原因是 216 的 bonus.json 是 .NET 管理页写出来的，整篇带 `//` 注释，
// 而 loadConfig 直接 json.Unmarshal → 失败 → 返回 nil → runLoop 整轮跳过。
// 后果不只是不发放：如果那份配置里的值**不等于**内置默认值，
// 泡点会静默按默认值跑（玩家侧表现为"点券数额不对"，很难联想到配置解析）。
//
// 回退验证：把 loadConfig/GetConfig 里的 StripJsoncComments 去掉，
// 本用例必须变红。
func TestBonusLoadConfigToleratesJSONC(t *testing.T) {
	dir := t.TempDir()
	log, err := logger.NewConsoleLogger(dir, logger.Error)
	if err != nil {
		t.Fatalf("建 logger 失败: %v", err)
	}
	// 必须关：logger 持有 error.log 句柄，Windows 上会让 t.TempDir 的清理失败
	// （报 "The process cannot access the file ... being used by another process"），
	// 断言明明过了也会被判 FAIL。
	t.Cleanup(func() { log.Close() })

	// 故意**不用**内置默认值，这样"解析失败回落默认值"一定会被抓到
	content := "// ============================================================\n" +
		"// 泡点配置（在线挂机奖励）—— 生产原件就是这个形状\n" +
		"// ============================================================\n" +
		"{\n" +
		"  // 是否启用泡点功能\n" +
		"  \"enabled\": true,\n" +
		"  // 发放间隔（秒）\n" +
		"  \"interval_seconds\": 120,\n" +
		"  // 每轮每账号发放点券数量（cera）\n" +
		"  \"amount_per_interval\": 250,\n" +
		"  \"active_threshold_minutes\": 7\n" +
		"}\n"

	svc := &BonusService{
		configPath: filepath.Join(dir, "bonus.json"),
		logger:     log,
		cancel:     make(chan struct{}),
	}
	if err := os.WriteFile(svc.configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}

	cfg := svc.loadConfig()
	if cfg == nil {
		t.Fatal("loadConfig 返回 nil（带注释的 bonus.json 没被容忍）—— 泡点会整轮不发放")
	}
	if cfg.IntervalSeconds != 120 || cfg.AmountPerInterval != 250 ||
		cfg.ActiveThresholdMinutes != 7 || !cfg.Enabled {
		t.Fatalf("读出来的值不对（可能回落了默认值）: %+v", *cfg)
	}

	got, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig 报错（管理后台的「泡点设置」页会读不出来）: %v", err)
	}
	if got.AmountPerInterval != 250 {
		t.Fatalf("GetConfig 值不对: %+v", *got)
	}
}

// TestBonusLoadConfigStillRejectsGarbage 反向钉住：真·坏 JSON 仍然要判失败。
//
// 否则「容忍注释」有可能会退化成「什么都当能解析」。
func TestBonusLoadConfigStillRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	log, err := logger.NewConsoleLogger(dir, logger.Error)
	if err != nil {
		t.Fatalf("建 logger 失败: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	svc := &BonusService{
		configPath: filepath.Join(dir, "bonus.json"),
		logger:     log,
		cancel:     make(chan struct{}),
	}
	if err := os.WriteFile(svc.configPath, []byte("not json at all\n"), 0o644); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	if cfg := svc.loadConfig(); cfg != nil {
		t.Fatalf("坏 JSON 不该被解析成功: %+v", *cfg)
	}
	if _, err := svc.GetConfig(); err == nil {
		t.Fatal("GetConfig 对坏 JSON 应当报错")
	}
}
