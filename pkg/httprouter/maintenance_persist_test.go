package httprouter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// 维护模式持久化（2026-10-19）
//
// 事故背景：维护模式原先只改网关内存，`systemctl restart gateway` 后复位成
// "不维护"。而运维的标准动作就是「更新前开维护 → 换二进制重启 → 更新完手动关」，
// 于是重启这一步把闸门自己打开了 —— 更新失败时玩家照样登录。
//
// 本文件锁三件事：
//   1. 开/关维护模式会写进 appsettings.override.json，**新进程 LoadConfig 后仍是该值**
//      （用"重新加载配置"模拟重启，这是判据的核心，只看内存不算数）；
//   2. 只改 Message 时 Enabled 不丢（字段级覆盖，不是整段替换）；
//   3. 放行名单（AdminAccounts）同样跨重启保留 —— 运维重启后不必重新填一遍。
// ─────────────────────────────────────────────────────────────────────────────

// reloadMaintenance 模拟网关重启：从同一个目录重新加载配置，返回维护模式快照。
//
// 必须先放一份 appsettings.json：LoadConfig 在主配置缺失时会**提前返回**，
// 连 override 都不读（生产中主配置必然存在，测试要还原这个前提，否则会误判成
// "override 没生效"）。内容用 `{}` —— 由 DefaultConfig 提供基线、override 覆盖。
func reloadMaintenance(t *testing.T, dir string) config.MaintenanceSection {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "appsettings.json"), []byte("{}\n"), 0644); err != nil {
		t.Fatalf("写基线 appsettings.json 失败: %v", err)
	}
	cfg, err := config.LoadConfig(filepath.Join(dir, "appsettings.json"))
	if err != nil {
		t.Fatalf("重启后加载配置失败: %v", err)
	}
	return cfg.MaintenanceSnapshot()
}

// 开启维护模式 → 重启仍是开启；关闭 → 重启仍是关闭。
func TestMaintenancePersistsAcrossReload(t *testing.T) {
	_, be, dir := newHeartbeatRuntimeFixture(t)

	// ① 开启
	on := true
	if _, err := be.SetMaintenance(&on, nil, nil); err != nil {
		t.Fatalf("开启维护模式失败: %v", err)
	}
	if snap := reloadMaintenance(t, dir); !snap.Enabled {
		t.Fatalf("重启后维护模式应仍为开启，实得 enabled=false（override 未落盘？）")
	}

	// ② 关闭（必须由人手动关，不能靠重启）
	off := false
	if _, err := be.SetMaintenance(&off, nil, nil); err != nil {
		t.Fatalf("关闭维护模式失败: %v", err)
	}
	if snap := reloadMaintenance(t, dir); snap.Enabled {
		t.Fatalf("手动关闭后重启不应再是维护中，实得 enabled=true")
	}
}

// 只改提示文案时，Enabled 不能被抹掉（同段兄弟字段必须保留）。
func TestMaintenanceKeepsSiblings(t *testing.T) {
	_, be, dir := newHeartbeatRuntimeFixture(t)

	on := true
	if _, err := be.SetMaintenance(&on, nil, nil); err != nil {
		t.Fatalf("开启维护模式失败: %v", err)
	}

	msg := "今晚 23:00 停机更新，预计 30 分钟"
	if _, err := be.SetMaintenance(nil, &msg, nil); err != nil {
		t.Fatalf("只改文案失败: %v", err)
	}

	snap := reloadMaintenance(t, dir)
	if !snap.Enabled {
		t.Fatalf("只改文案不应关掉维护模式（Enabled 被抹成零值）")
	}
	if snap.Message != msg {
		t.Fatalf("文案未持久化：期望 %q，实得 %q", msg, snap.Message)
	}
}

// 放行名单跨重启保留：运维重启网关后不用重新填一遍管理员账号。
func TestMaintenanceKeepsAdminAccounts(t *testing.T) {
	_, be, dir := newHeartbeatRuntimeFixture(t)

	on := true
	admins := []string{"admin1", "gm02"}
	if _, err := be.SetMaintenance(&on, nil, admins); err != nil {
		t.Fatalf("开启维护模式失败: %v", err)
	}

	snap := reloadMaintenance(t, dir)
	if len(snap.AdminAccounts) != 2 || snap.AdminAccounts[0] != "admin1" || snap.AdminAccounts[1] != "gm02" {
		t.Fatalf("放行名单未跨重启保留，实得 %v", snap.AdminAccounts)
	}
}

// override 里必须真的出现 Maintenance.Enabled 键（产物级判据：不是只改了内存）。
func TestMaintenanceWritesOverrideFile(t *testing.T) {
	_, be, dir := newHeartbeatRuntimeFixture(t)

	on := true
	if _, err := be.SetMaintenance(&on, nil, nil); err != nil {
		t.Fatalf("开启维护模式失败: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, config.OverrideFileName))
	if err != nil {
		t.Fatalf("override 文件不存在: %v", err)
	}
	var doc map[string]map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("override 不是合法 JSON: %v", err)
	}
	m, ok := doc["Maintenance"]
	if !ok {
		t.Fatalf("override 里没有 Maintenance 段: %s", string(raw))
	}
	if v, ok := m["Enabled"].(bool); !ok || !v {
		t.Fatalf("override 的 Maintenance.Enabled 应为 true，实得 %v（原始：%s）", m["Enabled"], string(raw))
	}
}
