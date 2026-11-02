package database

import (
	"path/filepath"
	"testing"
)

// newBanScopeTestDB 起一个最小网关库（本组用例不碰游戏库）。
func newBanScopeTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           filepath.Join(dir, "inventory.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("初始化 schema 失败: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// TestBanScopeGlobalHitsAllServers 锁定"全局封禁在任何服都命中"。
func TestBanScopeGlobalHitsAllServers(t *testing.T) {
	db := newBanScopeTestDB(t)

	if err := db.BanAccountScoped("badguy", "外挂", BanScopeGlobal); err != nil {
		t.Fatalf("封禁失败: %v", err)
	}

	for _, game := range []string{"s4a21", "s5a3", "s5a95", ""} {
		banned, err := db.IsBannedForServer("badguy", game)
		if err != nil {
			t.Fatalf("IsBannedForServer(%q): %v", game, err)
		}
		if !banned {
			t.Fatalf("全局封禁在服 %q 上竟然没命中", game)
		}
	}
}

// TestBanScopePerServerIsolated 锁定"分服封禁只在该服命中"。
//
// 这是"封号按服务器分开"的默认行为：封了 S5A3 的号，不该连带封掉 S4A21。
func TestBanScopePerServerIsolated(t *testing.T) {
	db := newBanScopeTestDB(t)

	if err := db.BanAccountScoped("cheater", "S5A3 专用外挂", "s5a3"); err != nil {
		t.Fatalf("封禁失败: %v", err)
	}

	banned, err := db.IsBannedForServer("cheater", "s5a3")
	if err != nil {
		t.Fatalf("IsBannedForServer(s5a3): %v", err)
	}
	if !banned {
		t.Fatal("分服封禁在本服上没命中")
	}

	// 其它服不该受影响
	for _, game := range []string{"s4a21", "s5a95"} {
		banned, err := db.IsBannedForServer("cheater", game)
		if err != nil {
			t.Fatalf("IsBannedForServer(%q): %v", game, err)
		}
		if banned {
			t.Fatalf("S5A3 的分服封禁在 %q 上也命中了 —— 分服隔离失效", game)
		}
	}
}

// TestLegacyBanRowsTreatedAsGlobal 锁定"老数据（scope 列为空/NULL）视为全局封禁"。
//
// 迁移后老库的封禁记录必须照旧生效，不能因为加了一列就让存量封禁失效。
func TestLegacyBanRowsTreatedAsGlobal(t *testing.T) {
	db := newBanScopeTestDB(t)

	// 模拟老数据：直接插入不带 scope 的行
	if _, err := db.gatewayDB.Exec(
		"INSERT INTO banned_accounts (name, reason, banned_at) VALUES (?, ?, ?)",
		"legacy", "老封禁", NowUnix()); err != nil {
		t.Fatalf("插入老数据失败: %v", err)
	}

	for _, game := range []string{"s4a21", "s5a3", "s5a95", ""} {
		banned, err := db.IsBannedForServer("legacy", game)
		if err != nil {
			t.Fatalf("IsBannedForServer(%q): %v", game, err)
		}
		if !banned {
			t.Fatalf("老封禁记录在服 %q 上没命中 —— 迁移把存量封禁弄丢了", game)
		}
	}
}

// TestUnbanRemovesRecord 锁定解封确实删除记录。
func TestUnbanRemovesRecord(t *testing.T) {
	db := newBanScopeTestDB(t)

	if err := db.BanAccountScoped("temp", "误封", BanScopeGlobal); err != nil {
		t.Fatalf("封禁失败: %v", err)
	}
	removed, err := db.UnbanAccount("temp")
	if err != nil {
		t.Fatalf("解封失败: %v", err)
	}
	if !removed {
		t.Fatal("解封应返回 removed=true")
	}
	banned, _ := db.IsBannedForServer("temp", "s4a21")
	if banned {
		t.Fatal("解封后仍判为封禁")
	}
}

// TestQueryBansIncludesScope 锁定后台封禁列表能读到 scope。
func TestQueryBansIncludesScope(t *testing.T) {
	db := newBanScopeTestDB(t)

	if err := db.BanAccountScoped("scoped", "只封 S5A3", "s5a3"); err != nil {
		t.Fatalf("封禁失败: %v", err)
	}

	total, entries, err := db.QueryBans("scoped", 1, 20)
	if err != nil {
		t.Fatalf("QueryBans: %v", err)
	}
	if total != 1 || len(entries) != 1 {
		t.Fatalf("应查到 1 条，实得 total=%d len=%d", total, len(entries))
	}
	if entries[0].Scope != "s5a3" {
		t.Fatalf("scope 应为 s5a3，实得 %q", entries[0].Scope)
	}
}

// TestAccountEventsRoundTrip 锁定事件流水能写能读、水位单调。
func TestAccountEventsRoundTrip(t *testing.T) {
	db := newBanScopeTestDB(t)

	if err := db.RecordAccountEvent(AccountEventRegister, "alice", "", BanScopeGlobal); err != nil {
		t.Fatalf("记录注册事件失败: %v", err)
	}
	if err := db.RecordAccountEvent(AccountEventBan, "bob", "外挂", BanScopeGlobal); err != nil {
		t.Fatalf("记录封禁事件失败: %v", err)
	}

	events, err := db.AccountEventsSince(0, 100)
	if err != nil {
		t.Fatalf("AccountEventsSince: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("应有 2 条事件，实得 %d", len(events))
	}
	if events[0].EventType != AccountEventRegister || events[0].Account != "alice" {
		t.Fatalf("第一条事件不对: %+v", events[0])
	}
	if events[1].EventType != AccountEventBan || events[1].Detail != "外挂" {
		t.Fatalf("第二条事件不对: %+v", events[1])
	}

	// since 过滤
	after, err := db.AccountEventsSince(events[0].ID, 100)
	if err != nil {
		t.Fatalf("AccountEventsSince(since): %v", err)
	}
	if len(after) != 1 || after[0].Account != "bob" {
		t.Fatalf("since 过滤不对: %+v", after)
	}
}

// TestApplyRemoteBanEvent 锁定"从网关应用全局封禁事件后，本地判封禁命中"。
func TestApplyRemoteBanEvent(t *testing.T) {
	db := newBanScopeTestDB(t)

	// 从网关应用一条全局封禁
	if err := db.ApplyRemoteAccountEvent(AccountEvent{
		ID: 1, EventType: AccountEventBan, Account: "remotebad",
		Detail: "主网关封禁", Scope: BanScopeGlobal, CreatedAt: NowUnix(),
	}); err != nil {
		t.Fatalf("应用远程封禁失败: %v", err)
	}

	banned, _ := db.IsBannedForServer("remotebad", "s4a21")
	if !banned {
		t.Fatal("远程全局封禁应用后本地没命中")
	}

	// 应用解封
	if err := db.ApplyRemoteAccountEvent(AccountEvent{
		ID: 2, EventType: AccountEventUnban, Account: "remotebad",
		Scope: BanScopeGlobal, CreatedAt: NowUnix(),
	}); err != nil {
		t.Fatalf("应用远程解封失败: %v", err)
	}
	banned, _ = db.IsBannedForServer("remotebad", "s4a21")
	if banned {
		t.Fatal("远程解封应用后本地仍判封禁")
	}
}

// TestApplyRemotePerServerBanIgnored 锁定"分服封禁不会跨服广播"。
//
// 主网关下发 scope=s5a3 的封禁时，从网关（假设是 s4a21）不该落地。
func TestApplyRemotePerServerBanIgnored(t *testing.T) {
	db := newBanScopeTestDB(t)

	if err := db.ApplyRemoteAccountEvent(AccountEvent{
		ID: 1, EventType: AccountEventBan, Account: "onlys5a3",
		Detail: "只封 S5A3", Scope: "s5a3", CreatedAt: NowUnix(),
	}); err != nil {
		t.Fatalf("应用远程分服封禁失败: %v", err)
	}

	banned, _ := db.IsBannedForServer("onlys5a3", "s4a21")
	if banned {
		t.Fatal("S5A3 的分服封禁被错误地广播到了 S4A21 —— 分服隔离失效")
	}
}

// TestSyncWatermark 锁定水位读写。
func TestSyncWatermark(t *testing.T) {
	db := newBanScopeTestDB(t)

	// 初始水位 0
	w, err := db.SyncWatermark("primary")
	if err != nil {
		t.Fatalf("SyncWatermark(初始): %v", err)
	}
	if w != 0 {
		t.Fatalf("初始水位应为 0，实得 %d", w)
	}

	if err := db.SetSyncWatermark("primary", 42); err != nil {
		t.Fatalf("SetSyncWatermark: %v", err)
	}
	w, _ = db.SyncWatermark("primary")
	if w != 42 {
		t.Fatalf("水位应为 42，实得 %d", w)
	}

	// 更新
	if err := db.SetSyncWatermark("primary", 100); err != nil {
		t.Fatalf("SetSyncWatermark(更新): %v", err)
	}
	w, _ = db.SyncWatermark("primary")
	if w != 100 {
		t.Fatalf("水位应更新为 100，实得 %d", w)
	}

	// 不同 peer 互不影响
	w, _ = db.SyncWatermark("other")
	if w != 0 {
		t.Fatalf("其它 peer 的水位应为 0，实得 %d", w)
	}
}
