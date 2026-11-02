package database

// ============================================================================
// 老库升级测试（2026-10-24）
//
// 背景：invite_codes / account_events / account_sync_state 都是后加的表，
// 用 CREATE TABLE IF NOT EXISTS 补建。**升级路径本身没被测过** ——
// 而这是每次发版都会走的路：玩家的 gateway.db 是旧的，新版本启动时要能补上新表。
//
// 如果漏测，症状是"本地测试全绿，线上升级后注册功能报 no such table"。
//
// 覆盖三条不变量：
//   ① 旧库（只有 accounts 等老表）→ EnsureInitialized 后新表存在且可用
//   ② 新库再次 EnsureInitialized 是幂等的（不报错、不丢数据）
//   ③ 旧库里已有的账号数据在升级后完好
// ============================================================================

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// legacyTables 是"升级前"就有的老表。
//
// 刻意**不含** invite_codes / account_events / account_sync_state ——
// 那三张是 2026-10-22~24 才加的。
var legacyTables = []string{
	`CREATE TABLE accounts (
		m_id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		pwd_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		cera INTEGER DEFAULT 0,
		token_cera INTEGER DEFAULT 0,
		happy_token_cera INTEGER DEFAULT 0,
		device_secret TEXT DEFAULT '',
		device_secret_issued_at TEXT DEFAULT '',
		device_history TEXT DEFAULT '',
		created_at INTEGER DEFAULT 0,
		last_login_at INTEGER DEFAULT 0,
		login_fail_count INTEGER DEFAULT 0,
		locked_until INTEGER DEFAULT 0
	)`,
	`CREATE TABLE register_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account TEXT NOT NULL,
		m_id TEXT NOT NULL,
		ip TEXT DEFAULT '',
		machine_id TEXT DEFAULT '',
		created_at INTEGER DEFAULT 0
	)`,
}

// newLegacyDB 造一个"升级前"的库：只有老表 + 一条老账号数据。
func newLegacyDB(t *testing.T) (string, *Database) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.db")

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("开旧库: %v", err)
	}
	for _, ddl := range legacyTables {
		if _, err := raw.Exec(ddl); err != nil {
			raw.Close()
			t.Fatalf("建老表失败: %v", err)
		}
	}
	// 塞一条"存量账号"——升级绝不能把它弄丢
	if _, err := raw.Exec(
		`INSERT INTO accounts (m_id, name, pwd_hash, salt, created_at)
		 VALUES ('100001', 'olduser', 'x', 'y', 1700000000)`); err != nil {
		raw.Close()
		t.Fatalf("塞存量账号失败: %v", err)
	}
	raw.Close()

	// 用新版 NewDatabase 打开同一个文件（模拟"升级后启动"）
	db, err := NewDatabase(DatabaseConfig{
		Path:               path,
		GamePath:           filepath.Join(dir, "inventory.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	t.Cleanup(db.Close)
	return path, db
}

// TestUpgradeFromLegacyAddsInviteTable 锁定"旧库升级后 invite_codes 可用"。
//
// ★ 这条最关键：如果 EnsureInitialized 漏了 invite_codes，
//   升级后的第一个注册请求就会报 no such table: invite_codes。
func TestUpgradeFromLegacyAddsInviteTable(t *testing.T) {
	_, db := newLegacyDB(t)

	// 升级前 invite_codes 不存在（确认这个测试真的在测"旧库"）
	var before int
	if err := db.gatewayDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='invite_codes'`).Scan(&before); err != nil {
		t.Fatalf("查 sqlite_master 失败: %v", err)
	}
	if before != 0 {
		t.Skip("该库已有 invite_codes，不是旧库")
	}

	// 升级
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("EnsureInitialized 失败: %v", err)
	}

	// 表应存在
	var after int
	if err := db.gatewayDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type='table' AND name='invite_codes'`).Scan(&after); err != nil {
		t.Fatalf("查 sqlite_master 失败: %v", err)
	}
	if after != 1 {
		t.Fatal("升级后 invite_codes 表应存在")
	}

	// ★ 而且真的能读写（建了表但列不对也会在这里暴露）
	if err := db.CreateInviteWithCode("TESTUPG1", "upgrade", "admin:test", 0); err != nil {
		t.Fatalf("升级后无法插邀请码: %v", err)
	}
	if r := db.ConsumeInvite("TESTUPG1", "u"); r != InviteConsumeOK {
		t.Fatalf("升级后无法消耗邀请码，实得 %d", r)
	}

	// 另外两张后加的表也要在
	for _, tbl := range []string{"account_events", "account_sync_state"} {
		var n int
		if err := db.gatewayDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master
			WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil {
			t.Fatalf("查 %s 失败: %v", tbl, err)
		}
		if n != 1 {
			t.Fatalf("升级后 %s 表应存在", tbl)
		}
	}
}

// TestUpgradePreservesLegacyData 锁定"升级不丢存量账号"。
func TestUpgradePreservesLegacyData(t *testing.T) {
	_, db := newLegacyDB(t)

	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("EnsureInitialized 失败: %v", err)
	}

	acc, err := db.GetAccountByName("olduser")
	if err != nil || acc == nil {
		t.Fatalf("存量账号丢了: err=%v acc=%v", err, acc)
	}
	if acc.MId != "100001" {
		t.Fatalf("存量账号 m_id 应为 100001，实得 %s", acc.MId)
	}
}

// TestEnsureInitializedIdempotent 锁定"重复调用是幂等的"。
//
// 网关重启时会再跑一次 EnsureInitialized，必须不报错也不动数据。
func TestEnsureInitializedIdempotent(t *testing.T) {
	_, db := newLegacyDB(t)

	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("首次 EnsureInitialized 失败: %v", err)
	}
	// 造点数据，第二次升级后要还在
	if err := db.CreateInviteWithCode("TESTIDEM", "idem", "admin:test", 0); err != nil {
		t.Fatalf("插码失败: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := db.EnsureInitialized(); err != nil {
			t.Fatalf("第 %d 次 EnsureInitialized 失败: %v", i+2, err)
		}
	}

	n, _ := db.CountUnusedInvites()
	if n != 1 {
		t.Fatalf("重复升级后邀请码数应为 1，实得 %d", n)
	}
}

// TestFreshDBHasInviteTable 锁定"全新库也有 invite_codes"（反方向保障）。
func TestFreshDBHasInviteTable(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           filepath.Join(dir, "inventory.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("开库: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("建表: %v", err)
	}
	t.Cleanup(db.Close)

	// 直接就能用，不需要额外 upgrade 步骤
	if _, err := db.GenerateInvites(1, "fresh", "admin:test", 0); err != nil {
		t.Fatalf("全新库应能直接生成邀请码: %v", err)
	}
}
