package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// newAntiCheatTestDB 起一个最小网关库（本组用例不碰游戏库）。
func newAntiCheatTestDB(t *testing.T) *Database {
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

// TestAntiCheatExemptRoundTrip：exempt / dedup_id 必须能存能取。
//
// 这两个字段是「豁免可见」的落地保证：插件已经在发，网关若丢了，
// 后台就永远看不到"这条命中是不是自研组件造成的"。
func TestAntiCheatExemptRoundTrip(t *testing.T) {
	db := newAntiCheatTestDB(t)

	in := []AntiCheatDetection{
		{
			RuleName: "CodeSectionCrcMismatch", Description: "d", ActualValue: 1, ThresholdValue: 0,
			EventTimestamp: 1000, Evidence: "e", ClientIP: "1.2.3.4", Account: "tester",
			ReportedAt: 2000, Exempt: 1, DedupID: 1234567890123,
		},
		{
			RuleName: "KillTooFast", Description: "d2", ActualValue: 94, ThresholdValue: 300,
			EventTimestamp: 1001, Evidence: "e2", ClientIP: "1.2.3.4", Account: "tester",
			ReportedAt: 2001, Exempt: 0, DedupID: 7,
		},
	}
	if err := db.InsertAntiCheatDetections(in); err != nil {
		t.Fatalf("批量插入失败: %v", err)
	}

	list, total, err := db.GetAntiCheatDetections(10, 0)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 2 || len(list) != 2 {
		t.Fatalf("应有 2 条，实际 total=%d len=%d", total, len(list))
	}
	// ORDER BY reported_at DESC：先是 2001（exempt=0），再是 2000（exempt=1）
	if list[0].Exempt != 0 || list[1].Exempt != 1 {
		t.Errorf("exempt 未正确往返: list[0]=%d list[1]=%d", list[0].Exempt, list[1].Exempt)
	}
	if list[1].DedupID != 1234567890123 {
		t.Errorf("dedup_id 未正确往返: got %d", list[1].DedupID)
	}

	// 按账号查也要带上这两个字段
	byAcct, n, err := db.GetAntiCheatDetectionsByAccount("tester", 10, 0)
	if err != nil || n != 2 {
		t.Fatalf("按账号查失败: n=%d err=%v", n, err)
	}
	found := false
	for _, d := range byAcct {
		if d.Exempt == 1 && d.DedupID == 1234567890123 {
			found = true
		}
	}
	if !found {
		t.Errorf("按账号查未取到 exempt/dedup_id")
	}

	// 单条插入路径同样要带上
	if err := db.InsertAntiCheatDetection(&AntiCheatDetection{
		RuleName: "ExemptActive", EventTimestamp: 1, ReportedAt: 2, Account: "tester",
		Exempt: 1, DedupID: 99,
	}); err != nil {
		t.Fatalf("单条插入失败: %v", err)
	}
}

// TestAntiCheatExemptMigration 老库（无 exempt/dedup_id 列）打开后必须自动补列，
// 且存量行不受影响（缺省 0）。
//
// ★ 这是本次上线的关键路径：线上 161 的库就是"老库"，跑的是 CREATE TABLE
// IF NOT EXISTS（表已存在 → 整段跳过）+ migrateSchema 补列。不补列的话，
// 新版客户端一上报就是"列数不匹配"整批写失败。
func TestAntiCheatExemptMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.db")

	// 1) 手工造一个「旧版」网关库：anticheat_detections 只有 10 列
	raw, err := openSQLite(path, 5)
	if err != nil {
		t.Fatalf("建旧库失败: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE anticheat_detections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_name TEXT NOT NULL,
			description TEXT DEFAULT '',
			actual_value REAL DEFAULT 0,
			threshold_value REAL DEFAULT 0,
			event_timestamp INTEGER NOT NULL,
			evidence TEXT DEFAULT '',
			client_ip TEXT DEFAULT '',
			account TEXT DEFAULT '',
			reported_at INTEGER NOT NULL
		);
		INSERT INTO anticheat_detections (rule_name, account, event_timestamp, reported_at)
			VALUES ('KillTooFast', 'olduser', 1, 2);`); err != nil {
		raw.Close()
		t.Fatalf("建旧 schema 失败: %v", err)
	}
	raw.Close()

	// 2) 正常打开（EnsureInitialized 会跑 migrateSchema）
	db, err := NewDatabase(DatabaseConfig{
		Path:               path,
		GamePath:           filepath.Join(dir, "inventory.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer db.Close()
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	// 3) 断言两列都补上了
	cols := map[string]bool{}
	rows, err := db.gatewayDB.Query("PRAGMA table_info(anticheat_detections)")
	if err != nil {
		t.Fatalf("PRAGMA 失败: %v", err)
	}
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			t.Fatalf("scan 失败: %v", err)
		}
		cols[name] = true
	}
	rows.Close()
	if !cols["exempt"] || !cols["dedup_id"] {
		t.Fatalf("迁移后仍缺列: %v", cols)
	}

	// 4) 存量行必须是缺省 0（迁移不能改动既有数据）
	list, total, err := db.GetAntiCheatDetections(10, 0)
	if err != nil || total != 1 {
		t.Fatalf("查询存量失败: total=%d err=%v", total, err)
	}
	if list[0].Exempt != 0 || list[0].DedupID != 0 {
		t.Errorf("存量行应为缺省 0，实际 exempt=%d dedup=%d", list[0].Exempt, list[0].DedupID)
	}

	// 5) 迁移必须幂等：重复跑不能报错
	if err := db.migrateSchema(); err != nil {
		t.Errorf("二次迁移应幂等，却报错: %v", err)
	}

	// 6) 迁移后新数据要能正常写入（列已就位）
	if err := db.InsertAntiCheatDetection(&AntiCheatDetection{
		RuleName: "ExemptActive", EventTimestamp: 3, ReportedAt: 4, Account: "newuser",
		Exempt: 1, DedupID: 42,
	}); err != nil {
		t.Fatalf("迁移后插入失败: %v", err)
	}
}
