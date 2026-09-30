package service

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
)

// makeAuditDb 造一个带 inventory_audit_log 表（含 3 个二级索引）的临时库存库。
// 表结构与线上一致：audit_id / created_at / session_id / owner_scope / owner_id /
// character_id / account_id / action_name / payload_json。
func makeAuditDb(t *testing.T, dir string, rows int, payloadBytes int) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "inventory.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	stmts := []string{
		"PRAGMA journal_mode=WAL",
		`CREATE TABLE inventory_audit_log (
			audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,
			session_id INTEGER NOT NULL DEFAULT 0,
			owner_scope TEXT NOT NULL DEFAULT '',
			owner_id INTEGER NOT NULL DEFAULT 0,
			character_id INTEGER NOT NULL DEFAULT 0,
			account_id INTEGER NOT NULL DEFAULT 0,
			action_name TEXT NOT NULL DEFAULT '',
			payload_json TEXT NOT NULL DEFAULT '{}')`,
		"CREATE INDEX idx_inventory_audit_action_time ON inventory_audit_log(action_name, created_at)",
		"CREATE INDEX idx_inventory_audit_char_time ON inventory_audit_log(character_id, created_at)",
		"CREATE INDEX idx_inventory_audit_account_time ON inventory_audit_log(account_id, created_at)",
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("setup %q: %v", s, err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.Prepare("INSERT INTO inventory_audit_log (created_at, character_id, account_id, action_name, payload_json) VALUES (?,?,?,?,?)")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	payload := strings.Repeat("x", payloadBytes)
	for i := 0; i < rows; i++ {
		if _, err := stmt.Exec("2026-09-25 01:19:28", i%800, i%20, "inventory_slot_update", payload); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	return path
}

func countAuditRows(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open ro: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM inventory_audit_log").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestPurgeGameAuditLog 正常路径：行清空 + 文件确实变小。
func TestPurgeGameAuditLog(t *testing.T) {
	dir := t.TempDir()
	const rows = 120000
	path := makeAuditDb(t, dir, rows, 128)

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	got, sizeBefore, sizeAfter, err := purgeGameAuditLog(path, nil)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got != rows {
		t.Fatalf("删除行数 = %d，期望 %d", got, rows)
	}
	if n := countAuditRows(t, path); n != 0 {
		t.Fatalf("清空后仍有 %d 行", n)
	}
	if sizeBefore != before.Size() {
		t.Errorf("sizeBefore(%d) 应等于调用前文件大小(%d)", sizeBefore, before.Size())
	}
	if sizeAfter >= sizeBefore {
		t.Fatalf("VACUUM 后文件没变小: %d -> %d", sizeBefore, sizeAfter)
	}
	// 重建后应该只剩几页（≤ 1MB），留足余量避免文件系统块大小差异导致抖动
	if sizeAfter > 1<<20 {
		t.Errorf("收缩后仍偏大: %d 字节", sizeAfter)
	}
}

// TestPurgeGameAuditLogIdempotent 再跑一次：0 行、无错、文件不再变。
func TestPurgeGameAuditLogIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := makeAuditDb(t, dir, 5000, 64)

	if _, _, _, err := purgeGameAuditLog(path, nil); err != nil {
		t.Fatalf("first purge: %v", err)
	}
	rows, before, after, err := purgeGameAuditLog(path, nil)
	if err != nil {
		t.Fatalf("second purge: %v", err)
	}
	if rows != 0 {
		t.Errorf("第二次应删 0 行，实得 %d", rows)
	}
	if before != after {
		t.Errorf("第二次不该改文件大小: %d -> %d", before, after)
	}
}

// TestPurgeGameAuditLogNoTable 老库/开发库没有这张表 → 静默跳过，不报错。
func TestPurgeGameAuditLogNoTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE characters (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	db.Close()

	rows, before, after, err := purgeGameAuditLog(path, nil)
	if err != nil {
		t.Fatalf("缺表不应报错，实得: %v", err)
	}
	if rows != 0 || before != after {
		t.Errorf("缺表应原样返回: rows=%d before=%d after=%d", rows, before, after)
	}
}

// TestPurgeAuditLogEnabledDefault 开关缺省必须是"开"。
// 现网 appsettings.json 里没有这个键，用 bool 会得到零值 false → 功能静默失效。
func TestPurgeAuditLogEnabledDefault(t *testing.T) {
	var s config.ServerSection
	if !s.PurgeAuditLogEnabled() {
		t.Fatal("未配置时应视为启用（true）")
	}
	f := false
	s.BackupPurgeAuditLog = &f
	if s.PurgeAuditLogEnabled() {
		t.Fatal("显式 false 应关闭")
	}
	tr := true
	s.BackupPurgeAuditLog = &tr
	if !s.PurgeAuditLogEnabled() {
		t.Fatal("显式 true 应启用")
	}
}

// TestBackupSkipsPurgeWithoutGameDb 没有游戏库可备份时绝不能删审计日志（会丢数据）。
func TestBackupSkipsPurgeWithoutGameDb(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Server.BackupDir = filepath.Join(dir, "backups")
	cfg.Database.GamePath = filepath.Join(dir, "nonexistent.db")
	cfg.Database.Path = ""
	cfg.Server.PvfPath = ""
	cfg.Server.WorkDir = ""

	mgr := &ServerManager{config: cfg}
	res := mgr.Backup()
	if res.Ok {
		t.Fatalf("没有可备份目标时应失败，实得 Ok=true")
	}
	if res.AuditPurgedRows != 0 {
		t.Errorf("不该删任何行，实得 %d", res.AuditPurgedRows)
	}
}

// TestBackupPurgesAfterSuccess 端到端（服务层）：备份成功后审计日志被清空、库变小。
func TestBackupPurgesAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	gamePath := makeAuditDb(t, filepath.Join(dir, "data"), 30000, 96)
	before, _ := os.Stat(gamePath)

	cfg := config.DefaultConfig()
	cfg.Server.BackupDir = filepath.Join(dir, "backups")
	cfg.Database.GamePath = gamePath
	cfg.Database.Path = ""
	cfg.Server.PvfPath = ""
	cfg.Server.WorkDir = ""

	mgr := &ServerManager{config: cfg}
	res := mgr.Backup()
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}
	if res.AuditPurgeError != "" {
		t.Fatalf("清理报错: %s", res.AuditPurgeError)
	}
	if res.AuditPurgedRows != 30000 {
		t.Fatalf("清理行数 = %d，期望 30000", res.AuditPurgedRows)
	}
	if res.GameDbBytesAfter >= res.GameDbBytesBefore {
		t.Fatalf("库未变小: %d -> %d", res.GameDbBytesBefore, res.GameDbBytesAfter)
	}
	// 备份产物里必须还留着完整审计日志（清的是线上库，不是备份）
	entries, err := os.ReadDir(cfg.Server.BackupDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var invFile string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "inventory-") {
			invFile = filepath.Join(cfg.Server.BackupDir, e.Name())
		}
	}
	if invFile == "" {
		t.Fatal("没找到 inventory 备份产物")
	}
	if n := countAuditRows(t, invFile); n != 30000 {
		t.Errorf("备份里应有完整 %d 行审计日志，实得 %d", 30000, n)
	}
	if res.GameDbBytesBefore < before.Size() {
		t.Errorf("before(%d) 不应小于原始文件(%d)", res.GameDbBytesBefore, before.Size())
	}
}
