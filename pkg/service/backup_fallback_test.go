package service

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/utils"
)

// ────────────────────────────────────────────────────────────────────────
// P2-2：备份的 VACUUM INTO 失败后，回退分支不能一律直接复制文件。
//
// 源库正在写入时 WAL 里还有未并回主库的页，纯文件复制不经过 SQLite，
// 复制出来的 .db 会停在半写入状态 —— 而这份副本是要当"备份"交付的。
// 回退于是分两种情况：不是 SQLite 库（PVF/文本）照旧复制；
// 是 SQLite 就先 wal_checkpoint(FULL) 再复制，checkpoint 也失败就报错。
// ────────────────────────────────────────────────────────────────────────

// 走法 (a)：源不是 SQLite 库时，回退必须老老实实做文件复制。
//
// 这里特意传 nil 句柄：非 SQLite 源应当在**完全不解引用 db** 的情况下返回，
// 这正好证明"是不是 SQLite"的判定发生在碰数据库之前 ——
// 否则对 PVF 硬跑 checkpoint 会让原本能成功的备份整体失败。
func TestFallbackCheckpointSkipsNonSQLiteSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "Script.pvf")
	if err := os.WriteFile(src, []byte("PVF\x00not-a-sqlite-database"), 0o644); err != nil {
		t.Fatalf("造样本失败: %v", err)
	}

	if isSQLiteFile(src) {
		t.Fatalf("文本文件被误判成 SQLite 库")
	}
	if err := fallbackCheckpoint(nil, src); err != nil {
		t.Fatalf("非 SQLite 源不该走 checkpoint，却返回错误: %v", err)
	}
}

// 端到端零回归：backupSqliteFile 对非 SQLite 源必须仍然成功。
// 旧实现的回退分支就是为这类文件准备的（PVF / 旧驱动），
// 改成"一律 checkpoint"会直接打断 PVF 备份。
func TestBackupSqliteFileCopiesNonSQLiteSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "Script.pvf")
	dst := filepath.Join(dir, "out", "Script.pvf")
	body := []byte("PVF\x00binary-ish\x00\x01\x02\x03")

	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatalf("造样本失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}

	if err := backupSqliteFile(src, dst); err != nil {
		t.Fatalf("非 SQLite 源的备份不该失败: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("读副本失败: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("副本内容不一致：期望 %d 字节，实际 %d 字节", len(body), len(got))
	}
}

// 走法 (c)：checkpoint 无法完成时必须报错，而不是交付一个不确定的副本。
//
// 构造：给一个已关闭的句柄 —— 真实场景对应"源库被别人独占 / 连接已失效"。
// 修复前这里会安静地做文件复制并返回 nil，运维拿到一份可能缺数据的"备份"却毫无察觉。
func TestFallbackCheckpointRefusesWhenCheckpointFails(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "gateway.db")

	rawDB := openTestSQLite(t, src)
	if _, err := rawDB.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	if !isSQLiteFile(src) {
		t.Fatalf("刚建的库没被识别成 SQLite")
	}

	// 关掉句柄：checkpoint 必然失败。
	if err := rawDB.Close(); err != nil {
		t.Fatalf("关闭句柄失败: %v", err)
	}

	err := fallbackCheckpoint(rawDB, src)
	if err == nil {
		t.Fatalf("checkpoint 不可用时必须报错，不能静默返回 nil（会交付不一致的副本）")
	}
}

// 走法 (b) 的核心：源是 SQLite 且 WAL 里还有未并回主库的页时，
// 回退必须先 checkpoint(FULL) 再复制，副本才能独立打开并查到最新数据。
//
// 用例自带对照组：先按"修复前的做法"直接复制一次主库文件，
// 断言它拿不到刚写的数据 —— 这条对照组证明了本用例有区分力，
// 否则测试可能只是碰巧绿。
func TestFallbackCheckpointMergesWalBeforeCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "gateway.db")

	rawDB := openTestSQLite(t, src)
	defer rawDB.Close()

	if _, err := rawDB.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	const marker = "after-create"
	if _, err := rawDB.Exec("INSERT INTO t (v) VALUES (?)", marker); err != nil {
		t.Fatalf("插入失败: %v", err)
	}

	// ── 对照组：修复前的回退做法（直接复制主库文件）──────────────
	naive := filepath.Join(dir, "naive-copy.db")
	if err := utils.CopyFile(src, naive); err != nil {
		t.Fatalf("对照组复制失败: %v", err)
	}
	if n := probeRowCount(t, naive, marker); n == 1 {
		t.Fatalf("对照组就能读到最新数据 —— 说明本环境写后已自动 checkpoint，" +
			"本用例失去区分力，需要换构造方式")
	}

	// ── 修复后的回退做法：先 checkpoint，再复制 ──────────────────
	if err := fallbackCheckpoint(rawDB, src); err != nil {
		t.Fatalf("SQLite 源的 checkpoint 不该失败: %v", err)
	}

	fixed := filepath.Join(dir, "fixed-copy.db")
	if err := utils.CopyFile(src, fixed); err != nil {
		t.Fatalf("复制失败: %v", err)
	}
	if n := probeRowCount(t, fixed, marker); n != 1 {
		t.Fatalf("checkpoint 后复制的副本仍读不到最新数据（count=%d）—— 备份不一致", n)
	}
}

// openTestSQLite 打开（或新建）一个 WAL 模式的裸 SQLite 连接。
// 不走 database 包的 EnsureInitialized：本用例只关心 WAL / checkpoint 行为，
// 不需要业务表结构。
func openTestSQLite(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		t.Fatalf("设置 WAL 失败: %v", err)
	}
	return db
}

// probeRowCount 用一个全新连接读副本里 v=marker 的行数。
// 读不到表（副本里压根没有这个表）返回 -1，与"表在但没数据"区分开。
func probeRowCount(t *testing.T, path, marker string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Logf("打开副本失败: %v", err)
		return -1
	}
	defer db.Close()

	var n int
	if err := db.QueryRow("SELECT count(*) FROM t WHERE v = ?", marker).Scan(&n); err != nil {
		return -1
	}
	return n
}
