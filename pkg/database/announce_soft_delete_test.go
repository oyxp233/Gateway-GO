package database

import (
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/models"
)

// TestDeleteAnnouncePopupSentVisible 已投递的弹窗也要能从后台删掉。
//
// 这条是本次报障的回归：旧实现只允许删 pending，已投递的一律 409，
// 而后台最常被点的恰恰是刚发出去那几条 —— 表现就是"撤销按钮无效"。
func TestDeleteAnnouncePopupSentVisible(t *testing.T) {
	db := newAnnounceTestDB(t)

	id, err := db.EnqueueAnnouncePopup("已经发出去的全服公告", 0, "tester")
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	// 先让它真的被插件取走（status -> sent）。
	if _, err := db.TakePendingAnnouncePopups(10, 900); err != nil {
		t.Fatalf("取弹窗失败: %v", err)
	}
	if n, list, _ := db.QueryAnnouncePopups(models.AnnouncePopupSent, 1, 10); n != 1 || list[0].ID != id {
		t.Fatalf("应有一条 sent 记录，实得 total=%d list=%+v", n, list)
	}

	ok, err := db.DeleteAnnouncePopup(id)
	if err != nil || !ok {
		t.Fatalf("sent 弹窗应可删，ok=%v err=%v", ok, err)
	}

	if n, _, _ := db.QueryAnnouncePopups("", 1, 10); n != 0 {
		t.Fatalf("删除后列表应为 0 条（不限状态过滤），实得 %d", n)
	}
	if n, _, _ := db.QueryAnnouncePopups(models.AnnouncePopupSent, 1, 10); n != 0 {
		t.Fatalf("删除后按 sent 过滤也应为 0 条，实得 %d", n)
	}
}

// TestDeleteAnnouncePopupIdempotent 重复删除返回 false 但不报错（后台连点两下不炸）。
func TestDeleteAnnouncePopupIdempotent(t *testing.T) {
	db := newAnnounceTestDB(t)

	id, err := db.EnqueueAnnouncePopup("只删一次", 0, "tester")
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}

	if ok, err := db.DeleteAnnouncePopup(id); err != nil || !ok {
		t.Fatalf("第一次删除应成功，ok=%v err=%v", ok, err)
	}
	if ok, err := db.DeleteAnnouncePopup(id); err != nil || ok {
		t.Fatalf("第二次删除应返回 false 且不报错，ok=%v err=%v", ok, err)
	}
	// 不存在的 id 同理。
	if ok, err := db.DeleteAnnouncePopup(999999); err != nil || ok {
		t.Fatalf("不存在的 id 应返回 false 且不报错，ok=%v err=%v", ok, err)
	}
}

// TestTakePendingSkipsDeleted 被删掉的待投递弹窗绝不能再被插件拉走。
//
// 少这个 deleted_at 过滤就会"删了还在飘"：后台看着已经没了，
// 玩家屏幕上照样弹出——运维最不能接受的一类不一致。
func TestTakePendingSkipsDeleted(t *testing.T) {
	db := newAnnounceTestDB(t)

	keep, err := db.EnqueueAnnouncePopup("保留的公告", 0, "tester")
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	drop, err := db.EnqueueAnnouncePopup("删掉的公告", 0, "tester")
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if ok, err := db.DeleteAnnouncePopup(drop); err != nil || !ok {
		t.Fatalf("删除失败，ok=%v err=%v", ok, err)
	}

	got, err := db.TakePendingAnnouncePopups(10, 900)
	if err != nil {
		t.Fatalf("取弹窗失败: %v", err)
	}
	if len(got) != 1 || got[0].ID != keep {
		t.Fatalf("只应取到未被删除的那条，实得 %+v", got)
	}

	// 被删的那条状态不能被改成 sent/expired —— 它就该留在 pending 且已删除。
	var status string
	var deletedAt int64
	if err := db.gatewayDB.QueryRow(
		"SELECT status, deleted_at FROM announce_popups WHERE id = ?", drop).Scan(&status, &deletedAt); err != nil {
		t.Fatalf("查被删记录失败: %v", err)
	}
	if status != models.AnnouncePopupPending || deletedAt == 0 {
		t.Fatalf("被删记录应保持 pending 且 deleted_at != 0，实得 status=%s deleted_at=%d", status, deletedAt)
	}
}

// TestEnsureColumnAddsDeletedAt 老库（没有 deleted_at 列）启动后必须自动补列。
//
// 线上 202 的网关库是 9/23 建的，里面没有这一列；不补列的话，
// 所有弹窗查询会在启动后直接报 "no such column: deleted_at"。
func TestEnsureColumnAddsDeletedAt(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	t.Cleanup(db.Close)

	// 手工造一张"升级前"的表：结构与线上 9/23 那版一致，没有 deleted_at。
	if _, err := db.gatewayDB.Exec(`
		CREATE TABLE announce_popups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			message TEXT NOT NULL,
			mode INTEGER DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'pending',
			created_by TEXT DEFAULT '',
			created_at INTEGER NOT NULL,
			sent_at INTEGER DEFAULT 0,
			delivered_at INTEGER DEFAULT 0
		)`); err != nil {
		t.Fatalf("建老表失败: %v", err)
	}
	if _, err := db.gatewayDB.Exec(
		"INSERT INTO announce_popups(message, status, created_at) VALUES('老公告', 'sent', 1000)"); err != nil {
		t.Fatalf("插入老数据失败: %v", err)
	}
	if hasColumn(t, db, "announce_popups", "deleted_at") {
		t.Fatal("前置条件不成立：老表里不该已经有 deleted_at")
	}

	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	if !hasColumn(t, db, "announce_popups", "deleted_at") {
		t.Fatal("迁移后应补上 deleted_at 列")
	}
	// 老数据要保留，且默认未删除（值为 0）。
	n, list, err := db.QueryAnnouncePopups("", 1, 10)
	if err != nil {
		t.Fatalf("迁移后查询失败: %v", err)
	}
	if n != 1 || len(list) != 1 || list[0].Message != "老公告" {
		t.Fatalf("老数据应保持可见，实得 total=%d list=%+v", n, list)
	}
	// 老数据同样可以删。
	if ok, err := db.DeleteAnnouncePopup(list[0].ID); err != nil || !ok {
		t.Fatalf("老数据应可删，ok=%v err=%v", ok, err)
	}
}

func hasColumn(t *testing.T, db *Database, table, column string) bool {
	t.Helper()
	rows, err := db.gatewayDB.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info 失败: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue any
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			t.Fatalf("扫描列信息失败: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}
