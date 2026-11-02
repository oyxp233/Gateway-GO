package database

// 邮件投递回执的幂等语义测试（纯网关库，不碰游戏库）。
//
// 这是「全服邮件重复点发送不会重复发」的正确性保证：
// 同一个 batch_id 下，同一个角色只会有一条 delivered 回执，
// 重试时被 DeliveredCharacters 跳过。

import (
	"path/filepath"
	"testing"
)

func openReceiptDB(t *testing.T) *Database {
	t.Helper()
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(t.TempDir(), "gateway.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开网关库失败: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMailReceiptIdempotent(t *testing.T) {
	db := openReceiptDB(t)
	const batch = "20261029-120000-abcdef"

	// 空批次：没有任何已投递角色
	done, err := db.DeliveredCharacters(batch)
	if err != nil {
		t.Fatalf("DeliveredCharacters: %v", err)
	}
	if len(done) != 0 {
		t.Fatalf("空批次不该有回执，实得 %d 条", len(done))
	}

	// 角色 1 成功、角色 2 失败
	if err := db.RecordMailReceipt(MailReceipt{
		BatchID: batch, CharacterID: 1, CharacterName: "甲",
		AccountKey: "dnf:10002", ItemCount: 2, Gold: 100,
		Status: MailReceiptDelivered,
	}); err != nil {
		t.Fatalf("写回执(1): %v", err)
	}
	if err := db.RecordMailReceipt(MailReceipt{
		BatchID: batch, CharacterID: 2, CharacterName: "乙",
		Status: MailReceiptFailed, Message: "连接超时",
	}); err != nil {
		t.Fatalf("写回执(2): %v", err)
	}

	done, err = db.DeliveredCharacters(batch)
	if err != nil {
		t.Fatalf("DeliveredCharacters: %v", err)
	}
	if _, ok := done[1]; !ok {
		t.Fatal("角色 1 应该算已投递")
	}
	if _, ok := done[2]; ok {
		t.Fatal("角色 2 是失败状态，不该算已投递")
	}

	// 重试：角色 2 这次成功 —— 回执应被覆盖成 delivered，且**不新增行**
	if err := db.RecordMailReceipt(MailReceipt{
		BatchID: batch, CharacterID: 2, CharacterName: "乙",
		Status: MailReceiptDelivered,
	}); err != nil {
		t.Fatalf("覆盖回执(2): %v", err)
	}
	summary, err := db.SummarizeMailBatch(batch)
	if err != nil {
		t.Fatalf("SummarizeMailBatch: %v", err)
	}
	t.Logf("批次统计: %+v", summary)
	if summary.Total != 2 {
		t.Fatalf("同批次同角色应覆盖而非新增，Total=%d want 2", summary.Total)
	}
	if summary.Delivered != 2 || summary.Failed != 0 {
		t.Fatalf("统计不对: %+v", summary)
	}
}

func TestMailReceiptBatchIsolation(t *testing.T) {
	db := openReceiptDB(t)

	// 两个不同批次各自独立：批次 A 发过角色 1，不影响批次 B 也要发角色 1
	if err := db.RecordMailReceipt(MailReceipt{
		BatchID: "batch-A", CharacterID: 1, Status: MailReceiptDelivered,
	}); err != nil {
		t.Fatal(err)
	}
	doneB, err := db.DeliveredCharacters("batch-B")
	if err != nil {
		t.Fatal(err)
	}
	if len(doneB) != 0 {
		t.Fatalf("批次 B 不该受批次 A 影响，实得 %d 条", len(doneB))
	}
}

func TestNewMailBatchIDUnique(t *testing.T) {
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		id := NewMailBatchID()
		if len(id) < 10 {
			t.Fatalf("批次号太短: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("批次号重复: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestMailReceiptRejectsBadInput(t *testing.T) {
	db := openReceiptDB(t)
	if err := db.RecordMailReceipt(MailReceipt{BatchID: "", CharacterID: 1}); err == nil {
		t.Fatal("空 batch_id 应该报错")
	}
	if err := db.RecordMailReceipt(MailReceipt{BatchID: "b", CharacterID: 0}); err == nil {
		t.Fatal("character_id=0 应该报错")
	}
}
