package database

// ============================================================================
// 邮件投递回执（永久幂等）
//
// 参考 PurpleMagic 的 benefit receipts 设计：**邮件、附件、回执在同一个
// 事务里提交**，回执一旦写下就永久有效，删除邮件不会重置它。
//
// ── 为什么 S5A3 必须有这一层 ──────────────────────────────────────────────
//
// S5A3 的邮箱是**整箱 replace** 语义（服务端 mysql_mail.go 的 replaceMails：
// DELETE 该角色全部邮件 → 按内存里的邮箱重插）。于是：
//
//	① 玩家在线时网关写库 → 玩家退出存档 → 邮件被删掉
//	② 运维看到"发了没收到" → 再点一次发送
//	③ 离线玩家收到两封，在线玩家还是零封
//
// 回执把「这条批次对这个角色发过没有」变成可查的事实，重试只补没成功的，
// 与 ①② 都解耦。
//
// ── 为什么回执放网关库（SQLite）而不是游戏库 ──────────────────────────────
//
//   - 游戏库是 S5A3 服务端的主权领地，多一张非它建的表会让服务端的
//     schema 巡检/迁移逻辑意外；
//   - 回执是**运营审计**数据，与游戏存档无关，放网关库反而更好备份与查询；
//   - S4A21 部署不需要这张表也能正常工作（GameBackend 不是 s5a3 时不写回执）。
// ============================================================================

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// 回执状态。只有 Delivered 会被当作"已成功、重试时跳过"。
const (
	// MailReceiptDelivered 投递成功（游戏库事务已提交）。
	MailReceiptDelivered = "delivered"
	// MailReceiptFailed 投递失败（可重试）。
	MailReceiptFailed = "failed"
	// MailReceiptSkipped 因故跳过（在线/无角色），重试时**要重试**。
	MailReceiptSkipped = "skipped"
)

// MailReceipt 一条投递回执。
type MailReceipt struct {
	BatchID       string
	CharacterID   int64
	CharacterName string
	AccountKey    string
	ItemCount     int
	Gold          int64
	Status        string
	Message       string
}

// RecordMailReceipt 写一条投递回执（同批次同角色覆盖写）。
//
// 用 `ON CONFLICT DO UPDATE` 而不是 INSERT OR REPLACE：后者会换掉自增 id，
// 让"这条回执什么时候第一次写下的"这个信息丢失。
func (db *Database) RecordMailReceipt(r MailReceipt) error {
	if db == nil || db.gatewayDB == nil {
		return errors.New("网关库未就绪")
	}
	batchID := strings.TrimSpace(r.BatchID)
	if batchID == "" {
		return errors.New("batch_id 不能为空")
	}
	if r.CharacterID <= 0 {
		return errors.New("character_id 非法")
	}
	status := strings.TrimSpace(r.Status)
	if status == "" {
		status = MailReceiptFailed
	}
	query := `
		INSERT INTO mail_dispatch_receipts
			(batch_id, character_id, character_name, account_key, item_count, gold, status, message, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(batch_id, character_id) DO UPDATE SET
			character_name = excluded.character_name,
			account_key    = excluded.account_key,
			item_count     = excluded.item_count,
			gold           = excluded.gold,
			status         = excluded.status,
			message        = excluded.message,
			created_at     = excluded.created_at`
	_, err := db.gatewayDB.Exec(query,
		batchID, r.CharacterID, r.CharacterName, r.AccountKey,
		r.ItemCount, r.Gold, status, r.Message, time.Now().Unix())
	return err
}

// DeliveredCharacters 返回某批次里**已经成功投递**的角色 ID 集合。
//
// 全服邮件重试时用它跳过已成功的：这是"点第二次不会重复发"的唯一依据。
func (db *Database) DeliveredCharacters(batchID string) (map[int64]struct{}, error) {
	out := make(map[int64]struct{})
	if db == nil || db.gatewayDB == nil {
		return out, nil
	}
	batchID = strings.TrimSpace(batchID)
	if batchID == "" {
		return out, nil
	}
	rows, err := db.gatewayDB.Query(
		"SELECT character_id FROM mail_dispatch_receipts WHERE batch_id = ? AND status = ?",
		batchID, MailReceiptDelivered)
	if err != nil {
		return out, fmt.Errorf("查询投递回执: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return out, err
		}
		out[id] = struct{}{}
	}
	return out, rows.Err()
}

// MailReceiptSummary 是某批次的统计（后台展示"这批发了多少/失败多少"）。
type MailReceiptSummary struct {
	BatchID   string `json:"batch_id"`
	Total     int    `json:"total"`
	Delivered int    `json:"delivered"`
	Failed    int    `json:"failed"`
	Skipped   int    `json:"skipped"`
}

// SummarizeMailBatch 统计某批次的回执。
func (db *Database) SummarizeMailBatch(batchID string) (MailReceiptSummary, error) {
	summary := MailReceiptSummary{BatchID: strings.TrimSpace(batchID)}
	if db == nil || db.gatewayDB == nil || summary.BatchID == "" {
		return summary, nil
	}
	rows, err := db.gatewayDB.Query(
		"SELECT status, COUNT(*) FROM mail_dispatch_receipts WHERE batch_id = ? GROUP BY status",
		summary.BatchID)
	if err != nil {
		return summary, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return summary, err
		}
		summary.Total += n
		switch status {
		case MailReceiptDelivered:
			summary.Delivered = n
		case MailReceiptFailed:
			summary.Failed = n
		case MailReceiptSkipped:
			summary.Skipped = n
		}
	}
	return summary, rows.Err()
}

// NewMailBatchID 生成一个批次号（后台一次"发送"对应一个批次）。
//
// 形如 `20261029-101530-a1b2c3`：前缀是可读时间（运维在日志里能对上是哪次），
// 后缀随机保证同一秒内多次发送不会撞号。
func NewMailBatchID() string {
	suffix, err := generateToken()
	if err != nil || len(suffix) < 6 {
		suffix = "000000"
	}
	return time.Now().Format("20060102-150405") + "-" + suffix[:6]
}
