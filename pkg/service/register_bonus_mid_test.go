package service

import (
	"database/sql"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
)

// setupRegisterBonusWorld 在 setupBonusWorld 之上补齐注册奖励发放路径需要的表：
// characters + mailbox_messages / mailbox_recipients / mailbox_attachments。
func setupRegisterBonusWorld(t *testing.T) (*database.Database, string) {
	t.Helper()
	db, gamePath := setupBonusWorld(t)

	conn, err := sql.Open("sqlite", "file:"+gamePath)
	if err != nil {
		t.Fatalf("打开游戏库失败: %v", err)
	}
	defer conn.Close()

	stmts := []string{
		`CREATE TABLE characters (
			character_id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id   INTEGER NOT NULL,
			name         BLOB,
			level        INTEGER DEFAULT 1,
			job          INTEGER DEFAULT 0,
			delete_flag  INTEGER DEFAULT 0)`,
		`CREATE TABLE mailbox_messages (
			message_id INTEGER PRIMARY KEY AUTOINCREMENT,
			sender_character_id INTEGER NOT NULL DEFAULT 0,
			sender_account_id INTEGER NOT NULL DEFAULT 0,
			sender_name TEXT NOT NULL DEFAULT '',
			receiver_character_id INTEGER NOT NULL,
			receiver_account_id INTEGER NOT NULL DEFAULT 0,
			receiver_name TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL DEFAULT '',
			body TEXT NOT NULL DEFAULT '',
			gold INTEGER NOT NULL DEFAULT 0,
			fee_gold INTEGER NOT NULL DEFAULT 0,
			mail_type INTEGER NOT NULL DEFAULT 0,
			source_protocol INTEGER NOT NULL DEFAULT 0,
			idempotency_key TEXT,
			request_hash TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			unlimited_flag INTEGER NOT NULL DEFAULT 0,
			expire_at TEXT NOT NULL,
			deleted_by_sender INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE mailbox_recipients (
			recipient_id INTEGER PRIMARY KEY AUTOINCREMENT,
			message_id INTEGER NOT NULL,
			character_id INTEGER NOT NULL,
			folder INTEGER NOT NULL DEFAULT 0,
			read_flag INTEGER NOT NULL DEFAULT 0,
			saved_flag INTEGER NOT NULL DEFAULT 0,
			deleted_flag INTEGER NOT NULL DEFAULT 0,
			received_gold_flag INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE mailbox_attachments (
			attachment_id INTEGER PRIMARY KEY AUTOINCREMENT,
			message_id INTEGER NOT NULL,
			ordinal INTEGER NOT NULL DEFAULT 0,
			item_type INTEGER NOT NULL DEFAULT 0,
			source_list_type INTEGER NOT NULL DEFAULT 0,
			source_slot_index INTEGER NOT NULL DEFAULT 0,
			item_template_id INTEGER NOT NULL,
			item_kind TEXT NOT NULL DEFAULT 'unknown',
			item_count INTEGER NOT NULL,
			expire_time INTEGER NOT NULL DEFAULT 0,
			claimed_flag INTEGER NOT NULL DEFAULT 0)`,
	}
	for _, s := range stmts {
		if _, err := conn.Exec(s); err != nil {
			t.Fatalf("建表失败: %v", err)
		}
	}
	return db, gamePath
}

func newRegisterBonusSvc(t *testing.T, db *database.Database) *RegisterBonusService {
	t.Helper()
	log, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("建日志失败: %v", err)
	}
	t.Cleanup(func() { log.Close() })
	return NewRegisterBonusService(db, &config.GatewayConfig{}, log)
}

func registerBonusCfg() *models.RegisterBonusConfig {
	return &models.RegisterBonusConfig{
		Enabled:                true,
		Cera:                   50000,
		TokenCera:              20000,
		HappyTokenCera:         10000,
		Gold:                   500000,
		Title:                  "注册奖励",
		Body:                   "欢迎",
		ItemExpireHours:        24,
		ItemSplitCount:         2000,
		ItemStackLimit:         20000,
		ItemDeliverLimit:       100,
		ItemAttachmentsPerMail: 10,
		Items: []models.RegisterBonusItem{
			{ItemId: 3037, Name: "无色小晶块", Count: 1000, Kind: 3},
			{ItemId: 3051, Name: "斯卡迪女王的印章", Count: 100, Kind: 3},
		},
	}
}

// 角色名是 GBK 裸字节：「地狱酷哥」
var gbkCharName = []byte{0xb5, 0xd8, 0xd3, 0xfc, 0xbf, 0xe1, 0xb8, 0xe7}

// TestProcessRegisteredUsesMIdNotAccountName 锁住 2026-09-29 修复的那个 bug：
//
//	processRegistered 曾经把「登录名」当 m_id 去查游戏库（AddCurrencyToGameAccount
//	/ FindFirstAliveCharacter 的 SQL 都是 WHERE m_id = ?）。而 AllocateNumericMId
//	会给「非纯数字登录名」另分配数字 m_id（kokiku -> 932320940），于是昵称型账号的
//	注册奖励永远命中 0 行、不报错也不记日志，静默丢失。
//
// 本用例刻意让 name != m_id，断言奖励落到 m_id 那一行；换回旧实现时它会失败。
func TestProcessRegisteredUsesMIdNotAccountName(t *testing.T) {
	db, gamePath := setupRegisterBonusWorld(t)

	const mId = "932320940"
	const name = "kokiku" // 昵称型：m_id 与登录名不同 —— 正是出问题的那一类

	execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES (?, 0)", mId)
	execOnGame(t, gamePath,
		"INSERT INTO characters (account_id, name, level, job, delete_flag) VALUES (1, ?, 31, 0, 0)",
		gbkCharName)
	seedAccount(t, db, mId, name)

	if err := db.InsertRegisterLog(&models.RegisterBonusLogRow{
		Account: name, RewardType: "registered", Status: "pending",
	}); err != nil {
		t.Fatalf("插登记行失败: %v", err)
	}
	reg, err := db.FindPendingRegister(name)
	if err != nil || reg == nil {
		t.Fatalf("读 pending 登记行失败: %v", err)
	}

	svc := newRegisterBonusSvc(t, db)
	if err := svc.processRegistered(name, reg, registerBonusCfg()); err != nil {
		t.Fatalf("processRegistered 报错: %v", err)
	}

	// 1) 点券必须落在 m_id 那一行（旧实现按 name 查 → 命中 0 行 → 一分不发）
	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id=?", mId); got != 50000 {
		t.Fatalf("点券没发到 m_id=%s 那一行：cera=%d（期望 50000）", mId, got)
	}
	if got := queryOnGame(t, gamePath, "SELECT token_cera FROM accounts WHERE m_id=?", mId); got != 20000 {
		t.Fatalf("代币没发放：token_cera=%d（期望 20000）", got)
	}
	if got := queryOnGame(t, gamePath, "SELECT happy_token_cera FROM accounts WHERE m_id=?", mId); got != 10000 {
		t.Fatalf("欢乐代币没发放：happy_token_cera=%d（期望 10000）", got)
	}

	// 2) 金币 + 物品邮件必须发给那个角色
	if got := queryOnGame(t, gamePath, "SELECT COUNT(*) FROM mailbox_messages"); got != 1 {
		t.Fatalf("邮件数=%d（期望 1）", got)
	}
	if got := queryOnGame(t, gamePath, "SELECT gold FROM mailbox_messages"); got != 500000 {
		t.Fatalf("邮件金币=%d（期望 500000）", got)
	}
	if got := queryOnGame(t, gamePath, "SELECT COUNT(*) FROM mailbox_attachments"); got != 2 {
		t.Fatalf("附件数=%d（期望 2）", got)
	}
	if got := queryOnGame(t, gamePath, "SELECT receiver_character_id FROM mailbox_messages"); got != 1 {
		t.Fatalf("收件角色=%d（期望 1）", got)
	}

	// 3) 登记行必须标记完成 —— 否则玩家下次登录会重复领取
	after, err := db.FindRegisterByID(reg.ID)
	if err != nil || after == nil {
		t.Fatalf("读登记行失败: %v", err)
	}
	if after.Status != "done" {
		t.Fatalf("登记行状态=%s（期望 done；否则下次登录会重复发放）", after.Status)
	}
}

// TestProcessRegisteredHoldsWhenGameAccountMissing 锁住"游戏库查不到该 m_id"的处理：
// 必须保持待发（返回 nil，登记行仍 pending），而不是静默当成已发放。
func TestProcessRegisteredHoldsWhenGameAccountMissing(t *testing.T) {
	db, gamePath := setupRegisterBonusWorld(t)

	const mId = "932320999"
	const name = "nobody"

	// 网关库有账号，游戏库故意没有这个 m_id 的账号行
	seedAccount(t, db, mId, name)

	if err := db.InsertRegisterLog(&models.RegisterBonusLogRow{
		Account: name, RewardType: "registered", Status: "pending",
	}); err != nil {
		t.Fatalf("插登记行失败: %v", err)
	}
	reg, err := db.FindPendingRegister(name)
	if err != nil || reg == nil {
		t.Fatalf("读 pending 登记行失败: %v", err)
	}

	svc := newRegisterBonusSvc(t, db)
	if err := svc.processRegistered(name, reg, registerBonusCfg()); err != nil {
		t.Fatalf("游戏库缺账号行时应保持待发（返回 nil），实际报错: %v", err)
	}

	if got := queryOnGame(t, gamePath, "SELECT COUNT(*) FROM mailbox_messages"); got != 0 {
		t.Fatalf("不应写入任何邮件，实际 %d 封", got)
	}
	after, err := db.FindRegisterByID(reg.ID)
	if err != nil || after == nil {
		t.Fatalf("读登记行失败: %v", err)
	}
	if after.Status != "pending" {
		t.Fatalf("登记行状态=%s（期望仍是 pending，好等账号就绪后重试）", after.Status)
	}
}
