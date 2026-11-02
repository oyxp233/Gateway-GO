package database

// ============================================================================
// 账号事件同步（三服合一，2026-10-24）
//
// 见评估-三服合一登录器-20261023.md 第五章：
//
// 主网关是账号主权方，记录注册/改密/封禁/删除事件；
// 从网关拉取事件流，应用到本地副本。这样"注册一次、三个服都能登"。
//
// ★ 凭据无法统一（硬约束）：S4A21 网关存 MD5，S5A3 服务端存 bcrypt。
//   所以同步的是**账号名 + 封禁状态**，不是密码哈希本身。
//   S5A3 的账号必须主动推送到服务端（见 service/s5a3_account.go 的 register）。
//
// ★ 水位单独存 account_sync_state 表：
//   从网关自己也会产生事件（本地封禁），两边 ID 空间不同，
//   混在 account_events 里会撞主键。
// ============================================================================

import (
	"time"
)

// AccountEvent 是一条账号事件。
//
// EventType 取值：
//   - "register"        → 新账号注册（detail 为空）
//   - "password_change" → 改密（detail 为空，不同步哈希）
//   - "ban"             → 封禁（detail = 原因，scope = global/服 id）
//   - "unban"           → 解封（detail 为空）
//   - "delete"          → 删号
type AccountEvent struct {
	ID        int64  `json:"id"`
	EventType string `json:"event_type"`
	Account   string `json:"account"`
	Detail    string `json:"detail"`
	Scope     string `json:"scope"`
	CreatedAt int64  `json:"created_at"`
}

// 事件类型常量。
const (
	AccountEventRegister       = "register"
	AccountEventPasswordChange = "password_change"
	AccountEventBan            = "ban"
	AccountEventUnban          = "unban"
	AccountEventDelete         = "delete"
)

// RecordAccountEvent 记录一条账号事件（主网关调用）。
//
// 事件是"只增不改"的流水，从网关按 id 增量拉取。
// 记录失败不阻断业务：事件同步是增强能力，不能因为写流水失败让注册/改密失败。
func (db *Database) RecordAccountEvent(eventType, account, detail, scope string) error {
	if scope == "" {
		scope = BanScopeGlobal
	}
	_, err := db.gatewayDB.Exec(
		"INSERT INTO account_events (event_type, account, detail, scope, created_at) VALUES (?, ?, ?, ?, ?)",
		eventType, account, detail, scope, time.Now().Unix())
	return err
}

// AccountEventsSince 返回 id > sinceID 的事件（从网关拉取用）。
//
// limit 限制单次返回条数，防止首次同步时一次拉太多。
func (db *Database) AccountEventsSince(sinceID int64, limit int) ([]AccountEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.gatewayDB.Query(
		"SELECT id, event_type, account, detail, scope, created_at FROM account_events "+
			"WHERE id > ? ORDER BY id ASC LIMIT ?", sinceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []AccountEvent
	for rows.Next() {
		var e AccountEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.Account, &e.Detail, &e.Scope, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// SyncWatermark 返回与指定 peer 的同步水位（已应用的最大事件 ID）。
func (db *Database) SyncWatermark(peer string) (int64, error) {
	var id int64
	err := db.gatewayDB.QueryRow(
		"SELECT COALESCE(last_event_id, 0) FROM account_sync_state WHERE peer = ?", peer).Scan(&id)
	if err != nil {
		// 没有记录 = 从未同步过，水位 0
		return 0, nil
	}
	return id, nil
}

// SetSyncWatermark 更新同步水位。
func (db *Database) SetSyncWatermark(peer string, lastEventID int64) error {
	_, err := db.gatewayDB.Exec(
		"INSERT INTO account_sync_state (peer, last_event_id, updated_at) VALUES (?, ?, ?) "+
			"ON CONFLICT(peer) DO UPDATE SET last_event_id = excluded.last_event_id, updated_at = excluded.updated_at",
		peer, lastEventID, time.Now().Unix())
	return err
}

// ApplyRemoteAccountEvent 应用一条从主网关同步来的事件（从网关调用）。
//
// 只同步"身份 + 封禁"两类信息，不同步密码哈希（见文件头说明）。
// 幂等：靠调用方维护水位（SyncWatermark），同一事件不会被重复应用。
func (db *Database) ApplyRemoteAccountEvent(e AccountEvent) error {
	switch e.EventType {
	case AccountEventBan:
		// 只落地全局封禁；分服封禁留在该服自己的网关（scope 不等于 global 时跳过）
		if e.Scope != "" && e.Scope != BanScopeGlobal {
			return nil
		}
		_, err := db.gatewayDB.Exec(
			"INSERT INTO banned_accounts (name, reason, banned_at, scope) VALUES (?, ?, ?, ?) "+
				"ON CONFLICT(name) DO UPDATE SET reason = excluded.reason, scope = excluded.scope",
			e.Account, e.Detail, e.CreatedAt, BanScopeGlobal)
		return err

	case AccountEventUnban:
		// 解封只删全局封禁记录，不动本服自己的分服封禁
		_, err := db.gatewayDB.Exec(
			"DELETE FROM banned_accounts WHERE name = ? AND (scope = ? OR scope IS NULL OR scope = '')",
			e.Account, BanScopeGlobal)
		return err

	case AccountEventRegister, AccountEventPasswordChange, AccountEventDelete:
		// 这三类在从网关只做水位推进，不动数据：
		//   - register：账号在从网关登录时兜底反查主网关（见 service 层）
		//   - password_change：同上（密码哈希不同源，同步不了）
		//   - delete：从网关不删本地账号（避免误删），只记录事件
		// 这是刻意的失败方向：宁可让玩家多一次反查，也不静默删数据。
		return nil
	}
	return nil
}
