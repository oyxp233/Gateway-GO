package database

import (
	"errors"
	"fmt"
	"strings"
)

// 删除账号相关的哨兵错误，调用方用 errors.Is 判定后映射到 HTTP 状态码。
var (
	// ErrAccountDeleteEmpty 账号名为空。
	ErrAccountDeleteEmpty = errors.New("账号名不能为空")
	// ErrAccountDeleteNotFound 网关库中不存在该账号。
	ErrAccountDeleteNotFound = errors.New("账号不存在")
	// ErrAccountHasCharacters 账号下仍有角色，拒绝删除。
	//
	// 这是硬性保护：游戏库 characters.account_id 对 accounts 是 ON DELETE CASCADE
	// （见服务端 Sqlite/item_schema.sql），而网关打开游戏库时带 _pragma=foreign_keys(1)，
	// 因此一旦删掉游戏库 accounts 行，该账号的全部角色及其随身数据会被 SQLite 连带删除。
	// 为避免"手一抖清掉一个真玩家"，这里选择拒绝而不是级联，由管理员先在游戏内删角色。
	ErrAccountHasCharacters = errors.New("账号下仍有角色，拒绝删除")
)

// AccountDeletePreview 描述"删除某账号"会波及的数据。
//
// 预演（PreviewAccountDelete）时只填充前半段统计；真正执行删除
// （DeleteAccount）时把后半段的动作回执一并填上，供前端展示。
type AccountDeletePreview struct {
	// ---- 删除前统计 ----
	Account        string `json:"account"`
	MId            string `json:"m_id"`
	Cera           int64  `json:"cera"`
	DeviceHistory  int64  `json:"device_history"`  // device_history 表行数
	Banned         bool   `json:"banned"`          // 是否在封禁表里
	BonusLogs      int64  `json:"bonus_logs"`      // 注册奖励流水行数
	AntiCheatRows  int64  `json:"anticheat_rows"`  // 反作弊检测行数
	GameConfigured bool   `json:"game_configured"` // 游戏库是否已配置
	GameAccount    bool   `json:"game_account"`    // 游戏库 accounts 是否有该账号
	GameRoles      int    `json:"game_roles"`      // 游戏库 characters 存活角色数

	// ---- 删除动作回执 ----
	DeletedGame    bool `json:"deleted_game"`    // 游戏库账号行已删除
	DeletedGateway bool `json:"deleted_gateway"` // 网关库账号行已删除
	PurgedLogs     bool `json:"purged_logs"`     // 是否一并清了审计流水
}

// PreviewAccountDelete 预演删除：只读，不写任何库。
//
// ★ 关键：游戏库一律用**网关库解析出的 m_id** 去关联，不能用账号名。
// 网关自注册的账号 name 与 m_id 是两回事（m_id 是注册时生成的**纯数字**号，
// 见 AccountService.Register / AllocateNumericMId；2026-09-23 之前是 64 位 hex，
// 那次改动的原因是客户端要求第 4 段为数字 —— 详见 AllocateNumericMId 的注释）。
// 只有从游戏库迁移过来的账号才恰好 name == m_id。
// 拿 name 当 m_id 去查游戏库必然查不到 —— 后果是"有角色就拒绝"这条保护静默失效，
// 且游戏侧的账号行也删不掉（删除后的同步会把它重新导回网关库）。
// 这也是 GetRolesByAccount 的做法（先 name -> m_id，再用 m_id 查游戏库）。
//
// 返回的错误用 errors.Is 判定：
//   - ErrAccountDeleteEmpty：账号名为空；
//   - ErrAccountDeleteNotFound：网关库无此账号。
func (db *Database) PreviewAccountDelete(name string) (*AccountDeletePreview, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrAccountDeleteEmpty
	}

	acc, err := db.GetAccountByName(name)
	if err != nil {
		return nil, fmt.Errorf("查询账号失败: %w", err)
	}
	if acc == nil {
		return nil, ErrAccountDeleteNotFound
	}

	p := &AccountDeletePreview{
		Account: name,
		MId:     acc.MId,
		Cera:    acc.Cera,
	}

	// 以下统计都是"辅助信息"，查不到不算失败（表结构差异 / 游戏库未配置）。
	p.DeviceHistory = db.countRows("SELECT COUNT(*) FROM device_history WHERE m_id = ?", acc.MId)
	p.BonusLogs = db.countRows("SELECT COUNT(*) FROM register_bonus_logs WHERE account = ?", name)
	p.AntiCheatRows = db.countRows("SELECT COUNT(*) FROM anticheat_detections WHERE account = ?", name)
	p.Banned = db.countRows("SELECT COUNT(*) FROM banned_accounts WHERE name = ?", name) > 0

	p.GameConfigured = db.GameConfigured()
	if p.GameConfigured && acc.MId != "" {
		p.GameAccount = db.countRowsGame("SELECT COUNT(*) FROM accounts WHERE m_id = ?", acc.MId) > 0
		p.GameRoles = int(db.countRowsGame(
			`SELECT COUNT(*) FROM characters c
			   JOIN accounts a ON a.account_id = c.account_id
			  WHERE a.m_id = ? AND c.delete_flag = 0`, acc.MId))
	}

	return p, nil
}

// DeleteAccount 永久删除账号（网关库 + 游戏库）。
//
// purgeLogs 为 true 时一并清掉 register_bonus_logs / anticheat_detections 里
// 与该账号相关的流水；默认 false —— 审计流水属于"证据"，删账号不该顺手抹掉，
// 只是接口会把它保留的行数回报给管理员。
//
// 执行顺序（两库无法共用事务，故按"先动非权威库、后动权威库"排）：
//  1. 预演 + 角色数校验 —— 有角色直接拒绝，一个字节都不写；
//  2. 游戏库 accounts 行删除（此刻已确认无角色，级联只会清账号级空表）；
//  3. 网关库单事务删除 accounts / device_history / banned_accounts（+ 可选流水）。
//
// 第 2 步成功而第 3 步失败时，返回的 preview 里 DeletedGame=true、DeletedGateway=false，
// 调用方可据此感知"半完成"状态（该账号将无法再登录网关，但残留的网关行需重试删除）。
func (db *Database) DeleteAccount(name string, purgeLogs bool) (*AccountDeletePreview, error) {
	preview, err := db.PreviewAccountDelete(name)
	if err != nil {
		return nil, err
	}
	if preview.GameRoles > 0 {
		return nil, fmt.Errorf("%w: %s 名下仍有 %d 个角色", ErrAccountHasCharacters, preview.Account, preview.GameRoles)
	}

	// ---- 1. 游戏库：删账号行（用 m_id，不是账号名） ----
	if preview.GameAccount {
		if _, err := db.gameDB.Exec("DELETE FROM accounts WHERE m_id = ?", preview.MId); err != nil {
			return nil, fmt.Errorf("删除游戏库账号失败: %w", err)
		}
		preview.DeletedGame = true
	}

	// ---- 2. 网关库：单事务清干净 ----
	tx, err := db.gatewayDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec("DELETE FROM accounts WHERE name = ?", preview.Account)
	if err != nil {
		return nil, fmt.Errorf("删除网关库账号失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// 预演时还在、真要删时没了：并发删除，按不存在处理。
		return nil, ErrAccountDeleteNotFound
	}

	if _, err := tx.Exec("DELETE FROM device_history WHERE m_id = ?", preview.MId); err != nil {
		return nil, fmt.Errorf("清理设备历史失败: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM banned_accounts WHERE name = ?", preview.Account); err != nil {
		return nil, fmt.Errorf("清理封禁记录失败: %w", err)
	}

	if purgeLogs {
		if _, err := tx.Exec("DELETE FROM register_bonus_logs WHERE account = ?", preview.Account); err != nil {
			return nil, fmt.Errorf("清理注册奖励流水失败: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM anticheat_detections WHERE account = ?", preview.Account); err != nil {
			return nil, fmt.Errorf("清理反作弊记录失败: %w", err)
		}
		preview.PurgedLogs = true
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交事务失败: %w", err)
	}
	preview.DeletedGateway = true

	return preview, nil
}

// countRows 在网关库上执行一个 COUNT(*) 查询，出错返回 0。
//
// 这些统计只用于展示/判断，属于"辅助信息"：表不存在或列名有差异都不该让
// 删除流程整体失败，因此错误按 0 处理。
func (db *Database) countRows(query string, args ...interface{}) int64 {
	if db.gatewayDB == nil {
		return 0
	}
	var n int64
	if err := db.gatewayDB.QueryRow(query, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}

// countRowsGame 同 countRows，但跑在游戏库上。
func (db *Database) countRowsGame(query string, args ...interface{}) int64 {
	if db.gameDB == nil {
		return 0
	}
	var n int64
	if err := db.gameDB.QueryRow(query, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}
