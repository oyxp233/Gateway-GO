package database

// ============================================================================
// S5A3 账号身份镜像（账号同步，2026-10-29）
//
// ── 为什么需要 ────────────────────────────────────────────────────────────
//
// S5A3 的账号主权在服务端 MySQL（`dnf90_web_accounts`），网关库
// `accounts` 表里通常一行都没有。这带来三个问题：
//
//  1. 后台「账号管理」直接读 `accounts` ⇒ 空列表（已改成直读 S5A3 库，
//     但其它依赖 `accounts` 的功能仍然缺这一行）；
//  2. `account_events`（账号事件流水）与三服合一的封禁广播都按账号名工作，
//     缺 `accounts` 行时"这个账号是谁"没法关联；
//  3. 网关侧任何"按 m_id 查账号"的路径（泡点镜像、登录器账号信息）都落空。
//
// ── 为什么只同步"身份"，不同步密码 ────────────────────────────────────────
//
// 这是三服合一评估文档第五章的硬约束（限制 #6）：
//
//	密码哈希不可全量跨服同步 —— S4A21 是 MD5、S5A3 是 bcrypt，两种凭据不可互换。
//
// 所以镜像行只写 `m_id` + `name`，`pwd_hash` / `salt` 留**空串**。
// 空哈希在网关侧**永远验不过**（`security.VerifyHash("")` 必然失败），
// 这正是我们要的：S5A3 的账号只能走服务端 bcrypt 校验，
// 网关这份镜像不允许成为一条绕过服务端的登录路径。
//
// ── 两种同步方式 ──────────────────────────────────────────────────────────
//
//   · `EnsureAccountMirror`（懒建）：S5A3 登录成功时补一行。成本 O(1)，
//     玩家登一次就有，不需要运维操作。
//   · `SyncS5A3AccountMirrors`（全量）：后台按钮触发，把 S5A3 库里的所有
//     账号补进网关库。用于"上线前先让后台列表/事件对得上"。
//
// 两者都幂等：已存在的行只更新 `name`（应对服务端改名），不碰其它列。
// ============================================================================

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrAccountMirrorNameConflict 表示网关库里已有另一个 m_id 占用了同名账号。
//
// 这种情况只会出现在"S4A21 与 S5A3 共存且两边有同名账号"的迁移期。
// 此时**不能**把 m_id 改掉（会串角色/串点券），只能跳过并如实报告。
var ErrAccountMirrorNameConflict = errors.New("网关库中已有同名账号但 m_id 不同（多服同名冲突）")

// EnsureAccountMirror 确保网关库 `accounts` 表里有该 S5A3 账号的身份镜像行。
//
// 返回 (是否新建, error)。已存在时返回 (false, nil)，只把 name 对齐到最新值。
//
// ★ 用 `INSERT … ON CONFLICT(m_id) DO UPDATE SET name = excluded.name`：
//   - 主键是 m_id，S5A3 的 account_id（`dnf:10002`）天然唯一；
//   - 只更新 name，**绝不更新 pwd_hash/salt** —— 镜像行的凭据必须保持为空，
//     否则一旦有人把 S4A21 的哈希写进来，网关就会多出一条能验密的路径。
//
// ★ name 上有 UNIQUE 约束。如果网关库已有同名但 m_id 不同的行（迁移期常见），
//   插入会报 UNIQUE 冲突 —— 此时返回 ErrAccountMirrorNameConflict，
//   由调用方决定是记日志跳过（登录路径）还是报给运维（全量同步）。
func (db *Database) EnsureAccountMirror(mId, name string) (bool, error) {
	if db == nil || db.gatewayDB == nil {
		return false, errors.New("网关库未就绪")
	}
	mId = strings.TrimSpace(mId)
	name = strings.TrimSpace(name)
	if mId == "" || name == "" {
		return false, errors.New("m_id 与账号名都不能为空")
	}

	// 先看 m_id 在不在：决定返回值是"新建"还是"已存在"。
	var existingMId string
	err := db.gatewayDB.QueryRow("SELECT m_id FROM accounts WHERE m_id = ?", mId).Scan(&existingMId)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("查询网关库账号 %s: %w", mId, err)
	}

	now := NowUnix()
	if existed {
		// 已存在：只对齐名字（服务端可能改过账号名）。
		// 若新名字撞上了另一个 m_id，UPDATE 会报 UNIQUE 冲突，如实上抛。
		if _, err := db.gatewayDB.Exec(
			"UPDATE accounts SET name = ?, updated_at = ? WHERE m_id = ?", name, now, mId); err != nil {
			if isUniqueViolation(err) {
				return false, ErrAccountMirrorNameConflict
			}
			return false, err
		}
		return false, nil
	}

	// 新建：凭据列留空串。created_at / updated_at 用网关时间戳（S5A3 那边的
	// 真实注册时间由 ListAccounts 直读 dnf90_web_accounts，不依赖这里）。
	_, err = db.gatewayDB.Exec(`
		INSERT INTO accounts
			(m_id, name, pwd_hash, salt, cera, token_cera, happy_token_cera,
			 device_secret, device_secret_issued_at, device_history, device_secret_last_rotated,
			 s5a9_digest, last_login_at, last_login_ip, failed_login_count, lockout_until,
			 created_at, updated_at, last_heartbeat)
		VALUES (?, ?, '', '', 0, 0, 0, '', '', '', 0, '', 0, '', 0, 0, ?, ?, 0)`,
		mId, name, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return false, ErrAccountMirrorNameConflict
		}
		return false, err
	}
	return true, nil
}

// isUniqueViolation 判断是否是 UNIQUE 约束冲突。
//
// modernc.org/sqlite 把错误包装成 `constraint failed: UNIQUE constraint failed: …`，
// 没有导出哨兵值，只能按文案判。这里只用于"区分冲突与其它错误"，
// 判错的后果是错误码不够精确，不会导致数据写坏。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "constraint failed")
}

// AccountMirrorSyncResult 是全量同步的结果（后台展示用）。
type AccountMirrorSyncResult struct {
	// Total 是 S5A3 库里的账号总数。
	Total int `json:"total"`
	// Created 是本次新建的镜像行数。
	Created int `json:"created"`
	// Existing 是本来就有的行数（只对齐了名字）。
	Existing int `json:"existing"`
	// Conflicts 是同名但 m_id 不同、被跳过的账号。
	Conflicts []string `json:"conflicts,omitempty"`
	// Failed 是写库失败的账号（带原因）。
	Failed []string `json:"failed,omitempty"`
}

// SyncS5A3AccountMirrors 把 S5A3 库里的全部账号补进网关库 `accounts` 表。
//
// 只同步身份（m_id + name），不同步密码 —— 原因见文件头。
//
// 返回的 Result 里区分"新建/已存在/冲突/失败"，运维据此判断要不要人工处理。
// 单个账号失败**不中断整批**：同步是幂等的，下次重跑会补上。
func (db *Database) SyncS5A3AccountMirrors() (*AccountMirrorSyncResult, error) {
	result := &AccountMirrorSyncResult{}
	if !db.S5A3GameConfigured() {
		return result, errS5A3GameNotConfigured
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	query := "SELECT account_id, account FROM " + db.s5a3AccountTable() + " ORDER BY id"
	rows, err := db.s5a3DB.QueryContext(ctx, query)
	if err != nil {
		return result, fmt.Errorf("读取 S5A3 账号列表: %w", err)
	}
	defer rows.Close()

	type pair struct{ mId, name string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.mId, &p.name); err != nil {
			return result, err
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	result.Total = len(pairs)

	for _, p := range pairs {
		created, err := db.EnsureAccountMirror(p.mId, p.name)
		switch {
		case err == nil && created:
			result.Created++
		case err == nil:
			result.Existing++
		case errors.Is(err, ErrAccountMirrorNameConflict):
			result.Conflicts = append(result.Conflicts, p.name)
		default:
			result.Failed = append(result.Failed, fmt.Sprintf("%s(%s): %v", p.name, p.mId, err))
		}
	}
	return result, nil
}
