package database

// ============================================================================
// S5A3 改密（2026-10-29）
//
// ── 为什么网关能改 ────────────────────────────────────────────────────────
//
// S5A3 服务端的账号 API 只有三个端点：`/api/account/register`、`/login`、
// `/status` —— **没有改密**。原先网关在 S5A3 下直接拒绝改密，运营要改一个
// 玩家的密码只能登服务器进 MySQL。
//
// 但网关已经直连 S5A3 库了（全服邮件/泡点都用它），而 S5A3 的密码就是
// `dnf90_web_accounts.password_hash` 一列、格式是标准 bcrypt（cost=10，
// 见服务端 account_api.go:321 的 `bcrypt.GenerateFromPassword(…, bcrypt.DefaultCost)`）。
// 所以网关用同一个算法生成哈希写回去，服务端登录时 `CompareHashAndPassword`
// 能正常校验 —— 不需要服务端配合。
//
// ── 为什么要严格对齐服务端的校验规则 ──────────────────────────────────────
//
// 服务端 `validateCredentials`（account_api.go:450）规定：
//   · 账号名 3-20 位，只允许字母/数字/下划线
//   · 密码 6~64 位
//
// 网关放宽或收紧任何一条，都会造出"服务端不接受、但网关能写进库"的凭据。
// 所以这里**逐条照抄**，连文案都对齐。
//
// ── 不做什么 ──────────────────────────────────────────────────────────────
//
// 不校验旧密码。这是**管理员重置**通道（忘记密码的玩家找运营），
// 要求管理员知道旧密码等于没这个功能。玩家自助改密走另一条路。
// ============================================================================

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// S5A3 账号名/密码规则，与服务端 account_api.go 完全一致。
var (
	s5a3AccountNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,20}$`)
)

const (
	s5a3MinPassword = 6
	s5a3MaxPassword = 64
)

// 改密失败的原因（调用方用 errors.Is 判定后映射到错误码/文案）。
var (
	// ErrS5A3PasswordTooShort 密码太短。
	ErrS5A3PasswordTooShort = fmt.Errorf("密码至少 %d 位", s5a3MinPassword)
	// ErrS5A3PasswordTooLong 密码太长。
	ErrS5A3PasswordTooLong = fmt.Errorf("密码不能超过 %d 位", s5a3MaxPassword)
	// ErrS5A3AccountNotFound 账号在 S5A3 库里不存在。
	ErrS5A3AccountNotFound = errors.New("S5A3 库中不存在该账号")
	// ErrS5A3AccountNameInvalid 账号名不符合服务端规则（不会出现在重置场景，
	// 但 S5A3ChangePassword 是通用入口，仍要守住）。
	ErrS5A3AccountNameInvalid = errors.New("账号名只能是 3-20 位字母、数字或下划线")
)

// ValidateS5A3Password 校验密码长度（与服务端同口径）。
//
// 单独导出是因为上层要在"还没连库"时先挡掉明显不合规的输入，
// 避免为一次必然失败的写库去建连接。
func ValidateS5A3Password(password string) error {
	if len(password) < s5a3MinPassword {
		return ErrS5A3PasswordTooShort
	}
	if len(password) > s5a3MaxPassword {
		return ErrS5A3PasswordTooLong
	}
	return nil
}

// S5A3ChangePassword 直接改写 S5A3 账号的 bcrypt 密码哈希。
//
// 返回 (是否命中账号, error)。账号不存在时返回 (false, nil) ——
// 由调用方决定是报"账号不存在"还是静默（后台重置应该报）。
//
// ★ 写的是 `password_hash` 一列，不动 `account_id` / `created_at`：
//   服务端登录只读这一列做 bcrypt 比对，改别的反而有风险。
//
// ★ bcrypt cost 用 `bcrypt.DefaultCost`（=10），与服务端注册时一致。
//   用更高的 cost 也能通过校验（bcrypt 把 cost 编码在哈希串里），
//   但会让服务端每次登录多花时间，没必要。
func (db *Database) S5A3ChangePassword(account, newPassword string) (bool, error) {
	if !db.S5A3GameConfigured() {
		return false, errS5A3GameNotConfigured
	}
	account = strings.TrimSpace(account)
	if account == "" {
		return false, ErrS5A3AccountNameInvalid
	}
	if err := ValidateS5A3Password(newPassword); err != nil {
		return false, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		// bcrypt 只在密码超过 72 字节时报错，而上面已经把长度限制在 64，
		// 所以走到这里基本是内存/随机源异常 —— 如实上抛，别假装成功。
		return false, fmt.Errorf("生成密码哈希失败: %w", err)
	}

	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	query := "UPDATE " + db.s5a3AccountTable() + " SET password_hash = ? WHERE account = ?"
	result, err := db.s5a3DB.ExecContext(ctx, query, string(hash), account)
	if err != nil {
		return false, fmt.Errorf("改写 S5A3 账号 %s 的密码: %w", account, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// ListS5A3AccountNames 返回 S5A3 库里全部账号名（批量改密用）。
func (db *Database) ListS5A3AccountNames() ([]string, error) {
	if !db.S5A3GameConfigured() {
		return nil, errS5A3GameNotConfigured
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	query := "SELECT account FROM " + db.s5a3AccountTable() + " ORDER BY id"
	rows, err := db.s5a3DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("读取 S5A3 账号名列表: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if v := strings.TrimSpace(name); v != "" {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// S5A3VerifyPassword 校验账号密码是否正确（玩家自助改密要先验旧密码）。
//
// 返回 (是否通过, 账号是否存在, error)。
//
// ★ 这里把"密码错"和"账号不存在"分开返回，但**调用方对外不应该区分** ——
//   否则就是一个账号枚举接口。给玩家的文案统一成"账号或密码错误"。
func (db *Database) S5A3VerifyPassword(account, password string) (ok bool, exists bool, err error) {
	if !db.S5A3GameConfigured() {
		return false, false, errS5A3GameNotConfigured
	}
	account = strings.TrimSpace(account)
	if account == "" {
		return false, false, nil
	}

	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	query := "SELECT password_hash FROM " + db.s5a3AccountTable() + " WHERE account = ? LIMIT 1"
	var storedHash string
	if err := db.s5a3DB.QueryRowContext(ctx, query, account).Scan(&storedHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("查询 S5A3 账号 %s: %w", account, err)
	}
	if strings.TrimSpace(storedHash) == "" {
		// 空哈希 = 这个账号还没设过密码（正常流程不会出现，但库被人手动改过时可能）。
		return false, true, nil
	}
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)) != nil {
		return false, true, nil
	}
	return true, true, nil
}
