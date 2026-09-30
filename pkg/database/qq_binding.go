package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ────────────────────────────────────────────────────────────────────────
// QQ 号绑定（2026-09-24）
//
// 设计口径（安南拍板）：
//   「账号名照旧，额外绑一个 QQ 号，登录框两个都能进」
//
// 所以这里**只存绑定关系**，不碰 accounts 表的任何字段 ——
// m_id / 密码 / 点券 / 角色全部保持原样，游戏库那边的关联一个字节都不动。
// 登录时由 service 层把「QQ 号」翻译成「账号名」，之后走的就是原来的登录流程。
//
// 两张表的作用域：
//   qq_bindings        —— 绑定关系，真源，只有网关进程写。
//   email_verify_codes —— 验证码，同时兼作**发信量统计**（按 created_at 计数）。
//                         日限额保护靠它，所以不能图省事只放内存。
// ────────────────────────────────────────────────────────────────────────

// 绑定相关的哨兵错误，供 service 层用 errors.Is 判定并映射成错误码。
var (
	// ErrQQBindNotFound 账号当前没有绑定 QQ 号（解绑、查询时用）。
	ErrQQBindNotFound = errors.New("账号未绑定 QQ 号")
	// ErrQQAlreadyBound 该账号已经绑定了另一个 QQ 号，需先解绑。
	ErrQQAlreadyBound = errors.New("账号已绑定 QQ 号")
	// ErrQQNumberTaken 该 QQ 号已被别的账号绑定。
	ErrQQNumberTaken = errors.New("QQ 号已被其他账号绑定")
)

// QQBinding 表示一条 QQ 号 ↔ 账号 的绑定关系。
type QQBinding struct {
	QQNumber string `json:"qq_number"`
	Account  string `json:"account"`
	BoundAt  int64  `json:"bound_at"`
	BoundIP  string `json:"bound_ip"`
}

// VerifyCode 表示一条邮件验证码记录（**不含明文**）。
type VerifyCode struct {
	ID        int64  `json:"id"`
	Target    string `json:"target"`
	Purpose   string `json:"purpose"`
	ExpiresAt int64  `json:"expires_at"`
	Used      bool   `json:"used"`
	Attempts  int    `json:"attempts"`
	CreatedAt int64  `json:"created_at"`
}

// 验证码用途。用常量而不是裸字符串：以后加「找回密码」时，
// 同一个 QQ 号在两个用途下各有一份码，互不覆盖。
const (
	// PurposeQQBind 绑定 QQ 号。
	PurposeQQBind = "qq_bind"
)

// HashVerifyCode 计算验证码的存储哈希。
//
// 为什么不裸 SHA256：验证码只有 6 位数字（100 万种），拿到库的人可以瞬间
// 全空间反查。把 target + purpose 揉进哈希后，同一串码对不同目标、不同用途
// 得到完全不同的值 —— 反查出来的结果只在「那一个目标的那一个用途」下有效。
// 加上 5 分钟过期，这个强度对私服场景足够。
//
// 不存明文是硬要求：`email_verify_codes` 会被后台和排查脚本读到，
// 明文码能让任何看到库的人直接绑走别人的账号。
func HashVerifyCode(target, purpose, code string) string {
	sum := sha256.Sum256([]byte(target + ":" + purpose + ":" + code))
	return hex.EncodeToString(sum[:])
}

// ── 绑定关系 ─────────────────────────────────────────────────────────────

// BindQQ 建立绑定。双向一对一：
// 一个 QQ 号只能绑一个账号，一个账号也只能绑一个 QQ 号。
//
// 「查 + 插」放在同一个事务里：两个玩家同时绑同一个 QQ 号时，
// 不能让两个请求都通过"查询显示没被绑"从而都写进去。
func (db *Database) BindQQ(qqNumber, account, ip string) error {
	qqNumber = strings.TrimSpace(qqNumber)
	account = strings.TrimSpace(account)
	if qqNumber == "" || account == "" {
		return fmt.Errorf("QQ 号与账号都不能为空")
	}

	tx, err := db.gatewayDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var owner string
	err = tx.QueryRow("SELECT account FROM qq_bindings WHERE qq_number = ?", qqNumber).Scan(&owner)
	switch {
	case err == nil:
		if owner == account {
			return fmt.Errorf("%w（该 QQ 号就是当前账号绑的）", ErrQQAlreadyBound)
		}
		return fmt.Errorf("%w（QQ 号 %s 已绑定账号 %s）", ErrQQNumberTaken, qqNumber, owner)
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	var boundQQ string
	err = tx.QueryRow("SELECT qq_number FROM qq_bindings WHERE account = ?", account).Scan(&boundQQ)
	switch {
	case err == nil:
		return fmt.Errorf("%w（当前绑定 %s，需先解绑）", ErrQQAlreadyBound, boundQQ)
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}

	if _, err := tx.Exec(
		"INSERT INTO qq_bindings (qq_number, account, bound_at, bound_ip) VALUES (?, ?, ?, ?)",
		qqNumber, account, NowUnix(), ip,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// UnbindQQ 解除账号的绑定，返回被解绑的 QQ 号。
//
// 记录返回值是为了让调用方能在审计日志里写清"解绑了哪个 QQ 号" ——
// 光记"账号 X 解绑成功"，事后答不上"原来绑的是哪个号"。
func (db *Database) UnbindQQ(account string) (string, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return "", fmt.Errorf("账号不能为空")
	}

	var qqNumber string
	err := db.gatewayDB.QueryRow("SELECT qq_number FROM qq_bindings WHERE account = ?", account).Scan(&qqNumber)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrQQBindNotFound
	}
	if err != nil {
		return "", err
	}

	if _, err := db.gatewayDB.Exec("DELETE FROM qq_bindings WHERE account = ?", account); err != nil {
		return "", err
	}
	return qqNumber, nil
}

// GetQQBindingByAccount 按账号查绑定。未绑定时返回 (nil, ErrQQBindNotFound)。
func (db *Database) GetQQBindingByAccount(account string) (*QQBinding, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return nil, ErrQQBindNotFound
	}

	var b QQBinding
	err := db.gatewayDB.QueryRow(
		"SELECT qq_number, account, bound_at, bound_ip FROM qq_bindings WHERE account = ?", account,
	).Scan(&b.QQNumber, &b.Account, &b.BoundAt, &b.BoundIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrQQBindNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// GetAccountByQQNumber 按 QQ 号查绑定的账号。未绑定时返回空串。
//
// 登录识别走它：这是**唯一**允许把玩家输入的 QQ 号翻译成账号名的地方。
func (db *Database) GetAccountByQQNumber(qqNumber string) (string, error) {
	qqNumber = strings.TrimSpace(qqNumber)
	if qqNumber == "" {
		return "", nil
	}

	var account string
	err := db.gatewayDB.QueryRow(
		"SELECT account FROM qq_bindings WHERE qq_number = ?", qqNumber,
	).Scan(&account)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return account, nil
}

// QQNumbersByAccounts 批量取「账号 → QQ 号」，给账号列表用。
//
// 存在的理由：列表一页可能 500 个账号，逐个查绑定表就是 500 次 SQL。
// 分片是因为 SQLite 的变量数有上限（默认 999），一次拼 500 个占位符安全。
func (db *Database) QQNumbersByAccounts(accounts []string) (map[string]string, error) {
	out := make(map[string]string)
	if len(accounts) == 0 {
		return out, nil
	}

	const chunk = 500
	for start := 0; start < len(accounts); start += chunk {
		end := start + chunk
		if end > len(accounts) {
			end = len(accounts)
		}
		part := accounts[start:end]

		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(part)), ",")
		args := make([]any, len(part))
		for i, a := range part {
			args[i] = a
		}

		rows, err := db.gatewayDB.Query(
			"SELECT account, qq_number FROM qq_bindings WHERE account IN ("+placeholders+")", args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var account, qqNumber string
			if err := rows.Scan(&account, &qqNumber); err != nil {
				rows.Close()
				return nil, err
			}
			out[account] = qqNumber
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

// CountQQBindings 统计绑定总数（后台概览用）。
func (db *Database) CountQQBindings() (int, error) {
	var n int
	err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM qq_bindings").Scan(&n)
	return n, err
}

// ── 邮件验证码 ───────────────────────────────────────────────────────────

// SaveVerifyCode 写入一条验证码，并顺手清掉过期记录。
//
// 清理放在这里而不是定时任务：验证码表是纯流水，唯一的写入点就是"发新码"，
// 在写入路径上删旧数据不会漏，也不用额外维护一个后台 goroutine。
//
// ★ 只能删 used = 1 的行。
// 日额度（CountVerifyCodesSince）是"按 created_at 统计当天发出的条数"，
// 若把**未用过**的过期行一并删掉，就等于把当天真实发出去的信从账上抹了 ——
// 一天里发够上限后，这些行会被逐条清走，额度检查永远不到阈值，
// 自保闸门形同虚设。所以：作废的（used=1）过了保留期就清，没作废的一律留着。
func (db *Database) SaveVerifyCode(target, purpose, codeHash string, expiresAt int64, requestIP string) error {
	if _, err := db.gatewayDB.Exec(
		"DELETE FROM email_verify_codes WHERE expires_at < ? AND used = 1", NowUnix()-3600,
	); err != nil {
		return err
	}

	_, err := db.gatewayDB.Exec(
		`INSERT INTO email_verify_codes (target, purpose, code_hash, expires_at, used, attempts, created_at, request_ip)
		 VALUES (?, ?, ?, ?, 0, 0, ?, ?)`,
		target, purpose, codeHash, expiresAt, NowUnix(), requestIP,
	)
	return err
}

// GetActiveVerifyCode 取该目标在该用途下**仍然有效**的最新一条验证码。
//
// 返回 (nil, "", nil) 表示"没有有效码" —— 这是正常状态（还没发过、已过期、
// 已用掉），不是错误。把"没有"和"查询失败"分开，业务层才能给出正确提示：
// 前者说"请先获取验证码"，后者说"系统繁忙"。
func (db *Database) GetActiveVerifyCode(target, purpose string, now int64) (*VerifyCode, string, error) {
	var (
		vc   VerifyCode
		hash string
		used int
	)
	err := db.gatewayDB.QueryRow(
		`SELECT id, target, purpose, code_hash, expires_at, used, attempts, created_at
		   FROM email_verify_codes
		  WHERE target = ? AND purpose = ? AND used = 0 AND expires_at > ?
		  ORDER BY id DESC LIMIT 1`,
		target, purpose, now,
	).Scan(&vc.ID, &vc.Target, &vc.Purpose, &hash, &vc.ExpiresAt, &used, &vc.Attempts, &vc.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	vc.Used = used != 0
	return &vc, hash, nil
}

// MarkVerifyCodeUsed 把验证码标记为已用（一次性）。
//
// 条件里带 used = 0：两个并发请求拿同一个码去校验时，只有第一个能把
// 它标成已用，第二个的 UPDATE 影响 0 行 —— 业务层据此判定"码已被用过"。
func (db *Database) MarkVerifyCodeUsed(id int64) (bool, error) {
	res, err := db.gatewayDB.Exec("UPDATE email_verify_codes SET used = 1 WHERE id = ? AND used = 0", id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// BumpVerifyCodeAttempts 累加错误尝试次数（防暴力猜码）。
func (db *Database) BumpVerifyCodeAttempts(id int64) error {
	_, err := db.gatewayDB.Exec("UPDATE email_verify_codes SET attempts = attempts + 1 WHERE id = ?", id)
	return err
}

// InvalidateVerifyCodes 作废该目标在该用途下的全部未用验证码。
//
// 发新码前调用：确保任何时刻只有一个码是"活的"，
// 否则玩家点两次"获取验证码"，两个码都能用，等于把爆破难度砍半。
func (db *Database) InvalidateVerifyCodes(target, purpose string) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE email_verify_codes SET used = 1 WHERE target = ? AND purpose = ? AND used = 0",
		target, purpose)
	return err
}

// CountVerifyCodesSince 统计某时刻之后**真正发出**的验证码数量（发信量保护用）。
//
// 只数 used = 0 的行。发信失败时业务层会把刚写的那条作废（used=1），
// 那条信根本没发出去，不该计入当日额度 —— 否则 SMTP 一抽风，
// 失败的请求就把额度吃光，等通道恢复了反而发不出去了。
//
// 注：成功消费掉的码（used=1）也不计入，但那条必然已经占过额度，
// 且此时账号已绑定，不会再发第二次，所以账不会算漏。
func (db *Database) CountVerifyCodesSince(since int64) (int, error) {
	var n int
	err := db.gatewayDB.QueryRow(
		"SELECT COUNT(*) FROM email_verify_codes WHERE created_at >= ? AND used = 0", since).Scan(&n)
	return n, err
}

// LastVerifyCodeAt 取该目标最近一次**仍在生效**的取码时刻，没有则 0（冷却判定用）。
//
// ★ 必须带 used = 0。
// 冷却的目的是"别让玩家连点烧额度"，前提是**他确实收到了一封**。
// 而发信失败的路径是：写行 → 发信失败 → 把该行作废（used=1）。
// 若这里不过滤 used，玩家会被自己那次根本没送达的请求锁在冷却期里 ——
// 明明一封没收，界面上却要等 60 秒，只能干瞪眼重试。
func (db *Database) LastVerifyCodeAt(target, purpose string) (int64, error) {
	var ts sql.NullInt64
	err := db.gatewayDB.QueryRow(
		"SELECT MAX(created_at) FROM email_verify_codes WHERE target = ? AND purpose = ? AND used = 0",
		target, purpose).Scan(&ts)
	if err != nil {
		return 0, err
	}
	return ts.Int64, nil
}
