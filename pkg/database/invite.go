package database

// ============================================================================
// 注册邀请码（2026-10-24）
//
// 用途：开启 Register.RequireInvite 后，注册必须带一个后台生成的邀请码。
// 这是"控制谁能注册"最直接的手段 —— 比 IP 限额精确（限额只能提高成本，
// 邀请码直接卡死入口）。
//
// 一码一用：used_by 非空即已消耗。
// 不做"一码多用"：邀请码的价值在于"可追溯 + 泄漏影响可控"，
// 多码复用会让一个泄漏的码被无限使用。
//
// ★ 归一化在**服务端**做（NormalizeInviteCode）：
//   玩家从聊天窗口/群里复制码时常带空格、大小写不一致、粘贴时带上连字符。
//   把"K7M2-P9QX"、"k7m2p9qx"、" K7M2 P9QX " 都归一成 "K7M2P9QX"，
//   这样玩家不用纠结格式 —— 否则会有一半人卡在"码明明是对的但提示无效"。
// ============================================================================

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"s4a21-gateway/pkg/utils"
)

// inviteAlphabet 是邀请码字符集。
//
// ★ 刻意去掉易混字符：0/O、1/I/L、2/Z、5/S、8/B。
// 邀请码是**人工抄写/口述**的（发在群里、念给朋友），
// 混字符会让"码是对的但输错了"成为主要客服问题。
const inviteAlphabet = "ACDEFGHJKMNPQRTUVWXY34679"

// inviteCodeLength 是邀请码的有效字符数（不含展示用连字符）。
const inviteCodeLength = 8

// InviteStatus 是邀请码的状态（列表页筛选用）。
type InviteStatus string

const (
	InviteStatusUnused   InviteStatus = "unused"   // 未使用且未过期未作废
	InviteStatusUsed     InviteStatus = "used"     // 已被使用
	InviteStatusDisabled InviteStatus = "disabled" // 后台作废
	InviteStatusExpired  InviteStatus = "expired"  // 已过期（未使用）
)

// InviteCode 是一条邀请码记录。
type InviteCode struct {
	Code      string `json:"code"`
	Note      string `json:"note"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	UsedBy    string `json:"used_by"`
	UsedAt    int64  `json:"used_at"`
	Disabled  bool   `json:"disabled"`
}

// Status 返回该码当前的状态（以 now 为基准）。
func (c InviteCode) Status(now int64) InviteStatus {
	switch {
	case c.Disabled:
		return InviteStatusDisabled
	case c.UsedBy != "":
		return InviteStatusUsed
	case c.ExpiresAt > 0 && now > c.ExpiresAt:
		return InviteStatusExpired
	default:
		return InviteStatusUnused
	}
}

// NormalizeInviteCode 归一化邀请码：去空格/连字符/制表符，转大写。
//
// 导出是为了让 auth / httprouter 两侧用同一套归一化 ——
// 各写一份必然出现"登录器能过、网页过不了"的诡异 bug。
func NormalizeInviteCode(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, ch := range strings.TrimSpace(raw) {
		switch ch {
		case ' ', '\t', '-', '_', '.', '\u00a0': // 含不换行空格（从网页复制常见）
			continue
		}
		if ch >= 'a' && ch <= 'z' {
			ch -= 32 // 转大写
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// FormatInviteCode 把归一化的码转成展示形式（XXXX-XXXX）。
//
// 只在**展示**时用（后台列表、导出）。存储与比对一律用归一化形式。
func FormatInviteCode(code string) string {
	if len(code) != inviteCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// generateInviteCode 生成一个随机邀请码（归一化形式）。
func generateInviteCode() (string, error) {
	buf := make([]byte, inviteCodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, inviteCodeLength)
	n := byte(len(inviteAlphabet))
	for i, b := range buf {
		// 取模偏差可忽略：alphabet 长度 24，256/24 的偏差在 8 字符码上
		// 影响的是"字符分布"而非"可猜性"（熵仍有 8*log2(24)≈36.7 bit）。
		out[i] = inviteAlphabet[int(b)%int(n)]
	}
	return string(out), nil
}

// GenerateInvites 批量生成邀请码并入库。
//
// count 上限 500（一次生成太多没有意义，也容易误操作）。
// note 是备注（批次/发给谁），expiresAt 为 0 表示永不过期。
//
// 返回生成的码（归一化形式）。碰撞时自动重试（8 位 24 字符集，
// 已生成几万个码时碰撞率仍然极低，但重试成本几乎为零）。
func (db *Database) GenerateInvites(count int, note, createdBy string, expiresAt int64) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("生成数量必须大于 0")
	}
	if count > 500 {
		count = 500
	}
	note = strings.TrimSpace(note)
	createdBy = strings.TrimSpace(createdBy)
	now := utils.NowUnix()

	tx, err := db.gatewayDB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	codes := make([]string, 0, count)
	for len(codes) < count {
		code, err := generateInviteCode()
		if err != nil {
			return nil, err
		}
		res, err := tx.Exec(
			`INSERT INTO invite_codes (code, note, created_by, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(code) DO NOTHING`,
			code, note, createdBy, now, expiresAt)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			codes = append(codes, code)
		}
		// n == 0 = 碰撞，下一轮重试
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// 邀请码消耗结果（供 service 层转成错误码）。
const (
	InviteConsumeOK         = 0
	InviteConsumeNotFound   = 1 // 码不存在
	InviteConsumeUsed       = 2 // 已被使用
	InviteConsumeDisabled   = 3 // 已作废
	InviteConsumeExpired    = 4 // 已过期
	InviteConsumeNormalized = 5 // 归一化后为空（调用方应先判空，这个是兜底）
)

// ConsumeInvite 校验并原子消耗一个邀请码。
//
// ★ 必须原子：并发下同一个码只能成功一次。
//   实现靠 `UPDATE ... WHERE used_by='' AND disabled=0` + 检查 RowsAffected，
//   而不是"先 SELECT 再 UPDATE"（那中间有窗口，两个请求会同时通过）。
//
// 返回 InviteConsume* 常量。调用方据此给出不同文案。
// ValidateInvite 只读校验邀请码是否可用（**不消耗**）。
//
// 与 ConsumeInvite 的判定口径完全一致，区别只是不改任何数据。
//
// 存在的理由（2026-11-01）：注册流程原本"先原子消耗再建号"，一旦后面撞上
// 注册限额 / 账号重名 / 库错，邀请码就被烧掉了 —— 玩家既没注册成功，码也废了，
// 只能找运营补发。现在改成「先用本函数给答复 → 建号成功后再 ConsumeInvite 绑定」，
// 失败时码原封不动。
//
// ★ 必须在注册锁内与 ConsumeInvite 配对使用（见 service.RegisterWithInvite）：
// 单看本函数是"检查后使用"（TOCTOU）模式，靠外层那把锁保证两次调用之间
// 不会插进别的注册。
func (db *Database) ValidateInvite(rawCode string) int {
	code := NormalizeInviteCode(rawCode)
	if code == "" {
		return InviteConsumeNormalized
	}

	row := db.gatewayDB.QueryRow(
		"SELECT used_by, disabled, expires_at FROM invite_codes WHERE code = ?", code)
	var usedBy string
	var disabled int
	var expiresAt int64
	if err := row.Scan(&usedBy, &disabled, &expiresAt); err != nil {
		return InviteConsumeNotFound
	}

	now := utils.NowUnix()
	switch {
	case disabled != 0:
		return InviteConsumeDisabled
	case usedBy != "":
		return InviteConsumeUsed
	case expiresAt > 0 && now > expiresAt:
		return InviteConsumeExpired
	default:
		return InviteConsumeOK
	}
}

// GetInviteByCode 按码精确查一条邀请码记录（先归一化再匹配）。
//
// 用途：要看"这个码绑给谁了"，不必翻分页列表 —— ListInvites 单页上限 200 条
// 且按 created_at 排序，批量生成的码时间戳完全相同，翻页顺序不稳定，
// 很容易"明明有这条却查不到"。找不到时返回 (nil, nil)，不算错误。
func (db *Database) GetInviteByCode(rawCode string) (*InviteCode, error) {
	code := NormalizeInviteCode(rawCode)
	if code == "" {
		return nil, nil
	}
	row := db.gatewayDB.QueryRow(
		`SELECT code, note, created_by, created_at, expires_at, used_by, used_at, disabled
		   FROM invite_codes WHERE code = ?`, code)

	var (
		c        InviteCode
		disabled int
	)
	if err := row.Scan(&c.Code, &c.Note, &c.CreatedBy, &c.CreatedAt,
		&c.ExpiresAt, &c.UsedBy, &c.UsedAt, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	c.Disabled = disabled != 0
	return &c, nil
}

func (db *Database) ConsumeInvite(rawCode, account string) int {
	code := NormalizeInviteCode(rawCode)
	if code == "" {
		return InviteConsumeNormalized
	}

	now := utils.NowUnix()

	// 一条 SQL 同时完成"校验未用/未作废/未过期"和"标记已用"。
	// 过期判定放进 WHERE：这样过期的码 RowsAffected=0，与"已用"一样被拒，
	// 不需要先查出来再判断（避免多一次往返和竞态）。
	res, err := db.gatewayDB.Exec(
		`UPDATE invite_codes
		    SET used_by = ?, used_at = ?
		  WHERE code = ?
		    AND used_by = ''
		    AND disabled = 0
		    AND (expires_at = 0 OR expires_at >= ?)`,
		account, now, code, now)
	if err != nil {
		return InviteConsumeNotFound
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return InviteConsumeOK
	}

	// 没更新成功 —— 查一次给出**具体**原因（文案要能指导玩家）
	row := db.gatewayDB.QueryRow(
		"SELECT used_by, disabled, expires_at FROM invite_codes WHERE code = ?", code)
	var usedBy string
	var disabled int
	var expiresAt int64
	if err := row.Scan(&usedBy, &disabled, &expiresAt); err != nil {
		return InviteConsumeNotFound
	}
	switch {
	case disabled != 0:
		return InviteConsumeDisabled
	case usedBy != "":
		return InviteConsumeUsed
	case expiresAt > 0 && now > expiresAt:
		return InviteConsumeExpired
	default:
		// 理论上不可达（UPDATE 失败但状态看起来可用）—— 按无效处理
		return InviteConsumeNotFound
	}
}

// CreateInviteWithCode 用**指定**的码插入一条邀请码（不随机生成）。
//
// 用途：
//   - 测试要一个固定码（随机码没法在断言里引用）
//   - 运营想给某人一个"好记的"码（如 VIP 批次）
//
// 码会先归一化。已存在时返回错误（不覆盖 —— 覆盖会让"谁用了这个码"的记录错乱）。
func (db *Database) CreateInviteWithCode(code, note, createdBy string, expiresAt int64) error {
	code = NormalizeInviteCode(code)
	if code == "" {
		return fmt.Errorf("邀请码不能为空")
	}
	_, err := db.gatewayDB.Exec(
		`INSERT INTO invite_codes (code, note, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		code, strings.TrimSpace(note), strings.TrimSpace(createdBy), utils.NowUnix(), expiresAt)
	return err
}

// ListInvites 分页查询邀请码。
//
// status 为空 = 全部；否则按 InviteStatus 过滤（在 SQL 里做，避免全表拉回内存）。
// keyword 匹配 code / note / used_by。
func (db *Database) ListInvites(status, keyword string, page, pageSize int) (int, []InviteCode, error) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	now := utils.NowUnix()

	// 状态条件（与 InviteCode.Status 的口径必须一致）
	var statusCond string
	switch InviteStatus(status) {
	case InviteStatusUnused:
		statusCond = "disabled = 0 AND used_by = '' AND (expires_at = 0 OR expires_at >= " +
			itoa64(now) + ")"
	case InviteStatusUsed:
		statusCond = "used_by != ''"
	case InviteStatusDisabled:
		statusCond = "disabled != 0"
	case InviteStatusExpired:
		statusCond = "disabled = 0 AND used_by = '' AND expires_at > 0 AND expires_at < " +
			itoa64(now)
	}

	var conds []string
	var args []interface{}
	if statusCond != "" {
		conds = append(conds, statusCond)
	}
	if keyword != "" {
		conds = append(conds, "(code LIKE ? OR note LIKE ? OR used_by LIKE ?)")
		kw := "%" + keyword + "%"
		args = append(args, kw, kw, kw)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM invite_codes"+where, args...).Scan(&total); err != nil {
		return 0, nil, err
	}

	query := "SELECT code, note, created_by, created_at, expires_at, used_by, used_at, disabled" +
		" FROM invite_codes" + where + " ORDER BY created_at DESC, code ASC LIMIT ? OFFSET ?"
	qargs := append(append([]interface{}{}, args...), pageSize, (page-1)*pageSize)

	rows, err := db.gatewayDB.Query(query, qargs...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	var out []InviteCode
	for rows.Next() {
		var c InviteCode
		var disabled int
		if err := rows.Scan(&c.Code, &c.Note, &c.CreatedBy, &c.CreatedAt,
			&c.ExpiresAt, &c.UsedBy, &c.UsedAt, &disabled); err != nil {
			return 0, nil, err
		}
		c.Disabled = disabled != 0
		out = append(out, c)
	}
	return total, out, rows.Err()
}

// RevokeInvite 作废一个未使用的邀请码。
//
// 只作废**未使用**的：已用的码作废没有意义（号已经建出来了），
// 而且会让"这个码被谁用了"的追溯记录变得含混。
//
// 返回是否真的改动了（false = 码不存在或已被使用）。
func (db *Database) RevokeInvite(rawCode string) (bool, error) {
	code := NormalizeInviteCode(rawCode)
	if code == "" {
		return false, nil
	}
	res, err := db.gatewayDB.Exec(
		"UPDATE invite_codes SET disabled = 1 WHERE code = ? AND used_by = '' AND disabled = 0",
		code)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CountUnusedInvites 返回当前可用（未用/未过期/未作废）的邀请码数量。
//
// 后台首页用它提示"邀请码快用完了"。
func (db *Database) CountUnusedInvites() (int, error) {
	var n int
	now := utils.NowUnix()
	err := db.gatewayDB.QueryRow(
		`SELECT COUNT(*) FROM invite_codes
		  WHERE disabled = 0 AND used_by = '' AND (expires_at = 0 OR expires_at >= ?)`,
		now).Scan(&n)
	return n, err
}

// ExportUnusedInvites 导出全部可用邀请码（后台"复制全部"用）。
//
// limit 兜底 2000：再多应该分批发，而不是一次性粘到群里。
func (db *Database) ExportUnusedInvites(limit int) ([]string, error) {
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	now := utils.NowUnix()
	rows, err := db.gatewayDB.Query(
		`SELECT code FROM invite_codes
		  WHERE disabled = 0 AND used_by = '' AND (expires_at = 0 OR expires_at >= ?)
		  ORDER BY created_at ASC LIMIT ?`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// itoa64 是 strconv.FormatInt 的最小替代（避免为此单独 import strconv）。
func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
