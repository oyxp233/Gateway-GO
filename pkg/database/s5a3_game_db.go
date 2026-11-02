package database

// ============================================================================
// S5A3 游戏库（MariaDB）后端
//
// ── 为什么需要这一层 ─────────────────────────────────────────────────────
//
// 网关原本的游戏库访问全部写死 S4A21 的 SQLite 表结构：
//
//	mailbox_messages / mailbox_recipients / mailbox_attachments
//	accounts(m_id, cera, token_cera, happy_token_cera)
//	characters(character_id, account_id, name, level, job)
//
// S5A3 的库是 MariaDB，表结构与列名**完全不同**：
//
//	dnf_mails / dnf_mail_attachments / dnf_mail_attachment_extra / dnf_mailboxes
//	dnf_account_metadata(account_id, entry_key, entry_value)   ← 点券在这里，是 key-value
//	dnf_characters(character_id varchar, account_id varchar 'dnf:10002', job varchar)
//	dnf90_web_accounts(account, password_hash, account_id)     ← 账号名 ↔ account_id
//
// 所以不是"改个连接串"就能复用，SQL 必须重写一套。
//
// ── 关键差异（踩过才知道）────────────────────────────────────────────────
//
//  1. **点券是账号级的 key-value**，不是列。`dnf_account_metadata` 里
//     entry_key='account_cera' 的那一行才是余额；`dnf_characters.cera` 列
//     存在但恒为 0，不要往那里写。
//
//  2. **m_id 就是 S5A3 的 account_id**（形如 `dnf:10002`）。网关 S5A3 登录
//     分支把 `result.MId` 设成服务端返回的 account_id（见 service/s5a3_account.go），
//     所以泡点/注册奖励拿到的 m_id 可以直接当 account_id 用。
//
//  3. **邮箱是整箱 replace 语义**（服务端 mysql_mail.go 的 replaceMails：
//     DELETE 全部该角色邮件再按内存重插）。这意味着**角色在线时写库会被覆盖**。
//     网关侧只能保证离线角色可靠，在线角色需要调用方自己排除（后台"全服邮件"
//     已经通过 S5A3 的 /api/game/admin 在线快照做了过滤）。
//
//  4. **附件 raw_entry 可以为 NULL**。服务端 mailboxAttachmentRaw 会用默认 0
//     铺底再按 PVF 补证据（注释里明写"GM 面板发的装备附件没有 0x77 行"）。
//     所以网关不需要自己编码 119 字节实例数据。
//
//  5. **character_id 是 varchar**，但内容全是十进制数字；对外仍按 int64 暴露，
//     与 S4A21 的调用方保持同一套签名。
// ============================================================================

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// errS5A3GameNotConfigured 表示没有配 S5A3 游戏库。
//
// 调用方拿到的应该是"明确说清楚缺什么"，而不是 nil 或空列表 —— 后者会让
// 运维以为"服务器上没有角色"，方向完全错。
var errS5A3GameNotConfigured = errors.New("未配置 S5A3 游戏库（Database.GameDSN 为空）")

// s5a3Timeout 是单条 S5A3 查询/写入的超时。
//
// 全服邮件是逐角色一个事务，网络抖动时必须能快速失败，不能把后台请求挂死。
const s5a3Timeout = 15 * time.Second

func (db *Database) s5a3Ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s5a3Timeout)
}

// ─────────────────────────────────────────────────────────────────────────────
// 账号解析
// ─────────────────────────────────────────────────────────────────────────────

// S5A3AccountIDByName 把登录名翻译成 S5A3 的 account_id（形如 dnf:10002）。
//
// ★ 为什么必须有：注册奖励/泡点的发放目标是 `dnf_account_metadata.account_id`，
// 而调用方手里只有登录名。S4A21 这条路走网关库 accounts 表的 m_id 列；
// S5A3 的账号根本不在网关库（账号主权在服务端 MySQL），必须直接查
// dnf90_web_accounts.account_id。
//
// 找不到返回空串 + nil：调用方据此"保持待发"，而不是当成错误。
func (db *Database) S5A3AccountIDByName(accountName string) (string, error) {
	if !db.S5A3GameConfigured() {
		return "", errS5A3GameNotConfigured
	}
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		return "", nil
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := "SELECT account_id FROM " + db.s5a3AccountTable() + " WHERE account = ? LIMIT 1"
	var accountID string
	err := db.s5a3DB.QueryRowContext(ctx, query, accountName).Scan(&accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("查询 S5A3 账号 %s: %w", accountName, err)
	}
	return strings.TrimSpace(accountID), nil
}

// S5A3AccountExists 判断 account_id 在 S5A3 库里是否有账号行。
func (db *Database) S5A3AccountExists(mId string) bool {
	if !db.S5A3GameConfigured() {
		return false
	}
	mId = strings.TrimSpace(mId)
	if mId == "" {
		return false
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := "SELECT 1 FROM " + db.s5a3Table("accounts") + " WHERE account_id = ? LIMIT 1"
	var probe int
	if err := db.s5a3DB.QueryRowContext(ctx, query, mId).Scan(&probe); err != nil {
		return false
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// 账号列表（后台「账号管理」）
// ─────────────────────────────────────────────────────────────────────────────

// s5a3LoadAccounts 从 S5A3 库读全量账号，拼成网关的 Account 结构。
//
// ★ 为什么不能沿用网关库 accounts 表：S5A3 的账号主权在服务端 MySQL，
//   网关库那张表通常一行都没有（只有历史同步脚本补过才有）⇒
//   后台「账号管理」会显示成空列表，运维以为"没玩家"。
//
// 字段来源：
//
//	MId           ← dnf90_web_accounts.account_id（dnf:10002，与登录会话的 MId 同值）
//	Name          ← dnf90_web_accounts.account
//	Cera          ← dnf_account_metadata[account_cera]
//	LastLoginAt   ← dnf90_web_accounts.last_login_at
//	LastLoginIP   ← dnf90_web_accounts.last_login_ip
//	CreatedAt     ← dnf90_web_accounts.created_at（真正的注册时间）
//	GameCreatedAt ← dnf_accounts.created_at（玩家首次进游戏的时间）
//
// 密码哈希/salt/设备绑定这些网关侧字段在 S5A3 下没有意义（密码由服务端 bcrypt
// 管理），留空即可 —— 前端不该在 S5A3 下展示它们。
func (db *Database) s5a3LoadAccounts() ([]Account, error) {
	if !db.S5A3GameConfigured() {
		return nil, errS5A3GameNotConfigured
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	query := fmt.Sprintf(`
		SELECT a.account_id, a.account, a.created_at, a.last_login_at, a.last_login_ip,
		       ga.created_at AS game_created_at,
		       COALESCE(m.entry_value, '0') AS cera
		FROM %s a
		LEFT JOIN %s ga ON ga.account_id = a.account_id COLLATE utf8mb4_unicode_ci
		LEFT JOIN %s m ON m.account_id = a.account_id COLLATE utf8mb4_unicode_ci AND m.entry_key = 'account_cera'
		ORDER BY a.id`, db.s5a3AccountTable(), db.s5a3Table("accounts"), db.s5a3Table("account_metadata"))
	rows, err := db.s5a3DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("查询 S5A3 账号列表: %w", err)
	}
	defer rows.Close()

	out := make([]Account, 0, 128)
	for rows.Next() {
		var a Account
		var createdAt sql.NullTime
		var lastLogin sql.NullTime
		var lastIP sql.NullString
		var gameCreated sql.NullTime
		var ceraRaw sql.NullString
		if err := rows.Scan(&a.MId, &a.Name, &createdAt, &lastLogin, &lastIP, &gameCreated, &ceraRaw); err != nil {
			return nil, err
		}
		if createdAt.Valid {
			a.CreatedAt = createdAt.Time.Unix()
		}
		if lastLogin.Valid {
			a.LastLoginAt = lastLogin.Time.Unix()
		}
		a.LastLoginIP = strings.TrimSpace(lastIP.String)
		if gameCreated.Valid {
			a.GameCreatedAt = gameCreated.Time.UTC().Format("2006-01-02 15:04:05")
		}
		a.Cera, _ = strconv.ParseInt(strings.TrimSpace(ceraRaw.String), 10, 64)
		out = append(out, a)
	}
	return out, rows.Err()
}

// s5a3GameAccountCreatedAt 批量取 dnf_accounts.created_at（玩家首次进游戏时间）。
func (db *Database) s5a3GameAccountCreatedAt(mIds []string) map[string]string {
	out := make(map[string]string, len(mIds))
	if !db.S5A3GameConfigured() || len(mIds) == 0 {
		return out
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := "SELECT account_id, created_at FROM " + db.s5a3Table("accounts") + " WHERE account_id = ?"
	for _, mId := range mIds {
		key := strings.TrimSpace(mId)
		if key == "" {
			continue
		}
		var createdAt sql.NullTime
		if err := db.s5a3DB.QueryRowContext(ctx, query, key).Scan(&key, &createdAt); err != nil {
			continue
		}
		if createdAt.Valid {
			out[key] = createdAt.Time.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return out
}

// s5a3SearchAccountMIdsByRole 按「角色名 或 角色ID」找出 account_id。
func (db *Database) s5a3SearchAccountMIdsByRole(keyword string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	if !db.S5A3GameConfigured() {
		return result, nil
	}
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return result, nil
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	// 角色 ID 是数字：命中就直查，省掉全表扫。
	if id, err := strconv.ParseInt(keyword, 10, 64); err == nil && id > 0 {
		query := "SELECT account_id FROM " + db.s5a3Table("characters") +
			" WHERE character_id = ? AND delete_flag = 0 LIMIT 1"
		var accountID string
		if err := db.s5a3DB.QueryRowContext(ctx, query, strconv.FormatInt(id, 10)).Scan(&accountID); err == nil {
			if key := strings.TrimSpace(accountID); key != "" {
				result[key] = struct{}{}
			}
		}
	}

	// 角色名模糊匹配。S5A3 的 name 是 utf8mb4（不是 S4A21 的 GBK 裸字节），
	// 所以可以直接交给 SQL 的 LIKE，不用取回来在 Go 里解码。
	query := "SELECT DISTINCT account_id FROM " + db.s5a3Table("characters") +
		" WHERE delete_flag = 0 AND name LIKE ?"
	rows, err := db.s5a3DB.QueryContext(ctx, query, "%"+keyword+"%")
	if err != nil {
		return nil, fmt.Errorf("按角色名查 S5A3 账号: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var accountID string
		if err := rows.Scan(&accountID); err != nil {
			continue
		}
		if key := strings.TrimSpace(accountID); key != "" {
			result[key] = struct{}{}
		}
	}
	return result, rows.Err()
}

// ─────────────────────────────────────────────────────────────────────────────
// 角色查询
// ─────────────────────────────────────────────────────────────────────────────

// s5a3CharacterSelect 是角色行的统一投影（三处查询共用，避免列顺序漂移）。
//
// account_id 取 dnf90_web_accounts.id（bigint），装进 Character.AccountId；
// account_id 字符串（dnf:10002）另存到 Character.AccountKey。
const s5a3CharacterSelect = `
	SELECT CAST(c.character_id AS UNSIGNED) AS cid,
	       COALESCE(a.id, 0)               AS acc_num,
	       c.account_id                    AS acc_key,
	       c.name                          AS cname,
	       c.level                         AS clevel,
	       c.job                           AS cjob,
	       c.grow_type                     AS cgrow
	FROM %s c
	LEFT JOIN %s a ON a.account_id COLLATE utf8mb4_unicode_ci = c.account_id
	WHERE c.delete_flag = 0`

// s5a3ScanCharacters 把查询结果扫成 []Character。
func s5a3ScanCharacters(rows *sql.Rows) ([]Character, error) {
	defer rows.Close()
	var out []Character
	for rows.Next() {
		var c Character
		var accKey sql.NullString
		var name sql.NullString
		var jobRaw sql.NullString
		if err := rows.Scan(&c.CharacterId, &c.AccountId, &accKey, &name, &c.Level, &jobRaw, &c.GrowType); err != nil {
			return nil, err
		}
		c.Name = strings.TrimSpace(name.String)
		c.AccountKey = strings.TrimSpace(accKey.String)
		// job 在 S5A3 里是 varchar，但内容全是十进制数字（0=鬼剑士…）。
		// 解析不出来时留 0，不报错 —— 一个职业编码坏掉不该让整批邮件发不出去。
		if parsed, err := strconv.Atoi(strings.TrimSpace(jobRaw.String)); err == nil {
			c.Job = parsed
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// s5a3GetAllAliveCharacters 取全服存活角色（全服邮件的目标集合）。
func (db *Database) s5a3GetAllAliveCharacters() ([]Character, error) {
	if !db.S5A3GameConfigured() {
		return nil, errS5A3GameNotConfigured
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := fmt.Sprintf(s5a3CharacterSelect, db.s5a3Table("characters"), db.s5a3AccountTable())
	rows, err := db.s5a3DB.QueryContext(ctx, query+" ORDER BY c.character_id")
	if err != nil {
		return nil, fmt.Errorf("查询 S5A3 角色列表: %w", err)
	}
	return s5a3ScanCharacters(rows)
}

// s5a3GetCharacter 按角色 ID 取单个角色。
func (db *Database) s5a3GetCharacter(characterId int64) (*Character, error) {
	if !db.S5A3GameConfigured() {
		return nil, errS5A3GameNotConfigured
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := fmt.Sprintf(s5a3CharacterSelect, db.s5a3Table("characters"), db.s5a3AccountTable())
	rows, err := db.s5a3DB.QueryContext(ctx, query+" AND c.character_id = ? LIMIT 1", strconv.FormatInt(characterId, 10))
	if err != nil {
		return nil, fmt.Errorf("查询 S5A3 角色 %d: %w", characterId, err)
	}
	list, err := s5a3ScanCharacters(rows)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return &list[0], nil
}

// s5a3GetCharactersByAccount 按账号数值 ID（dnf90_web_accounts.id）取角色。
func (db *Database) s5a3GetCharactersByAccount(accountId int64) ([]Character, error) {
	if !db.S5A3GameConfigured() {
		return nil, errS5A3GameNotConfigured
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := fmt.Sprintf(s5a3CharacterSelect, db.s5a3Table("characters"), db.s5a3AccountTable())
	rows, err := db.s5a3DB.QueryContext(ctx, query+" AND a.id = ? ORDER BY c.slot", accountId)
	if err != nil {
		return nil, fmt.Errorf("查询 S5A3 账号 %d 的角色: %w", accountId, err)
	}
	return s5a3ScanCharacters(rows)
}

// s5a3FindFirstAliveCharacter 按 m_id（= account_id 字符串）取首个存活角色。
func (db *Database) s5a3FindFirstAliveCharacter(mId string) (*Character, error) {
	if !db.S5A3GameConfigured() {
		return nil, errS5A3GameNotConfigured
	}
	mId = strings.TrimSpace(mId)
	if mId == "" {
		return nil, nil
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := fmt.Sprintf(s5a3CharacterSelect, db.s5a3Table("characters"), db.s5a3AccountTable())
	rows, err := db.s5a3DB.QueryContext(ctx, query+" AND c.account_id = ? ORDER BY c.slot, c.character_id LIMIT 1", mId)
	if err != nil {
		return nil, fmt.Errorf("查询 S5A3 账号 %s 的首个角色: %w", mId, err)
	}
	list, err := s5a3ScanCharacters(rows)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return &list[0], nil
}

// s5a3GetRolesByAccount 按网关账号名取角色（后台"账号管理 → 角色"用）。
func (db *Database) s5a3GetRolesByAccount(accountName string) ([]RoleInfo, error) {
	if !db.S5A3GameConfigured() {
		return nil, errS5A3GameNotConfigured
	}
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		return nil, nil
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := fmt.Sprintf(`
		SELECT CAST(c.character_id AS UNSIGNED), c.name, c.level, c.job, c.grow_type, c.exp
		FROM %s c
		JOIN %s a ON a.account_id COLLATE utf8mb4_unicode_ci = c.account_id
		WHERE a.account = ? AND c.delete_flag = 0
		ORDER BY c.slot`, db.s5a3Table("characters"), db.s5a3AccountTable())
	rows, err := db.s5a3DB.QueryContext(ctx, query, accountName)
	if err != nil {
		return nil, fmt.Errorf("查询 S5A3 账号 %s 的角色: %w", accountName, err)
	}
	defer rows.Close()
	var out []RoleInfo
	for rows.Next() {
		var r RoleInfo
		var name, jobRaw sql.NullString
		if err := rows.Scan(&r.CharacterId, &name, &r.Level, &jobRaw, &r.GrowType, &r.Exp); err != nil {
			return nil, err
		}
		r.Name = strings.TrimSpace(name.String)
		if parsed, err := strconv.Atoi(strings.TrimSpace(jobRaw.String)); err == nil {
			r.Job = parsed
		}
		r.JobName = JobDisplayName(r.Job, r.GrowType)
		out = append(out, r)
	}
	return out, rows.Err()
}

// s5a3CurrentRoleName 取账号最近活动的角色名（在线列表兜底显示用）。
func (db *Database) s5a3CurrentRoleName(account string) string {
	if !db.S5A3GameConfigured() {
		return ""
	}
	account = strings.TrimSpace(account)
	if account == "" {
		return ""
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := fmt.Sprintf(`
		SELECT c.name FROM %s c
		JOIN %s a ON a.account_id COLLATE utf8mb4_unicode_ci = c.account_id
		WHERE a.account = ? AND c.delete_flag = 0
		ORDER BY c.updated_at DESC LIMIT 1`, db.s5a3Table("characters"), db.s5a3AccountTable())
	var name sql.NullString
	if err := db.s5a3DB.QueryRowContext(ctx, query, account).Scan(&name); err != nil {
		return ""
	}
	return strings.TrimSpace(name.String)
}

// s5a3GetCurrentRolesByMIds 批量取「这些账号的当前角色」（在线列表用）。
//
// 与 S4A21 版本同语义：按 updated_at 倒序，每个 m_id 取第一行。
func (db *Database) s5a3GetCurrentRolesByMIds(mIds []string) (map[string]OnlineRoleCandidate, error) {
	out := make(map[string]OnlineRoleCandidate, len(mIds))
	if !db.S5A3GameConfigured() || len(mIds) == 0 {
		return out, nil
	}
	// 逐个查：账号数在在线列表这个场景是几十个量级，用 IN 拼参数反而更啰嗦。
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := fmt.Sprintf(`
		SELECT c.account_id, CAST(c.character_id AS UNSIGNED), c.name, c.level, c.job, c.updated_at,
		       (SELECT COUNT(*) FROM %s c2 WHERE c2.account_id = c.account_id AND c2.delete_flag = 0)
		FROM %s c
		WHERE c.account_id = ? AND c.delete_flag = 0
		ORDER BY c.updated_at DESC, c.character_id DESC
		LIMIT 1`, db.s5a3Table("characters"), db.s5a3Table("characters"))
	for _, mId := range mIds {
		key := strings.TrimSpace(mId)
		if key == "" {
			continue
		}
		var cand OnlineRoleCandidate
		var name, jobRaw sql.NullString
		var updatedAt sql.NullTime
		err := db.s5a3DB.QueryRowContext(ctx, query, key).Scan(
			&cand.MId, &cand.CharacterId, &name, &cand.Level, &jobRaw, &updatedAt, &cand.RoleCount)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return out, fmt.Errorf("查询 S5A3 账号 %s 的当前角色: %w", key, err)
		}
		cand.Name = strings.TrimSpace(name.String)
		if parsed, err := strconv.Atoi(strings.TrimSpace(jobRaw.String)); err == nil {
			cand.Job = parsed
		}
		if updatedAt.Valid {
			cand.LastActiveAt = updatedAt.Time.UTC().Format("2006-01-02 15:04:05")
		}
		out[key] = cand
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 点券（dnf_account_metadata 的 key-value）
// ─────────────────────────────────────────────────────────────────────────────

// s5a3CurrencyKey 把网关的列名映射到 S5A3 的 metadata entry_key。
//
// 网关沿用 S4A21 的三个列名（cera / token_cera / happy_token_cera），
// S5A3 侧对应三个 entry_key。映射只此一处，别在别处再写一遍。
func s5a3CurrencyKey(column string) (string, error) {
	switch column {
	case "cera":
		return "account_cera", nil
	case "token_cera":
		return "account_token_cera", nil
	case "happy_token_cera":
		return "account_happy_token_cera", nil
	default:
		return "", fmt.Errorf("unsupported currency column: %s", column)
	}
}

// s5a3AddCurrency 原子累加账号点券，返回受影响行数（0 = 该账号没有这一行）。
//
// ★ 用 `INSERT ... ON DUPLICATE KEY UPDATE` 做**库里自增**，不是"读出来改再写回"：
//   - 读改写会在并发（泡点主循环 + 后台发放）时丢掉一笔；
//   - 显式 `+ ?` 而不是 `VALUES(entry_value)`：后者在 MySQL 8.0.20+ 已废弃，
//     MariaDB 上语义才等价（S5A3 服务端 AddAccountEpicPieceBalance 用的是同一种写法）。
//
// ★ 必须 CAST 成 SIGNED：entry_value 是 longtext，直接 `+` 会按字符串拼接。
//   负数（扣点券）也要能算，所以是 SIGNED 不是 UNSIGNED。
//
// 余额下限保护：扣到负数时钳到 0。宁可少扣，也不要出现负余额让客户端显示异常。
func (db *Database) s5a3AddCurrency(mId, column string, amount int64) (int64, error) {
	if !db.S5A3GameConfigured() {
		return 0, errS5A3GameNotConfigured
	}
	mId = strings.TrimSpace(mId)
	if mId == "" {
		return 0, errors.New("m_id 为空")
	}
	entryKey, err := s5a3CurrencyKey(column)
	if err != nil {
		return 0, err
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	// 账号行必须存在才能挂 metadata（没有外键约束，但语义上要求）。
	// 不存在时直接返回 0 行：调用方据此提示"该账号还没进过游戏"。
	existsQuery := "SELECT 1 FROM " + db.s5a3Table("accounts") + " WHERE account_id = ?"
	var probe int
	if err := db.s5a3DB.QueryRowContext(ctx, existsQuery, mId).Scan(&probe); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("检查 S5A3 账号 %s: %w", mId, err)
	}

	query := "INSERT INTO " + db.s5a3Table("account_metadata") +
		" (account_id, entry_key, entry_value) VALUES (?, ?, ?)" +
		" ON DUPLICATE KEY UPDATE entry_value = CAST(GREATEST(0, CAST(entry_value AS SIGNED) + ?) AS CHAR)"
	result, err := db.s5a3DB.ExecContext(ctx, query, mId, entryKey, strconv.FormatInt(amount, 10), amount)
	if err != nil {
		return 0, fmt.Errorf("累加 S5A3 账号 %s 的 %s: %w", mId, entryKey, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	// MySQL 语义：插入 = 1，更新且值变化 = 2，更新但值没变 = 0。
	// 累加 0 或钳在 0 时会是 0 行，这在"账号存在"的前提下仍算成功，
	// 所以这里把 0 统一报成 1，避免调用方误判成"账号不存在"。
	if affected == 0 {
		return 1, nil
	}
	return affected, nil
}

// s5a3GetCeraByMId 取账号点券余额。
func (db *Database) s5a3GetCeraByMId(mId string) (int64, error) {
	balance, _, _, ok := db.s5a3GetCurrencyTriple(mId)
	if !ok {
		return 0, nil
	}
	return balance, nil
}

// s5a3GetCurrencyTriple 一次取三种余额。
func (db *Database) s5a3GetCurrencyTriple(mId string) (cera, token, happy int64, ok bool) {
	if !db.S5A3GameConfigured() {
		return 0, 0, 0, false
	}
	mId = strings.TrimSpace(mId)
	if mId == "" {
		return 0, 0, 0, false
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()
	query := "SELECT entry_key, entry_value FROM " + db.s5a3Table("account_metadata") +
		" WHERE account_id = ? AND entry_key IN (?, ?, ?)"
	rows, err := db.s5a3DB.QueryContext(ctx, query, mId, "account_cera", "account_token_cera", "account_happy_token_cera")
	if err != nil {
		return 0, 0, 0, false
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		switch key {
		case "account_cera":
			cera = parsed
		case "account_token_cera":
			token = parsed
		case "account_happy_token_cera":
			happy = parsed
		}
	}
	return cera, token, happy, true
}

// ─────────────────────────────────────────────────────────────────────────────
// 邮件
// ─────────────────────────────────────────────────────────────────────────────

// s5a3SendMailWithGold 向指定角色投递一封带附件（可选带金币）的邮件。
//
// 写三张表：
//  1. dnf_mailboxes        —— 邮箱本体行（没有这一行，服务端 Load 会返回 found=false）
//  2. dnf_mails            —— 邮件头
//  3. dnf_mail_attachments —— 附件（raw_entry 留 NULL，服务端按 PVF 补证据）
//
// ★ **不做幂等**：同一批发放重复调用会产生多封邮件。幂等由上层
//   （注册奖励的 receipt 键 / 后台的操作确认）保证，这一层只管写。
//
// ★ **角色在线时会被覆盖**：服务端退出时按内存整箱 replace（DELETE+重插），
//   网关刚写的会被删掉。调用方必须先排除在线角色。
func (db *Database) s5a3SendMailWithGold(
	characterId int64,
	characterName, title, body string,
	gold int64,
	items []MailItem,
	expireHours int,
) error {
	if !db.S5A3GameConfigured() {
		return errS5A3GameNotConfigured
	}
	charKey := strconv.FormatInt(characterId, 10)
	if characterId <= 0 || charKey == "0" {
		return errors.New("角色 ID 无效")
	}
	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	tx, err := db.s5a3DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	var expireAt any
	if expireHours > 0 {
		expireAt = now.Add(time.Duration(expireHours) * time.Hour)
	}

	// 1. 邮箱本体：没有这行，服务端 loadMails 之前就返回 found=false。
	//
	// ★ 先 `INSERT ... ON DUPLICATE KEY UPDATE` 再 `SELECT ... FOR UPDATE` 锁住它：
	//   与 PurpleMagic 的做法一致（"锁定原角色、账号和邮箱父行，只插入新邮件"）。
	//   行锁只能挡住**另一个网关事务**，挡不住服务端的整箱 replace
	//   （服务端 replaceMails 的 DELETE 会等我们提交，然后照样删）——
	//   所以调用方仍必须先排除在线角色，这里只是把并发窗口收窄。
	mailboxUpsert := "INSERT INTO " + db.s5a3Table("mailboxes") + " (character_id, updated_at) VALUES (?, ?)" +
		" ON DUPLICATE KEY UPDATE updated_at = VALUES(updated_at)"
	if _, err := tx.ExecContext(ctx, mailboxUpsert, charKey, now); err != nil {
		return fmt.Errorf("写入 S5A3 邮箱 %s: %w", charKey, err)
	}
	var lockedCharID string
	lockQuery := "SELECT character_id FROM " + db.s5a3Table("mailboxes") + " WHERE character_id = ? FOR UPDATE"
	if err := tx.QueryRowContext(ctx, lockQuery, charKey).Scan(&lockedCharID); err != nil {
		return fmt.Errorf("锁定 S5A3 邮箱 %s: %w", charKey, err)
	}

	// 2. 邮件头。mail_id 取该角色当前最大值 +1，与 S5A3 服务端 nextMailID 同口径
	//    （客户端按 uint32 解析，所以不能塞时间戳进去）。
	var nextMailID int64
	maxQuery := "SELECT COALESCE(MAX(CAST(mail_id AS UNSIGNED)), 0) + 1 FROM " + db.s5a3Table("mails") + " WHERE character_id = ?"
	if err := tx.QueryRowContext(ctx, maxQuery, charKey).Scan(&nextMailID); err != nil {
		return fmt.Errorf("计算 S5A3 邮件号 %s: %w", charKey, err)
	}
	mailKey := strconv.FormatInt(nextMailID, 10)

	mailInsert := "INSERT INTO " + db.s5a3Table("mails") +
		" (character_id, mail_id, sender_character_id, sender_name, recipient_character_id," +
		"  recipient_name, title, body, gold, read_flag, claimed_flag, deleted_flag, created_at, expire_at)" +
		" VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)"
	if _, err := tx.ExecContext(ctx, mailInsert,
		charKey, mailKey, s5a3SystemSenderName,
		charKey, characterName, title, body, gold, now, expireAt); err != nil {
		return fmt.Errorf("写入 S5A3 邮件头 %s/%s: %w", charKey, mailKey, err)
	}

	// 3. 附件。raw_entry 留 NULL：服务端 mailboxAttachmentRaw 会按 PVF 补，
	//    自己编 119 字节反而容易填错（S4A21 时代踩过）。
	if len(items) > 0 {
		attachInsert := "INSERT INTO " + db.s5a3Table("mail_attachments") +
			" (character_id, mail_id, attachment_index, item_id, item_count, bind_flag, expire_at, raw_entry)" +
			" VALUES (?, ?, ?, ?, ?, 0, ?, NULL)"
		extraInsert := "INSERT INTO " + db.s5a3Table("mail_attachment_extra") +
			" (character_id, mail_id, attachment_index, extra_key, extra_value) VALUES (?, ?, ?, ?, ?)"
		for index, item := range items {
			count := item.Count
			if count <= 0 {
				count = 1
			}
			if _, err := tx.ExecContext(ctx, attachInsert,
				charKey, mailKey, index, item.ItemTemplateId, count, expireAt); err != nil {
				return fmt.Errorf("写入 S5A3 邮件附件 %s/%s#%d: %w", charKey, mailKey, index, err)
			}
			// item_kind 是服务端判定"装扮/宠物/普通道具"的依据
			// （mail/body.go 的 mailboxAttachmentIsAvatar 读它），必须落。
			kind := item.Kind
			if kind <= 0 {
				kind = 3
			}
			if _, err := tx.ExecContext(ctx, extraInsert,
				charKey, mailKey, index, "item_kind", strconv.Itoa(kind)); err != nil {
				return fmt.Errorf("写入 S5A3 附件属性 %s/%s#%d: %w", charKey, mailKey, index, err)
			}
			if _, err := tx.ExecContext(ctx, extraInsert,
				charKey, mailKey, index, "source", s5a3MailSource); err != nil {
				return fmt.Errorf("写入 S5A3 附件来源 %s/%s#%d: %w", charKey, mailKey, index, err)
			}
		}
	}

	return tx.Commit()
}

const (
	// s5a3SystemSenderName 是系统邮件的发件人显示名。
	s5a3SystemSenderName = "系统"
	// s5a3MailSource 写进附件 extra 的来源标记，便于事后审计"这封是谁发的"。
	s5a3MailSource = "gateway_broadcast"
)

// s5a3ClearMailbox 清空某个角色的全部邮件（附件与属性一并删）。
func (db *Database) s5a3ClearMailbox(characterId int64) (int64, error) {
	if !db.S5A3GameConfigured() {
		return 0, errS5A3GameNotConfigured
	}
	charKey := strconv.FormatInt(characterId, 10)
	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	tx, err := db.s5a3DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// 先数一下要删多少（返回值给后台显示"清掉了几封"）。
	var total int64
	countQuery := "SELECT COUNT(*) FROM " + db.s5a3Table("mails") + " WHERE character_id = ?"
	if err := tx.QueryRowContext(ctx, countQuery, charKey).Scan(&total); err != nil {
		return 0, err
	}
	// 删除顺序与 S5A3 服务端 replaceMails 一致：先子表后主表。
	for _, table := range []string{"mail_attachment_extra", "mail_attachments", "mail_metadata", "mails"} {
		query := "DELETE FROM " + db.s5a3Table(table) + " WHERE character_id = ?"
		if _, err := tx.ExecContext(ctx, query, charKey); err != nil {
			return 0, fmt.Errorf("清空 S5A3 %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}
