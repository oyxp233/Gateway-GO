package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Character 游戏角色信息。
type Character struct {
	CharacterId int64
	AccountId   int64
	Name        string
	Level       int
	Job         int
	// GrowType 是转职/觉醒编码（低 4 位 = 转职，高 4 位 = 觉醒）。
	// S4A21 的查询不取这一列，留 0；S5A3 的 dnf_characters 有 grow_type 列。
	GrowType int
	// AccountKey 是 S5A3 的 account_id 字符串（形如 "dnf:10002"）。
	//
	// ★ 为什么需要它：S5A3 的 dnf_characters.account_id 是 varchar，
	//   而 AccountId 是 int64（装的是 dnf90_web_accounts.id）。
	//   邮件/点券路径要用字符串形式的 account_id 时读这个字段。
	//   S4A21 后端不填（保持空串）。
	AccountKey string
}

// BackupFile 备份目录中的一个备份文件。
//
// 字段名与前端 loadBackups() 的取值一一对应（path/size/modified_at）。
type BackupFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	// ModifiedAt 是 Unix 秒（UTC），前端 fmtTime() 按秒乘 1000 渲染。
	ModifiedAt int64 `json:"modified_at"`
}

// ListBackups 列出备份目录中的备份文件。
//
// 返回结构化对象而不是裸路径：管理后台要显示「大小 / 时间」两列。
// 历史实现返回 []string，前端拿不到 stat 信息，只能显示 "-"。
//
// 覆盖 .db / .sqlite / .bak / .pvf / .gz / .tgz 六类：
//   - 改造前：游戏库、网关库存成 .db，服务端 PVF 存成 Script-<时间戳>.pvf；
//   - 2026-10-16 起：产物改为分类压缩包 db-/pvf-/logs-<北京时间>.tar.gz。
//
// ★ .gz 这一类是**必须**加的：漏了它就正好重演注释里写的那个历史缺陷 ——
//
//	备份明明成功、界面却显示"暂无备份"。每加一种产出格式都要回来看这里。
//
// 按修改时间**倒序**（最新备份在前），同秒时用文件名兜底保证顺序稳定。
func ListBackups(backupDir string) ([]BackupFile, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, err
	}

	var backups []BackupFile
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".db", ".sqlite", ".bak", ".pvf", ".gz", ".tgz":
		default:
			continue
		}
		// 跳过写了一半的临时文件。
		// ★ 这一步比扩展名判断更靠后是刻意的：压缩包落盘用的是
		//   <名字>.tar.gz.tmp，先判扩展名的话它压根进不到这里；
		//   反过来若只看后缀，一个正好叫 xxx.gz 的半截文件会被当成成品列出来。
		if strings.HasSuffix(strings.ToLower(e.Name()), ".tmp") {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupFile{
			Name:       e.Name(),
			Path:       filepath.Join(backupDir, e.Name()),
			Size:       info.Size(),
			ModifiedAt: info.ModTime().UTC().Unix(),
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		if backups[i].ModifiedAt != backups[j].ModifiedAt {
			return backups[i].ModifiedAt > backups[j].ModifiedAt
		}
		return backups[i].Name < backups[j].Name
	})
	return backups, nil
}

// MigrateAccountsFromGameDb 首次启动时把游戏库账号迁入网关库。
//
// 幂等：网关库非空时跳过。
// 兼容两代游戏库账号表：
//   - 老库有 salt 列：password_hash + salt 一并照抄；
//   - 新版（服务端 v11，只有 password_hash）：password_hash 存的就是客户端上报的
//     pwd_md5 明文，此时 salt 置空，网关侧登录按「空 salt 直比 MD5」处理。
//
// 关键约束（与 .NET 原网关一致）：
//   - 游戏库 accounts.m_id 本身就是账号名，**原样照抄**到网关库的 m_id 与 name，
//     绝不可随机生成 m_id，否则账号名与 m_id 的映射断裂，角色/点券全部对不上；
//   - 网关库用 INSERT OR IGNORE，已存在的账号不覆盖（保留网关侧改密等状态）。
func (db *Database) MigrateAccountsFromGameDb() (*MigrationResult, error) {
	res, err := db.syncAccountsFromGameDb(true)
	if err != nil {
		return nil, err
	}
	return &MigrationResult{
		Message:      res.Message,
		Imported:     res.Imported,
		Skipped:      res.Skipped,
		Failed:       res.Failed,
		GameAccounts: res.GameAccounts,
	}, nil
}

// SyncGameAccounts 手动全量同步：把游戏库 accounts 全部账号同步进网关库。
//
// 幂等，可重复执行；已存在的网关账号不覆盖。语义与 .NET 原网关
// SyncAccountsFromGameDbAsync 完全一致，详见 MigrateAccountsFromGameDb 的说明。
func (db *Database) SyncGameAccounts() (*SyncResult, error) {
	return db.syncAccountsFromGameDb(false)
}

// syncAccountsFromGameDb 是迁移与手动同步的共用实现。
//
// onlyIfGatewayEmpty 为 true 时表示启动期自动迁移，网关库有账号即跳过。
func (db *Database) syncAccountsFromGameDb(onlyIfGatewayEmpty bool) (*SyncResult, error) {
	// S5A3：账号主权在服务端 MySQL，没有 S4A21 那种 accounts(m_id, pwd_hash, salt)
	// 表可同步。这里的"同步"在 S5A3 下语义不成立，明确说明而不是报"游戏库未配置"
	// （后者会让运维以为 GameDSN 没配对，方向完全错）。
	if db.GameBackend() == "s5a3" {
		return &SyncResult{Message: "S5A3 服的账号由服务端 MySQL 管理，不需要（也无法）同步到网关库；后台账号列表直接读 dnf90_web_accounts"}, nil
	}
	if !db.GameConfigured() {
		return &SyncResult{Message: "游戏库未配置（GamePath 为空）"}, nil
	}

	if onlyIfGatewayEmpty {
		count, err := db.CountAccounts()
		if err != nil {
			return nil, fmt.Errorf("count accounts: %w", err)
		}
		if count > 0 {
			return &SyncResult{Message: fmt.Sprintf("网关库已有 %d 个账号，跳过自动迁移", count)}, nil
		}
	}

	// 探测游戏库是否带 salt 列（老库有、新版 v11 无）
	hasSalt, err := db.gameAccountsHasSaltColumn()
	if err != nil {
		return nil, fmt.Errorf("probe game accounts schema: %w", err)
	}

	query := "SELECT m_id, password_hash FROM accounts"
	if hasSalt {
		query = "SELECT m_id, password_hash, salt FROM accounts"
	}
	rows, err := db.gameDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query game db accounts: %w", err)
	}
	defer rows.Close()

	type gameAccount struct {
		MId            string
		PasswordHash   string
		Salt           string
		Cera           int64
		TokenCera      int64
		HappyTokenCera int64
	}

	var accounts []gameAccount
	for rows.Next() {
		var a gameAccount
		if hasSalt {
			if err := rows.Scan(&a.MId, &a.PasswordHash, &a.Salt); err != nil {
				continue
			}
		} else {
			if err := rows.Scan(&a.MId, &a.PasswordHash); err != nil {
				continue
			}
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate game db accounts: %w", err)
	}

	// 点券在游戏库的 accounts 表里，单独取一次；取不到不算失败（导 0）。
	ceraMap := make(map[string][3]int64, len(accounts))
	if ceraRows, err := db.gameDB.Query(
		"SELECT m_id, cera, token_cera, happy_token_cera FROM accounts"); err == nil {
		for ceraRows.Next() {
			var mId string
			var cera, tokenCera, happyTokenCera int64
			if err := ceraRows.Scan(&mId, &cera, &tokenCera, &happyTokenCera); err == nil {
				ceraMap[mId] = [3]int64{cera, tokenCera, happyTokenCera}
			}
		}
		ceraRows.Close()
	}

	var imported, skipped, failed int

	// 单事务批量插入。SQLite 事务内单条语句失败不会让整笔事务失效，
	// 因此逐条处理、失败的跳过，已成功的部分照常提交。
	tx, err := db.gatewayDB.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO accounts
		     (m_id, name, pwd_hash, salt, cera, token_cera, happy_token_cera, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	now := NowUnix()
	for _, a := range accounts {
		mId := strings.TrimSpace(a.MId)
		if mId == "" {
			skipped++
			continue
		}

		// 账号名沿用游戏库 m_id —— 这是原网关的行为，也是唯一能保证
		// 「账号名 → m_id → 角色/点券」链路正确的方式。
		currency := ceraMap[mId]
		res, err := stmt.Exec(
			mId,            // m_id：照抄游戏库
			mId,            // name：与新库 m_id 一致
			a.PasswordHash, // 老库是加盐哈希，新库是 pwd_md5 明文
			a.Salt,         // 新库为空字符串，登录侧走「空 salt 直比 MD5」分支
			currency[0], currency[1], currency[2],
			now,
		)
		if err != nil {
			failed++
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			imported++
		} else {
			// INSERT OR IGNORE 命中已存在账号
			skipped++
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &SyncResult{
		Message: fmt.Sprintf("同步完成: 共 %d 个游戏库账号，新增 %d，已存在跳过 %d，失败 %d",
			len(accounts), imported, skipped, failed),
		GameAccounts: len(accounts),
		Imported:     imported,
		Skipped:      skipped,
		Failed:       failed,
	}, nil
}

// SyncPasswordHashToGameDb 把密码 MD5 同步写回游戏库 accounts.password_hash。
//
// 背景：服务端 v11 的 accounts 表没有 salt 列，password_hash 直接存放客户端
// 上报的 pwd_md5，服务端补丁的密码校验比对的就是这一列。网关侧改了密码而
// 不同步，玩家用新密码能过网关验证，却会被游戏服务端拦下。
//
// 约束：
//   - 只写现有列，不改 schema；
//   - 游戏库未配置、账号名或 MD5 为空时直接返回 nil（不是错误，静默跳过）；
//   - 未命中任何行返回错误，便于调用方记录告警（该账号的游戏侧密码会不一致）。
func (db *Database) SyncPasswordHashToGameDb(account, pwdMd5 string) error {
	if !db.GameConfigured() {
		return nil
	}
	account = strings.TrimSpace(account)
	pwdMd5 = strings.TrimSpace(pwdMd5)
	if account == "" || pwdMd5 == "" {
		return nil
	}

	res, err := db.gameDB.Exec(
		"UPDATE accounts SET password_hash = ? WHERE m_id = ?", pwdMd5, account)
	if err != nil {
		return fmt.Errorf("更新游戏库密码失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("游戏库未找到账号 %s（服务端密码校验会拦住该账号）", account)
	}
	return nil
}

// gameAccountsHasSaltColumn 探测游戏库 accounts 表是否带 salt 列。
//
// 服务端 v11 之后的 schema（item_schema.sql）没有 salt 列，
// password_hash 直接存放客户端上报的 pwd_md5。
func (db *Database) gameAccountsHasSaltColumn() (bool, error) {
	rows, err := db.gameDB.Query("PRAGMA table_info(accounts)")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			continue
		}
		if strings.EqualFold(name, "salt") {
			return true, nil
		}
	}
	return false, rows.Err()
}

// GetCeraMap 批量获取多个账号的点券余额。
func (db *Database) GetCeraMap(names []string) (map[string]int64, error) {
	result := make(map[string]int64)
	if len(names) == 0 {
		return result, nil
	}
	if db.GameBackend() == "s5a3" {
		// ★ 审查 H1（2026-11-17）：names 是【账号名】（tianzi），
		// 而 s5a3GetCurrencyTriple 执行 `WHERE account_id = ?`，要的是 dnf:10043。
		// 旧代码直接把 name 传进去 → 恒查不到 → 在线列表 cera 全 0。
		// 这里先把账号名解析成 account_id 再查（与 GetMIdsByNames 的 S5A3 分支同口径）。
		return getCeraMapS5A3(names,
			func(name string) (string, error) { return db.S5A3AccountIDByName(name) },
			func(accountID string) (int64, bool) {
				cera, _, _, ok := db.s5a3GetCurrencyTriple(accountID)
				return cera, ok
			}), nil
	}
	if !db.GameConfigured() {
		return result, nil
	}

	for _, name := range names {
		// 游戏库用 m_id 查询
		var cera int64
		err := db.gameDB.QueryRow("SELECT cera FROM accounts WHERE m_id = ?", name).Scan(&cera)
		if err != nil {
			result[name] = 0
			continue
		}
		result[name] = cera
	}
	return result, nil
}

// getCeraMapS5A3 是 GetCeraMap 的 S5A3 分支核心逻辑，解析与查询都作为参数注入。
//
// ★ 为什么拆出来：S5A3 的余额查的是 MariaDB（dnf_account_metadata），本地测试没有
// 真实库、也没有 sqlmock。把「账号名→account_id」和「account_id→cera」两步注入后，
// 就能用一个假实现精确锁住审查 H1 的区分力 —— 传账号名查必得 0、传 account_id 才得钱，
// 这样旧 bug 一旦回归，单测立刻变红，不必依赖线上真实数据。
//
// 解析失败 / 查不到账号 / 查询失败都记 0，不影响整张在线表（fail-soft，与其余后端一致）。
func getCeraMapS5A3(names []string, resolve func(string) (string, error), getCera func(string) (int64, bool)) map[string]int64 {
	result := make(map[string]int64)
	for _, name := range names {
		accountID, err := resolve(name)
		if err != nil || strings.TrimSpace(accountID) == "" {
			result[name] = 0
			continue
		}
		if cera, ok := getCera(accountID); ok {
			result[name] = cera
		} else {
			result[name] = 0
		}
	}
	return result
}

// GetCeraByMId 通过 MId 获取点券余额（游戏库）。
//
// S5A3 后端的余额在 dnf_account_metadata 的 account_cera 行里（不是列）。
func (db *Database) GetCeraByMId(mId string) (int64, error) {
	if db.GameBackend() == "s5a3" {
		return db.s5a3GetCeraByMId(mId)
	}
	if !db.GameConfigured() {
		return 0, nil
	}
	var cera int64
	err := db.gameDB.QueryRow("SELECT cera FROM accounts WHERE m_id = ?", mId).Scan(&cera)
	if err != nil {
		return 0, err
	}
	return cera, nil
}

// GetCurrencyTripleByMId 通过 MId 获取游戏库点券三项（cera/token_cera/happy_token_cera）。
//
// ok=false 表示游戏库未配置、账号无游戏库行或查询失败 —— 调用方应回退网关库镜像值，
// 不把"游戏库没这行"当成错误上抛（新注册还没进过游戏的账号属正常情况）。
func (db *Database) GetCurrencyTripleByMId(mId string) (cera, token, happy int64, ok bool) {
	if mId == "" {
		return 0, 0, 0, false
	}
	if db.GameBackend() == "s5a3" {
		return db.s5a3GetCurrencyTriple(mId)
	}
	if !db.GameConfigured() {
		return 0, 0, 0, false
	}
	err := db.gameDB.QueryRow(
		"SELECT cera, token_cera, happy_token_cera FROM accounts WHERE m_id = ?", mId).
		Scan(&cera, &token, &happy)
	if err != nil {
		return 0, 0, 0, false
	}
	return cera, token, happy, true
}

// CurrencyTriple 账号三币种余额（游戏库 accounts 表）。
type CurrencyTriple struct {
	Cera           int64
	TokenCera      int64
	HappyTokenCera int64
}

// GetCurrencyTriplesByMIds 批量取多个 m_id 的三币种余额（返回 m_id → 余额）。
//
// G-11（2026-10-04 审查）：AccountService.ListAccounts 原先在分页循环里逐行调
// GetCurrencyTripleByMId ⇒ 翻一页（最多 500 行）就是 **500 次跨库查询**，
// SQLite 单写者模型下会拖慢同机写入与心跳。这里照 QQNumbersByAccounts 的同一套路
// 做 IN 分批批取（单条 SQL）。
//
// 语义与逐行版一致：不在返回 map 里 = 游戏库没有该 m_id 的行，调用方自行回退网关库镜像。
// 查询出错时返回**已取到的部分**（并只记日志由调用方决定），不让账号列表整个失败 ——
// 三币种是附加展示。
func (db *Database) GetCurrencyTriplesByMIds(mIds []string) map[string]CurrencyTriple {
	out := make(map[string]CurrencyTriple)
	if len(mIds) == 0 {
		return out
	}
	// S5A3 后端：逐个查 metadata（IN 拼 key-value 表反而更啰嗦，
	// 且账号列表这个场景的条数是分页量级，几十次往返可接受）。
	if db.GameBackend() == "s5a3" {
		for _, id := range mIds {
			if id == "" {
				continue
			}
			if cera, token, happy, ok := db.s5a3GetCurrencyTriple(id); ok {
				out[id] = CurrencyTriple{Cera: cera, TokenCera: token, HappyTokenCera: happy}
			}
		}
		return out
	}
	if !db.GameConfigured() {
		return out
	}
	// 去重 + 去空：IN 列表越短越快，也避免重复参数白占位。
	seen := make(map[string]struct{}, len(mIds))
	uniq := make([]string, 0, len(mIds))
	for _, id := range mIds {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	if len(uniq) == 0 {
		return out
	}

	const chunk = 500
	for start := 0; start < len(uniq); start += chunk {
		end := start + chunk
		if end > len(uniq) {
			end = len(uniq)
		}
		part := uniq[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(part)), ",")
		args := make([]any, len(part))
		for i, id := range part {
			args[i] = id
		}

		rows, err := db.gameDB.Query(
			"SELECT m_id, cera, token_cera, happy_token_cera FROM accounts WHERE m_id IN ("+placeholders+")",
			args...)
		if err != nil {
			return out
		}
		for rows.Next() {
			var id string
			var t CurrencyTriple
			if err := rows.Scan(&id, &t.Cera, &t.TokenCera, &t.HappyTokenCera); err != nil {
				rows.Close()
				return out
			}
			out[id] = t
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return out
		}
		rows.Close()
	}
	return out
}

// GetRolesByAccount 获取账号的角色列表。
// 游戏库 characters 表：character_id, account_id, name, job, level, exp
//
// 2026-09-23 修复"查角色无效"：原实现把网关库查询错误与"账号不存在"
// 一律吞成 (nil, nil)，前端只能显示"没有查到角色"；且查询没过滤
// delete_flag。现在错误如实上抛，并对"游戏库无 m_id 关联"给出明确提示
// （游戏侧 accounts 只有 m_id 没有账号名，若玩家登录时 m_id 未正确落库，
// 角色就挂不到网关账号上 —— 这是当前唯一的关联键）。
func (db *Database) GetRolesByAccount(accountName string) ([]RoleInfo, error) {
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		return nil, fmt.Errorf("账号名不能为空")
	}
	// S5A3：账号名直接在 dnf90_web_accounts 上，不需要经网关库转 m_id。
	if db.GameBackend() == "s5a3" {
		return db.s5a3GetRolesByAccount(accountName)
	}
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}

	// 先通过网关库获取 m_id
	var mId string
	err := db.gatewayDB.QueryRow("SELECT m_id FROM accounts WHERE name = ?", accountName).Scan(&mId)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("网关库中不存在账号 %s", accountName)
	}
	if err != nil {
		return nil, fmt.Errorf("查询网关库失败: %w", err)
	}
	if mId == "" {
		return nil, fmt.Errorf("账号 %s 的 m_id 为空（网关库记录异常）", accountName)
	}

	// 游戏库用 m_id 查询角色（排除已删除角色）。
	// name 多带一个 typeof()：该列存的是 GBK 裸字节（typeof=blob），
	// 必须按列类型解码，否则中文角色名会显示成乱码。见 charset.go。
	// grow_type 是转职/觉醒编码（低 4 位转职、高 4 位觉醒），职业中文名由
	// JobDisplayName 按它解析 —— 光有 job 只能得到基础职业名（见 jobnames.go）。
	rows, err := db.gameDB.Query(
		"SELECT c.character_id, c.name, typeof(c.name), c.level, c.job, c.grow_type, c.exp FROM characters c JOIN accounts a ON c.account_id = a.account_id WHERE a.m_id = ? AND c.delete_flag = 0 ORDER BY c.character_id ASC", mId)
	if err != nil {
		return nil, fmt.Errorf("查询游戏库失败: %w", err)
	}
	defer rows.Close()

	var roles []RoleInfo
	for rows.Next() {
		var r RoleInfo
		var rawName []byte
		var nameType string
		if err := rows.Scan(&r.CharacterId, &rawName, &nameType, &r.Level, &r.Job, &r.GrowType, &r.Exp); err != nil {
			continue
		}
		r.Name = DecodeGameText(rawName, nameType)
		r.JobName = JobDisplayName(r.Job, r.GrowType)
		roles = append(roles, r)
	}

	// 网关账号存在但游戏库连账号行都没有：给出可行动的提示，而不是"没有角色"
	if len(roles) == 0 {
		var n int
		if err := db.gameDB.QueryRow("SELECT COUNT(*) FROM accounts WHERE m_id = ?", mId).Scan(&n); err == nil && n == 0 {
			return nil, fmt.Errorf("游戏库中没有与该账号 m_id 关联的记录（玩家登录游戏时 m_id 未正确落库，无法按账号名关联：游戏库 accounts 表没有账号名列）")
		}
	}

	return roles, nil
}

// SendMail 发送物品邮件到游戏库。
// 游戏库邮件表结构待确认，当前使用简化实现。
func (db *Database) SendMail(characterId int64, items []MailItem) error {
	return db.SendMailToCharacter(characterId, "", "系统邮件", "", items, 720)
}

// SendMailToCharacter 发送物品邮件到指定角色（使用游戏库真实表结构）。
func (db *Database) SendMailToCharacter(characterId int64, characterName, title, body string, items []MailItem, expireHours int) error {
	return db.SendMailWithGold(characterId, characterName, title, body, 0, items, expireHours)
}

// SendMailWithGold 发送带金币的邮件到指定角色（注册奖励金币随首封邮件发放）。
func (db *Database) SendMailWithGold(characterId int64, characterName, title, body string, gold int64, items []MailItem, expireHours int) error {
	// S5A3：表结构与 S4A21 完全不同（dnf_mails / dnf_mail_attachments），
	// 走独立实现。raw_entry 留 NULL，由服务端按 PVF 补证据。
	if db.GameBackend() == "s5a3" {
		return db.s5a3SendMailWithGold(characterId, characterName, title, body, gold, items, expireHours)
	}
	if !db.GameConfigured() {
		return fmt.Errorf("游戏库未配置")
	}

	tx, err := db.gameDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	expireAt := time.Now().UTC().Add(time.Duration(expireHours) * time.Hour).Format("2006-01-02 15:04:05")

	// 1. 插入邮件本体
	result, err := tx.Exec(`
		INSERT INTO mailbox_messages (
			sender_character_id, sender_account_id, sender_name,
			receiver_character_id, receiver_account_id, receiver_name,
			title, body, gold, fee_gold, mail_type, source_protocol,
			idempotency_key, created_at, unlimited_flag, expire_at, deleted_by_sender
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 3, 0, ?, ?, 0, ?, 0)`,
		0, 0, "系统",
		characterId, 0, characterName,
		title, body, gold,
		generateTokenString(), now, expireAt)
	if err != nil {
		return fmt.Errorf("insert mailbox_messages: %w", err)
	}
	messageId, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("get message_id: %w", err)
	}

	// 2. 插入收件人
	_, err = tx.Exec(`
		INSERT INTO mailbox_recipients (
			message_id, character_id, folder, read_flag, saved_flag, deleted_flag, received_gold_flag, created_at
		) VALUES (?, ?, 0, 0, 0, 0, 0, ?)`,
		messageId, characterId, now)
	if err != nil {
		return fmt.Errorf("insert mailbox_recipients: %w", err)
	}

	// 3. 插入附件
	ordinal := 0
	for _, item := range items {
		_, err = tx.Exec(`
			INSERT INTO mailbox_attachments (
				message_id, ordinal, item_type, source_list_type, source_slot_index,
				item_template_id, item_kind, item_count, expire_time, claimed_flag
			) VALUES (?, ?, ?, 0, 0, ?, ?, ?, 0, 0)`,
			messageId, ordinal, item.ItemType,
			item.ItemTemplateId, fmt.Sprintf("%d", item.Kind), item.Count)
		if err != nil {
			return fmt.Errorf("insert mailbox_attachments: %w", err)
		}
		ordinal++
	}

	return tx.Commit()
}

// AddCurrencyToGameAccount 给游戏库账号累加点券，返回受影响行数。
// column 必须是白名单列（cera/token_cera/happy_token_cera）。
//
// S5A3 后端：余额不是列，而是 dnf_account_metadata 里 entry_key='account_cera'
// 的一行（key-value）。写法和返回语义见 s5a3AddCurrency。
func (db *Database) AddCurrencyToGameAccount(mId, column string, amount int64) (int64, error) {
	if db.GameBackend() == "s5a3" {
		return db.s5a3AddCurrency(mId, column, amount)
	}
	if !db.GameConfigured() {
		return 0, nil
	}
	switch column {
	case "cera", "token_cera", "happy_token_cera":
	default:
		return 0, fmt.Errorf("unsupported currency column: %s", column)
	}

	result, err := db.gameDB.Exec(
		"UPDATE accounts SET "+column+" = IFNULL("+column+", 0) + ? WHERE m_id = ?",
		amount, mId)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// FindFirstAliveCharacter 查询账号首个存活角色（注册奖励发件目标）。
func (db *Database) FindFirstAliveCharacter(mId string) (*Character, error) {
	if db.GameBackend() == "s5a3" {
		return db.s5a3FindFirstAliveCharacter(mId)
	}
	if !db.GameConfigured() {
		return nil, nil
	}

	row := db.gameDB.QueryRow(`
		SELECT c.character_id, c.account_id, c.name, typeof(c.name), c.level, c.job
		FROM characters c
		JOIN accounts a ON a.account_id = c.account_id
		WHERE a.m_id = ? AND c.delete_flag = 0
		ORDER BY c.character_id ASC
		LIMIT 1`, mId)

	var c Character
	var rawName []byte
	var nameType string
	if err := row.Scan(&c.CharacterId, &c.AccountId, &rawName, &nameType, &c.Level, &c.Job); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	c.Name = DecodeGameText(rawName, nameType)
	return &c, nil
}

// GetCharacter 查询角色。
func (db *Database) GetCharacter(characterId int64) (*Character, error) {
	if db.GameBackend() == "s5a3" {
		return db.s5a3GetCharacter(characterId)
	}
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}

	row := db.gameDB.QueryRow("SELECT character_id, account_id, name, typeof(name), level, job FROM characters WHERE character_id = ? AND delete_flag = 0", characterId)
	var c Character
	var rawName []byte
	var nameType string
	err := row.Scan(&c.CharacterId, &c.AccountId, &rawName, &nameType, &c.Level, &c.Job)
	if err != nil {
		return nil, err
	}
	c.Name = DecodeGameText(rawName, nameType)
	return &c, nil
}

// OnlineRoleCandidate 一个在线账号当前在玩的角色（推定）。
//
// 「当前角色」不是权威字段 —— 服务端只在内存里记在线状态，库里不落。
// 这里用 characters.updated_at 推定：服务端每次角色数据变更（升级/经验/外观/
// 退出存档等）都会把它刷成 CURRENT_TIMESTAMP，所以**该账号名下 updated_at 最新
// 的那个角色**就是在玩的那个。
//
// 实测依据：正式服库快照的最后 60 秒内恰好 5 个角色被刷新，分属 5 个不同账号，
// 每个账号各 1 个 —— 与当时的在线人数吻合。
//
// 注意：updated_at 是「最后活动时间」，挂机不动的玩家可能滞后，
// 所以调用方应把 LastActiveAt 一并展示，别把它当成精确的在线时长。
type OnlineRoleCandidate struct {
	MId          string
	CharacterId  int64
	Name         string
	Level        int
	Job          int
	LastActiveAt string // characters.updated_at，UTC 文本（"2006-01-02 15:04:05"）
	RoleCount    int    // 该账号存活角色总数（含非当前角色）
}

// GetCurrentRolesByMIds 批量取「这些账号的当前角色」。
//
// 一次查询搞定：按 updated_at 倒序扫，每个 m_id 取到的第一行即当前角色，
// 同时统计该账号的存活角色总数。返回的 map 只包含查到的账号。
//
// 单查询的变量数受 SQLite 限制，按 chunk 分批。
func (db *Database) GetCurrentRolesByMIds(mIds []string) (map[string]OnlineRoleCandidate, error) {
	out := make(map[string]OnlineRoleCandidate)
	if db.GameBackend() == "s5a3" {
		return db.s5a3GetCurrentRolesByMIds(mIds)
	}
	if !db.GameConfigured() {
		return out, nil
	}

	// 去重 + 去空
	seen := make(map[string]struct{}, len(mIds))
	uniq := make([]string, 0, len(mIds))
	for _, m := range mIds {
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		uniq = append(uniq, m)
	}
	if len(uniq) == 0 {
		return out, nil
	}

	const chunkSize = 400
	for start := 0; start < len(uniq); start += chunkSize {
		end := start + chunkSize
		if end > len(uniq) {
			end = len(uniq)
		}
		chunk := uniq[start:end]

		placeholders := make([]string, 0, len(chunk))
		args := make([]interface{}, 0, len(chunk))
		for _, m := range chunk {
			placeholders = append(placeholders, "?")
			args = append(args, m)
		}

		query := "SELECT a.m_id, c.character_id, c.name, typeof(c.name), c.level, c.job, " +
			"IFNULL(c.updated_at, '') FROM characters c " +
			"JOIN accounts a ON c.account_id = a.account_id " +
			"WHERE a.m_id IN (" + strings.Join(placeholders, ",") + ") AND c.delete_flag = 0 " +
			"ORDER BY a.m_id ASC, c.updated_at DESC, c.character_id DESC"

		rows, err := db.gameDB.Query(query, args...)
		if err != nil {
			return out, fmt.Errorf("查询在线角色失败: %w", err)
		}
		for rows.Next() {
			var mId string
			var rawName []byte
			var nameType string
			var c OnlineRoleCandidate
			if err := rows.Scan(&mId, &c.CharacterId, &rawName, &nameType, &c.Level, &c.Job, &c.LastActiveAt); err != nil {
				continue
			}
			c.MId = mId
			c.Name = DecodeGameText(rawName, nameType)

			if prev, ok := out[mId]; ok {
				// 已取过当前角色，本行只用来累加角色数
				prev.RoleCount++
				out[mId] = prev
				continue
			}
			c.RoleCount = 1
			out[mId] = c
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
	}
	return out, nil
}

// CurrentRoleName 按账号名解析「当前在玩的角色名」。
//
// 两步：账号名 → m_id（网关库）→ 当前角色（游戏库，characters.updated_at 最新的一条）。
// 与「在线角色」接口（GetCurrentRolesByMIds）同一口径，只是把那条链封成一次调用，
// 供外挂检测上报落库时补角色名 —— 上报只在有检测结果时才发，频率低，不必加缓存。
//
// 为什么角色名不在客户端取（2026-10-02 实测结论，别再试一遍）：
//   - 参考/偏移.txt 里没有角色名偏移，只有账号基址 0x399A7C8 / 角色等级 0x3A3D4E4 /
//     角色基质 0x3A5B348，而账号基址读出来是乱码 ⇒ 静态结构里的账号/角色名是**加密存放**的；
//   - 明文只出现在堆上的 UI / 名字字典缓冲里（如 0x2929xxxx 那张 [id][len][GBK名][...] 表），
//     但**全地址空间没有任何 4 字节对齐的指针指向它们** ⇒ 拿不到稳定偏移；
//   - 客户端 VMProtect 加壳，也不能静态读 exe 反推。
//
// 所以角色名一律由服务端解析，不依赖客户端。
//
// 查不到时返回空串。**不要回退成账号名**：后台「角色」列需要靠「空」识别「未知」，
// 把账号名填进去会让这一列失去区分能力，还会掩盖「解析失败」这个事实。
func (db *Database) CurrentRoleName(account string) string {
	if db == nil || strings.TrimSpace(account) == "" {
		return ""
	}
	if db.GameBackend() == "s5a3" {
		return db.s5a3CurrentRoleName(account)
	}
	if !db.GameConfigured() {
		return ""
	}
	mIds, err := db.GetMIdsByNames([]string{account})
	if err != nil || len(mIds) == 0 {
		return ""
	}
	mId := mIds[account]
	if mId == "" {
		return ""
	}
	roles, err := db.GetCurrentRolesByMIds([]string{mId})
	if err != nil {
		return ""
	}
	if c, ok := roles[mId]; ok {
		return strings.TrimSpace(c.Name)
	}
	return ""
}

// ResolveMIdByCharacterID 反查角色所属账号的 m_id。
//
// 用途：游戏服务端上报事件时只带 character_id/character_name（服务端没有"账号名"这个概念），
// 管理后台要按账号检索就得把角色映射回 m_id。
//
// 找不到不是错误：可能角色属于已删号、或游戏库没配。返回 ("", nil) 让调用方按"未知"处理 ——
// 这类事件照样入库（宁可有 account 空的记录，也不要因为关联失败丢事件）。
func (db *Database) ResolveMIdByCharacterID(characterId int64) (string, error) {
	if characterId <= 0 || !db.GameConfigured() {
		return "", nil
	}
	var mId string
	err := db.gameDB.QueryRow(
		"SELECT a.m_id FROM characters c JOIN accounts a ON c.account_id = a.account_id WHERE c.character_id = ?",
		characterId).Scan(&mId)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return mId, nil
}

// GetCharactersByAccount 查询账号下所有存活角色。
//
// S5A3 的 accountId 是 dnf90_web_accounts.id（数值），不是 dnf_characters.account_id
// 那个字符串（dnf:10002）—— 转换在 s5a3GetCharactersByAccount 里做。
func (db *Database) GetCharactersByAccount(accountId int64) ([]Character, error) {
	if db.GameBackend() == "s5a3" {
		return db.s5a3GetCharactersByAccount(accountId)
	}
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}

	rows, err := db.gameDB.Query("SELECT character_id, account_id, name, typeof(name), level, job FROM characters WHERE account_id = ? AND delete_flag = 0", accountId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var characters []Character
	for rows.Next() {
		var c Character
		var rawName []byte
		var nameType string
		if err := rows.Scan(&c.CharacterId, &c.AccountId, &rawName, &nameType, &c.Level, &c.Job); err != nil {
			return nil, err
		}
		c.Name = DecodeGameText(rawName, nameType)
		characters = append(characters, c)
	}
	return characters, nil
}

// GetAllAliveCharacters 查询所有存活角色（全服邮件的目标集合）。
func (db *Database) GetAllAliveCharacters() ([]Character, error) {
	if db.GameBackend() == "s5a3" {
		return db.s5a3GetAllAliveCharacters()
	}
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}

	rows, err := db.gameDB.Query("SELECT character_id, account_id, name, typeof(name), level, job FROM characters WHERE delete_flag = 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var characters []Character
	for rows.Next() {
		var c Character
		var rawName []byte
		var nameType string
		if err := rows.Scan(&c.CharacterId, &c.AccountId, &rawName, &nameType, &c.Level, &c.Job); err != nil {
			return nil, err
		}
		c.Name = DecodeGameText(rawName, nameType)
		characters = append(characters, c)
	}
	return characters, nil
}

func generateTokenString() string {
	buf := make([]byte, 16)
	cryptoRandRead(buf)
	return fmt.Sprintf("%x", buf)
}

// ClearMailbox 清空指定角色收到的邮件，返回删除的邮件数量。
//
// 游戏库真实表结构是 mailbox_messages / mailbox_recipients / mailbox_attachments 三表，
// 三表均带 ON DELETE CASCADE 指向 mailbox_messages(message_id)。
// 因此这里以 mailbox_messages 为主表删除，并显式清理两张子表，
// 以保证即使连接未开启 foreign_keys 也能清干净。
func (db *Database) ClearMailbox(characterId int64) (int64, error) {
	if db.GameBackend() == "s5a3" {
		return db.s5a3ClearMailbox(characterId)
	}
	if !db.GameConfigured() {
		return 0, fmt.Errorf("游戏库未配置")
	}
	if characterId <= 0 {
		return 0, fmt.Errorf("角色 ID 非法: %d", characterId)
	}

	tx, err := db.gameDB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 1. 先统计并删除附件与收件人记录（按 message_id 关联，避免留下孤儿行）
	if _, err := tx.Exec(`
		DELETE FROM mailbox_attachments
		WHERE message_id IN (
			SELECT message_id FROM mailbox_messages WHERE receiver_character_id = ?
		)`, characterId); err != nil {
		return 0, fmt.Errorf("delete mailbox_attachments: %w", err)
	}

	if _, err := tx.Exec(`
		DELETE FROM mailbox_recipients
		WHERE character_id = ?
		   OR message_id IN (
				SELECT message_id FROM mailbox_messages WHERE receiver_character_id = ?
			)`, characterId, characterId); err != nil {
		return 0, fmt.Errorf("delete mailbox_recipients: %w", err)
	}

	// 2. 删除邮件本体，受影响行数即为清空数量
	result, err := tx.Exec(
		"DELETE FROM mailbox_messages WHERE receiver_character_id = ?", characterId)
	if err != nil {
		return 0, fmt.Errorf("delete mailbox_messages: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

// generateSalt 生成随机 salt（避免循环依赖）。
func generateSalt() (string, error) {
	buf := make([]byte, 32)
	if _, err := cryptoRandRead(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}

// generateToken 生成随机 token。
func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := cryptoRandRead(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", buf), nil
}
