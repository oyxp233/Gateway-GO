package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"s4a21-gateway/pkg/models"

	_ "modernc.org/sqlite"
)

// Database 封装 SQLite 双库访问。
type Database struct {
	gatewayDB *sql.DB
	gameDB    *sql.DB
	cfg       DatabaseConfig
}

// DatabaseConfig 数据库配置。
type DatabaseConfig struct {
	Path               string
	GamePath           string
	WalMode            bool
	BusyTimeoutSeconds int
}

// NewDatabase 创建数据库连接池。
func NewDatabase(cfg DatabaseConfig) (*Database, error) {
	if cfg.WalMode {
		// 确保目录存在
		if dir := filepath.Dir(cfg.Path); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("create db dir %s: %w", dir, err)
			}
		}
	}

	gatewayDB, err := openSQLite(cfg.Path, cfg.BusyTimeoutSeconds)
	if err != nil {
		return nil, fmt.Errorf("open gateway db %s: %w", cfg.Path, err)
	}

	if cfg.WalMode {
		if _, err := gatewayDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
			gatewayDB.Close()
			return nil, fmt.Errorf("set WAL mode on gateway db: %w", err)
		}
	}

	db := &Database{
		gatewayDB: gatewayDB,
		cfg:       cfg,
	}

	if cfg.GamePath != "" {
		gameDB, err := openSQLite(cfg.GamePath, cfg.BusyTimeoutSeconds)
		if err != nil {
			gatewayDB.Close()
			return nil, fmt.Errorf("open game db %s: %w", cfg.GamePath, err)
		}
		db.gameDB = gameDB
	}

	return db, nil
}

func openSQLite(path string, busyTimeoutSec int) (*sql.DB, error) {
	// modernc.org/sqlite 使用 "sqlite" 驱动名
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", path, busyTimeoutSec*1000))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite 单写者模式
	return db, nil
}

// EnsureInitialized 建表并确保网关库结构正确。
func (db *Database) EnsureInitialized() error {
	schema := `
	CREATE TABLE IF NOT EXISTS accounts (
		m_id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		pwd_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		cera INTEGER DEFAULT 0,
		token_cera INTEGER DEFAULT 0,
		happy_token_cera INTEGER DEFAULT 0,
		device_secret TEXT DEFAULT '',
		device_secret_issued_at TEXT DEFAULT '',
		device_history TEXT DEFAULT '',
		device_secret_last_rotated INTEGER DEFAULT 0,
		last_login_at INTEGER DEFAULT 0,
		last_login_ip TEXT DEFAULT '',
		failed_login_count INTEGER DEFAULT 0,
		lockout_until INTEGER DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER DEFAULT 0,
		last_heartbeat INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_accounts_name ON accounts(name);
	CREATE INDEX IF NOT EXISTS idx_accounts_last_heartbeat ON accounts(last_heartbeat);

	CREATE TABLE IF NOT EXISTS device_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		m_id TEXT NOT NULL,
		device_secret TEXT NOT NULL,
		ip TEXT NOT NULL DEFAULT '',
		login_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_device_history_mid ON device_history(m_id);

	CREATE TABLE IF NOT EXISTS banned_accounts (
		name TEXT PRIMARY KEY,
		reason TEXT DEFAULT '',
		banned_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS register_bonus_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account TEXT NOT NULL,
		account_id INTEGER DEFAULT 0,
		character_id INTEGER DEFAULT 0,
		character_name TEXT DEFAULT '',
		reward_type TEXT NOT NULL,
		item_id INTEGER DEFAULT 0,
		item_name TEXT DEFAULT '',
		kind INTEGER DEFAULT 0,
		quantity INTEGER DEFAULT 0,
		status TEXT NOT NULL,
		message TEXT DEFAULT '',
		created_at TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_rblog_account ON register_bonus_logs(account, status);

	CREATE TABLE IF NOT EXISTS anticheat_detections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_name TEXT NOT NULL,
		description TEXT DEFAULT '',
		actual_value REAL DEFAULT 0,
		threshold_value REAL DEFAULT 0,
		event_timestamp INTEGER NOT NULL,
		evidence TEXT DEFAULT '',
		client_ip TEXT DEFAULT '',
		account TEXT DEFAULT '',
		reported_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_anticheat_rule ON anticheat_detections(rule_name);
	CREATE INDEX IF NOT EXISTS idx_anticheat_account ON anticheat_detections(account);
	CREATE INDEX IF NOT EXISTS idx_anticheat_reported ON anticheat_detections(reported_at);

	-- ========================================================================
	-- 全服公告（2026-09-24）
	--
	-- 三张表的分工：
	--   announce_config  —— 业务配置的 key/value 持久化。用 KV 而不是宽表单行，
	--                       是因为字段还会长（以后要加播报分类、开关），KV 加键不用改表。
	--   announce_events  —— 通关/未通关/拾取事件流水，供后台分类查询与登录器排行榜聚合。
	--   announce_popups  —— 管理后台排队的弹窗公告；插件拉走即置 sent。
	--
	-- 唯一真源：三张表都由**网关进程**读写（admin 进程只读 announce_events/popups）。
	-- ========================================================================
	CREATE TABLE IF NOT EXISTS announce_config (
		cfg_key TEXT PRIMARY KEY,
		cfg_value TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS announce_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT NOT NULL,
		account TEXT DEFAULT '',
		character_id INTEGER DEFAULT 0,
		character_name TEXT DEFAULT '',
		dungeon_id INTEGER DEFAULT 0,
		dungeon_name TEXT DEFAULT '',
		difficulty INTEGER DEFAULT 0,
		hell_mode INTEGER DEFAULT 0,
		elapsed_ms INTEGER DEFAULT 0,
		item_id INTEGER DEFAULT 0,
		item_name TEXT DEFAULT '',
		item_rarity INTEGER DEFAULT 0,
		is_equipment INTEGER DEFAULT 0,
		item_level INTEGER DEFAULT 0,
		equipment_type TEXT DEFAULT '',
		physical_attack INTEGER DEFAULT 0,
		magical_attack INTEGER DEFAULT 0,
		physical_defense INTEGER DEFAULT 0,
		magical_defense INTEGER DEFAULT 0,
		broadcast INTEGER DEFAULT 0,
		created_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_announce_kind_created ON announce_events(kind, created_at);
	CREATE INDEX IF NOT EXISTS idx_announce_rarity ON announce_events(item_rarity, created_at);
	CREATE INDEX IF NOT EXISTS idx_announce_player ON announce_events(character_name, item_rarity);
	CREATE INDEX IF NOT EXISTS idx_announce_item ON announce_events(item_id, item_rarity);
	CREATE INDEX IF NOT EXISTS idx_announce_created ON announce_events(created_at);

	CREATE TABLE IF NOT EXISTS announce_popups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		message TEXT NOT NULL,
		mode INTEGER DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'pending',
		created_by TEXT DEFAULT '',
		created_at INTEGER NOT NULL,
		sent_at INTEGER DEFAULT 0,
		delivered_at INTEGER DEFAULT 0,
		-- 0 = 未删除；非 0 = 后台已删除，列表不再显示。
		-- 用软删除而不是 DELETE：公告是运维动作的审计痕迹，删掉就再也答不上
		-- "这条公告到底发出去没有、谁发的、什么时候发的"。
		deleted_at INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_announce_popup_status ON announce_popups(status, id);

	-- ========================================================================
	-- QQ 号绑定（2026-09-24）
	--
	-- 玩家用 QQ 号 + 邮箱验证码证明"号是他的"，之后 QQ 号就能当账号名登录。
	-- 为什么不用官方 QQ 互联：腾讯只返回 openid（不透明字符串），拿不到 QQ 号，
	-- 且桌面客户端没有可用类目（详见 交付物/登录器绑定QQ登录-准备清单-20260924.md）。
	--
	-- ★ 这两张表**不碰 accounts 任何字段** —— m_id / 密码 / 点券 / 角色全保持原样，
	--   登录时只是把"QQ 号"翻译成"账号名"，之后走原流程。
	-- ========================================================================
	CREATE TABLE IF NOT EXISTS qq_bindings (
		-- 玩家 QQ 号（纯数字）。主键 = 一个 QQ 号只能绑一个账号。
		qq_number TEXT PRIMARY KEY,
		-- 绑定的账号名。UNIQUE = 一个账号只能绑一个 QQ 号。
		-- 注意这里存的是**账号名**而不是 m_id：登录入口本来就是账号名，
		-- 用 m_id 反查会多一跳，而且 m_id 是纯数字、和 QQ 号长得一样，容易搞混。
		account TEXT NOT NULL UNIQUE,
		bound_at INTEGER NOT NULL,
		bound_ip TEXT DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS email_verify_codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		-- 收码目标：这里是 QQ 号（收件地址 = <QQ号>@qq.com）。
		target TEXT NOT NULL,
		purpose TEXT NOT NULL,
		-- 只存哈希，不存明文。明文码会让任何读到库的人直接绑走别人的账号。
		code_hash TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		used INTEGER NOT NULL DEFAULT 0,
		-- 错误尝试次数（防暴力猜 6 位码）。
		attempts INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		request_ip TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_evc_lookup ON email_verify_codes(target, purpose, used, expires_at);
	-- 日发信量保护靠这条索引：COUNT(*) WHERE created_at >= 今日零点。
	CREATE INDEX IF NOT EXISTS idx_evc_created ON email_verify_codes(created_at);
	`

	if _, err := db.gatewayDB.Exec(schema); err != nil {
		return err
	}

	// 迁移：为旧数据库添加新列
	if err := db.migrateSchema(); err != nil {
		return err
	}

	return nil
}

// migrateSchema 为旧数据库添加缺失的列。
func (db *Database) migrateSchema() error {
	// 检查 accounts 表的列
	rows, err := db.gatewayDB.Query("PRAGMA table_info(accounts)")
	if err != nil {
		return err
	}
	defer rows.Close()

	existingCols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		existingCols[name] = true
	}

	// 添加缺失的列
	if !existingCols["device_secret_issued_at"] {
		if _, err := db.gatewayDB.Exec("ALTER TABLE accounts ADD COLUMN device_secret_issued_at TEXT DEFAULT ''"); err != nil {
			return err
		}
	}
	if !existingCols["device_history"] {
		if _, err := db.gatewayDB.Exec("ALTER TABLE accounts ADD COLUMN device_history TEXT DEFAULT ''"); err != nil {
			return err
		}
	}

	// register_bonus_logs 旧表(m_id 为主键列)升级：补齐新字段
	if err := db.migrateRegisterBonusLog(); err != nil {
		return err
	}

	// announce_popups.deleted_at：软删除是后加的，老库没有这一列。
	// 补上之后，删除公告才是"不再显示"而不是"物理消失"。
	if err := db.ensureColumn("announce_popups", "deleted_at", "INTEGER DEFAULT 0"); err != nil {
		return err
	}

	return nil
}

// ensureColumn 幂等地给已存在的表补一列。
//
// 只用 PRAGMA 判断列是否存在，不依赖 user_version / schema 版本号 ——
// 网关库的升级历来是"缺什么补什么"，加列必须能重复执行且对老库无害。
func (db *Database) ensureColumn(table, column, ddl string) error {
	rows, err := db.gatewayDB.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	exists := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			exists = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = db.gatewayDB.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + ddl)
	return err
}

// migrateRegisterBonusLog 为旧版 register_bonus_logs 表补齐字段。
func (db *Database) migrateRegisterBonusLog() error {
	rows, err := db.gatewayDB.Query("PRAGMA table_info(register_bonus_logs)")
	if err != nil {
		return err
	}
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	rows.Close()

	// 表不存在时由 CREATE TABLE IF NOT EXISTS 建全量列，无需迁移
	if len(cols) == 0 {
		return nil
	}

	addColumn := func(name, ddl string) error {
		if !cols[name] {
			if _, err := db.gatewayDB.Exec("ALTER TABLE register_bonus_logs ADD COLUMN " + ddl); err != nil {
				return err
			}
		}
		return nil
	}

	for _, c := range []struct{ name, ddl string }{
		{"account", "account TEXT DEFAULT ''"},
		{"account_id", "account_id INTEGER DEFAULT 0"},
		{"character_id", "character_id INTEGER DEFAULT 0"},
		{"character_name", "character_name TEXT DEFAULT ''"},
		{"item_id", "item_id INTEGER DEFAULT 0"},
		{"item_name", "item_name TEXT DEFAULT ''"},
		{"kind", "kind INTEGER DEFAULT 0"},
		{"quantity", "quantity INTEGER DEFAULT 0"},
		{"created_at", "created_at TEXT DEFAULT ''"},
	} {
		if err := addColumn(c.name, c.ddl); err != nil {
			return err
		}
	}

	// 旧表用 m_id 作账号标识，迁移为新 account 字段
	if cols["m_id"] && !cols["account"] {
		if _, err := db.gatewayDB.Exec("UPDATE register_bonus_logs SET account = m_id"); err != nil {
			return err
		}
	}

	// created_at 旧表为 INTEGER，保留原语义不清空；新写入使用 TEXT 格式。
	// 此处仅保证列存在；旧数据 created_at 为数字字符串，展示层可容错。
	if indexErr := db.ensureIndex("idx_rblog_account", "CREATE INDEX IF NOT EXISTS idx_rblog_account ON register_bonus_logs(account, status)"); indexErr != nil {
		return indexErr
	}
	return nil
}

func (db *Database) ensureIndex(name, ddl string) error {
	_, err := db.gatewayDB.Exec(ddl)
	return err
}

// Close 关闭所有数据库连接。
func (db *Database) Close() {
	if db.gatewayDB != nil {
		db.gatewayDB.Close()
	}
	if db.gameDB != nil {
		db.gameDB.Close()
	}
}

// Gateway 返回网关库的连接。
func (db *Database) Gateway() *sql.DB {
	return db.gatewayDB
}

// Game 返回游戏库存库的连接，可能为 nil。
func (db *Database) Game() *sql.DB {
	return db.gameDB
}

// GameConfigured 检查游戏库存库是否已配置。
func (db *Database) GameConfigured() bool {
	return db.gameDB != nil
}

// NowUnix 返回当前 Unix 时间戳（秒）。
func NowUnix() int64 {
	return time.Now().Unix()
}

// NowUnixNano 返回当前 Unix 纳秒时间戳。
func NowUnixNano() int64 {
	return time.Now().UnixNano()
}

// ExecTx 在网关库上执行事务。
//
// ⚠️ context 必须显式传非 nil：database/sql 的 conn() 内部会调 ctx.Done()，
// 传 nil 接口会直接 panic。更坑的是 panic 之后 t.Cleanup 里的 DB.Close() 会卡在
// 连接锁上，表现为"测试挂死到超时"而不是报错，排查成本极高。2026-09-23 踩过。
func (db *Database) ExecTx(fn func(tx *sql.Tx) error) error {
	tx, err := db.gatewayDB.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ExecTxBoth 在网关库和游戏库上执行事务（跨库事务，非原子，需调用方处理补偿）。
func (db *Database) ExecTxBoth(fn func(txGw *sql.Tx, txGame *sql.Tx) error) error {
	txGw, err := db.gatewayDB.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			txGw.Rollback()
		}
	}()

	var txGame *sql.Tx
	if db.gameDB != nil {
		txGame, err = db.gameDB.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				txGame.Rollback()
			}
		}()
	}

	if err := fn(txGw, txGame); err != nil {
		return err
	}

	if err := txGw.Commit(); err != nil {
		return err
	}
	if txGame != nil {
		if err := txGame.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// IsBanned 检查账号是否被封禁。
func (db *Database) IsBanned(name string) (bool, error) {
	var count int
	err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM banned_accounts WHERE name = ?", name).Scan(&count)
	return count > 0, err
}

// BanAccount 封禁账号。
func (db *Database) BanAccount(name, reason string) error {
	_, err := db.gatewayDB.Exec(
		"INSERT INTO banned_accounts (name, reason, banned_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET reason = excluded.reason",
		name, reason, NowUnix())
	return err
}

// UnbanAccount 解封账号，返回是否存在。
func (db *Database) UnbanAccount(name string) (bool, error) {
	result, err := db.gatewayDB.Exec("DELETE FROM banned_accounts WHERE name = ?", name)
	if err != nil {
		return false, err
	}
	rows, _ := result.RowsAffected()
	return rows > 0, nil
}

// QueryBans 查询封禁列表。
func (db *Database) QueryBans(keyword string, page, pageSize int) (int, []BanEntry, error) {
	var total int
	countQuery := "SELECT COUNT(*) FROM banned_accounts"
	args := []interface{}{}
	if keyword != "" {
		countQuery += " WHERE name LIKE ?"
		args = append(args, "%"+keyword+"%")
	}
	if err := db.gatewayDB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return 0, nil, err
	}

	query := "SELECT name, reason, banned_at FROM banned_accounts"
	if keyword != "" {
		query += " WHERE name LIKE ?"
	}
	query += " ORDER BY banned_at DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, (page-1)*pageSize)

	rows, err := db.gatewayDB.Query(query, args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	var entries []BanEntry
	for rows.Next() {
		var e BanEntry
		if err := rows.Scan(&e.Name, &e.Reason, &e.BannedAt); err != nil {
			return 0, nil, err
		}
		entries = append(entries, e)
	}
	return total, entries, nil
}

// BanEntry 封禁记录。
type BanEntry struct {
	Name     string
	Reason   string
	BannedAt int64
}

// GetAccountByName 通过名称查询账号。
func (db *Database) GetAccountByName(name string) (*Account, error) {
	row := db.gatewayDB.QueryRow(
		"SELECT m_id, name, pwd_hash, salt, cera, token_cera, happy_token_cera, device_secret, device_secret_issued_at, device_history, device_secret_last_rotated, last_login_at, last_login_ip, failed_login_count, lockout_until, created_at, last_heartbeat FROM accounts WHERE name = ?",
		name)

	var a Account
	if err := row.Scan(
		&a.MId, &a.Name, &a.PwdHash, &a.Salt, &a.Cera, &a.TokenCera, &a.HappyTokenCera,
		&a.DeviceSecret, &a.DeviceSecretIssuedAt, &a.DeviceHistory, &a.DeviceSecretLastRotated,
		&a.LastLoginAt, &a.LastLoginIP, &a.FailedLoginCount, &a.LockoutUntil, &a.CreatedAt, &a.LastHeartbeat); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// GetAccountByMId 通过 MId 查询账号。
func (db *Database) GetAccountByMId(mId string) (*Account, error) {
	row := db.gatewayDB.QueryRow(
		"SELECT m_id, name, pwd_hash, salt, cera, token_cera, happy_token_cera, device_secret, device_secret_issued_at, device_history, device_secret_last_rotated, last_login_at, last_login_ip, failed_login_count, lockout_until, created_at, last_heartbeat FROM accounts WHERE m_id = ?",
		mId)

	var a Account
	if err := row.Scan(
		&a.MId, &a.Name, &a.PwdHash, &a.Salt, &a.Cera, &a.TokenCera, &a.HappyTokenCera,
		&a.DeviceSecret, &a.DeviceSecretIssuedAt, &a.DeviceHistory, &a.DeviceSecretLastRotated,
		&a.LastLoginAt, &a.LastLoginIP, &a.FailedLoginCount, &a.LockoutUntil, &a.CreatedAt, &a.LastHeartbeat); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// InsertAccount 插入新账号。
func (db *Database) InsertAccount(a *Account) error {
	_, err := db.gatewayDB.Exec(
		`INSERT INTO accounts (m_id, name, pwd_hash, salt, cera, token_cera, happy_token_cera, device_secret, device_secret_last_rotated, last_login_at, last_login_ip, failed_login_count, lockout_until, created_at, last_heartbeat)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.MId, a.Name, a.PwdHash, a.Salt, a.Cera, a.TokenCera, a.HappyTokenCera,
		a.DeviceSecret, a.DeviceSecretLastRotated, a.LastLoginAt, a.LastLoginIP,
		a.FailedLoginCount, a.LockoutUntil, a.CreatedAt, a.LastHeartbeat)
	return err
}

// UpdateAccountPwd 更新账号密码。
func (db *Database) UpdateAccountPwd(name, pwdHash, salt string) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET pwd_hash = ?, salt = ?, updated_at = ? WHERE name = ?",
		pwdHash, salt, NowUnix(), name)
	return err
}

// UpdateAccountHeartbeat 更新账号心跳。
func (db *Database) UpdateAccountHeartbeat(name string) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET last_heartbeat = ? WHERE name = ?",
		NowUnix(), name)
	return err
}

// UpdateAccountLogin 更新账号最后登录信息。
func (db *Database) UpdateAccountLogin(name, ip string, failedCount int, lockoutUntil int64) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET last_login_at = ?, last_login_ip = ?, failed_login_count = ?, lockout_until = ?, updated_at = ? WHERE name = ?",
		NowUnix(), ip, failedCount, lockoutUntil, NowUnix(), name)
	return err
}

// UpdateAccountDeviceSecret 更新账号设备密钥。
func (db *Database) UpdateAccountDeviceSecret(name, secret string, rotatedAt int64) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET device_secret = ?, device_secret_last_rotated = ? WHERE name = ?",
		secret, rotatedAt, name)
	return err
}

// UpdateDeviceSecret 更新设备密钥和历史记录（使用 m_id）。
func (db *Database) UpdateDeviceSecret(mId, secret, historyJSON string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET device_secret = ?, device_secret_issued_at = ?, device_history = ? WHERE m_id = ?",
		secret, now, historyJSON, mId)
	return err
}

// UpdateAccountCera 更新账号点券。
func (db *Database) UpdateAccountCera(mId string, deltaCera int64) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET cera = cera + ?, updated_at = ? WHERE m_id = ?",
		deltaCera, NowUnix(), mId)
	return err
}

// ActiveAccount 活跃账号（泡点发放用）。Name 用于日志展示（历史版本打
// m_id——一串对玩家不可读的哈希/ID，管理员对不上账号）。
type ActiveAccount struct {
	MId  string
	Name string
}

// GetActiveAccounts 查询最近 activeThresholdMinutes 分钟内有过心跳的账号。
//
// ⚠️ 2026-09-23 起**不再用于泡点发放**。旧实现用它反推"谁在线"，但它读的是
// 网关库 accounts.last_heartbeat（由登录器 HTTP 心跳更新），与内存会话表
// 完全脱钩：会话被 CleanExpiredSessions 清理后心跳字段仍是旧值，导致
// 「清理超时会话」的下一行又给已掉线玩家发放泡点。
//
// 泡点的权威口径已改为 session.SessionManager.CollectBonusAwards
// （按玩家真实在游戏频道内的时长计费）。本方法保留仅作只读统计用途。
func (db *Database) GetActiveAccounts(activeThresholdMinutes int) ([]ActiveAccount, error) {
	now := NowUnix()
	threshold := now - int64(activeThresholdMinutes*60)

	rows, err := db.gatewayDB.Query(
		"SELECT m_id, name FROM accounts WHERE last_heartbeat >= ? AND last_heartbeat > 0",
		threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []ActiveAccount
	for rows.Next() {
		var a ActiveAccount
		if err := rows.Scan(&a.MId, &a.Name); err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}

// UpdateAccountTokenCera 更新账号代币点券。
func (db *Database) UpdateAccountTokenCera(mId string, delta int64) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET token_cera = token_cera + ?, updated_at = ? WHERE m_id = ?",
		delta, NowUnix(), mId)
	return err
}

// UpdateAccountHappyTokenCera 更新账号快乐代币点券。
func (db *Database) UpdateAccountHappyTokenCera(mId string, delta int64) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE accounts SET happy_token_cera = happy_token_cera + ?, updated_at = ? WHERE m_id = ?",
		delta, NowUnix(), mId)
	return err
}

// ResetAccountPwd 重置账号密码。
func (db *Database) ResetAccountPwd(name, pwdHash, salt string) error {
	return db.UpdateAccountPwd(name, pwdHash, salt)
}

// ClearDeviceSecret 解除账号设备绑定。
//
// 传入账号名（accounts.name），清除该账号的全部设备凭证痕迹：
//   - device_secret：设备密钥本体；
//   - device_secret_issued_at：密钥签发时间（不清会导致冷却期误判）；
//   - device_secret_last_rotated：上次换发时间；
//   - device_history：设备登录历史表（按 m_id 关联）。
//
// 说明：原实现只清了 device_secret 与 device_secret_last_rotated，且用
// name 直接匹配；现改为先解析出 m_id，再一并清理历史表，语义与原网关
// “解除设备绑定”一致。accounts 表中查不到该账号时返回首行错误。
func (db *Database) ClearDeviceSecret(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("账号名不能为空")
	}

	acc, err := db.GetAccountByName(name)
	if err != nil {
		return err
	}
	if acc == nil {
		return fmt.Errorf("账号不存在: %s", name)
	}

	tx, err := db.gatewayDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`UPDATE accounts
		    SET device_secret = '',
		        device_secret_issued_at = '',
		        device_history = '',
		        device_secret_last_rotated = 0
		  WHERE name = ?`, name); err != nil {
		return err
	}

	if acc.MId != "" {
		if _, err := tx.Exec("DELETE FROM device_history WHERE m_id = ?", acc.MId); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// UnlockAccount 解锁账号（清除锁定）。
func (db *Database) UnlockAccount(name string) (bool, error) {
	result, err := db.gatewayDB.Exec(
		"UPDATE accounts SET failed_login_count = 0, lockout_until = 0 WHERE name = ? AND lockout_until > ?",
		name, NowUnix())
	if err != nil {
		return false, err
	}
	rows, _ := result.RowsAffected()
	return rows > 0, nil
}

// UnlockAllAccounts 解锁所有账号。
func (db *Database) UnlockAllAccounts() (int64, error) {
	result, err := db.gatewayDB.Exec(
		"UPDATE accounts SET failed_login_count = 0, lockout_until = 0 WHERE lockout_until > ?",
		NowUnix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// InsertDeviceHistory 插入设备历史记录。
func (db *Database) InsertDeviceHistory(mId, secret, ip string) error {
	_, err := db.gatewayDB.Exec(
		"INSERT INTO device_history (m_id, device_secret, ip, login_at) VALUES (?, ?, ?, ?)",
		mId, secret, ip, NowUnix())
	return err
}

// GetDeviceHistory 获取设备历史。
func (db *Database) GetDeviceHistory(mId string, limit int) ([]DeviceHistoryEntry, error) {
	rows, err := db.gatewayDB.Query(
		"SELECT id, m_id, device_secret, ip, login_at FROM device_history WHERE m_id = ? ORDER BY login_at DESC LIMIT ?",
		mId, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []DeviceHistoryEntry
	for rows.Next() {
		var e DeviceHistoryEntry
		if err := rows.Scan(&e.Id, &e.MId, &e.DeviceSecret, &e.IP, &e.LoginAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// TrimDeviceHistory 裁剪设备历史，只保留最近 maxHistory 条。
func (db *Database) TrimDeviceHistory(mId string, maxHistory int) error {
	_, err := db.gatewayDB.Exec(
		`DELETE FROM device_history WHERE m_id = ? AND id NOT IN (
			SELECT id FROM device_history WHERE m_id = ? ORDER BY login_at DESC LIMIT ?
		)`,
		mId, mId, maxHistory)
	return err
}

// ListAccounts 分页查询账号列表。
//
// keyword 是**四字段联合查询**：账号名 / m_id / 角色名 / 角色ID，任意命中即算匹配。
// 后两个字段在游戏库，所以先由 SearchAccountMIdsByRole 解析成 m_id 集合，
// 再和账号名、m_id 一起在内存里过一遍。
func (db *Database) ListAccounts(keyword string, page, pageSize int) (int, []Account, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 500 {
		pageSize = 50
	}

	// 一次性取回**全部**账号行，三条理由：
	//   1. 排序要按游戏库的注册时间，而那是另一个库的列，SQL 里 join 不到；
	//   2. keyword 里的「角色名 / 角色ID」也跨库，SQL 拼不出这样的联合条件；
	//   3. 账号量级就是"玩家数"（202 上 106 个），全量加载没有压力。
	// 若将来涨到十万级，应在网关库冗余 game_created_at 与角色名索引，
	// 再把过滤 / 排序 / 分页都还给 SQL。
	//
	// 角色名那一项还有个硬约束：游戏库 characters.name 存的是 GBK 裸字节
	// （typeof='blob'），拿 UTF-8 的 LIKE 模式去比永远比不中（blob 与 text 是
	// 不同存储类，直接判不等），所以只能取回后在 Go 里解码再比。
	rows, err := db.gatewayDB.Query(
		"SELECT m_id, name, cera, last_login_at, last_login_ip, failed_login_count, " +
			"lockout_until, last_heartbeat, created_at FROM accounts")
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	all := make([]Account, 0, 256)
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.MId, &a.Name, &a.Cera, &a.LastLoginAt, &a.LastLoginIP,
			&a.FailedLoginCount, &a.LockoutUntil, &a.LastHeartbeat, &a.CreatedAt); err != nil {
			return 0, nil, err
		}
		all = append(all, a)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if len(all) == 0 {
		return 0, []Account{}, nil
	}

	// 补游戏库的真实注册时间（整批查一次）。
	// 查不到的留空 —— 前端回退展示网关库时间并标注来源；
	// 游戏库查询失败也不阻断列表，只是注册时间不够准。
	mIds := make([]string, 0, len(all))
	for i := range all {
		mIds = append(mIds, all[i].MId)
	}
	if gameCreated, gerr := db.GetGameAccountCreatedAt(mIds); gerr == nil {
		for i := range all {
			all[i].GameCreatedAt = gameCreated[all[i].MId]
		}
	}

	// 封禁标记（网关库 banned_accounts）。查不到就全部按未封禁处理，不阻断列表。
	if banned, berr := db.ListBannedNames(); berr == nil {
		for i := range all {
			_, all[i].Banned = banned[all[i].Name]
		}
	}
	// 登录失败锁定：lockout_until 还没到就是锁定中。
	now := time.Now().Unix()
	for i := range all {
		all[i].Locked = all[i].LockoutUntil > now
	}

	// 关键字过滤。roleMIds 是「角色名或角色ID」命中的账号；游戏库查询失败时
	// 退化成只按账号名/m_id 匹配，而不是整个列表报错。
	if kw := strings.TrimSpace(keyword); kw != "" {
		roleMIds, rerr := db.SearchAccountMIdsByRole(kw)
		if rerr != nil || roleMIds == nil {
			roleMIds = map[string]struct{}{}
		}
		needle := strings.ToLower(kw)
		matched := make([]Account, 0, len(all))
		for _, a := range all {
			if strings.Contains(strings.ToLower(a.Name), needle) ||
				strings.Contains(strings.ToLower(a.MId), needle) {
				matched = append(matched, a)
				continue
			}
			if _, ok := roleMIds[a.MId]; ok {
				matched = append(matched, a)
			}
		}
		all = matched
	}

	// 按注册时间正序（老账号在前），**排序键用游戏库的时间**。
	//
	// 必须用界面上显示的那一列来排：网关库那列是导入批次时间，一次性导入的账号
	// 全挤在同一秒（202 上 106 个账号的 created_at 完全一致），拿它排序等于没排 ——
	// 界面上会出现"显示 9/13 的行排在显示 9/12 的行前面"这种自相矛盾的列表。
	sort.SliceStable(all, func(i, j int) bool {
		ki, kj := accountSortKey(all[i]), accountSortKey(all[j])
		if ki != kj {
			return ki < kj
		}
		// 键相同时按名字，保证翻页顺序稳定（否则同键的行可能跨页重复/漏出）。
		return all[i].Name < all[j].Name
	})

	total := len(all)
	start := (page - 1) * pageSize
	if start >= total {
		return total, []Account{}, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return total, all[start:end], nil
}

// SearchAccountMIdsByRole 按「角色名 或 角色ID」找出账号 m_id。
//
// 角色名精确与否：角色名走包含匹配（管理员往往只记得一半），角色ID走精确匹配
// （数字走包含会误伤，比如搜 "38" 命中 10038）。
//
// 全量取回再在 Go 里过滤，而不是在远端 SQL 里 LIKE：见 ListAccounts 的注释 ——
// characters.name 是 GBK blob，SQL 的 LIKE 对它无效。角色量级很小
// （202 上约 240 个），一次全量读没有任何压力。
func (db *Database) SearchAccountMIdsByRole(keyword string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	keyword = strings.TrimSpace(keyword)
	if keyword == "" || !db.GameConfigured() {
		return result, nil
	}

	rows, err := db.gameDB.Query(
		"SELECT c.character_id, c.name, typeof(c.name), a.m_id " +
			"FROM characters c JOIN accounts a ON c.account_id = a.account_id " +
			"WHERE c.delete_flag = 0")
	if err != nil {
		return nil, fmt.Errorf("查询游戏库角色失败: %w", err)
	}
	defer rows.Close()

	needle := strings.ToLower(keyword)
	for rows.Next() {
		var cid int64
		var rawName []byte
		var nameType, mId string
		if err := rows.Scan(&cid, &rawName, &nameType, &mId); err != nil {
			continue
		}
		if mId == "" {
			continue
		}
		if strconv.FormatInt(cid, 10) == keyword {
			result[mId] = struct{}{}
			continue
		}
		name := strings.ToLower(DecodeGameText(rawName, nameType))
		if name != "" && strings.Contains(name, needle) {
			result[mId] = struct{}{}
		}
	}
	return result, rows.Err()
}

// ListBannedNames 返回被封禁账号名的集合（供列表批量打标记）。
func (db *Database) ListBannedNames() (map[string]struct{}, error) {
	rows, err := db.gatewayDB.Query("SELECT name FROM banned_accounts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		result[name] = struct{}{}
	}
	return result, rows.Err()
}

// accountSortKey 账号列表的排序键。
//
// 游戏库的注册时间是 TEXT、UTC、零填充定长（'2026-09-13 13:21:47'），
// 字典序与时间序一致，可以直接当字符串比。
//
// 游戏库还没有该账号时，把网关库的 Unix 秒按**同样的格式**转成 UTC 文本 ——
// 两个来源必须能放进同一个序列里比较，否则回退行会全部挤到最前面或最后面。
func accountSortKey(a Account) string {
	if a.GameCreatedAt != "" {
		return a.GameCreatedAt
	}
	if a.CreatedAt <= 0 {
		return ""
	}
	return time.Unix(a.CreatedAt, 0).UTC().Format("2006-01-02 15:04:05")
}

// ListAllAccountNames 列出所有账号名。
func (db *Database) ListAllAccountNames() ([]string, error) {
	rows, err := db.gatewayDB.Query("SELECT name FROM accounts ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// GetMIdsByNames 批量把账号名映射成 m_id（在线角色列表用）。
//
// 网关内存里的会话只记账号名，而游戏库的角色是按 m_id 关联的，
// 中间这一步必须走网关库。查不到的账号**不出现在返回值里**（调用方按"无角色"处理）。
//
// 单查询变量数受 SQLite 限制，按 chunk 分批。
func (db *Database) GetMIdsByNames(names []string) (map[string]string, error) {
	out := make(map[string]string)
	seen := make(map[string]struct{}, len(names))
	uniq := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		uniq = append(uniq, n)
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
		for _, n := range chunk {
			placeholders = append(placeholders, "?")
			args = append(args, n)
		}

		rows, err := db.gatewayDB.Query(
			"SELECT name, m_id FROM accounts WHERE name IN ("+strings.Join(placeholders, ",")+")",
			args...)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var name, mId string
			if err := rows.Scan(&name, &mId); err != nil {
				rows.Close()
				return out, err
			}
			out[name] = mId
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
	}
	return out, nil
}

// GetGameAccountCreatedAt 批量取游戏库里账号的真实注册时间。
//
// 返回 m_id → created_at 原文（TEXT，UTC）。**查不到的 m_id 不出现在返回值里**，
// 调用方据此判断"游戏库还没有这个账号"，回退到网关库的时间。
//
// 为什么不能用网关库的 created_at：那是本网关写库的时刻。2026-09-24 导入的那批
// 账号全部落在同一秒，管理后台的「注册时间」列整列一模一样 —— 玩家真正的注册
// 时间只存在于游戏库（服务端建号时写 CURRENT_TIMESTAMP）。
func (db *Database) GetGameAccountCreatedAt(mIds []string) (map[string]string, error) {
	out := make(map[string]string)
	if db.gameDB == nil {
		return out, nil
	}

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

		rows, err := db.gameDB.Query(
			"SELECT m_id, IFNULL(created_at,'') FROM accounts WHERE m_id IN ("+
				strings.Join(placeholders, ",")+")", args...)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var mId, createdAt string
			if err := rows.Scan(&mId, &createdAt); err != nil {
				rows.Close()
				return out, err
			}
			// 空时间按"没查到"处理，避免把空串当成有效注册时间。
			if createdAt != "" {
				out[mId] = createdAt
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
	}
	return out, nil
}

// CountAccounts 统计账号数量。
func (db *Database) CountAccounts() (int, error) {
	var count int
	err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM accounts").Scan(&count)
	return count, err
}

// InsertRegisterLog 插入注册奖励日志（流水）。
func (db *Database) InsertRegisterLog(row *models.RegisterBonusLogRow) error {
	createdAt := row.CreatedAt
	if createdAt == "" {
		createdAt = time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	_, err := db.gatewayDB.Exec(`
		INSERT INTO register_bonus_logs
			(account, account_id, character_id, character_name, reward_type,
			 item_id, item_name, kind, quantity, status, message, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.Account, row.AccountID, row.CharacterID, row.CharacterName, row.RewardType,
		row.ItemID, row.ItemName, row.Kind, row.Quantity, row.Status, row.Message, createdAt)
	return err
}

// CountRegisterLog 统计指定账号某奖励类型的登记行数（幂等检查用）。
func (db *Database) CountRegisterLog(account, rewardType string) (int64, error) {
	var n int64
	err := db.gatewayDB.QueryRow(
		"SELECT COUNT(1) FROM register_bonus_logs WHERE account = ? AND reward_type = ?",
		account, rewardType).Scan(&n)
	return n, err
}

// FindPendingRegister 取指定账号最早的 pending 登记行。
func (db *Database) FindPendingRegister(account string) (*models.RegisterBonusLogRow, error) {
	row := db.gatewayDB.QueryRow(`
		SELECT id, account, account_id, character_id, character_name, reward_type,
		       item_id, item_name, kind, quantity, status, message, created_at
		FROM register_bonus_logs
		WHERE account = ? AND reward_type = 'registered' AND status = 'pending'
		ORDER BY id ASC LIMIT 1`, account)

	var r models.RegisterBonusLogRow
	if err := row.Scan(&r.ID, &r.Account, &r.AccountID, &r.CharacterID, &r.CharacterName,
		&r.RewardType, &r.ItemID, &r.ItemName, &r.Kind, &r.Quantity, &r.Status, &r.Message, &r.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// ClaimRegisterPending 原子抢占 pending 登记行（并发防重复发放）。
func (db *Database) ClaimRegisterPending(id int64) (bool, error) {
	result, err := db.gatewayDB.Exec(
		"UPDATE register_bonus_logs SET status = 'processing' WHERE id = ? AND status = 'pending'", id)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n == 1, nil
}

// ReleaseRegisterClaim 把已抢占但未完成的行退回 pending。
func (db *Database) ReleaseRegisterClaim(id int64) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE register_bonus_logs SET status = 'pending' WHERE id = ? AND status = 'processing'", id)
	return err
}

// MarkRegisterDone 将登记行标记为完成。
func (db *Database) MarkRegisterDone(id int64) error {
	_, err := db.gatewayDB.Exec(
		"UPDATE register_bonus_logs SET status = 'done' WHERE id = ? AND status IN ('pending','processing')", id)
	return err
}

// QueryRegisterLogs 查询注册奖励日志。
func (db *Database) QueryRegisterLogs(account, rewardType, status string, page, pageSize int) (int, []*models.RegisterBonusLogRow, error) {
	var total int
	countQuery := "SELECT COUNT(*) FROM register_bonus_logs"
	whereClauses := []string{}
	args := []interface{}{}
	if account != "" {
		whereClauses = append(whereClauses, "account LIKE ?")
		args = append(args, "%"+account+"%")
	}
	if rewardType != "" {
		whereClauses = append(whereClauses, "reward_type = ?")
		args = append(args, rewardType)
	}
	if status != "" {
		whereClauses = append(whereClauses, "status = ?")
		args = append(args, status)
	}
	if len(whereClauses) > 0 {
		countQuery += " WHERE " + strings.Join(whereClauses, " AND ")
	}
	if err := db.gatewayDB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return 0, nil, err
	}

	query := `
		SELECT id, account, account_id, character_id, character_name, reward_type,
		       item_id, item_name, kind, quantity, status, message, created_at
		FROM register_bonus_logs`
	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, (page-1)*pageSize)

	rows, err := db.gatewayDB.Query(query, args...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	var entries []*models.RegisterBonusLogRow
	for rows.Next() {
		var r models.RegisterBonusLogRow
		if err := rows.Scan(&r.ID, &r.Account, &r.AccountID, &r.CharacterID, &r.CharacterName,
			&r.RewardType, &r.ItemID, &r.ItemName, &r.Kind, &r.Quantity, &r.Status, &r.Message, &r.CreatedAt); err != nil {
			return 0, nil, err
		}
		entries = append(entries, &r)
	}
	return total, entries, nil
}

// FindRegisterByID 按 ID 查询注册奖励日志行。
func (db *Database) FindRegisterByID(id int64) (*models.RegisterBonusLogRow, error) {
	row := db.gatewayDB.QueryRow(`
		SELECT id, account, account_id, character_id, character_name, reward_type,
		       item_id, item_name, kind, quantity, status, message, created_at
		FROM register_bonus_logs WHERE id = ?`, id)

	var r models.RegisterBonusLogRow
	if err := row.Scan(&r.ID, &r.Account, &r.AccountID, &r.CharacterID, &r.CharacterName,
		&r.RewardType, &r.ItemID, &r.ItemName, &r.Kind, &r.Quantity, &r.Status, &r.Message, &r.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// Account 网关库中的账号记录。
type Account struct {
	MId                     string
	Name                    string
	PwdHash                 string
	Salt                    string
	Cera                    int64
	TokenCera               int64
	HappyTokenCera          int64
	DeviceSecret            string
	DeviceSecretIssuedAt    string
	DeviceHistory           string
	DeviceSecretLastRotated int64
	LastLoginAt             int64
	LastLoginIP             string
	FailedLoginCount        int
	LockoutUntil            int64
	CreatedAt               int64
	LastHeartbeat           int64
	// GameCreatedAt 游戏库 accounts.created_at 的原文（TEXT，UTC，如 "2026-08-11 13:32:12"）。
	//
	// 它才是**玩家真正的注册时间**：网关库的 CreatedAt 是本网关写库那一刻的时间戳，
	// 批量导入的账号会全部挤在同一秒（实测 2026-09-24 那批全是 09:41:36）。
	// 空串表示游戏库里还没有这个 m_id 的行（注册了但从未进过游戏，服务端尚未懒建）。
	GameCreatedAt string
	// Banned 是否在网关库 banned_accounts 表里（只由 ListAccounts 填充）。
	Banned bool
	// Locked 账号是否处于登录失败锁定中（lockout_until 还没到）。只由 ListAccounts 填充。
	//
	// 注意与 Banned 的区别：Banned 是管理员主动封禁（要解封），Locked 是连续登录失败
	// 触发的自动锁定（到期自动失效，或管理员手动解锁）。界面上是两个不同的标签。
	Locked bool
}

// DeviceHistoryEntry 设备历史记录。
type DeviceHistoryEntry struct {
	Id           int64
	MId          string
	DeviceSecret string
	IP           string
	LoginAt      int64
}

// RoleInfo 角色信息。
type RoleInfo struct {
	CharacterId int64  `json:"character_id"`
	Name        string `json:"name"`
	Level       int    `json:"level"`
	Job         int    `json:"job"`
	// GrowType 转职/觉醒编码：低 4 位 = 转职，高 4 位 = 觉醒。
	// 由它 + Job 解出 JobName（见 JobDisplayName）。
	GrowType int `json:"grow_type"`
	// JobName 职业中文名（转职/觉醒名优先，其次基础职业名）。
	JobName string `json:"job_name"`
	Exp     int64  `json:"exp"`
}

// MailItem 邮件物品。
type MailItem struct {
	ItemTemplateId int
	Count          int
	Kind           int
	ItemType       int
}

// MigrationResult 迁移结果。
type MigrationResult struct {
	Message      string
	Imported     int
	Skipped      int
	Failed       int
	GameAccounts int
}

// SyncResult 同步结果。
type SyncResult struct {
	Message      string
	GameAccounts int
	Imported     int
	Skipped      int
	Failed       int
}

// ==================== 外挂检测数据库方法 ====================

// AntiCheatDetection 外挂检测记录。
type AntiCheatDetection struct {
	ID             int64
	RuleName       string
	Description    string
	ActualValue    float64
	ThresholdValue float64
	EventTimestamp int64
	Evidence       string
	ClientIP       string
	Account        string
	ReportedAt     int64
}

// InsertAntiCheatDetection 插入外挂检测记录。
func (db *Database) InsertAntiCheatDetection(d *AntiCheatDetection) error {
	_, err := db.gatewayDB.Exec(
		"INSERT INTO anticheat_detections (rule_name, description, actual_value, threshold_value, event_timestamp, evidence, client_ip, account, reported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		d.RuleName, d.Description, d.ActualValue, d.ThresholdValue, d.EventTimestamp, d.Evidence, d.ClientIP, d.Account, d.ReportedAt,
	)
	return err
}

// InsertAntiCheatDetections 批量插入外挂检测记录。
func (db *Database) InsertAntiCheatDetections(detections []AntiCheatDetection) error {
	tx, err := db.gatewayDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, d := range detections {
		_, err := tx.Exec(
			"INSERT INTO anticheat_detections (rule_name, description, actual_value, threshold_value, event_timestamp, evidence, client_ip, account, reported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			d.RuleName, d.Description, d.ActualValue, d.ThresholdValue, d.EventTimestamp, d.Evidence, d.ClientIP, d.Account, d.ReportedAt,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetAntiCheatDetections 获取检测记录列表（分页）。
func (db *Database) GetAntiCheatDetections(limit, offset int) ([]AntiCheatDetection, int, error) {
	var total int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM anticheat_detections").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.gatewayDB.Query(
		"SELECT id, rule_name, description, actual_value, threshold_value, event_timestamp, evidence, client_ip, account, reported_at FROM anticheat_detections ORDER BY reported_at DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	detections := make([]AntiCheatDetection, 0)
	for rows.Next() {
		var d AntiCheatDetection
		if err := rows.Scan(&d.ID, &d.RuleName, &d.Description, &d.ActualValue, &d.ThresholdValue, &d.EventTimestamp, &d.Evidence, &d.ClientIP, &d.Account, &d.ReportedAt); err != nil {
			return nil, 0, err
		}
		detections = append(detections, d)
	}

	return detections, total, nil
}

// GetAntiCheatDetectionsByAccount 获取指定账号的检测记录。
func (db *Database) GetAntiCheatDetectionsByAccount(account string, limit, offset int) ([]AntiCheatDetection, int, error) {
	var total int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM anticheat_detections WHERE account = ?", account).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.gatewayDB.Query(
		"SELECT id, rule_name, description, actual_value, threshold_value, event_timestamp, evidence, client_ip, account, reported_at FROM anticheat_detections WHERE account = ? ORDER BY reported_at DESC LIMIT ? OFFSET ?",
		account, limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	detections := make([]AntiCheatDetection, 0)
	for rows.Next() {
		var d AntiCheatDetection
		if err := rows.Scan(&d.ID, &d.RuleName, &d.Description, &d.ActualValue, &d.ThresholdValue, &d.EventTimestamp, &d.Evidence, &d.ClientIP, &d.Account, &d.ReportedAt); err != nil {
			return nil, 0, err
		}
		detections = append(detections, d)
	}

	return detections, total, nil
}

// GetAntiCheatPlayerSummary 获取玩家检测汇总。
func (db *Database) GetAntiCheatPlayerSummary(limit, offset int) ([]map[string]interface{}, int, error) {
	var total int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(DISTINCT account) FROM anticheat_detections WHERE account != ''").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.gatewayDB.Query(`
		SELECT 
			account,
			COUNT(*) as detection_count,
			MAX(reported_at) as last_detection_at,
			GROUP_CONCAT(DISTINCT rule_name) as rule_names
		FROM anticheat_detections 
		WHERE account != '' 
		GROUP BY account 
		ORDER BY detection_count DESC 
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	summaries := make([]map[string]interface{}, 0)
	for rows.Next() {
		var account, ruleNames string
		var count, lastAt int64
		if err := rows.Scan(&account, &count, &lastAt, &ruleNames); err != nil {
			return nil, 0, err
		}
		summaries = append(summaries, map[string]interface{}{
			"account":         account,
			"detectionCount":  count,
			"lastDetectionAt": lastAt,
			"ruleNames":       strings.Split(ruleNames, ","),
		})
	}

	return summaries, total, nil
}

// GetAntiCheatRuleStats 获取各规则统计。
func (db *Database) GetAntiCheatRuleStats() (map[string]int, error) {
	rows, err := db.gatewayDB.Query("SELECT rule_name, COUNT(*) FROM anticheat_detections GROUP BY rule_name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var ruleName string
		var count int
		if err := rows.Scan(&ruleName, &count); err != nil {
			return nil, err
		}
		stats[ruleName] = count
	}

	return stats, nil
}

// ClearAntiCheatDetections 清空检测记录。
func (db *Database) ClearAntiCheatDetections() error {
	_, err := db.gatewayDB.Exec("DELETE FROM anticheat_detections")
	return err
}

// ==================== m_id 分配（纯数字，客户端硬约束） ====================
//
// ★★★ 为什么 m_id 必须是纯数字（2026-09-23 定案，五条证据互证）
//
// DNF 客户端把启动参数第 4 段（模板里的 {m_id}）**按数字解析**；解析失败时不报错，
// 而是回落到字面量 "invalid_id" 上报给游戏服务端：
//
//	网关填第 4 段 = 743c14ec…（64hex）
//	  → 客户端解析失败 → 上行 m_id = "invalid_id"
//	  → 服务端 LoginHandler: _accountRepository.Create("invalid_id", pwd)
//	  → 游戏库 accounts 多出一行 m_id='invalid_id'（幽灵行），角色挂它名下
//	  → 网关侧按真 m_id 关联的泡点 / 点券 / 查角色**全部落空**
//
// 服务端日志实证：`Login request parsed: m_id=invalid_id pwd_md5=…`
// （同一行的 pwd_md5 —— 即启动参数第 5 段的 token —— 是完好的，证明只有 m_id
// 这一项被客户端丢弃）。
//
// 权威口径（三方一致）：
//   - 服务端常量 DefaultLoginMid = "10038"（纯数字）；
//   - 原 .NET 网关 AccountService.cs:594 把 {m_id} 填成**账号名**，而原生产账号名
//     本身就是数字；
//   - 本地单机库 Data/inventory.db 的 24 个账号 m_id 全是纯数字；
//   - D:\DNFLauncher_V1.2.0\launcher_settings.json 里 "Account": "10038"。
//
// 取值区间 [10000, 999999999]：上限压在 int32 内（2^31-1 = 2147483647 之上仍有
// 富余），规避客户端可能的整型宽度限制；下限避开历史小号段。
const (
	mIdLowerBound int64 = 10000
	mIdUpperBound int64 = 999999999
)

// mIdAllocMu 串行化数字 m_id 的分配。
//
// 分配序列是「取当前上界 → 试占位 → 由调用方插入」，本身非原子：并发注册两个账号
// 可能选中同一个候选值。accounts.m_id 是 PRIMARY KEY，SQLite 会挡下脏写，但表现是
// 其中一个注册直接失败（5001）。进程内加锁把"撞车"变成"自动换下一个"，
// 注册成功率不受影响。
var mIdAllocMu sync.Mutex

// mIdIssued 记录本进程已分配出去、但可能尚未落库的数字 m_id。
//
// 光靠"查库判重"不够：AllocateNumericMId 返回号之后、调用方 INSERT 之前存在窗口，
// 并发注册会拿到同一个号（第二个 INSERT 撞主键直接报 5001）。分配即登记，把窗口关掉。
// 进程重启后内存表清空，但此时号已落盘，判重照常生效。
//
// 读写必须在持有 mIdAllocMu 时进行。
var mIdIssued = map[string]bool{}

// IsNumericMId 判断字符串是否满足 m_id 的客户端约束：3~10 位纯数字。
func IsNumericMId(mId string) bool {
	if len(mId) < 3 || len(mId) > 10 {
		return false
	}
	for i := 0; i < len(mId); i++ {
		if mId[i] < '0' || mId[i] > '9' {
			return false
		}
	}
	return true
}

// mIdTaken 判断候选 m_id 是否已被网关库或游戏库占用。
//
// 两侧都要查：网关库撞了会写坏主键；游戏库撞了更要命 —— 服务端按 m_id 关联
// accounts，重号会把两个玩家的角色 / 点券并到一起。查询失败按"已占用"处理（保守）。
func (db *Database) mIdTaken(mId string) (bool, error) {
	var n int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM accounts WHERE m_id = ?", mId).Scan(&n); err != nil {
		return true, fmt.Errorf("查询网关库 m_id 占用失败: %w", err)
	}
	if n > 0 {
		return true, nil
	}
	if db.gameDB != nil {
		if err := db.gameDB.QueryRow("SELECT COUNT(*) FROM accounts WHERE m_id = ?", mId).Scan(&n); err != nil {
			return true, fmt.Errorf("查询游戏库 m_id 占用失败: %w", err)
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// numericMIdCeiling 取两侧库中最大的合法数字 m_id，作为递增分配起点。
// 库中没有任何数字 m_id 时返回下限 mIdLowerBound。
func (db *Database) numericMIdCeiling() (int64, error) {
	ceiling := mIdLowerBound
	collect := func(conn *sql.DB, label string) error {
		if conn == nil {
			return nil
		}
		rows, err := conn.Query("SELECT m_id FROM accounts")
		if err != nil {
			return fmt.Errorf("读取%s账号 m_id 失败: %w", label, err)
		}
		defer rows.Close()
		for rows.Next() {
			var mId string
			if err := rows.Scan(&mId); err != nil {
				return err
			}
			if !IsNumericMId(mId) {
				continue
			}
			v, err := strconv.ParseInt(mId, 10, 64)
			if err != nil || v < mIdLowerBound || v > mIdUpperBound {
				continue
			}
			if v > ceiling {
				ceiling = v
			}
		}
		return rows.Err()
	}
	if err := collect(db.gatewayDB, "网关库"); err != nil {
		return 0, err
	}
	if err := collect(db.gameDB, "游戏库"); err != nil {
		return 0, err
	}
	return ceiling, nil
}

// AllocateNumericMId 分配一个未被占用的纯数字 m_id。
//
// preferred 是优先候选（注册时传账号名）：账号名本身是合法数字、且两侧库都没占用时
// 直接复用 —— 这与原 .NET 网关「{m_id} 填账号名」的口径一致，管理员看到
// m_id=10038 就能对上账号。否则从当前上界 +1 递增取号。
//
// 递增而非随机：可读、可人工核对、不会与历史号段意外重叠；删除账号不回收号（取 max+1）。
func (db *Database) AllocateNumericMId(preferred string) (string, error) {
	mIdAllocMu.Lock()
	defer mIdAllocMu.Unlock()
	// remember=true：注册路径分配后由调用方立即落库，先登记防并发重号。
	return db.allocateNumericMIdLocked(preferred, nil, true)
}

// allocateNumericMIdLocked 是分配实现，调用方必须持有 mIdAllocMu。
//
// reserved 表示"本次调用中已计划占用、但尚未落库"的号：迁移多个账号时前一条还没
// UPDATE，后一条绝不能把同一个号再分一次。
//
// remember 决定是否把结果登记进 mIdIssued：注册路径要（防并发重号）；迁移的
// dry-run 不要 —— 否则"看计划"会把号占掉，真 apply 时分到别的号，两次输出对不上。
func (db *Database) allocateNumericMIdLocked(preferred string, reserved map[string]bool, remember bool) (string, error) {
	free := func(mId string) (bool, error) {
		if mIdIssued[mId] {
			return false, nil
		}
		if reserved != nil && reserved[mId] {
			return false, nil
		}
		taken, err := db.mIdTaken(mId)
		if err != nil {
			return false, err
		}
		return !taken, nil
	}
	claim := func(mId string) string {
		if remember {
			mIdIssued[mId] = true
		}
		return mId
	}

	preferred = strings.TrimSpace(preferred)
	if IsNumericMId(preferred) {
		ok, err := free(preferred)
		if err != nil {
			return "", err
		}
		if ok {
			return claim(preferred), nil
		}
	}

	ceiling, err := db.numericMIdCeiling()
	if err != nil {
		return "", err
	}
	candidate := ceiling + 1
	if candidate <= mIdLowerBound {
		candidate = mIdLowerBound + 1
	}
	for ; candidate <= mIdUpperBound; candidate++ {
		mId := strconv.FormatInt(candidate, 10)
		ok, err := free(mId)
		if err != nil {
			return "", err
		}
		if ok {
			return claim(mId), nil
		}
	}
	return "", fmt.Errorf("数字 m_id 号段已耗尽（%d~%d）", mIdLowerBound, mIdUpperBound)
}

// MIdMigration 一条 m_id 迁移记录。
type MIdMigration struct {
	Account string `json:"account"`
	OldMId  string `json:"old_m_id"`
	NewMId  string `json:"new_m_id"`
}

// MIdMigrationPlan m_id 数字化迁移的计划（dry-run）或执行结果。
type MIdMigrationPlan struct {
	DryRun           bool           `json:"dry_run"`
	Migrations       []MIdMigration `json:"migrations"`
	GameInvalidOwner string         `json:"game_invalid_owner"`
	GameInvalidNew   string         `json:"game_invalid_new_m_id"`
	GameInvalidRows  int            `json:"game_invalid_rows"`
	ShadowAccounts   []string       `json:"shadow_accounts"`
}

// MigrateLegacyNumericMIds 把历史遗留的**非纯数字** m_id 账号改成数字 m_id。
//
// dryRun=true 只计算计划，一个字节都不落库（网关库 / 游戏库都不动）。
//
// gameInvalidOwner 指定游戏库幽灵行（m_id='invalid_id'）的归属账号名：客户端回落值
// 在游戏库留下的那行，角色挂在它的 account_id 下。传入后把该行改挂到该账号的新
// 数字 m_id，角色 / 点券即归位。传空字符串则不动游戏库。
//
// ShadowAccounts 仅作提示，不自动删除：那是 SyncGameAccounts 按游戏库 m_id 当账号名
// 同步进来的影子行（name == m_id 且非数字），与本次迁移无关，删不删由运维决定。
func (db *Database) MigrateLegacyNumericMIds(dryRun bool, gameInvalidOwner string) (*MIdMigrationPlan, error) {
	plan := &MIdMigrationPlan{DryRun: dryRun}

	type accountRow struct{ name, mId string }
	rows, err := db.gatewayDB.Query("SELECT name, m_id FROM accounts ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("读取网关账号失败: %w", err)
	}
	var all []accountRow
	for rows.Next() {
		var a accountRow
		if err := rows.Scan(&a.name, &a.mId); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var targets []accountRow
	for _, a := range all {
		if a.name == a.mId && !IsNumericMId(a.mId) {
			// 影子行（同步自游戏库）：不是真账号，跳过，只在报告里点名。
			plan.ShadowAccounts = append(plan.ShadowAccounts, a.name)
			continue
		}
		if IsNumericMId(a.mId) {
			continue // 已是数字，无需迁移
		}
		targets = append(targets, a)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].name < targets[j].name })

	mIdAllocMu.Lock()
	reserved := map[string]bool{}
	for _, t := range targets {
		// remember=false：号只在本次规划内用 reserved 互斥；dry-run 不能占号，
		// 否则"看计划"与真 apply 分配出的号会不一致。
		newMId, err := db.allocateNumericMIdLocked(t.name, reserved, false)
		if err != nil {
			mIdAllocMu.Unlock()
			return nil, fmt.Errorf("为账号 %s 分配 m_id 失败: %w", t.name, err)
		}
		reserved[newMId] = true
		plan.Migrations = append(plan.Migrations, MIdMigration{Account: t.name, OldMId: t.mId, NewMId: newMId})
		if gameInvalidOwner != "" && t.name == gameInvalidOwner {
			plan.GameInvalidOwner = t.name
			plan.GameInvalidNew = newMId
		}
	}
	mIdAllocMu.Unlock()

	if gameInvalidOwner != "" && plan.GameInvalidNew == "" {
		// owner 的 m_id 已经是纯数字（重复部署 / 之前手工订正过）：
		// 直接用它现有的 m_id 去处理幽灵行，而不是报错 —— 否则"msp 已数字化、
		// 但游戏库还留着 invalid_id 行"这个真实场景就没法修，重跑一次也会失败。
		if acc, err := db.GetAccountByName(gameInvalidOwner); err == nil && acc != nil && IsNumericMId(acc.MId) {
			plan.GameInvalidOwner = gameInvalidOwner
			plan.GameInvalidNew = acc.MId
		} else {
			return nil, fmt.Errorf(
				"--game-invalid-owner 指定的账号 %s 不存在或 m_id 仍非数字（先确认账号名）", gameInvalidOwner)
		}
	}

	// 幽灵行影响面：dry-run 也要如实预告，别让运维到 apply 那一步才发现要动多少行。
	if plan.GameInvalidOwner != "" && db.gameDB != nil {
		var n int
		if err := db.gameDB.QueryRow(
			"SELECT COUNT(*) FROM accounts WHERE m_id = 'invalid_id'").Scan(&n); err == nil {
			plan.GameInvalidRows = n
		}
	}

	if dryRun {
		return plan, nil
	}

	for _, m := range plan.Migrations {
		if err := db.rewriteMId(m.OldMId, m.NewMId); err != nil {
			return nil, fmt.Errorf("改写账号 %s 的 m_id 失败: %w", m.Account, err)
		}
	}
	if plan.GameInvalidNew != "" && db.gameDB != nil {
		res, err := db.gameDB.Exec("UPDATE accounts SET m_id = ? WHERE m_id = 'invalid_id'", plan.GameInvalidNew)
		if err != nil {
			return nil, fmt.Errorf("游戏库幽灵行归位失败: %w", err)
		}
		n, _ := res.RowsAffected()
		plan.GameInvalidRows = int(n)
	}
	return plan, nil
}

// rewriteMId 在网关库内把旧 m_id 改成新 m_id，并同步所有按 m_id 关联的表。
//
// 关联表只认 m_id（游戏库 accounts 没有账号名列）。漏改一张就会出现
// "账号能登录、但设备历史/流水挂不上"的隐性故障。
func (db *Database) rewriteMId(oldMId, newMId string) error {
	if oldMId == newMId {
		return nil
	}
	tx, err := db.gatewayDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("UPDATE accounts SET m_id = ?, updated_at = ? WHERE m_id = ?",
		newMId, NowUnix(), oldMId); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE device_history SET m_id = ? WHERE m_id = ?", newMId, oldMId); err != nil {
		return err
	}
	return tx.Commit()
}
