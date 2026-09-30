package database

import (
	"path/filepath"
	"testing"
)

// newGameCreatedTestDB 造一个「网关库整批同一秒、游戏库各不相同的注册时间」场景。
//
// 这正是线上真实情况：2026-09-24 那批账号被一次性导入网关库，
// 于是网关库 created_at 全都等于导入那一刻；玩家真正的注册时间只在游戏库。
//
//	网关库：alice / bobokiss / msp   created_at 全是 1758600000（同一秒）
//	游戏库：10038 → "2026-08-11 13:32:12"
//	        2030  → "2010-01-01 00:14:33"（老号，迁移时保留了原注册时间）
//	        99999 → **没有这一行**（注册了但从未进过游戏，服务端还没懒建）
func newGameCreatedTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	gamePath := filepath.Join(dir, "inventory.db")

	game, err := openSQLite(gamePath, 5)
	if err != nil {
		t.Fatalf("打开测试游戏库失败: %v", err)
	}
	if _, err := game.Exec(`
		CREATE TABLE accounts (
			account_id INTEGER PRIMARY KEY AUTOINCREMENT,
			m_id       TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO accounts(m_id, created_at) VALUES
			('10038', '2026-08-11 13:32:12'),
			('2030',  '2010-01-01 00:14:33'),
			('8888',  '');`); err != nil {
		game.Close()
		t.Fatalf("建测试游戏库 schema 失败: %v", err)
	}
	game.Close()

	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           gamePath,
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("初始化网关库 schema 失败: %v", err)
	}
	t.Cleanup(db.Close)

	const sameSecond = 1758600000
	accounts := []struct{ mid, name string }{
		{"10038", "alice"},
		{"2030", "bobokiss"},
		{"99999", "msp"},
		{"8888", "ghost"},
	}
	for _, a := range accounts {
		if _, err := db.gatewayDB.Exec(
			"INSERT INTO accounts(m_id, name, pwd_hash, salt, created_at) VALUES(?,?,?,?,?)",
			a.mid, a.name, "hash", "salt", sameSecond); err != nil {
			t.Fatalf("插入网关库账号失败: %v", err)
		}
	}
	return db
}

// TestGetGameAccountCreatedAt 批量取游戏库注册时间：空值与非命中都不返回。
func TestGetGameAccountCreatedAt(t *testing.T) {
	db := newGameCreatedTestDB(t)

	got, err := db.GetGameAccountCreatedAt([]string{"10038", "2030", "99999", "8888", "10038", ""})
	if err != nil {
		t.Fatalf("GetGameAccountCreatedAt 失败: %v", err)
	}

	if want := "2026-08-11 13:32:12"; got["10038"] != want {
		t.Errorf("10038 注册时间应为 %q，实得 %q", want, got["10038"])
	}
	if want := "2010-01-01 00:14:33"; got["2030"] != want {
		t.Errorf("2030 注册时间应为 %q，实得 %q", want, got["2030"])
	}
	// 游戏库没有 99999 这一行 —— 必须"查不到"，不能造一个空串条目出来。
	if _, ok := got["99999"]; ok {
		t.Errorf("99999 在游戏库没有行，不该出现在结果里: %q", got["99999"])
	}
	// created_at 是空串的行按"没查到"处理，否则前端会显示一个空白的注册时间。
	if _, ok := got["8888"]; ok {
		t.Errorf("游戏库 created_at 为空串时不该当成有效注册时间: %q", got["8888"])
	}
	if len(got) != 2 {
		t.Errorf("应只有 10038 / 2030 两条，实得 %d 条: %v", len(got), got)
	}
}

func TestGetGameAccountCreatedAtEmptyInput(t *testing.T) {
	db := newGameCreatedTestDB(t)

	got, err := db.GetGameAccountCreatedAt(nil)
	if err != nil {
		t.Fatalf("空输入不该报错: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("空输入应返回空 map，实得 %v", got)
	}
}

// TestListAccountsFillsGameCreatedAt 列表接口必须把游戏库注册时间带出来。
//
// 这条是本次报障的回归：以前整列都是同一个导入时刻，
// 现在 alice/bobokiss 要能显示出各自在游戏库里的真实注册时间。
func TestListAccountsFillsGameCreatedAt(t *testing.T) {
	db := newGameCreatedTestDB(t)

	total, accounts, err := db.ListAccounts("", 1, 50)
	if err != nil {
		t.Fatalf("ListAccounts 失败: %v", err)
	}
	if total != 4 {
		t.Fatalf("应有 4 个账号，实得 %d", total)
	}

	byName := map[string]Account{}
	for _, a := range accounts {
		byName[a.Name] = a
	}

	if got := byName["alice"].GameCreatedAt; got != "2026-08-11 13:32:12" {
		t.Errorf("alice 应带出游戏库注册时间，实得 %q", got)
	}
	if got := byName["bobokiss"].GameCreatedAt; got != "2010-01-01 00:14:33" {
		t.Errorf("bobokiss 应带出游戏库注册时间，实得 %q", got)
	}
	if got := byName["msp"].GameCreatedAt; got != "" {
		t.Errorf("msp 游戏库没有行，GameCreatedAt 应为空串，实得 %q", got)
	}
	// 网关库那一列仍然是同一个值 —— 保留它做排序兜底，前端只在没有游戏库值时用。
	if byName["msp"].CreatedAt != 1758600000 {
		t.Errorf("msp 网关库 created_at 应保持原值 1758600000，实得 %d", byName["msp"].CreatedAt)
	}
}

// TestListAccountsSortedByGameCreatedAt 列表排序键必须是**游戏库**时间。
//
// 反例（这条测试存在的理由）：四个账号在网关库里 created_at 完全相同（同一批导入），
// 若按网关库那列排，顺序直接退化成按姓名；可界面上显示的是游戏库时间，
// 于是列表看上去"完全没排序"。202 上 106 个账号正是这个情况。
//
// 期望顺序（游戏库时间正序，无游戏库值的回落到网关库时间）：
//
//	bobokiss 2010-01-01（游戏库）
//	ghost    —— 游戏库 created_at 是空串 → 回落网关库 1758600000（2025-09-23）
//	msp      —— 游戏库没有该行       → 回落网关库 1758600000（2025-09-23）
//	alice    2026-08-11（游戏库）
func TestListAccountsSortedByGameCreatedAt(t *testing.T) {
	db := newGameCreatedTestDB(t)

	_, accounts, err := db.ListAccounts("", 1, 50)
	if err != nil {
		t.Fatalf("ListAccounts 失败: %v", err)
	}
	names := make([]string, 0, len(accounts))
	for _, a := range accounts {
		names = append(names, a.Name)
	}
	want := []string{"bobokiss", "ghost", "msp", "alice"}
	if len(names) != len(want) {
		t.Fatalf("账号数应为 %d，实得 %d: %v", len(want), len(names), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("顺序应为 %v，实得 %v", want, names)
		}
	}

	// 分页切片也要跟着新顺序走（内存排序后切片，不能回到 SQL 分页）。
	_, page1, err := db.ListAccounts("", 1, 2)
	if err != nil {
		t.Fatalf("第 1 页失败: %v", err)
	}
	total, page2, err := db.ListAccounts("", 2, 2)
	if err != nil {
		t.Fatalf("第 2 页失败: %v", err)
	}
	if total != 4 {
		t.Errorf("total 应为 4（不受分页影响），实得 %d", total)
	}
	got1 := []string{page1[0].Name, page1[1].Name}
	got2 := []string{page2[0].Name, page2[1].Name}
	if got1[0] != "bobokiss" || got1[1] != "ghost" || got2[0] != "msp" || got2[1] != "alice" {
		t.Errorf("分页结果与整体顺序不一致：page1=%v page2=%v", got1, got2)
	}
}

// TestListAccountsSortKeyFormat 回落到网关库时间时，格式必须与游戏库一致。
//
// 两个来源要放进同一个序列里比：游戏库是 '2006-01-02 15:04:05' 的 UTC 文本，
// 网关库是 Unix 秒。若把 Unix 秒直接拿来比字符串，回退行会全部乱序。
func TestListAccountsSortKeyFormat(t *testing.T) {
	got := accountSortKey(Account{CreatedAt: 1758600000})
	if got != "2025-09-23 04:00:00" {
		t.Errorf("网关库时间应转成 UTC 文本 '2025-09-23 04:00:00'，实得 %q", got)
	}
	// 有游戏库值时必须原样用游戏库的（不做任何再格式化）。
	if got := accountSortKey(Account{GameCreatedAt: "2010-01-01 00:14:33"}); got != "2010-01-01 00:14:33" {
		t.Errorf("有游戏库时间时应原样使用，实得 %q", got)
	}
	// 两个都没有 → 空串（排最前，不会 panic）。
	if got := accountSortKey(Account{}); got != "" {
		t.Errorf("无任何时间应返回空串，实得 %q", got)
	}
}
