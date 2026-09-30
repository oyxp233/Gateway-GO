package database

import (
	"path/filepath"
	"testing"
	"time"
)

// newAccountSearchTestDB 造一个「四字段联合查询」场景。
//
// 网关库（4 个账号）：
//
//	alice  m_id=2030   普通
//	msp    m_id=10038  被封禁（banned_accounts）
//	ghost  m_id=8888   登录失败锁定中（lockout_until 在未来）
//	tester m_id=4004   普通
//
// 游戏库角色（名字用 charset_test.go 里的**真实 GBK 字节**）：
//
//	501 → 2030  "阿亮"(blob)      level 86 job 0 grow_type 33（剑神）
//	502 → 10038 "兔兔"(blob)
//	503 → 4004  "毒奶"(blob)
//	504 → 8888  "Brave"(text)     历史 UTF-8 行，按列类型原样透传
//	505 → 8888  "已删角色"(blob)  delete_flag=1，任何查询都不该命中
func newAccountSearchTestDB(t *testing.T) *Database {
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
			m_id       TEXT NOT NULL UNIQUE
		);
		INSERT INTO accounts(m_id) VALUES ('2030'), ('10038'), ('8888'), ('4004');

		CREATE TABLE characters (
			character_id INTEGER PRIMARY KEY,
			account_id   INTEGER NOT NULL,
			name         TEXT NOT NULL,
			level        INTEGER NOT NULL DEFAULT 1,
			job          INTEGER NOT NULL DEFAULT 0,
			grow_type    INTEGER NOT NULL DEFAULT 0,
			exp          INTEGER NOT NULL DEFAULT 0,
			delete_flag  INTEGER NOT NULL DEFAULT 0
		);`); err != nil {
		game.Close()
		t.Fatalf("建测试游戏库 schema 失败: %v", err)
	}

	roles := []struct {
		cid, accId int64
		name       interface{}
		del        int
	}{
		{501, 1, []byte{0xb0, 0xa2, 0xc1, 0xc1}, 0},                         // 阿亮（GBK blob）
		{502, 2, []byte{0xcd, 0xc3, 0xcd, 0xc3}, 0},                         // 兔兔（GBK blob）
		{503, 4, []byte{0xb6, 0xbe, 0xc4, 0xcc}, 0},                         // 毒奶（GBK blob）
		{504, 3, "Brave", 0},                                                // 历史 UTF-8 行：传 string，落库 typeof='text'
		{505, 3, []byte{0xd2, 0xd1, 0xc9, 0xbe, 0xbd, 0xc7, 0xc9, 0xab}, 1}, // 已删角色
	}
	for _, r := range roles {
		if _, err := game.Exec(
			"INSERT INTO characters(character_id, account_id, name, level, job, grow_type, delete_flag) VALUES(?,?,?,86,0,33,?)",
			r.cid, r.accId, r.name, r.del); err != nil {
			game.Close()
			t.Fatalf("插入测试角色失败: %v", err)
		}
	}
	game.Close()

	// 夹具自检：504 必须是 text 列、其余是 blob —— 否则"按列类型解码"这条路径没被覆盖。
	var braveType string
	check, err := openSQLite(gamePath, 5)
	if err == nil {
		_ = check.QueryRow("SELECT typeof(name) FROM characters WHERE character_id = 504").Scan(&braveType)
		check.Close()
	}
	if braveType != "text" {
		t.Fatalf("夹具不正确：角色 504 的 typeof(name)=%q，应为 text", braveType)
	}

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

	accounts := []struct {
		mid, name string
		lockout   int64
	}{
		{"2030", "alice", 0},
		{"10038", "msp", 0},
		{"8888", "ghost", time.Now().Unix() + 3600}, // 锁定中
		{"4004", "tester", 0},
	}
	for _, a := range accounts {
		if _, err := db.gatewayDB.Exec(
			"INSERT INTO accounts(m_id, name, pwd_hash, salt, created_at, lockout_until) VALUES(?,?,?,?,?,?)",
			a.mid, a.name, "hash", "salt", 1758600000, a.lockout); err != nil {
			t.Fatalf("插入网关库账号失败: %v", err)
		}
	}
	if err := db.BanAccount("msp", "测试封禁"); err != nil {
		t.Fatalf("写入封禁记录失败: %v", err)
	}
	return db
}

func namesOf(accounts []Account) []string {
	out := make([]string, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, a.Name)
	}
	return out
}

func assertNames(t *testing.T, keyword string, want ...string) {
	t.Helper()
	db := newAccountSearchTestDB(t)
	_, accounts, err := db.ListAccounts(keyword, 1, 100)
	if err != nil {
		t.Fatalf("ListAccounts(%q) 失败: %v", keyword, err)
	}
	got := namesOf(accounts)
	if len(got) != len(want) {
		t.Fatalf("ListAccounts(%q) 命中 %v，期望 %v", keyword, got, want)
	}
	gotSet := map[string]bool{}
	for _, n := range got {
		gotSet[n] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Fatalf("ListAccounts(%q) 命中 %v，期望 %v", keyword, got, want)
		}
	}
}

// TestListAccountsSearchByAccountName 账号名模糊、大小写不敏感。
func TestListAccountsSearchByAccountName(t *testing.T) {
	assertNames(t, "ali", "alice")
	assertNames(t, "ALI", "alice")
	assertNames(t, "est", "tester")
	assertNames(t, "nonexistent")
}

// TestListAccountsSearchByMId m_id 模糊匹配。
func TestListAccountsSearchByMId(t *testing.T) {
	assertNames(t, "2030", "alice")
	assertNames(t, "1003", "msp")
}

// TestListAccountsSearchByRoleName 按**角色名**查账号。
//
// 这条是本批最容易做错的一处：游戏库 characters.name 存的是 GBK 裸字节
// （typeof='blob'），SQL 的 LIKE 拿 UTF-8 模式去比永远比不中，必须在 Go 里解码后比。
func TestListAccountsSearchByRoleName(t *testing.T) {
	assertNames(t, "阿亮", "alice")
	assertNames(t, "兔兔", "msp")
	assertNames(t, "奶", "tester")    // 模糊：毒奶
	assertNames(t, "Brave", "ghost") // 历史 text 列角色名也要能搜到
}

// TestListAccountsSearchByRoleId 角色ID 走**精确**匹配。
//
// 数字走包含会误伤：搜 "50" 会命中 501/502/503/504/505，管理员根本分不清。
func TestListAccountsSearchByRoleId(t *testing.T) {
	assertNames(t, "501", "alice")
	assertNames(t, "503", "tester")
	// 505 是已删角色 → 不该命中；504 属于 ghost，但 "50" 也不是完整 ID
	assertNames(t, "50")
	assertNames(t, "505")
}

// TestListAccountsSearchSkipsDeletedRoles 已删角色不参与查询。
func TestListAccountsSearchSkipsDeletedRoles(t *testing.T) {
	assertNames(t, "已删角色")
}

// TestListAccountsBannedAndLocked 状态两列：封禁与登录失败锁定分开标记。
func TestListAccountsBannedAndLocked(t *testing.T) {
	db := newAccountSearchTestDB(t)
	_, accounts, err := db.ListAccounts("", 1, 100)
	if err != nil {
		t.Fatalf("ListAccounts 失败: %v", err)
	}
	byName := map[string]Account{}
	for _, a := range accounts {
		byName[a.Name] = a
	}
	if !byName["msp"].Banned {
		t.Errorf("msp 应在 banned_accounts 里，Banned 应为 true")
	}
	if byName["msp"].Locked {
		t.Errorf("msp 没有 lockout_until，不该被判为锁定")
	}
	if !byName["ghost"].Locked {
		t.Errorf("ghost 的 lockout_until 在未来，应判为锁定中")
	}
	if byName["ghost"].Banned {
		t.Errorf("ghost 没被封禁，Banned 应为 false")
	}
	if byName["alice"].Banned || byName["alice"].Locked {
		t.Errorf("alice 是正常账号，两个标记都应为 false")
	}
}

// TestListAccountsHonorsPageSize 管理页可选 50/100/200/500，不能被内部限死成 50。
func TestListAccountsHonorsPageSize(t *testing.T) {
	db := newAccountSearchTestDB(t) // 4 个账号
	for _, size := range []int{50, 100, 200, 500} {
		total, page1, err := db.ListAccounts("", 1, size)
		if err != nil {
			t.Fatalf("page_size=%d 失败: %v", size, err)
		}
		if total != 4 || len(page1) != 4 {
			t.Fatalf("page_size=%d 应一次拿到 4 个账号，实得 total=%d len=%d", size, total, len(page1))
		}
	}
	// 超过上限的值被夹到 50（不是报错），保证前端传错也不会拖垮库
	if _, _, err := db.ListAccounts("", 1, 100000); err != nil {
		t.Fatalf("超大 page_size 不该报错: %v", err)
	}
}

// TestSearchAccountMIdsByRoleEmptyInput 空关键字 / 未配置游戏库都返回空 map，不报错。
func TestSearchAccountMIdsByRoleEmptyInput(t *testing.T) {
	db := newAccountSearchTestDB(t)
	for _, kw := range []string{"", "   "} {
		got, err := db.SearchAccountMIdsByRole(kw)
		if err != nil {
			t.Fatalf("空关键字不该报错: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("空关键字应返回空集合，实得 %v", got)
		}
	}
}
