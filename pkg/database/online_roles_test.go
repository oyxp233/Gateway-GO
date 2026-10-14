package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newOnlineTestDB 建一套「网关库 + 游戏库」，游戏库里的角色名**刻意用 GBK 裸字节**，
// updated_at 也刻意错开 —— 这两点是「在线角色」功能最容易搞错的地方。
//
// 场景：
//
//	10038 → 角色 500「兔兔」(最近活动) + 角色 501「毒奶」(较早)  → 当前角色应为 500，RoleCount=2
//	10038 → 角色 502 delete_flag=1（已删除）                      → 必须不计入
//	2030  → 角色 600「Msp」                                       → 当前角色 600，RoleCount=1
//	99999 → 无角色                                                → 查不到，不出现在结果里
func newOnlineTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	gamePath := filepath.Join(dir, "inventory.db")

	game, err := openSQLite(gamePath, 5)
	if err != nil {
		t.Fatalf("打开测试游戏库失败: %v", err)
	}

	// GBK 字节直接以 BLOB 形式写入 name 列（与真实库一致：typeof(name)='blob'）
	tuTu := []byte{0xcd, 0xc3, 0xcd, 0xc3}                                         // 兔兔
	duNai := []byte{0xb6, 0xbe, 0xc4, 0xcc}                                        // 毒奶
	catPunch := []byte{0xc3, 0xa8, 0xc3, 0xa8, 0xc8, 0xad, 0xb4, 0xf2, 0xc4, 0xe3} // 猫猫拳打你

	if _, err := game.Exec(`
		CREATE TABLE accounts (
			account_id    INTEGER PRIMARY KEY AUTOINCREMENT,
			m_id          TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE characters (
			character_id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id   INTEGER NOT NULL,
			name         TEXT NOT NULL,
			level        INTEGER NOT NULL DEFAULT 1,
			job          INTEGER NOT NULL DEFAULT 0,
			grow_type    INTEGER NOT NULL DEFAULT 0,
			exp          INTEGER NOT NULL DEFAULT 0,
			delete_flag  INTEGER NOT NULL DEFAULT 0,
			updated_at   TEXT
		);
		INSERT INTO accounts(account_id, m_id) VALUES (1, '10038'), (2, '2030'), (3, '99999');`); err != nil {
		game.Close()
		t.Fatalf("建测试游戏库 schema 失败: %v", err)
	}

	// grow_type 是转职/觉醒编码，JobDisplayName 靠它解出「剑魂」这类中文职业名。
	// 500 = job5（神枪手女）first=2 second=2 → 绯红玫瑰；600 = job0 未转职 → 鬼剑士（男）。
	insert := `INSERT INTO characters(character_id, account_id, name, level, job, grow_type, exp, delete_flag, updated_at)
	           VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`
	rows := []struct {
		cid      int
		acc      int
		name     []byte
		level    int
		job      int
		growType int
		del      int
		update   string
	}{
		{500, 1, tuTu, 86, 5, 0x22, 0, "2026-09-24 01:24:59"},
		{501, 1, duNai, 70, 4, 0, 0, "2026-09-20 10:00:00"},
		{502, 1, catPunch, 40, 1, 0, 1, "2026-09-25 23:59:59"}, // 已删除，且时间最新
		{600, 2, []byte("Msp"), 86, 0, 0, 0, "2026-09-24 01:24:36"},
	}
	for _, r := range rows {
		if _, err := game.Exec(insert, r.cid, r.acc, r.name, r.level, r.job, r.growType, r.del, r.update); err != nil {
			game.Close()
			t.Fatalf("插入测试角色失败: %v", err)
		}
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
	return db
}

// TestGetCurrentRolesByMIds 当前角色必须是「updated_at 最新且未删除」的那个。
//
// 反例（这条测试存在的理由）：若漏了 delete_flag 过滤，已删角色 502 的
// updated_at 是全场最新，会被误当成当前角色；若按 character_id 取最大也会取到 502。
func TestGetCurrentRolesByMIds(t *testing.T) {
	db := newOnlineTestDB(t)

	got, err := db.GetCurrentRolesByMIds([]string{"10038", "2030", "99999", "不存在的号", "10038"})
	if err != nil {
		t.Fatalf("GetCurrentRolesByMIds 失败: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("应只有 10038 / 2030 有角色，实得 %d 个: %v", len(got), got)
	}

	a, ok := got["10038"]
	if !ok {
		t.Fatal("缺少 m_id=10038 的结果")
	}
	if a.CharacterId != 500 {
		t.Errorf("10038 的当前角色应为 500（updated_at 最新的存活角色），实得 %d", a.CharacterId)
	}
	if a.Name != "兔兔" {
		t.Errorf("GBK 角色名解码失败: got %q, want 兔兔", a.Name)
	}
	if a.Level != 86 || a.Job != 5 {
		t.Errorf("等级/职业不符: level=%d job=%d", a.Level, a.Job)
	}
	if a.LastActiveAt != "2026-09-24 01:24:59" {
		t.Errorf("LastActiveAt 不符: %q", a.LastActiveAt)
	}
	if a.RoleCount != 2 {
		t.Errorf("10038 存活角色数应为 2（502 已删除不计），实得 %d", a.RoleCount)
	}

	b, ok := got["2030"]
	if !ok {
		t.Fatal("缺少 m_id=2030 的结果")
	}
	if b.CharacterId != 600 || b.Name != "Msp" || b.RoleCount != 1 {
		t.Errorf("2030 结果不符: %+v", b)
	}

	if _, exists := got["99999"]; exists {
		t.Error("无角色的账号不应出现在结果里")
	}
}

// TestGetCurrentRolesByMIdsEmptyInput 空输入必须安全返回空表，不报错、不查库。
func TestGetCurrentRolesByMIdsEmptyInput(t *testing.T) {
	db := newOnlineTestDB(t)
	for _, in := range [][]string{nil, {}, {""}, {"", ""}} {
		got, err := db.GetCurrentRolesByMIds(in)
		if err != nil {
			t.Fatalf("输入 %v 不应报错: %v", in, err)
		}
		if len(got) != 0 {
			t.Fatalf("输入 %v 应返回空表，实得 %v", in, got)
		}
	}
}

// TestGetMIdsByNames 账号名 → m_id 的批量映射；查不到的账号**不出现**在结果里。
func TestGetMIdsByNames(t *testing.T) {
	db := newOnlineTestDB(t)

	if err := db.InsertAccount(&Account{
		MId: "10038", Name: "msp", PwdHash: "h", Salt: "",
		CreatedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("插入网关账号失败: %v", err)
	}
	if err := db.InsertAccount(&Account{
		MId: "2030", Name: "阿亮", PwdHash: "h", Salt: "",
		CreatedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("插入网关账号失败: %v", err)
	}

	got, err := db.GetMIdsByNames([]string{"msp", "阿亮", "查无此人", "msp", ""})
	if err != nil {
		t.Fatalf("GetMIdsByNames 失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应映射到 2 个账号，实得 %d 个: %v", len(got), got)
	}
	if got["msp"] != "10038" || got["阿亮"] != "2030" {
		t.Fatalf("映射结果不符: %v", got)
	}
	if _, ok := got["查无此人"]; ok {
		t.Error("不存在的账号不应出现在结果里")
	}
}

// TestCurrentRoleName 按账号名解析「当前角色名」——外挂检测上报落库时补角色名走的就是它。
//
// 三条必须钉死的口径：
//  1. 账号名 → m_id 这一步走**网关库**（游戏库角色是按 m_id 关联的），跨库不能一条 SQL 搞定；
//  2. 取的是 updated_at 最新**且未删除**的角色，与在线角色接口同口径；
//  3. 查不到时返回**空串**，绝不能回退成账号名 —— 后台「角色」列要靠「空」识别「未知」，
//     填账号名会同时毁掉这一列的区分能力、并掩盖「解析失败」这个事实。
func TestCurrentRoleName(t *testing.T) {
	db := newOnlineTestDB(t)

	if err := db.InsertAccount(&Account{
		MId: "10038", Name: "msp", PwdHash: "h", Salt: "",
		CreatedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("插入网关账号失败: %v", err)
	}

	// 10038 名下有两个存活角色：500「兔兔」(updated_at 最新)、501「毒奶」(较早)，
	// 外加 502「猫猫拳打你」已删除且 updated_at 全场最新。
	if got := db.CurrentRoleName("msp"); got != "兔兔" {
		t.Errorf("msp 的当前角色应为 兔兔（updated_at 最新的存活角色），实得 %q", got)
	}

	// 账号不存在 / 无角色 / 空输入：一律空串
	for _, in := range []string{"2030", "99999", "查无此人", "", "   "} {
		if got := db.CurrentRoleName(in); got != "" {
			t.Errorf("输入 %q 应得空串（不得回退成账号名），实得 %q", in, got)
		}
	}
}

// TestListAccountsOrderedByCreatedAt 账号列表按注册时间正序（老账号在前），
// 且必须把 created_at 带出来给前端显示。
func TestListAccountsOrderedByCreatedAt(t *testing.T) {
	db := newOnlineTestDB(t)

	seed := []struct {
		mId     string
		name    string
		created int64
	}{
		{"3003", "zzz_late", 3000},
		{"1001", "aaa_early", 1000},
		{"2002", "mmm_mid", 2000},
	}
	for _, s := range seed {
		if err := db.InsertAccount(&Account{
			MId: s.mId, Name: s.name, PwdHash: "h", Salt: "", CreatedAt: s.created,
		}); err != nil {
			t.Fatalf("插入账号失败: %v", err)
		}
	}

	total, accounts, err := db.ListAccounts("", 1, 50)
	if err != nil {
		t.Fatalf("ListAccounts 失败: %v", err)
	}
	if total != 3 {
		t.Fatalf("账号总数应为 3，实得 %d", total)
	}

	wantOrder := []string{"aaa_early", "mmm_mid", "zzz_late"}
	for i, want := range wantOrder {
		if accounts[i].Name != want {
			t.Fatalf("第 %d 位应为 %s（注册时间正序），实得 %s —— 顺序: %v",
				i, want, accounts[i].Name, []string{accounts[0].Name, accounts[1].Name, accounts[2].Name})
		}
	}
	// created_at 必须真的带出来，否则前端「注册时间」列永远显示 "-"
	if accounts[0].CreatedAt != 1000 {
		t.Errorf("CreatedAt 未带出: got %d, want 1000", accounts[0].CreatedAt)
	}
}

// TestGetRolesByAccountDecodesGBK 管理后台「查角色」走的这条路径必须解出中文。
//
// 这条是真实用户报障的回归：后台角色名显示成「????」，根因是
// characters.name 存 GBK 裸字节而网关按 UTF-8 读。
func TestGetRolesByAccountDecodesGBK(t *testing.T) {
	db := newOnlineTestDB(t)
	if err := db.InsertAccount(&Account{
		MId: "10038", Name: "msp", PwdHash: "h", Salt: "", CreatedAt: 1,
	}); err != nil {
		t.Fatalf("插入网关账号失败: %v", err)
	}

	roles, err := db.GetRolesByAccount("msp")
	if err != nil {
		t.Fatalf("GetRolesByAccount 失败: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("应有 2 个存活角色，实得 %d: %+v", len(roles), roles)
	}

	// 按 character_id 升序（查询里有 ORDER BY），500 在前
	if roles[0].CharacterId != 500 || roles[1].CharacterId != 501 {
		t.Fatalf("应按 character_id 升序: %+v", roles)
	}
	if roles[0].Name != "兔兔" {
		t.Errorf("角色 500 名应为「兔兔」，实得 %q（GBK 解码没生效）", roles[0].Name)
	}
	if roles[1].Name != "毒奶" {
		t.Errorf("角色 501 名应为「毒奶」，实得 %q", roles[1].Name)
	}
	for _, r := range roles {
		if strings.ContainsRune(r.Name, '\uFFFD') {
			t.Errorf("角色名含替换字符 U+FFFD，说明仍在按 UTF-8 读 GBK 字节: %q", r.Name)
		}
	}
}

// TestListBackupsStructured 备份列表必须带大小/时间，且覆盖 .pvf。
//
// 历史缺陷：返回裸路径 + 只认 .db/.sqlite/.bak → 管理后台「大小/时间」两列永远是 "-"，
// 而且刚备份成功的 Script-*.pvf 根本不显示（看起来像"备份没成功"）。
func TestListBackupsStructured(t *testing.T) {
	dir := t.TempDir()

	mk := func(name string, size int, age time.Duration) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatalf("造文件失败: %v", err)
		}
		mod := time.Now().Add(-age)
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatalf("改时间失败: %v", err)
		}
	}

	mk("inventory-20260924-020713.db", 2048, 3*time.Hour)    // 旧
	mk("Script-20260924-020713.pvf", 1024*1024, 3*time.Hour) // PVF，同批
	mk("gateway-20260924-023000.db", 512, 0)                 // 最新
	mk("notes.txt", 10, 0)                                   // 不该出现
	mk(".hidden.db", 10, 0)                                  // 隐藏文件不该出现

	got, err := ListBackups(dir)
	if err != nil {
		t.Fatalf("ListBackups 失败: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("应列出 3 个备份（.db ×2 + .pvf ×1），实得 %d: %+v", len(got), got)
	}

	// 最新在前
	if got[0].Name != "gateway-20260924-023000.db" {
		t.Errorf("应按修改时间倒序，首个为 gateway-*.db，实得 %s", got[0].Name)
	}

	var pvf *BackupFile
	for i := range got {
		if filepath.Ext(got[i].Name) == ".pvf" {
			pvf = &got[i]
		}
	}
	if pvf == nil {
		t.Fatal(".pvf 未被列出 —— 管理后台会看不到 PVF 备份")
	}
	if pvf.Size != 1024*1024 {
		t.Errorf("PVF 大小不符: got %d", pvf.Size)
	}
	if pvf.ModifiedAt <= 0 {
		t.Error("ModifiedAt 未填充，前端「时间」列会显示 '-'")
	}
	if pvf.Path != filepath.Join(dir, pvf.Name) {
		t.Errorf("Path 应为完整路径: %q", pvf.Path)
	}
}
