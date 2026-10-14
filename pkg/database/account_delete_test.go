package database

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// newDeleteTestDB 建一套「网关库 + 游戏库」的临时环境。
//
// 游戏库只建最小 schema，但**关键约束照抄服务端** Sqlite/item_schema.sql：
// characters.account_id 对 accounts(account_id) 是 ON DELETE CASCADE。
// 这正是"有角色的账号拒绝删除"这条保护存在的理由，测试必须能复现该级联。
func newDeleteTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	gamePath := filepath.Join(dir, "inventory.db")

	game, err := openSQLite(gamePath, 5)
	if err != nil {
		t.Fatalf("打开测试游戏库失败: %v", err)
	}
	if _, err := game.Exec(`
		CREATE TABLE accounts (
			account_id    INTEGER PRIMARY KEY AUTOINCREMENT,
			m_id          TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL DEFAULT '',
			cera          INTEGER DEFAULT 0
		);
		CREATE TABLE characters (
			character_id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id   INTEGER NOT NULL,
			name         TEXT NOT NULL,
			job          INTEGER DEFAULT 0,
			level        INTEGER DEFAULT 1,
			delete_flag  INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
		);`); err != nil {
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
	return db
}

// accountMId 生成 seedAccount 使用的 m_id。
//
// ★ 故意让 m_id ≠ name：网关自注册的账号，m_id 是注册时分配的**纯数字**号
// （AllocateNumericMId；2026-09-23 之前是 64 位 hex），与账号名无关。
// 游戏库侧的关联必须走 m_id（见 PreviewAccountDelete 的注释）。
// 这里刻意用 "m"+name 这种非数字形态，模拟**迁移前的老数据**（2026-09-23 之前
// 注册的账号，或从游戏库同步来的账号），迁移路径要能正确处理它们。
// 早期版本的测试把游戏库行的 m_id 写成账号名，正好掩盖了"用 name 当 m_id"的 BUG。
func accountMId(name string) string { return "m" + name }

// seedAccount 造一个测试账号：网关库账号行 + 设备历史 + 封禁 + 审计流水。
func seedAccount(t *testing.T, db *Database, name string) string {
	t.Helper()
	mId := accountMId(name)
	acc := &Account{
		MId: mId, Name: name, PwdHash: "hash", Salt: "salt",
		Cera: 123, CreatedAt: NowUnix(),
	}
	if err := db.InsertAccount(acc); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
	if err := db.InsertDeviceHistory(mId, "secret-1", "127.0.0.1"); err != nil {
		t.Fatalf("插入设备历史失败: %v", err)
	}
	if err := db.InsertDeviceHistory(mId, "secret-2", "127.0.0.2"); err != nil {
		t.Fatalf("插入设备历史失败: %v", err)
	}
	if err := db.BanAccount(name, "测试封禁"); err != nil {
		t.Fatalf("插入封禁记录失败: %v", err)
	}
	if _, err := db.gatewayDB.Exec(`
		INSERT INTO register_bonus_logs (account, reward_type, status, created_at)
		VALUES (?, 'test', 'ok', '2026-09-23 00:00:00')`, name); err != nil {
		t.Fatalf("插入注册奖励流水失败: %v", err)
	}
	if _, err := db.gatewayDB.Exec(`
		INSERT INTO anticheat_detections (rule_name, account, event_timestamp, reported_at)
		VALUES ('test-rule', ?, 1, 1)`, name); err != nil {
		t.Fatalf("插入反作弊记录失败: %v", err)
	}
	// 注册流水（register_logs）：它比其他两类多一层身份 —— 还是**注册限额的计数依据**。
	// 插两条（同账号、不同 IP / 机器码），方便断言"默认保留 / purgeLogs 才清 / 清了就释放配额"。
	if err := db.InsertRegistrationLog(name, mId, "127.0.0.1", "AA:BB:CC:DD:EE:01", NowUnix()); err != nil {
		t.Fatalf("插入注册流水失败: %v", err)
	}
	if err := db.InsertRegistrationLog(name, mId, "127.0.0.2", "AA:BB:CC:DD:EE:02", NowUnix()); err != nil {
		t.Fatalf("插入注册流水失败: %v", err)
	}
	return mId
}

// seedGameAccount 在游戏库建账号行（m_id 取 accountMId，与网关侧一致）；chars 为角色名。
func seedGameAccount(t *testing.T, db *Database, name string, chars ...string) {
	t.Helper()
	seedGameAccountByMId(t, db, accountMId(name), chars...)
}

// seedGameAccountByMId 按指定 m_id 在游戏库建账号行，用于构造"诱饵行"。
func seedGameAccountByMId(t *testing.T, db *Database, mId string, chars ...string) {
	t.Helper()
	res, err := db.gameDB.Exec(
		"INSERT INTO accounts (m_id, password_hash, cera) VALUES (?, 'pwdmd5', 42)", mId)
	if err != nil {
		t.Fatalf("插入游戏库账号失败 (m_id=%s): %v", mId, err)
	}
	accId, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("取游戏库 account_id 失败: %v", err)
	}
	for _, c := range chars {
		if _, err := db.gameDB.Exec(
			"INSERT INTO characters (account_id, name, level) VALUES (?, ?, 1)", accId, c); err != nil {
			t.Fatalf("插入角色失败: %v", err)
		}
	}
}

func gatewayCount(t *testing.T, db *Database, query string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := db.gatewayDB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("查询网关库失败 (%s): %v", query, err)
	}
	return n
}

func gameCount(t *testing.T, db *Database, query string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := db.gameDB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("查询游戏库失败 (%s): %v", query, err)
	}
	return n
}

// 预演：账号不存在 / 账号名为空，都要在**不动任何数据**的前提下报对错误码。
func TestPreviewAccountDelete_ErrorCases(t *testing.T) {
	db := newDeleteTestDB(t)

	if _, err := db.PreviewAccountDelete("  "); !errors.Is(err, ErrAccountDeleteEmpty) {
		t.Fatalf("空账号名应返回 ErrAccountDeleteEmpty，实际: %v", err)
	}
	if _, err := db.PreviewAccountDelete("nobody"); !errors.Is(err, ErrAccountDeleteNotFound) {
		t.Fatalf("不存在的账号应返回 ErrAccountDeleteNotFound，实际: %v", err)
	}
}

// 预演要把"会被波及的数据"如实统计出来，且自身不得写库。
func TestPreviewAccountDelete_CountsWithoutWriting(t *testing.T) {
	db := newDeleteTestDB(t)
	seedAccount(t, db, "tester")
	seedGameAccount(t, db, "tester", "roleA")

	p, err := db.PreviewAccountDelete("tester")
	if err != nil {
		t.Fatalf("预演失败: %v", err)
	}
	if p.Account != "tester" || p.MId != "mtester" {
		t.Fatalf("账号/m_id 不对: %+v", p)
	}
	if p.DeviceHistory != 2 {
		t.Errorf("设备历史应为 2，实际 %d", p.DeviceHistory)
	}
	if !p.Banned {
		t.Errorf("应报告账号处于封禁状态")
	}
	if p.BonusLogs != 1 || p.AntiCheatRows != 1 {
		t.Errorf("审计流水统计不对: 奖励=%d 反作弊=%d", p.BonusLogs, p.AntiCheatRows)
	}
	if !p.GameConfigured || !p.GameAccount {
		t.Errorf("应报告游戏库已配置且存在该账号: %+v", p)
	}
	if p.GameRoles != 1 {
		t.Errorf("应报告 1 个角色，实际 %d", p.GameRoles)
	}
	if p.DeletedGateway || p.DeletedGame || p.PurgedLogs {
		t.Errorf("预演不得带删除回执: %+v", p)
	}

	// 预演是只读的：账号与角色都还在
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM accounts WHERE name='tester'"); n != 1 {
		t.Errorf("预演不应改动网关库，账号数=%d", n)
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM characters"); n != 1 {
		t.Errorf("预演不应改动游戏库，角色数=%d", n)
	}
}

// 无角色的账号：两库都删干净，审计流水按默认保留。
func TestDeleteAccount_RemovesBothSidesAndKeepsAuditByDefault(t *testing.T) {
	db := newDeleteTestDB(t)
	seedAccount(t, db, "tester")
	seedGameAccount(t, db, "tester") // 无角色

	p, err := db.DeleteAccount("tester", false)
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if !p.DeletedGateway || !p.DeletedGame {
		t.Fatalf("两库都应标记已删除: %+v", p)
	}
	if p.PurgedLogs {
		t.Errorf("未要求清流水时 PurgedLogs 应为 false")
	}

	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM accounts WHERE name='tester'"); n != 0 {
		t.Errorf("网关库账号未删净: %d", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM device_history WHERE m_id='mtester'"); n != 0 {
		t.Errorf("设备历史未删净: %d", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM banned_accounts WHERE name='tester'"); n != 0 {
		t.Errorf("封禁记录未删净: %d", n)
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM accounts WHERE m_id=?", accountMId("tester")); n != 0 {
		t.Errorf("游戏库账号未删净: %d", n)
	}
	// 默认保留审计流水：删账号不该顺手抹掉证据
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM register_bonus_logs WHERE account='tester'"); n != 1 {
		t.Errorf("默认应保留注册奖励流水，实际 %d", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM anticheat_detections WHERE account='tester'"); n != 1 {
		t.Errorf("默认应保留反作弊记录，实际 %d", n)
	}
	// 注册流水同样默认保留 —— 所以删号**不返还**该 IP/机器码的当日配额（防刷）
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM register_logs WHERE account='tester'"); n != 2 {
		t.Errorf("默认应保留注册流水，实际 %d", n)
	}
	if p.RegisterRows != 2 {
		t.Errorf("预演应统计到 2 条注册流水，实际 %d", p.RegisterRows)
	}

	// 幂等性：再删一次应报"不存在"，而不是静默成功
	if _, err := db.DeleteAccount("tester", false); !errors.Is(err, ErrAccountDeleteNotFound) {
		t.Errorf("重复删除应返回 ErrAccountDeleteNotFound，实际: %v", err)
	}
}

// purgeLogs=true 时审计流水一并清掉。
func TestDeleteAccount_PurgeLogs(t *testing.T) {
	db := newDeleteTestDB(t)
	seedAccount(t, db, "tester")

	if _, err := db.DeleteAccount("tester", true); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM register_bonus_logs WHERE account='tester'"); n != 0 {
		t.Errorf("要求清流水后仍有 %d 条奖励流水", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM anticheat_detections WHERE account='tester'"); n != 0 {
		t.Errorf("要求清流水后仍有 %d 条反作弊记录", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM register_logs WHERE account='tester'"); n != 0 {
		t.Errorf("要求清流水后仍有 %d 条注册流水", n)
	}
}

// ★ purgeLogs 之所以要和另外两类流水分开说：**它是唯一有"配额副作用"的一类**。
//
// register_logs 同时是注册限额（同 IP 每日 N 个 / 同机器码累计 M 个）的计数依据：
//   - 默认保留 ⇒ 删号不能用来刷配额（"注册→删→再注册"绕不过限额）；
//   - purgeLogs ⇒ 该账号的流水被清 ⇒ **该 IP / 机器码的配额随之回落**，
//     这正是"管理员误伤了共用出口 IP 的正常玩家、要手动放行"的处置手段。
func TestDeleteAccount_PurgeLogsReleasesRegisterQuota(t *testing.T) {
	db := newDeleteTestDB(t)

	seedAccount(t, db, "tester")
	if n, err := db.CountRegistrationsByIPSince("127.0.0.1", 0); err != nil || n != 1 {
		t.Fatalf("前置：127.0.0.1 应有 1 条注册流水，实际 %d (err=%v)", n, err)
	}

	// 默认删号：流水留着 ⇒ 配额不动
	if _, err := db.DeleteAccount("tester", false); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if n, _ := db.CountRegistrationsByIPSince("127.0.0.1", 0); n != 1 {
		t.Errorf("默认保留注册流水 ⇒ 配额不应释放，实际 %d", n)
	}

	// purgeLogs 删号：流水一并清 ⇒ 配额释放
	seedAccount(t, db, "tester2")
	if n, _ := db.CountRegistrationsByIPSince("127.0.0.1", 0); n != 2 {
		t.Fatalf("前置：清过一次后应累计 2 条，实际 %d", n)
	}
	if _, err := db.DeleteAccount("tester2", true); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if n, _ := db.CountRegistrationsByIPSince("127.0.0.1", 0); n != 1 {
		t.Errorf("purgeLogs 后配额应回落，实际 %d", n)
	}
}

// ★ 核心保护：账号还有角色时必须拒绝删除，且一个字节都不写。
//
// 同一用例里顺带证明"这条保护是必要的"：绕过接口直接删游戏库账号行，
// FK 级联会把角色一起带走（character 数从 1 变 0）。
func TestDeleteAccount_RefusesWhenCharactersExist(t *testing.T) {
	db := newDeleteTestDB(t)
	seedAccount(t, db, "tester")
	seedGameAccount(t, db, "tester", "roleA")

	_, err := db.DeleteAccount("tester", true)
	if !errors.Is(err, ErrAccountHasCharacters) {
		t.Fatalf("有角色时应返回 ErrAccountHasCharacters，实际: %v", err)
	}

	// 被拒绝后，两库都必须保持原样
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM accounts WHERE name='tester'"); n != 1 {
		t.Errorf("拒绝删除后网关库账号不应消失，实际 %d", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM device_history WHERE m_id='mtester'"); n != 2 {
		t.Errorf("拒绝删除后设备历史不应被清理，实际 %d", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM register_bonus_logs WHERE account='tester'"); n != 1 {
		t.Errorf("拒绝删除后流水不应被清理，实际 %d", n)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM register_logs WHERE account='tester'"); n != 2 {
		t.Errorf("拒绝删除后注册流水不应被清理，实际 %d", n)
	}
	// 游戏库行挂在 m_id 上（不是账号名）
	if n := gameCount(t, db, "SELECT COUNT(*) FROM accounts WHERE m_id=?", accountMId("tester")); n != 1 {
		t.Errorf("拒绝删除后游戏库账号不应消失，实际 %d", n)
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM characters"); n != 1 {
		t.Errorf("拒绝删除后角色不应消失，实际 %d", n)
	}

	// 证明保护的必要性：绕开接口直接删游戏库账号行，角色会被 FK 级联带走
	if _, err := db.gameDB.Exec("DELETE FROM accounts WHERE m_id = ?", accountMId("tester")); err != nil {
		t.Fatalf("直接删游戏库账号失败（预期级联生效）: %v", err)
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM characters"); n != 0 {
		t.Fatalf("游戏库 characters 应是 ON DELETE CASCADE（角色随账号消失），实际剩 %d 个 —— "+
			"若级联失效，说明测试 schema 与服务端不一致，这条保护的依据需要重新确认", n)
	}
}

// ★ 回归：游戏库侧必须按 m_id 关联，不能用账号名。
//
// 真实场景：网关自注册的账号 m_id 是随机 64 位 hex，与账号名无关（Register 里生成）；
// 只有从游戏库迁移过来的账号才恰好 name == m_id。早期实现把账号名当 m_id 传给游戏库，
// 后果是"有角色就拒绝"这条保护**静默失效**，而且游戏侧账号行也删不掉
// （删完再同步会被重新导回网关库，表现为"删了又回来了"）。
//
// 构造两个游戏库行来区分两种口径：
//   - 诱饵行：m_id 恰好等于账号名，0 个角色
//   - 真实行：m_id = acc.MId，1 个角色
//
// 正确实现看到真实行 -> 1 个角色 -> 拒绝；用错键的实现看到诱饵行 -> 放行（本用例失败）。
func TestPreviewAccountDelete_UsesMIdNotName(t *testing.T) {
	db := newDeleteTestDB(t)
	seedAccount(t, db, "tester")                 // 网关侧 m_id = "mtester"
	seedGameAccountByMId(t, db, "tester")        // 诱饵行（无角色）
	seedGameAccount(t, db, "tester", "realHero") // 真实行（1 个角色）

	p, err := db.PreviewAccountDelete("tester")
	if err != nil {
		t.Fatalf("预演失败: %v", err)
	}
	if p.MId != "mtester" {
		t.Fatalf("预演应回报网关侧 m_id，实际 %q", p.MId)
	}
	if !p.GameAccount {
		t.Errorf("应按 m_id=mtester 命中游戏库账号（命中诱饵行同样算错）: %+v", p)
	}
	if p.GameRoles != 1 {
		t.Errorf("应按 m_id 看到 1 个角色，实际 %d —— 说明关联键不是 m_id", p.GameRoles)
	}

	if _, err := db.DeleteAccount("tester", false); !errors.Is(err, ErrAccountHasCharacters) {
		t.Fatalf("有角色时必须拒绝删除，实际: %v", err)
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM accounts"); n != 2 {
		t.Errorf("拒绝删除后游戏库两行都应还在，实际 %d", n)
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM characters"); n != 1 {
		t.Errorf("拒绝删除后角色应还在，实际 %d", n)
	}
}

// 迁移账号场景：name == m_id，游戏库必须能正常命中并删除。
func TestDeleteAccount_MigratedAccountNameEqualsMId(t *testing.T) {
	db := newDeleteTestDB(t)
	// 模拟 MigrateAccountsFromGameDb 的写法：m_id 与 name 都取游戏库的 m_id
	if err := db.InsertAccount(&Account{
		MId: "legacy001", Name: "legacy001", PwdHash: "h", Salt: "", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入迁移账号失败: %v", err)
	}
	seedGameAccountByMId(t, db, "legacy001")

	p, err := db.PreviewAccountDelete("legacy001")
	if err != nil {
		t.Fatalf("预演失败: %v", err)
	}
	if !p.GameAccount {
		t.Fatalf("迁移账号（name==m_id）应能命中游戏库行: %+v", p)
	}
	if _, err := db.DeleteAccount("legacy001", false); err != nil {
		t.Fatalf("删除迁移账号失败: %v", err)
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM accounts"); n != 0 {
		t.Errorf("游戏库行未删掉，剩 %d", n)
	}
}

// 游戏库未配置时，删除只作用于网关库，且必须成功（不能因为没游戏库就报错）。
func TestDeleteAccount_WithoutGameDB(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDatabase(DatabaseConfig{
		Path: filepath.Join(dir, "gateway.db"), GamePath: "",
		WalMode: true, BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	defer db.Close()
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("初始化 schema 失败: %v", err)
	}
	if err := db.InsertAccount(&Account{
		MId: "m1", Name: "solo", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}

	p, err := db.DeleteAccount("solo", false)
	if err != nil {
		t.Fatalf("游戏库未配置时应能正常删除: %v", err)
	}
	if p.GameConfigured || p.DeletedGame {
		t.Errorf("游戏库未配置时不应标记已删游戏侧: %+v", p)
	}
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM accounts"); n != 0 {
		t.Errorf("账号未删净: %d", n)
	}
}

// 批量场景：几个账号中混入"不存在"和"有角色"，各自独立成败、互不影响。
func TestDeleteAccount_IndependentPerAccount(t *testing.T) {
	db := newDeleteTestDB(t)
	seedAccount(t, db, "clean1")
	seedGameAccount(t, db, "clean1")
	seedAccount(t, db, "hasrole")
	seedGameAccount(t, db, "hasrole", "roleA")
	seedAccount(t, db, "clean2")
	seedGameAccount(t, db, "clean2")

	names := []string{"clean1", "ghost", "hasrole", "clean2"}
	var okNames, refused, notFound []string
	for _, n := range names {
		p, err := db.PreviewAccountDelete(n)
		switch {
		case errors.Is(err, ErrAccountDeleteNotFound):
			notFound = append(notFound, n)
			continue
		case err != nil:
			t.Fatalf("预演 %s 意外失败: %v", n, err)
		}
		if p.GameRoles > 0 {
			refused = append(refused, n)
			continue
		}
		if _, err := db.DeleteAccount(n, false); err != nil {
			t.Fatalf("删除 %s 失败: %v", n, err)
		}
		okNames = append(okNames, n)
	}

	if fmt.Sprint(okNames) != "[clean1 clean2]" {
		t.Errorf("成功集不对: %v", okNames)
	}
	if fmt.Sprint(refused) != "[hasrole]" {
		t.Errorf("拒绝集不对: %v", refused)
	}
	if fmt.Sprint(notFound) != "[ghost]" {
		t.Errorf("不存在集不对: %v", notFound)
	}
	// 被拒绝的账号必须完好
	if n := gatewayCount(t, db, "SELECT COUNT(*) FROM accounts WHERE name='hasrole'"); n != 1 {
		t.Errorf("被拒绝的账号应保留")
	}
	if n := gameCount(t, db, "SELECT COUNT(*) FROM characters"); n != 1 {
		t.Errorf("被拒绝账号的角色应保留，实际 %d", n)
	}
}
