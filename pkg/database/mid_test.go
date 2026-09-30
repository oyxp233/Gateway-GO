package database

import (
	"fmt"
	"sync"
	"testing"
)

// resetMIdIssued 清空进程内"已分配号"表。
//
// mIdIssued 是包级全局（同一进程里所有 Database 实例共用），用例之间会互相污染：
// 上一个用例分配掉的号会在下一个用例里被跳过，断言随执行顺序漂移。
func resetMIdIssued(t *testing.T) {
	t.Helper()
	mIdAllocMu.Lock()
	mIdIssued = map[string]bool{}
	mIdAllocMu.Unlock()
}

func TestIsNumericMId(t *testing.T) {
	cases := map[string]bool{
		"10038":                     true,  // 服务端 DefaultLoginMid 口径
		"100":                       true,  // 3 位下限
		"999999999":                 true,  // 9 位
		"1000000000":                true,  // 10 位
		"10000000000":               false, // 11 位，超长
		"1":                         false, // 太短
		"":                          false,
		"743c14ecd2888d4ad56ac85fe": false, // 64hex
		"invalid_id":                false,
		"12a45":                     false,
		"-10001":                    false,
		" 10038":                    false, // 带空格不合法（调用方先 TrimSpace）
	}
	for in, want := range cases {
		if got := IsNumericMId(in); got != want {
			t.Errorf("IsNumericMId(%q) = %v, want %v", in, got, want)
		}
	}
}

// 账号名本身是数字时优先复用 —— 与原 .NET 网关「{m_id} 填账号名」的口径一致。
func TestAllocateNumericMIdReusesNumericAccountName(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	mId, err := db.AllocateNumericMId("10038")
	if err != nil {
		t.Fatalf("分配失败: %v", err)
	}
	if mId != "10038" {
		t.Fatalf("期望复用账号名 10038，实际 %s", mId)
	}
}

// 游戏库已占用的号必须绕开：撞号会把两个玩家的角色/点券并到一起。
func TestAllocateNumericMIdSkipsGameDbOccupied(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)
	seedGameAccountByMId(t, db, "10001")

	mId, err := db.AllocateNumericMId("msp")
	if err != nil {
		t.Fatalf("分配失败: %v", err)
	}
	if mId != "10002" {
		t.Fatalf("期望绕开游戏库已占用的 10001 得到 10002，实际 %s", mId)
	}
}

// 网关库占用的号同样绕开。
func TestAllocateNumericMIdSkipsGatewayDbOccupied(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)
	if err := db.InsertAccount(&Account{
		MId: "10001", Name: "taken", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}

	mId, err := db.AllocateNumericMId("msp")
	if err != nil {
		t.Fatalf("分配失败: %v", err)
	}
	if mId != "10002" {
		t.Fatalf("期望绕开已占用的 10001 得到 10002，实际 %s", mId)
	}
}

// 非数字账号名走递增取号，且从下限起步。
func TestAllocateNumericMIdIncrementsFromLowerBound(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	first, err := db.AllocateNumericMId("msp")
	if err != nil {
		t.Fatalf("分配失败: %v", err)
	}
	if first != "10001" {
		t.Fatalf("首个数字 m_id 期望 10001，实际 %s", first)
	}
	second, err := db.AllocateNumericMId("kanna")
	if err != nil {
		t.Fatalf("分配失败: %v", err)
	}
	if second == first {
		t.Fatalf("两次分配返回同一个号: %s", second)
	}
}

// ★ 并发注册不能拿到重复号。
//
// 分配与 INSERT 之间存在窗口（AllocateNumericMId 不落库），只靠"查库判重"会撞车；
// mIdIssued 进程内登记就是为堵这个洞。
func TestAllocateNumericMIdUniqueUnderConcurrency(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	const n = 50
	var wg sync.WaitGroup
	results := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mId, err := db.AllocateNumericMId(fmt.Sprintf("user%02d", i))
			if err != nil {
				return
			}
			results[i] = mId
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for i, m := range results {
		if m == "" {
			t.Fatalf("第 %d 个分配失败", i)
		}
		if !IsNumericMId(m) {
			t.Fatalf("分配出非数字 m_id: %q", m)
		}
		if seen[m] {
			t.Fatalf("并发分配出重复号: %s", m)
		}
		seen[m] = true
	}
}

// dry-run 必须一个字节都不改。
func TestMigrateLegacyNumericMIdsDryRunKeepsData(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	const legacy = "743c14ecd2888d4ad56ac85febf1a9154a4a235800d0e8cff37789283fd4d4ee"
	if err := db.InsertAccount(&Account{
		MId: legacy, Name: "msp", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
	if err := db.InsertDeviceHistory(legacy, "secret", "127.0.0.1"); err != nil {
		t.Fatalf("插入设备历史失败: %v", err)
	}
	seedGameAccountByMId(t, db, "invalid_id", "12123")

	plan, err := db.MigrateLegacyNumericMIds(true, "msp")
	if err != nil {
		t.Fatalf("dry-run 失败: %v", err)
	}
	if len(plan.Migrations) != 1 || plan.Migrations[0].Account != "msp" {
		t.Fatalf("迁移计划不符: %+v", plan.Migrations)
	}
	if !IsNumericMId(plan.Migrations[0].NewMId) {
		t.Fatalf("计划里的新 m_id 不是数字: %s", plan.Migrations[0].NewMId)
	}
	if plan.GameInvalidNew != plan.Migrations[0].NewMId {
		t.Fatalf("幽灵行归属号应与 msp 的新号一致，得到 %s", plan.GameInvalidNew)
	}
	if plan.GameInvalidRows != 1 {
		t.Fatalf("dry-run 也应预告幽灵行行数，得到 %d", plan.GameInvalidRows)
	}

	// 关键断言：库里的数据没被动过
	acc, err := db.GetAccountByName("msp")
	if err != nil || acc == nil {
		t.Fatalf("读取账号失败: %v", err)
	}
	if acc.MId != legacy {
		t.Fatalf("dry-run 改了网关库 m_id: %s", acc.MId)
	}
	var stillInvalid int
	if err := db.gameDB.QueryRow(
		"SELECT COUNT(*) FROM accounts WHERE m_id = 'invalid_id'").Scan(&stillInvalid); err != nil {
		t.Fatalf("查询游戏库失败: %v", err)
	}
	if stillInvalid != 1 {
		t.Fatalf("dry-run 动了游戏库幽灵行")
	}
}

// apply：网关库 m_id、device_history、游戏库幽灵行三处一起改，角色归位。
func TestMigrateLegacyNumericMIdsApplies(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	const legacy = "743c14ecd2888d4ad56ac85febf1a9154a4a235800d0e8cff37789283fd4d4ee"
	if err := db.InsertAccount(&Account{
		MId: legacy, Name: "msp", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
	if err := db.InsertDeviceHistory(legacy, "secret", "127.0.0.1"); err != nil {
		t.Fatalf("插入设备历史失败: %v", err)
	}
	seedGameAccountByMId(t, db, "invalid_id", "12123")

	plan, err := db.MigrateLegacyNumericMIds(false, "msp")
	if err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	newMId := plan.Migrations[0].NewMId

	acc, err := db.GetAccountByName("msp")
	if err != nil || acc == nil {
		t.Fatalf("读取账号失败: %v", err)
	}
	if acc.MId != newMId {
		t.Fatalf("网关库 m_id 未更新: %s", acc.MId)
	}

	// device_history 必须跟着改（按 m_id 关联，漏改会静默失联）
	var oldHist, newHist int
	if err := db.gatewayDB.QueryRow(
		"SELECT COUNT(*) FROM device_history WHERE m_id = ?", legacy).Scan(&oldHist); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if err := db.gatewayDB.QueryRow(
		"SELECT COUNT(*) FROM device_history WHERE m_id = ?", newMId).Scan(&newHist); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if oldHist != 0 || newHist != 1 {
		t.Fatalf("device_history 未随 m_id 迁移: old=%d new=%d", oldHist, newHist)
	}

	// 游戏库幽灵行改挂，account_id 不变 → 角色仍在同一个 account_id 下
	var accId int64
	if err := db.gameDB.QueryRow(
		"SELECT account_id FROM accounts WHERE m_id = ?", newMId).Scan(&accId); err != nil {
		t.Fatalf("游戏库幽灵行未改挂: %v", err)
	}
	var chars int
	if err := db.gameDB.QueryRow(
		"SELECT COUNT(*) FROM characters WHERE account_id = ? AND delete_flag = 0", accId).Scan(&chars); err != nil {
		t.Fatalf("查询角色失败: %v", err)
	}
	if chars != 1 {
		t.Fatalf("角色未随幽灵行归位: %d", chars)
	}
	if plan.GameInvalidRows != 1 {
		t.Fatalf("GameInvalidRows 期望 1，实际 %d", plan.GameInvalidRows)
	}
}

// 影子账号（name == m_id 且非数字，SyncGameAccounts 同步产物）不参与迁移，只点名。
func TestMigrateLegacyNumericMIdsSkipsShadowAccount(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	if err := db.InsertAccount(&Account{
		MId: "invalid_id", Name: "invalid_id", PwdHash: "h", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入影子账号失败: %v", err)
	}
	if err := db.InsertAccount(&Account{
		MId:  "743c14ecd2888d4ad56ac85febf1a9154a4a235800d0e8cff37789283fd4d4ee",
		Name: "msp", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}

	plan, err := db.MigrateLegacyNumericMIds(true, "")
	if err != nil {
		t.Fatalf("dry-run 失败: %v", err)
	}
	if len(plan.Migrations) != 1 || plan.Migrations[0].Account != "msp" {
		t.Fatalf("应只迁移真账号 msp，实际 %+v", plan.Migrations)
	}
	found := false
	for _, s := range plan.ShadowAccounts {
		if s == "invalid_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("影子账号未在报告中点名: %+v", plan.ShadowAccounts)
	}
}

// 全部已是数字 m_id 时，迁移应为空操作。
func TestMigrateLegacyNumericMIdsNoopWhenAllNumeric(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	if err := db.InsertAccount(&Account{
		MId: "10001", Name: "msp", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}

	plan, err := db.MigrateLegacyNumericMIds(false, "")
	if err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if len(plan.Migrations) != 0 {
		t.Fatalf("不该有迁移项: %+v", plan.Migrations)
	}
}

// ★ 幂等：owner 的 m_id 已是数字、但游戏库还留着 invalid_id 幽灵行时，
// 仍要能把幽灵行改挂过去，而不是报错退出（重复部署 / 手工订正后的常见状态）。
func TestMigrateLegacyNumericMIdsIdempotentForNumericOwner(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	if err := db.InsertAccount(&Account{
		MId: "10001", Name: "msp", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
	seedGameAccountByMId(t, db, "invalid_id", "12123")

	plan, err := db.MigrateLegacyNumericMIds(false, "msp")
	if err != nil {
		t.Fatalf("重复迁移不该失败: %v", err)
	}
	if len(plan.Migrations) != 0 {
		t.Fatalf("msp 已是数字，不该有迁移项: %+v", plan.Migrations)
	}
	if plan.GameInvalidNew != "10001" {
		t.Fatalf("应沿用 msp 现有 m_id=10001，实际 %q", plan.GameInvalidNew)
	}
	var accId int64
	if err := db.gameDB.QueryRow(
		"SELECT account_id FROM accounts WHERE m_id = ?", "10001").Scan(&accId); err != nil {
		t.Fatalf("幽灵行未改挂: %v", err)
	}
	var chars int
	if err := db.gameDB.QueryRow(
		"SELECT COUNT(*) FROM characters WHERE account_id = ?", accId).Scan(&chars); err != nil {
		t.Fatalf("查询角色失败: %v", err)
	}
	if chars != 1 {
		t.Fatalf("角色未归位: %d", chars)
	}
}

// owner 名字写错时要报明确错误，不能静默无声。
func TestMigrateLegacyNumericMIdsUnknownOwnerErrors(t *testing.T) {
	db := newDeleteTestDB(t)
	resetMIdIssued(t)

	if err := db.InsertAccount(&Account{
		MId: "10001", Name: "msp", PwdHash: "h", Salt: "s", CreatedAt: NowUnix()}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}

	if _, err := db.MigrateLegacyNumericMIds(true, "nosuchaccount"); err == nil {
		t.Fatal("owner 不存在时应报错")
	}
}
