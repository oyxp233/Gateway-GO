package database

// 真实 S5A3 库的冒烟测试（只读，不写）。
//
// 跑法：
//   DNFBRIDGE_REAL_S5A3_DSN='dnf:pass@tcp(127.0.0.1:13306)/dnf_local?...' \
//     go test ./pkg/database/ -run TestZZRealS5A3ReadOnly -v -count=1
//
// 没设环境变量时 Skip —— CI / 没装库的机器上不该因此变红。

import (
	"os"
	"strings"
	"testing"
)

func openRealS5A3(t *testing.T) *Database {
	t.Helper()
	dsn := os.Getenv("DNFBRIDGE_REAL_S5A3_DSN")
	if dsn == "" {
		t.Skip("未设置 DNFBRIDGE_REAL_S5A3_DSN，跳过真实库测试")
	}
	db, err := NewDatabase(DatabaseConfig{
		Path:               t.TempDir() + "/gateway.db",
		GameDSN:            dsn,
		GameTablePrefix:    "dnf",
		GameAccountTable:   "dnf90_web_accounts",
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("建网关库表失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestZZRealS5A3ReadOnly(t *testing.T) {
	db := openRealS5A3(t)
	if got := db.GameBackend(); got != "s5a3" {
		t.Fatalf("GameBackend = %q, want s5a3", got)
	}

	chars, err := db.GetAllAliveCharacters()
	if err != nil {
		t.Fatalf("GetAllAliveCharacters: %v", err)
	}
	t.Logf("角色数 = %d", len(chars))
	for _, c := range chars {
		t.Logf("  id=%d accountId=%d accountKey=%q name=%q level=%d job=%d grow=%d",
			c.CharacterId, c.AccountId, c.AccountKey, c.Name, c.Level, c.Job, c.GrowType)
	}
	if len(chars) == 0 {
		t.Fatal("真实库里应该有角色")
	}

	first := chars[0]
	one, err := db.GetCharacter(first.CharacterId)
	if err != nil || one == nil {
		t.Fatalf("GetCharacter(%d) = %v, %v", first.CharacterId, one, err)
	}
	if one.Name != first.Name {
		t.Fatalf("GetCharacter 名字不一致: %q vs %q", one.Name, first.Name)
	}

	if first.AccountKey != "" {
		acct, err := db.S5A3AccountIDByName("msp")
		if err != nil {
			t.Fatalf("S5A3AccountIDByName: %v", err)
		}
		t.Logf("账号 msp → account_id = %q", acct)

		if acct != "" {
			cera, token, happy, ok := db.GetCurrencyTripleByMId(acct)
			t.Logf("三币种 cera=%d token=%d happy=%d ok=%v", cera, token, happy, ok)
			if !ok {
				t.Fatal("GetCurrencyTripleByMId 应该返回 ok")
			}
			if !db.S5A3AccountExists(acct) {
				t.Log("注意：dnf_accounts 还没有该账号行（玩家未进过游戏）")
			}
		}
	}

	roles, err := db.GetRolesByAccount("msp")
	if err != nil {
		t.Fatalf("GetRolesByAccount: %v", err)
	}
	t.Logf("账号 msp 的角色数 = %d", len(roles))
	for _, r := range roles {
		t.Logf("  id=%d name=%q level=%d job=%d(%s) grow=%d",
			r.CharacterId, r.Name, r.Level, r.Job, r.JobName, r.GrowType)
	}
}

// TestZZRealS5A3SendMailRoundTrip 向**空邮箱的角色**投递一封测试邮件，
// 校验三张表都写对了，然后自己清理干净。
//
// 只在显式设置 DNFBRIDGE_REAL_S5A3_WRITE=1 时跑 —— 默认不动真实数据。
func TestZZRealS5A3SendMailRoundTrip(t *testing.T) {
	if os.Getenv("DNFBRIDGE_REAL_S5A3_WRITE") != "1" {
		t.Skip("未设置 DNFBRIDGE_REAL_S5A3_WRITE=1，跳过写入测试")
	}
	db := openRealS5A3(t)

	// 目标：character_id=4（测试号，邮箱 0 封）
	const charID int64 = 4
	if before, err := db.s5a3ClearMailbox(charID); err == nil {
		t.Logf("清理前置：删掉 %d 封旧邮件", before)
	}

	items := []MailItem{
		{ItemTemplateId: 10000001, Count: 3, Kind: 3, ItemType: 0},
	}
	if err := db.SendMailWithGold(charID, "21331", "网关投递测试", "这是一封自动化测试邮件，收到请忽略。", 1234, items, 24); err != nil {
		t.Fatalf("SendMailWithGold: %v", err)
	}

	// 校验：邮件头 + 附件 + 属性
	var title string
	var gold int64
	var sender string
	if err := db.s5a3DB.QueryRow(
		"SELECT title, gold, sender_name FROM "+db.s5a3Table("mails")+" WHERE character_id = ?",
		"4").Scan(&title, &gold, &sender); err != nil {
		t.Fatalf("读回邮件头失败: %v", err)
	}
	t.Logf("邮件头: title=%q gold=%d sender=%q", title, gold, sender)
	if title != "网关投递测试" || gold != 1234 || sender != "系统" {
		t.Fatalf("邮件头内容不对: title=%q gold=%d sender=%q", title, gold, sender)
	}

	var itemID, itemCount int64
	var rawEntry []byte
	if err := db.s5a3DB.QueryRow(
		"SELECT item_id, item_count, raw_entry FROM "+db.s5a3Table("mail_attachments")+" WHERE character_id = ?",
		"4").Scan(&itemID, &itemCount, &rawEntry); err != nil {
		t.Fatalf("读回附件失败: %v", err)
	}
	t.Logf("附件: item_id=%d count=%d raw_entry_len=%d", itemID, itemCount, len(rawEntry))
	if itemID != 10000001 || itemCount != 3 {
		t.Fatalf("附件内容不对: id=%d count=%d", itemID, itemCount)
	}

	var kindValue string
	if err := db.s5a3DB.QueryRow(
		"SELECT extra_value FROM "+db.s5a3Table("mail_attachment_extra")+" WHERE character_id = ? AND extra_key = 'item_kind'",
		"4").Scan(&kindValue); err != nil {
		t.Fatalf("读回附件属性失败: %v", err)
	}
	t.Logf("item_kind = %q", kindValue)
	if kindValue != "3" {
		t.Fatalf("item_kind 应为 3，实得 %q", kindValue)
	}

	// 清理
	if removed, err := db.s5a3ClearMailbox(charID); err != nil {
		t.Fatalf("清理失败（需要人工删掉 character_id=4 的测试邮件）: %v", err)
	} else {
		t.Logf("清理完成：删掉 %d 封", removed)
	}
}

// TestZZRealS5A3CurrencyRoundTrip 验证点券原子自增/扣减能正确落在
// dnf_account_metadata 的 account_cera 上，并且**加减对称**（净变化 0）。
//
// 只在 DNFBRIDGE_REAL_S5A3_WRITE=1 时跑。
func TestZZRealS5A3CurrencyRoundTrip(t *testing.T) {
	if os.Getenv("DNFBRIDGE_REAL_S5A3_WRITE") != "1" {
		t.Skip("未设置 DNFBRIDGE_REAL_S5A3_WRITE=1，跳过写入测试")
	}
	db := openRealS5A3(t)

	const mId = "dnf:10002"
	before, _, _, ok := db.GetCurrencyTripleByMId(mId)
	if !ok {
		t.Fatalf("读不到 %s 的余额", mId)
	}
	t.Logf("初始 account_cera = %d", before)

	// +7
	if n, err := db.AddCurrencyToGameAccount(mId, "cera", 7); err != nil || n == 0 {
		t.Fatalf("加 7 失败: n=%d err=%v", n, err)
	}
	mid, _, _, _ := db.GetCurrencyTripleByMId(mId)
	t.Logf("加 7 之后 = %d", mid)
	if mid != before+7 {
		t.Fatalf("加 7 结果不对: %d, want %d", mid, before+7)
	}

	// -7（还原）
	if n, err := db.AddCurrencyToGameAccount(mId, "cera", -7); err != nil || n == 0 {
		t.Fatalf("减 7 失败: n=%d err=%v", n, err)
	}
	after, _, _, _ := db.GetCurrencyTripleByMId(mId)
	t.Logf("减 7 之后 = %d", after)
	if after != before {
		t.Fatalf("加减不对称，余额被改坏了: 初始 %d，现在 %d", before, after)
	}

	// 负数保护：扣到 0 以下应钳在 0，然后补回来
	if _, err := db.AddCurrencyToGameAccount(mId, "cera", -(before + 1000)); err != nil {
		t.Fatalf("大额扣减失败: %v", err)
	}
	clamped, _, _, _ := db.GetCurrencyTripleByMId(mId)
	t.Logf("超额扣减后 = %d（应为 0）", clamped)
	if clamped != 0 {
		t.Logf("注意：钳位未生效，余额 = %d", clamped)
	}
	// 还原
	if _, err := db.AddCurrencyToGameAccount(mId, "cera", before); err != nil {
		t.Fatalf("还原失败: %v", err)
	}
	final, _, _, _ := db.GetCurrencyTripleByMId(mId)
	t.Logf("还原后 = %d（初始 %d）", final, before)
	if final != before {
		t.Fatalf("还原失败，余额现在是 %d，应为 %d", final, before)
	}
}

// TestZZRealS5A3ListAccounts 验证后台「账号管理」的数据源在 S5A3 下能列出账号。
func TestZZRealS5A3ListAccounts(t *testing.T) {
	db := openRealS5A3(t)
	total, list, err := db.ListAccounts("", 1, 50)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	t.Logf("账号总数 = %d，本页 %d 条", total, len(list))
	for _, a := range list {
		t.Logf("  mId=%q name=%q cera=%d created=%d gameCreated=%q lastIP=%q",
			a.MId, a.Name, a.Cera, a.CreatedAt, a.GameCreatedAt, a.LastLoginIP)
	}
	if total == 0 {
		t.Fatal("S5A3 库里有 3 个账号，ListAccounts 不该返回 0")
	}

	// 按角色名搜
	hit, err := db.SearchAccountMIdsByRole("烦烦烦")
	if err != nil {
		t.Fatalf("SearchAccountMIdsByRole: %v", err)
	}
	t.Logf("角色名「烦烦烦」命中账号: %v", hit)
	if len(hit) == 0 {
		t.Fatal("应该命中 dnf:10002")
	}
}

// TestZZRealS5A3PasswordRoundTrip 验证改密链路：
// 写 bcrypt → 用新密码验过、旧密码验不过 → 再改回原密码。
//
// ★ 会临时改真实账号的密码，跑完必须还原。只在
//   DNFBRIDGE_REAL_S5A3_WRITE=1 且显式给了测试账号时执行。
func TestZZRealS5A3PasswordRoundTrip(t *testing.T) {
	if os.Getenv("DNFBRIDGE_REAL_S5A3_WRITE") != "1" {
		t.Skip("未设置 DNFBRIDGE_REAL_S5A3_WRITE=1，跳过写入测试")
	}
	account := os.Getenv("DNFBRIDGE_REAL_S5A3_PWD_ACCOUNT")
	oldPwd := os.Getenv("DNFBRIDGE_REAL_S5A3_PWD_OLD")
	if account == "" || oldPwd == "" {
		t.Skip("未设置 DNFBRIDGE_REAL_S5A3_PWD_ACCOUNT / _PWD_OLD，跳过改密测试（会改动真实密码）")
	}
	db := openRealS5A3(t)

	// 先确认原密码是对的（否则后面的"改回"会写错）
	ok, exists, err := db.S5A3VerifyPassword(account, oldPwd)
	if err != nil {
		t.Fatalf("校验原密码出错: %v", err)
	}
	if !exists {
		t.Fatalf("S5A3 库中没有账号 %q", account)
	}
	if !ok {
		t.Fatalf("账号 %q 的原密码与给定值不符，为安全起见中止", account)
	}

	const tmpPwd = "tmp-test-pwd-9f3a"
	if hit, err := db.S5A3ChangePassword(account, tmpPwd); err != nil || !hit {
		t.Fatalf("改密失败: hit=%v err=%v", hit, err)
	}
	t.Cleanup(func() {
		if hit, err := db.S5A3ChangePassword(account, oldPwd); err != nil || !hit {
			t.Errorf("★ 还原密码失败，请手工把 %q 的密码改回原值: hit=%v err=%v", account, hit, err)
		} else {
			t.Logf("已还原 %q 的密码", account)
		}
	})

	// 新密码应通过、旧密码应失败
	if ok, _, err := db.S5A3VerifyPassword(account, tmpPwd); err != nil || !ok {
		t.Fatalf("新密码校验失败: ok=%v err=%v", ok, err)
	}
	if ok, _, err := db.S5A3VerifyPassword(account, oldPwd); err != nil || ok {
		t.Fatalf("旧密码不该再通过: ok=%v err=%v", ok, err)
	}
	t.Log("改密链路正确：新密码通过、旧密码失效")
}

// TestZZRealS5A3PasswordValidation 只测校验规则（不写库）。
func TestZZRealS5A3PasswordValidation(t *testing.T) {
	cases := []struct {
		pwd string
		ok  bool
	}{
		{"", false},
		{"12345", false},   // 5 位，太短
		{"123456", true},   // 6 位，边界通过
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false}, // 太长
	}
	for _, c := range cases {
		err := ValidateS5A3Password(c.pwd)
		if (err == nil) != c.ok {
			t.Errorf("ValidateS5A3Password(len=%d) = %v, want ok=%v", len(c.pwd), err, c.ok)
		}
	}
}

// TestZZRealS5A3PasswordChain 用**备份/还原哈希**的方式验证改密链路，
// 不需要知道账号原密码。
//
// 流程：读出 msp 的 password_hash → 改成临时密码 → 用临时密码验过、
// 用任意错误密码验不过 → 把原哈希写回去（t.Cleanup 保证一定还原）。
func TestZZRealS5A3PasswordChain(t *testing.T) {
	if os.Getenv("DNFBRIDGE_REAL_S5A3_WRITE") != "1" {
		t.Skip("未设置 DNFBRIDGE_REAL_S5A3_WRITE=1，跳过写入测试")
	}
	db := openRealS5A3(t)
	const account = "msp"

	ctx, cancel := db.s5a3Ctx()
	defer cancel()

	var original string
	if err := db.s5a3DB.QueryRowContext(ctx,
		"SELECT password_hash FROM "+db.s5a3AccountTable()+" WHERE account = ?", account).Scan(&original); err != nil {
		t.Fatalf("读原哈希失败: %v", err)
	}
	if len(original) < 20 {
		t.Fatalf("原哈希异常: %q", original)
	}
	t.Logf("原哈希: %s…", original[:20])

	t.Cleanup(func() {
		c, cancel := db.s5a3Ctx()
		defer cancel()
		if _, err := db.s5a3DB.ExecContext(c,
			"UPDATE "+db.s5a3AccountTable()+" SET password_hash = ? WHERE account = ?", original, account); err != nil {
			t.Errorf("★ 还原哈希失败，请手工恢复 msp 的 password_hash: %v", err)
		} else {
			t.Log("已还原原哈希")
		}
	})

	const tmpPwd = "tmp-probe-7c2e"
	hit, err := db.S5A3ChangePassword(account, tmpPwd)
	if err != nil || !hit {
		t.Fatalf("改密失败: hit=%v err=%v", hit, err)
	}

	if ok, exists, err := db.S5A3VerifyPassword(account, tmpPwd); err != nil || !ok || !exists {
		t.Fatalf("新密码应通过: ok=%v exists=%v err=%v", ok, exists, err)
	}
	if ok, _, err := db.S5A3VerifyPassword(account, "definitely-wrong"); err != nil || ok {
		t.Fatalf("错误密码不该通过: ok=%v err=%v", ok, err)
	}
	// 不存在的账号：exists 必须为 false
	if ok, exists, err := db.S5A3VerifyPassword("no-such-account-zzz", "x"); err != nil || ok || exists {
		t.Fatalf("不存在的账号: ok=%v exists=%v err=%v", ok, exists, err)
	}
	t.Log("改密链路正确：新密码通过、错误密码拒绝、不存在账号区分正确")
}

// TestZZRealS5A3AccountMirror 验证账号身份镜像同步（只写网关库 SQLite）。
func TestZZRealS5A3AccountMirror(t *testing.T) {
	db := openRealS5A3(t)

	result, err := db.SyncS5A3AccountMirrors()
	if err != nil {
		t.Fatalf("SyncS5A3AccountMirrors: %v", err)
	}
	t.Logf("同步结果: total=%d created=%d existing=%d conflicts=%v failed=%v",
		result.Total, result.Created, result.Existing, result.Conflicts, result.Failed)
	if result.Total == 0 {
		t.Fatal("S5A3 库里有账号，Total 不该是 0")
	}

	// 幂等：再跑一次应该全部落到 existing
	second, err := db.SyncS5A3AccountMirrors()
	if err != nil {
		t.Fatalf("第二次同步: %v", err)
	}
	t.Logf("第二次: created=%d existing=%d", second.Created, second.Existing)
	if second.Created != 0 {
		t.Fatalf("幂等性破坏：第二次还新建了 %d 行", second.Created)
	}

	// 镜像行的密码必须为空（不能成为绕过服务端的登录路径）
	var pwdHash, salt string
	if err := db.gatewayDB.QueryRow(
		"SELECT pwd_hash, salt FROM accounts WHERE m_id = ?", "dnf:10002").Scan(&pwdHash, &salt); err != nil {
		t.Fatalf("读镜像行失败: %v", err)
	}
	t.Logf("镜像行: pwd_hash=%q salt=%q", pwdHash, salt)
	if pwdHash != "" || salt != "" {
		t.Fatal("镜像行的密码/盐必须为空 —— 否则网关多出一条能验密的路径")
	}
}
