package database

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func newQQBindTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		BusyTimeoutSeconds: 5,
		WalMode:            true,
	})
	if err != nil {
		t.Fatalf("建测试库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	return db
}

// TestSchemaHasQQBindTables 断言两张新表真的建出来了。
// 部署后"表不存在"是这类改动最典型的翻车方式（老库没跑迁移），
// 所以先在单测里锁住。
func TestSchemaHasQQBindTables(t *testing.T) {
	db := newQQBindTestDB(t)

	for _, table := range []string{"qq_bindings", "email_verify_codes"} {
		rows, err := db.gatewayDB.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Fatalf("查表 %s 结构失败: %v", table, err)
		}
		n := 0
		for rows.Next() {
			n++
		}
		rows.Close()
		if n == 0 {
			t.Fatalf("表 %s 不存在或没有列", table)
		}
	}
}

func TestBindQQAndLookup(t *testing.T) {
	db := newQQBindTestDB(t)

	if err := db.BindQQ("2805420962", "alice", "10.0.0.1"); err != nil {
		t.Fatalf("绑定失败: %v", err)
	}

	b, err := db.GetQQBindingByAccount("alice")
	if err != nil {
		t.Fatalf("按账号查绑定失败: %v", err)
	}
	if b.QQNumber != "2805420962" || b.Account != "alice" || b.BoundIP != "10.0.0.1" {
		t.Fatalf("绑定内容不对: %+v", b)
	}
	if b.BoundAt <= 0 {
		t.Fatalf("bound_at 未写入: %d", b.BoundAt)
	}

	account, err := db.GetAccountByQQNumber("2805420962")
	if err != nil {
		t.Fatalf("按 QQ 号查账号失败: %v", err)
	}
	if account != "alice" {
		t.Fatalf("按 QQ 号查账号 = %q，期望 alice", account)
	}

	if n, err := db.CountQQBindings(); err != nil || n != 1 {
		t.Fatalf("绑定总数 = %d (err=%v)，期望 1", n, err)
	}
}

func TestGetAccountByQQNumberEmptyWhenMissing(t *testing.T) {
	db := newQQBindTestDB(t)

	// 没绑过 = 返回空串 + 无错误。"没有"不是错误。
	account, err := db.GetAccountByQQNumber("9999999")
	if err != nil {
		t.Fatalf("查不存在的 QQ 号不该报错: %v", err)
	}
	if account != "" {
		t.Fatalf("查不存在的 QQ 号应返回空串，实得 %q", account)
	}
	if account, err := db.GetAccountByQQNumber("  "); err != nil || account != "" {
		t.Fatalf("空输入应返回空串且无错误，实得 %q err=%v", account, err)
	}
}

func TestGetQQBindingByAccountNotFound(t *testing.T) {
	db := newQQBindTestDB(t)
	if _, err := db.GetQQBindingByAccount("nobody"); !errors.Is(err, ErrQQBindNotFound) {
		t.Fatalf("未绑定的账号应返回 ErrQQBindNotFound，实得 %v", err)
	}
}

// 一个 QQ 号只能绑一个账号。
func TestBindQQRejectsSecondAccountForSameQQ(t *testing.T) {
	db := newQQBindTestDB(t)

	if err := db.BindQQ("10001", "alice", ""); err != nil {
		t.Fatalf("首次绑定失败: %v", err)
	}
	err := db.BindQQ("10001", "bob", "")
	if !errors.Is(err, ErrQQNumberTaken) {
		t.Fatalf("同一 QQ 号绑第二个账号应返回 ErrQQNumberTaken，实得 %v", err)
	}
	// 冲突时不能留下半条数据。
	if n, _ := db.CountQQBindings(); n != 1 {
		t.Fatalf("冲突后绑定总数 = %d，期望 1", n)
	}
	if a, _ := db.GetAccountByQQNumber("10001"); a != "alice" {
		t.Fatalf("冲突后原绑定被改动，实得 %q", a)
	}
}

// 一个账号只能绑一个 QQ 号。
func TestBindQQRejectsSecondQQForSameAccount(t *testing.T) {
	db := newQQBindTestDB(t)

	if err := db.BindQQ("10001", "alice", ""); err != nil {
		t.Fatalf("首次绑定失败: %v", err)
	}
	err := db.BindQQ("10002", "alice", "")
	if !errors.Is(err, ErrQQAlreadyBound) {
		t.Fatalf("同账号绑第二个 QQ 应返回 ErrQQAlreadyBound，实得 %v", err)
	}
	if n, _ := db.CountQQBindings(); n != 1 {
		t.Fatalf("冲突后绑定总数 = %d，期望 1", n)
	}
}

// 重复绑同一对也应当被拒（不是静默成功）：玩家看到的是"你已经绑过这个号了"。
func TestBindQQDuplicateSamePair(t *testing.T) {
	db := newQQBindTestDB(t)

	if err := db.BindQQ("10001", "alice", ""); err != nil {
		t.Fatalf("首次绑定失败: %v", err)
	}
	if err := db.BindQQ("10001", "alice", ""); !errors.Is(err, ErrQQAlreadyBound) {
		t.Fatalf("重复绑同一对应返回 ErrQQAlreadyBound，实得 %v", err)
	}
}

func TestBindQQRejectsEmptyInput(t *testing.T) {
	db := newQQBindTestDB(t)
	if err := db.BindQQ("", "alice", ""); err == nil {
		t.Fatal("空 QQ 号必须被拒")
	}
	if err := db.BindQQ("10001", "  ", ""); err == nil {
		t.Fatal("空账号必须被拒")
	}
}

func TestUnbindQQ(t *testing.T) {
	db := newQQBindTestDB(t)

	if err := db.BindQQ("10001", "alice", ""); err != nil {
		t.Fatalf("绑定失败: %v", err)
	}

	qq, err := db.UnbindQQ("alice")
	if err != nil {
		t.Fatalf("解绑失败: %v", err)
	}
	if qq != "10001" {
		t.Fatalf("解绑应返回原 QQ 号 10001，实得 %q", qq)
	}

	if _, err := db.GetAccountByQQNumber("10001"); err != nil {
		t.Fatalf("解绑后查询出错: %v", err)
	}
	if n, _ := db.CountQQBindings(); n != 0 {
		t.Fatalf("解绑后绑定总数 = %d，期望 0", n)
	}

	// 再解绑一次要报"未绑定"，而不是静默成功。
	if _, err := db.UnbindQQ("alice"); !errors.Is(err, ErrQQBindNotFound) {
		t.Fatalf("重复解绑应返回 ErrQQBindNotFound，实得 %v", err)
	}
}

// 解绑后 QQ 号要能被别的账号重新绑上（不能留唯一索引残留）。
func TestUnbindFreesQQNumber(t *testing.T) {
	db := newQQBindTestDB(t)

	if err := db.BindQQ("10001", "alice", ""); err != nil {
		t.Fatalf("绑定失败: %v", err)
	}
	if _, err := db.UnbindQQ("alice"); err != nil {
		t.Fatalf("解绑失败: %v", err)
	}
	if err := db.BindQQ("10001", "bob", ""); err != nil {
		t.Fatalf("解绑后 QQ 号应可重新绑定，实得 %v", err)
	}
	if a, _ := db.GetAccountByQQNumber("10001"); a != "bob" {
		t.Fatalf("重绑后归属应为 bob，实得 %q", a)
	}
}

func TestQQNumbersByAccountsBatch(t *testing.T) {
	db := newQQBindTestDB(t)

	pairs := map[string]string{"alice": "10001", "bob": "10002", "carol": "10003"}
	for account, qq := range pairs {
		if err := db.BindQQ(qq, account, ""); err != nil {
			t.Fatalf("绑定 %s 失败: %v", account, err)
		}
	}

	got, err := db.QQNumbersByAccounts([]string{"alice", "bob", "carol", "nobody"})
	if err != nil {
		t.Fatalf("批量查询失败: %v", err)
	}
	for account, qq := range pairs {
		if got[account] != qq {
			t.Fatalf("账号 %s 的 QQ 号 = %q，期望 %q", account, got[account], qq)
		}
	}
	// 没绑的账号不该出现在结果里（列表页据此判断要不要渲染第二行）。
	if _, ok := got["nobody"]; ok {
		t.Fatal("未绑定的账号不该出现在批量结果里")
	}

	empty, err := db.QQNumbersByAccounts(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("空输入应返回空 map 且无错误，实得 %v err=%v", empty, err)
	}
}

// 分片边界：SQLite 变量数有上限，超过一片的账号必须全部拿回来（不丢数据）。
func TestQQNumbersByAccountsAcrossChunks(t *testing.T) {
	db := newQQBindTestDB(t)

	const total = 620 // 跨过 500 的分片边界
	tx, err := db.gatewayDB.Begin()
	if err != nil {
		t.Fatalf("开事务失败: %v", err)
	}
	for i := 0; i < total; i++ {
		if _, err := tx.Exec(
			"INSERT INTO qq_bindings (qq_number, account, bound_at, bound_ip) VALUES (?, ?, 1, '')",
			fmt.Sprintf("2%09d", i), fmt.Sprintf("user%04d", i),
		); err != nil {
			tx.Rollback()
			t.Fatalf("插入第 %d 条失败: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交失败: %v", err)
	}

	accounts := make([]string, 0, total)
	for i := 0; i < total; i++ {
		accounts = append(accounts, fmt.Sprintf("user%04d", i))
	}
	got, err := db.QQNumbersByAccounts(accounts)
	if err != nil {
		t.Fatalf("批量查询失败: %v", err)
	}
	if len(got) != total {
		t.Fatalf("跨分片批量查询丢了数据：实得 %d 条，期望 %d 条", len(got), total)
	}
	if got["user0000"] != "2000000000" || got["user0619"] != "2000000619" {
		t.Fatalf("跨分片内容错位: user0000=%q user0619=%q", got["user0000"], got["user0619"])
	}
}

// ── 验证码 ──────────────────────────────────────────────────────────────

func TestSaveAndGetActiveVerifyCode(t *testing.T) {
	db := newQQBindTestDB(t)
	now := NowUnix()
	hash := HashVerifyCode("10001", PurposeQQBind, "123456")

	if err := db.SaveVerifyCode("10001", PurposeQQBind, hash, now+300, "10.0.0.1"); err != nil {
		t.Fatalf("保存验证码失败: %v", err)
	}

	vc, gotHash, err := db.GetActiveVerifyCode("10001", PurposeQQBind, now)
	if err != nil {
		t.Fatalf("取验证码失败: %v", err)
	}
	if vc == nil {
		t.Fatal("应取到有效验证码")
	}
	if gotHash != hash {
		t.Fatalf("哈希不一致: %q vs %q", gotHash, hash)
	}
	if vc.Used || vc.Attempts != 0 {
		t.Fatalf("新码状态不对: used=%v attempts=%d", vc.Used, vc.Attempts)
	}
}

func TestGetActiveVerifyCodeIgnoresExpiredAndUsed(t *testing.T) {
	db := newQQBindTestDB(t)
	now := NowUnix()

	// 已过期
	if err := db.SaveVerifyCode("10001", PurposeQQBind, "h1", now-1, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if vc, _, _ := db.GetActiveVerifyCode("10001", PurposeQQBind, now); vc != nil {
		t.Fatal("过期验证码不该被取到")
	}

	// 未过期但已用
	if err := db.SaveVerifyCode("10002", PurposeQQBind, "h2", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	vc, _, err := db.GetActiveVerifyCode("10002", PurposeQQBind, now)
	if err != nil || vc == nil {
		t.Fatalf("应取到未用验证码: vc=%v err=%v", vc, err)
	}
	if ok, err := db.MarkVerifyCodeUsed(vc.ID); err != nil || !ok {
		t.Fatalf("标记已用失败: ok=%v err=%v", ok, err)
	}
	if vc2, _, _ := db.GetActiveVerifyCode("10002", PurposeQQBind, now); vc2 != nil {
		t.Fatal("已用验证码不该被取到")
	}
}

// 一次性：同一个码只能被核销一次。
func TestMarkVerifyCodeUsedOnlyOnce(t *testing.T) {
	db := newQQBindTestDB(t)
	now := NowUnix()
	if err := db.SaveVerifyCode("10001", PurposeQQBind, "h", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	vc, _, _ := db.GetActiveVerifyCode("10001", PurposeQQBind, now)

	ok, err := db.MarkVerifyCodeUsed(vc.ID)
	if err != nil || !ok {
		t.Fatalf("首次核销应成功: ok=%v err=%v", ok, err)
	}
	ok, err = db.MarkVerifyCodeUsed(vc.ID)
	if err != nil {
		t.Fatalf("二次核销出错: %v", err)
	}
	if ok {
		t.Fatal("同一个码不该能被核销两次")
	}
}

func TestBumpVerifyCodeAttempts(t *testing.T) {
	db := newQQBindTestDB(t)
	now := NowUnix()
	if err := db.SaveVerifyCode("10001", PurposeQQBind, "h", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	vc, _, _ := db.GetActiveVerifyCode("10001", PurposeQQBind, now)

	for i := 1; i <= 3; i++ {
		if err := db.BumpVerifyCodeAttempts(vc.ID); err != nil {
			t.Fatalf("累加失败: %v", err)
		}
		got, _, _ := db.GetActiveVerifyCode("10001", PurposeQQBind, now)
		if got.Attempts != i {
			t.Fatalf("尝试次数 = %d，期望 %d", got.Attempts, i)
		}
	}
}

// 发新码前作废旧码：任何时刻只有一个"活"码，否则爆破难度直接砍半。
func TestInvalidateVerifyCodes(t *testing.T) {
	db := newQQBindTestDB(t)
	now := NowUnix()

	if err := db.SaveVerifyCode("10001", PurposeQQBind, "old", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if err := db.SaveVerifyCode("10001", PurposeQQBind, "new", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	// 同 target+purpose 只留最后一条活码 —— 先作废再写才是正确流程，
	// 这里手工作废后确认只剩下新码。
	if err := db.InvalidateVerifyCodes("10001", PurposeQQBind); err != nil {
		t.Fatalf("作废失败: %v", err)
	}
	if err := db.SaveVerifyCode("10001", PurposeQQBind, "newest", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	vc, hash, err := db.GetActiveVerifyCode("10001", PurposeQQBind, now)
	if err != nil || vc == nil {
		t.Fatalf("应取到活码: vc=%v err=%v", vc, err)
	}
	if hash != "newest" {
		t.Fatalf("取到的应是最后写入的码，实得 %q", hash)
	}
}

// 统计口径：只数窗口内的，且写入时会顺手清掉过期一小时以上的记录。
func TestCountVerifyCodesSinceAndCleanup(t *testing.T) {
	db := newQQBindTestDB(t)
	now := NowUnix()

	if err := db.SaveVerifyCode("10001", PurposeQQBind, "h1", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if err := db.SaveVerifyCode("10002", PurposeQQBind, "h2", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	n, err := db.CountVerifyCodesSince(now - 60)
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("窗口内条数 = %d，期望 2", n)
	}
	if n, _ := db.CountVerifyCodesSince(now + 3600); n != 0 {
		t.Fatalf("未来窗口应为 0，实得 %d", n)
	}

	// ── 过期清理：只清 used=1，未用过的过期行必须留着 ──
	//
	// 这条断言是 2026-09-24 改过的，别改回去。
	// 原来的实现是"过期超过 1 小时就删，不看 used"，看着更干净，实则捅了额度统计：
	// 日额度按 created_at 数当天发出的条数，而这些**真实发出去过**的行
	// 会在同一天内被逐条清走 —— 一天发满上限后额度检查永远回不到阈值，
	// 自保闸门（DailyLimit 80）等于不存在。所以：
	//   未用过（used=0）→ 留着记账，无论多老；
	//   已作废（used=1）→ 过了保留期就清。
	if _, err := db.gatewayDB.Exec(
		"INSERT INTO email_verify_codes (target, purpose, code_hash, expires_at, used, attempts, created_at, request_ip) VALUES ('old-unused','qq_bind','h', ?, 0,0, ?, ''), ('old-used','qq_bind','h', ?, 1,0, ?, '')",
		now-7200, now-7200, now-7200, now-7200); err != nil {
		t.Fatalf("插入老记录失败: %v", err)
	}
	if err := db.SaveVerifyCode("10003", PurposeQQBind, "h3", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	unusedLeft := countRows(t, db, "SELECT COUNT(*) FROM email_verify_codes WHERE target = 'old-unused'")
	if unusedLeft != 1 {
		t.Fatalf("未用过的过期行必须保留（否则日额度会被清空、自保失效），实得 %d 条", unusedLeft)
	}
	usedLeft := countRows(t, db, "SELECT COUNT(*) FROM email_verify_codes WHERE target = 'old-used'")
	if usedLeft != 0 {
		t.Fatalf("已作废的过期行应被清掉，实得 %d 条", usedLeft)
	}
}

// countRows 小工具：单值 COUNT 查询，省掉每处三行样板。
func countRows(t *testing.T, db *Database, query string) int {
	t.Helper()
	var n int
	if err := db.gatewayDB.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("查询 %q 失败: %v", query, err)
	}
	return n
}

func TestLastVerifyCodeAt(t *testing.T) {
	db := newQQBindTestDB(t)

	// 从未发过 = 0（不是错误）
	ts, err := db.LastVerifyCodeAt("10001", PurposeQQBind)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if ts != 0 {
		t.Fatalf("从未发过应为 0，实得 %d", ts)
	}

	now := NowUnix()
	if err := db.SaveVerifyCode("10001", PurposeQQBind, "h", now+300, ""); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	ts, err = db.LastVerifyCodeAt("10001", PurposeQQBind)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if ts != now {
		t.Fatalf("最近发码时刻 = %d，期望 %d", ts, now)
	}

	// ★ 作废之后必须归 0。
	// 业务层发信失败时的动作是"把刚写的那条作废"（used=1，行还在）。
	// 如果这里仍把作废的行算作"最近发过码"，玩家就会被自己那次**根本没送达**的
	// 请求锁死在 60 秒冷却里 —— 一封没收着，界面却让他等着。
	// 这条断言就是钉住这个坑的。
	if err := db.InvalidateVerifyCodes("10001", PurposeQQBind); err != nil {
		t.Fatalf("作废失败: %v", err)
	}
	ts, err = db.LastVerifyCodeAt("10001", PurposeQQBind)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if ts != 0 {
		t.Fatalf("码被作废后不该再有冷却依据，期望 0，实得 %d", ts)
	}
}

// 日额度统计不能把"发信失败后作废"的行算进去 —— 否则 SMTP 一抽风，
// 失败的请求把额度吃光，等通道恢复了反而发不出去了。
func TestCountVerifyCodesSinceIgnoresInvalidated(t *testing.T) {
	db := newQQBindTestDB(t)
	now := NowUnix()

	for _, qq := range []string{"10001", "10002", "10003"} {
		if err := db.SaveVerifyCode(qq, PurposeQQBind, "h-"+qq, now+300, ""); err != nil {
			t.Fatalf("保存失败: %v", err)
		}
	}
	if n, _ := db.CountVerifyCodesSince(now - 60); n != 3 {
		t.Fatalf("作废前应为 3 条，实得 %d", n)
	}

	// 模拟 10002 那一封发信失败后被作废
	if err := db.InvalidateVerifyCodes("10002", PurposeQQBind); err != nil {
		t.Fatalf("作废失败: %v", err)
	}
	n, err := db.CountVerifyCodesSince(now - 60)
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("作废的那条不该计入额度，期望 2，实得 %d", n)
	}
}

// 哈希必须与 target / purpose 绑定：否则撞库时一个码能通吃。
func TestHashVerifyCodeScopedByTargetAndPurpose(t *testing.T) {
	base := HashVerifyCode("10001", PurposeQQBind, "123456")
	if base == "" {
		t.Fatal("哈希不该为空")
	}
	if base == HashVerifyCode("10002", PurposeQQBind, "123456") {
		t.Fatal("不同目标必须得到不同哈希")
	}
	if base == HashVerifyCode("10001", "reset_password", "123456") {
		t.Fatal("不同用途必须得到不同哈希")
	}
	if base == HashVerifyCode("10001", PurposeQQBind, "123457") {
		t.Fatal("不同验证码必须得到不同哈希")
	}
	if base != HashVerifyCode("10001", PurposeQQBind, "123456") {
		t.Fatal("同输入必须稳定")
	}
	// 不能等于裸 SHA256（那样 rainbow 表一查就出原码）。
	if base == "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92" {
		t.Fatal("哈希退化成裸 SHA256 了")
	}
}
