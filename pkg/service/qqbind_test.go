package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
)

// ────────────────────────────────────────────────────────────────────────
// fakeSender：记录"发出去的邮件"，一行网络代码都不走。
//
// 这是把 Sender 抽成接口的全部理由：绑定逻辑的正确性（频控、一次性、
// 唯一性、登录识别）必须能在单测里跑完，而不是每次改一行都拿真实邮箱去试。
// ────────────────────────────────────────────────────────────────────────

type fakeMail struct{ To, Subject, Body string }

type fakeSender struct {
	mu      sync.Mutex
	sent    []fakeMail
	failN   int // 前 N 次调用返回错误（测发信失败分支）
	failErr error
}

func (f *fakeSender) Send(to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failN > 0 {
		f.failN--
		if f.failErr != nil {
			return f.failErr
		}
		return errors.New("smtp: 模拟发送失败")
	}
	f.sent = append(f.sent, fakeMail{To: to, Subject: subject, Body: body})
	return nil
}

func (f *fakeSender) Enabled() bool { return true }

func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeSender) last(t *testing.T) fakeMail {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		t.Fatal("没有发出任何邮件")
	}
	return f.sent[len(f.sent)-1]
}

// disabledSender 模拟"没配 SMTP"。
type disabledSender struct{}

func (disabledSender) Send(to, subject, body string) error { return errors.New("未启用") }
func (disabledSender) Enabled() bool                       { return false }

// codeRe 从邮件正文里抠出 6 位验证码。
//
// 测试里**只能**这么拿明文 —— 数据库里只有哈希（这是设计要求），
// 所以"能从这个正则里取到码"本身就顺带验证了邮件正文格式没被改坏。
var codeRe = regexp.MustCompile(`你的验证码是：(\d{6})`)

func codeFromBody(t *testing.T, body string) string {
	t.Helper()
	m := codeRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("邮件正文里找不到 6 位验证码:\n%s", body)
	}
	return m[1]
}

// ── 夹具 ────────────────────────────────────────────────────────────────

func newQQBindSvcFixture(t *testing.T, accounts ...string) (*QQBindService, *database.Database, *fakeSender) {
	t.Helper()

	dir := t.TempDir()
	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		BusyTimeoutSeconds: 5,
		WalMode:            true,
	})
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("建表失败: %v", err)
	}

	for i, name := range accounts {
		acc := &database.Account{
			MId:       fmt.Sprintf("90%04d", i),
			Name:      name,
			PwdHash:   "hash",
			Salt:      "salt",
			Cera:      100,
			CreatedAt: database.NowUnix(),
		}
		if err := db.InsertAccount(acc); err != nil {
			t.Fatalf("插入账号 %s 失败: %v", name, err)
		}
	}

	cfg := config.DefaultConfig()
	cfg.Smtp = config.SmtpSection{
		Enabled:               true,
		Host:                  "smtp.qq.com",
		Port:                  465,
		UseSSL:                true,
		Username:              "sender@qq.com",
		Password:              "not-a-real-code",
		FromName:              "S4A21",
		DailyLimit:            80,
		PerMinuteLimit:        20,
		CodeTTLSeconds:        300,
		ResendCooldownSeconds: 60,
		TimeoutSeconds:        15,
	}

	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("建日志失败: %v", err)
	}
	// ★ 必须显式关掉。
	//
	// ConsoleLogger 持有 error.log 的文件句柄；不关的话，t.TempDir() 的清理会
	// 因"文件正被另一个进程使用"失败，于是**断言全过、测试却报 FAIL** ——
	// 症状是满屏 `TempDir RemoveAll cleanup: unlinkat ... being used by another process`，
	// 极易误判成功能坏了。
	t.Cleanup(func() { lg.Close() })

	sender := &fakeSender{}
	return NewQQBindService(db, sender, cfg, lg), db, sender
}

// issue 走一遍"发码"并返回明文验证码（测试内部用）。
func issue(t *testing.T, svc *QQBindService, sender *fakeSender, account, qq string) string {
	t.Helper()
	code, msg := svc.SendBindCode(account, qq, "10.0.0.1")
	if code != models.Err.Ok {
		t.Fatalf("发码失败: code=%d msg=%s", code, msg)
	}
	return codeFromBody(t, sender.last(t).Body)
}

// ── 发码 ────────────────────────────────────────────────────────────────

func TestSendBindCodeHappyPath(t *testing.T) {
	svc, db, sender := newQQBindSvcFixture(t, "alice")

	code, msg := svc.SendBindCode("alice", "2805420962", "10.0.0.1")
	if code != models.Err.Ok {
		t.Fatalf("发码应成功，实得 code=%d msg=%s", code, msg)
	}
	if sender.count() != 1 {
		t.Fatalf("应发出 1 封邮件，实得 %d", sender.count())
	}

	mail := sender.last(t)
	if mail.To != "2805420962@qq.com" {
		t.Fatalf("收件人 = %q，期望 2805420962@qq.com", mail.To)
	}
	if !strings.Contains(mail.Subject, "验证码") {
		t.Fatalf("邮件标题异常: %q", mail.Subject)
	}
	// 正文必须写清来意，否则玩家会当诈骗举报。
	if !strings.Contains(mail.Body, "2805420962") || !strings.Contains(mail.Body, "alice") {
		t.Fatalf("正文没写清绑的是哪个号/哪个账号:\n%s", mail.Body)
	}
	if strings.Contains(mail.Body, "http") {
		t.Fatalf("验证码邮件不该带链接（更容易被判垃圾邮件）:\n%s", mail.Body)
	}
	// 提示里不该回显完整 QQ 号。
	if strings.Contains(msg, "2805420962") {
		t.Fatalf("提示消息回显了完整 QQ 号: %q", msg)
	}

	// ★ 库里只能有哈希，不能有明文。
	// 注意这里的 verifyCode 是从邮件正文里抠出来的**明文**，
	// 而上面那个 code 是错误码 —— 两个别搞混。
	verifyCode := codeFromBody(t, mail.Body)
	vc, stored, err := db.GetActiveVerifyCode("2805420962", database.PurposeQQBind, database.NowUnix())
	if err != nil || vc == nil {
		t.Fatalf("库里应有一条有效码: vc=%v err=%v", vc, err)
	}
	if stored == verifyCode {
		t.Fatal("数据库里存了验证码明文")
	}
	if stored != database.HashVerifyCode("2805420962", database.PurposeQQBind, verifyCode) {
		t.Fatalf("哈希不匹配: %s", stored)
	}
}

func TestSendBindCodeRejectsBadFormat(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice")

	for _, bad := range []string{"", "1234", "0123456", "abcdef", "123456789012", "12345 6", "-123456"} {
		code, _ := svc.SendBindCode("alice", bad, "10.0.0.1")
		if code != models.Err.QQNumberInvalid {
			t.Errorf("QQ 号 %q 应被拒（1024），实得 %d", bad, code)
		}
	}
	if sender.count() != 0 {
		t.Fatalf("非法输入不该发信，实发 %d 封", sender.count())
	}
}

func TestSendBindCodeRejectsWhenMailDisabled(t *testing.T) {
	svc, _, _ := newQQBindSvcFixture(t, "alice")
	svc.sender = disabledSender{}

	code, _ := svc.SendBindCode("alice", "2805420962", "10.0.0.1")
	if code != models.Err.MailServiceDisabled {
		t.Fatalf("邮件服务未开启应返回 1030，实得 %d", code)
	}
}

// ★ 顺序钉死：发信通道是否可用，必须排在"请求本身合不合法"的判定**之后**。
//
// 有两种退化方式都会踩这个坑，所以两条都断言：
//  1. 线上把 SMTP 关掉时，玩家点绑定只想看到"邮件没了" —— 但若真正的原因是
//     "这个 QQ 号已经被别人绑了"，只回 1030 会让排障完全看不出问题在哪；
//  2. 更实际的影响在回归里 —— 本机 E2E 默认不开 SMTP，一旦 1030 挡在最前面，
//     1032/1033/1034 这几条最容易写错的判定在测试里**一次都跑不到**。
func TestSendBindCodeChecksRequestBeforeMailChannel(t *testing.T) {
	t.Run("格式非法优先于服务未开", func(t *testing.T) {
		svc, _, _ := newQQBindSvcFixture(t, "alice")
		svc.sender = disabledSender{}
		if code, _ := svc.SendBindCode("alice", "12abc", ""); code != models.Err.QQNumberInvalid {
			t.Fatalf("应为 1024，实得 %d", code)
		}
	})

	t.Run("账号已绑优先于服务未开", func(t *testing.T) {
		svc, db, _ := newQQBindSvcFixture(t, "alice")
		if err := db.BindQQ("10001", "alice", ""); err != nil {
			t.Fatalf("预置绑定失败: %v", err)
		}
		svc.sender = disabledSender{}
		if code, _ := svc.SendBindCode("alice", "2805420962", ""); code != models.Err.AccountAlreadyBound {
			t.Fatalf("应为 1032，实得 %d", code)
		}
	})

	t.Run("QQ号被占优先于服务未开", func(t *testing.T) {
		svc, db, _ := newQQBindSvcFixture(t, "alice", "bob")
		if err := db.BindQQ("2805420962", "alice", ""); err != nil {
			t.Fatalf("预置绑定失败: %v", err)
		}
		svc.sender = disabledSender{}
		if code, _ := svc.SendBindCode("bob", "2805420962", ""); code != models.Err.QQNumberTaken {
			t.Fatalf("应为 1033，实得 %d", code)
		}
	})

	t.Run("账号名撞车不再拦截（直接轮到服务未开）", func(t *testing.T) {
		svc, _, _ := newQQBindSvcFixture(t, "alice", "10038")
		svc.sender = disabledSender{}
		// 10038 是别人的账号名。以前这里返回 1034 拦下，现在放行，
		// 于是检查继续往下走到最后一道"邮件服务未开启"。
		if code, _ := svc.SendBindCode("alice", "10038", ""); code != models.Err.MailServiceDisabled {
			t.Fatalf("账号名撞车应放行并继续到 1030，实得 %d", code)
		}
	})

	t.Run("一切正常才轮到服务未开", func(t *testing.T) {
		svc, _, _ := newQQBindSvcFixture(t, "alice")
		svc.sender = disabledSender{}
		if code, _ := svc.SendBindCode("alice", "2805420962", ""); code != models.Err.MailServiceDisabled {
			t.Fatalf("应为 1030，实得 %d", code)
		}
	})
}

func TestSendBindCodeRejectsQQTaken(t *testing.T) {
	svc, db, _ := newQQBindSvcFixture(t, "alice", "bob")
	// 预置：这个 QQ 号已经被 alice 绑了
	if err := db.BindQQ("2805420962", "alice", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	code, msg := svc.SendBindCode("bob", "2805420962", "10.0.0.1")
	if code != models.Err.QQNumberTaken {
		t.Fatalf("QQ 号已被绑应返回 1033，实得 %d msg=%s", code, msg)
	}
}

func TestSendBindCodeRejectsAlreadyBoundAccount(t *testing.T) {
	svc, db, _ := newQQBindSvcFixture(t, "alice")
	if err := db.BindQQ("10001", "alice", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	code, msg := svc.SendBindCode("alice", "20002", "10.0.0.1")
	if code != models.Err.AccountAlreadyBound {
		t.Fatalf("账号已绑定应返回 1032，实得 %d msg=%s", code, msg)
	}
	if !strings.Contains(msg, "解绑") {
		t.Fatalf("提示应告诉玩家先解绑: %q", msg)
	}
}

// ★ 与现有账号名撞车的绑定：**允许**，只记日志。
//
// 早期这里是拒绝（1034），理由是"数字 X 既被 B 绑成 QQ 号、又是 A 的账号名"
// 会让登录识别二选一，总有一方登不进。现在登录侧有了 `qq:<数字>` 显式前缀，
// A 输裸数字、B 带前缀，各归各家，歧义不存在了 —— 再拦下去就等于让 B
// 彻底用不了这个 QQ 号，而 B 并没有做错任何事。
func TestSendBindCodeAllowsQQNumberMatchingOtherAccountName(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice", "10038")

	code, msg := svc.SendBindCode("alice", "10038", "10.0.0.1")
	if code != models.Err.Ok {
		t.Fatalf("与别人账号名同名应允许发码，实得 %d msg=%s", code, msg)
	}
	if sender.count() != 1 {
		t.Fatalf("应真的发出 1 封，实发 %d 封", sender.count())
	}
}

// ★ 拿**自己的**账号名当 QQ 号来绑：以前是 100% 被误伤的一种。
//
// 存量账号名大量是纯数字，很多人当年就用自己的 QQ 号注册。他来绑定自己的
// QQ 号时，"这个数字是某个现存账号名"这条检查必然命中 —— 而命中的那个人
// 就是他自己。翻译前后是同一个账号，没有任何歧义，没理由拦。
func TestSendBindCodeAllowsBindingOwnAccountName(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "123456")

	code, msg := svc.SendBindCode("123456", "123456", "10.0.0.1")
	if code != models.Err.Ok {
		t.Fatalf("绑自己的账号名应允许，实得 %d msg=%s", code, msg)
	}
	if sender.count() != 1 {
		t.Fatalf("应真的发出 1 封，实发 %d 封", sender.count())
	}
}

func TestSendBindCodeResendCooldown(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice")

	issue(t, svc, sender, "alice", "2805420962")

	code, msg := svc.SendBindCode("alice", "2805420962", "10.0.0.1")
	if code != models.Err.SendTooFrequent {
		t.Fatalf("冷却期内应返回 1028，实得 %d msg=%s", code, msg)
	}
	if sender.count() != 1 {
		t.Fatalf("冷却期内不该再发信，实发 %d 封", sender.count())
	}
}

func TestSendBindCodeDailyLimit(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice", "bob")
	svc.cfg.Smtp.DailyLimit = 2
	svc.cfg.Smtp.ResendCooldownSeconds = 0 // 关掉冷却，只测额度

	// 用不同 QQ 号绕过冷却（模拟一天里不同玩家在绑）
	for i, qq := range []string{"20001", "20002"} {
		if code, msg := svc.SendBindCode("alice", qq, "10.0.0.1"); code != models.Err.Ok {
			t.Fatalf("第 %d 封应成功，实得 code=%d msg=%s", i+1, code, msg)
		}
	}
	if sender.count() != 2 {
		t.Fatalf("应发出 2 封，实得 %d", sender.count())
	}

	code, msg := svc.SendBindCode("bob", "20003", "10.0.0.1")
	if code != models.Err.SendQuotaExhausted {
		t.Fatalf("超出日额度应返回 1031，实得 %d msg=%s", code, msg)
	}
	if sender.count() != 2 {
		t.Fatalf("超额度后不该再发信，实发 %d 封", sender.count())
	}
}

// ★ 发信失败不能留下"有效但收不到"的码。
func TestSendBindCodeMailFailureLeavesNoActiveCode(t *testing.T) {
	svc, db, sender := newQQBindSvcFixture(t, "alice")
	sender.failN = 1

	code, msg := svc.SendBindCode("alice", "2805420962", "10.0.0.1")
	if code != models.Err.MailSendFailed {
		t.Fatalf("发信失败应返回 1029，实得 %d msg=%s", code, msg)
	}
	if sender.count() != 0 {
		t.Fatalf("失败的邮件不该被计入已发，实得 %d", sender.count())
	}

	vc, _, err := db.GetActiveVerifyCode("2805420962", database.PurposeQQBind, database.NowUnix())
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if vc != nil {
		t.Fatalf("发信失败后库里仍有有效码（应作废）: id=%d", vc.ID)
	}

	// ★ 而且不能把玩家锁进冷却。
	//
	// 发信失败的路径是"写行 → 作废（used=1，行还在）"。
	// 冷却若只看 MAX(created_at) 不看 used，玩家就会被自己那次**根本没送达**的
	// 请求锁在 60 秒里：一封没收着，界面上却告诉他"请 45 秒后再试"。
	// 这里连发第二次（failN 已消耗完，这次会成功）验证冷却确实不生效。
	code2, msg2 := svc.SendBindCode("alice", "2805420962", "10.0.0.1")
	if code2 != models.Err.Ok {
		t.Fatalf("上一次发信失败后应能立刻重试（冷却不该生效），实得 code=%d msg=%s", code2, msg2)
	}
	if sender.count() != 1 {
		t.Fatalf("重试应真的发出 1 封，实得 %d", sender.count())
	}
}

// ── 绑定 ────────────────────────────────────────────────────────────────

func TestBindHappyPath(t *testing.T) {
	svc, db, sender := newQQBindSvcFixture(t, "alice")
	code := issue(t, svc, sender, "alice", "2805420962")

	errCode, msg := svc.Bind("alice", "2805420962", code, "10.0.0.1")
	if errCode != models.Err.Ok {
		t.Fatalf("绑定应成功，实得 code=%d msg=%s", errCode, msg)
	}

	account, err := db.GetAccountByQQNumber("2805420962")
	if err != nil || account != "alice" {
		t.Fatalf("绑定未落库: account=%q err=%v", account, err)
	}
	if svc.BindingOf("alice") != "2805420962" {
		t.Fatalf("BindingOf 没读到: %q", svc.BindingOf("alice"))
	}
}

// ★ 撞了别人账号名的绑定：成功提示必须当场告诉玩家要带 `qq:` 前缀登录。
//
// 不说清楚的话，他过两天用裸数字登录、进了别人（账号名主人）的号、
// 只看到一句"密码错误"，只会来投诉 —— 而客服那边也未必想得到是撞了账号名。
func TestBindMessageHintsPrefixWhenQQMatchesAccountName(t *testing.T) {
	svc, db, sender := newQQBindSvcFixture(t, "alice", "10038")
	code := issue(t, svc, sender, "alice", "10038")

	errCode, msg := svc.Bind("alice", "10038", code, "10.0.0.1")
	if errCode != models.Err.Ok {
		t.Fatalf("撞账号名也应能绑上，实得 code=%d msg=%s", errCode, msg)
	}
	if !strings.Contains(msg, loginQQPrefix+"10038") {
		t.Fatalf("提示里应出现 qq:10038，实得 %q", msg)
	}
	if owner, _ := db.GetAccountByQQNumber("10038"); owner != "alice" {
		t.Fatalf("绑定未落库: %q", owner)
	}
}

// 反向对照：没有冲突时提示里**不该**出现前缀。
//
// 否则绝大多数玩家会以为"必须带 qq: 才能登"，把一个可选写法当成规定动作。
func TestBindMessageHasNoPrefixHintWhenNoConflict(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice")
	code := issue(t, svc, sender, "alice", "2805420962")

	errCode, msg := svc.Bind("alice", "2805420962", code, "10.0.0.1")
	if errCode != models.Err.Ok {
		t.Fatalf("绑定应成功，实得 code=%d msg=%s", errCode, msg)
	}
	if strings.Contains(msg, loginQQPrefix) {
		t.Fatalf("无冲突时不该提前缀，实得 %q", msg)
	}
}

func TestBindRejectsWrongCodeAndCountsAttempts(t *testing.T) {
	svc, db, sender := newQQBindSvcFixture(t, "alice")
	code := issue(t, svc, sender, "alice", "2805420962")
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}

	for i := 1; i <= maxVerifyCodeAttempts; i++ {
		errCode, msg := svc.Bind("alice", "2805420962", wrong, "10.0.0.1")
		if i < maxVerifyCodeAttempts {
			if errCode != models.Err.VerifyCodeInvalid {
				t.Fatalf("第 %d 次错码应返回 1025，实得 %d msg=%s", i, errCode, msg)
			}
		} else if errCode != models.Err.VerifyCodeAttemptsExceed {
			t.Fatalf("第 %d 次应因次数过多被拒（1027），实得 %d msg=%s", i, errCode, msg)
		}
	}

	// 次数用尽后，正确的码也不再接受（必须重新获取）。
	if errCode, _ := svc.Bind("alice", "2805420962", code, "10.0.0.1"); errCode != models.Err.VerifyCodeAttemptsExceed {
		t.Fatalf("次数用尽后正码也应被拒（1027），实得 %d", errCode)
	}
	// 整个过程不该产生任何绑定。
	if n, _ := db.CountQQBindings(); n != 0 {
		t.Fatalf("错误尝试不该建立绑定，实得 %d 条", n)
	}
}

func TestBindRejectsExpiredCode(t *testing.T) {
	svc, db, _ := newQQBindSvcFixture(t, "alice")

	// 直接写一条**已过期**的码（等价于玩家拿到码后拖过了 5 分钟）。
	if err := db.SaveVerifyCode(
		"2805420962", database.PurposeQQBind,
		database.HashVerifyCode("2805420962", database.PurposeQQBind, "123456"),
		database.NowUnix()-1, "10.0.0.1",
	); err != nil {
		t.Fatalf("写过期码失败: %v", err)
	}

	if errCode, _ := svc.Bind("alice", "2805420962", "123456", "10.0.0.1"); errCode != models.Err.VerifyCodeExpired {
		t.Fatalf("过期码应返回 1026，实得 %d", errCode)
	}
}

func TestBindCodeIsSingleUse(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice", "bob")
	code := issue(t, svc, sender, "alice", "2805420962")

	if errCode, _ := svc.Bind("alice", "2805420962", code, "10.0.0.1"); errCode != models.Err.Ok {
		t.Fatalf("首次绑定应成功，实得 %d", errCode)
	}
	// 同一个码再用一次（换个账号来试）：必须失败。
	if errCode, msg := svc.Bind("bob", "2805420962", code, "10.0.0.1"); errCode == models.Err.Ok {
		t.Fatalf("同一个码不该能绑两次: msg=%s", msg)
	}
}

func TestBindRejectsEmptyCode(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice")
	issue(t, svc, sender, "alice", "2805420962")

	if errCode, _ := svc.Bind("alice", "2805420962", "   ", "10.0.0.1"); errCode != models.Err.VerifyCodeInvalid {
		t.Fatalf("空验证码应返回 1025，实得 %d", errCode)
	}
}

func TestBindRejectsBadQQFormat(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice")
	code := issue(t, svc, sender, "alice", "2805420962")

	if errCode, _ := svc.Bind("alice", "abc", code, "10.0.0.1"); errCode != models.Err.QQNumberInvalid {
		t.Fatalf("非法 QQ 号应返回 1024，实得 %d", errCode)
	}
}

// 一个账号只能绑一个 QQ：已经绑了之后再想绑第二个号，**发码阶段就该被拦**。
func TestSendBindCodeRejectsSecondQQForBoundAccount(t *testing.T) {
	svc, _, sender := newQQBindSvcFixture(t, "alice")

	code1 := issue(t, svc, sender, "alice", "2805420962")
	if errCode, _ := svc.Bind("alice", "2805420962", code1, "10.0.0.1"); errCode != models.Err.Ok {
		t.Fatalf("首次绑定失败")
	}

	sentBefore := sender.count()
	if errCode, msg := svc.SendBindCode("alice", "30003", "10.0.0.1"); errCode != models.Err.AccountAlreadyBound {
		t.Fatalf("已绑定的账号换号绑应返回 1032，实得 %d msg=%s", errCode, msg)
	}
	if sender.count() != sentBefore {
		t.Fatal("被拒的请求不该发信（白烧一封额度）")
	}
}

// ★ 发码之后、提交之前状态变了：这期间**账号**被绑走了。
//
// 唯一性不能只靠发码那一刻的检查 —— Bind 里那次才是最后一道闸。
func TestBindRejectsWhenAccountGotBoundInBetween(t *testing.T) {
	svc, db, sender := newQQBindSvcFixture(t, "alice")

	code := issue(t, svc, sender, "alice", "2805420962")

	// 模拟"这期间别处（后台 / 另一个登录器）给它绑了另一个号"
	if err := db.BindQQ("30003", "alice", "后台"); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	if errCode, msg := svc.Bind("alice", "2805420962", code, "10.0.0.1"); errCode != models.Err.AccountAlreadyBound {
		t.Fatalf("提交时应发现账号已被绑，返回 1032，实得 %d msg=%s", errCode, msg)
	}
	// 原来那个绑定不能被覆盖，也不该留下半条新数据。
	if got, _ := db.GetAccountByQQNumber("30003"); got != "alice" {
		t.Fatalf("原绑定被破坏: %q", got)
	}
	if got, _ := db.GetAccountByQQNumber("2805420962"); got != "" {
		t.Fatalf("冲突时不该留下新绑定，实得 %q", got)
	}
	if n, _ := db.CountQQBindings(); n != 1 {
		t.Fatalf("冲突后绑定总数 = %d，期望 1", n)
	}
}

// ★ 发码之后、提交之前：QQ 号被别的账号抢走了。
func TestBindRejectsWhenQQGotTakenInBetween(t *testing.T) {
	svc, db, sender := newQQBindSvcFixture(t, "alice", "bob")

	code := issue(t, svc, sender, "alice", "2805420962")

	if err := db.BindQQ("2805420962", "bob", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	if errCode, _ := svc.Bind("alice", "2805420962", code, "10.0.0.1"); errCode != models.Err.QQNumberTaken {
		t.Fatalf("QQ 号被抢走应返回 1033，实得 %d", errCode)
	}
	// 抢走的那个不能被顶掉。
	if got, _ := db.GetAccountByQQNumber("2805420962"); got != "bob" {
		t.Fatalf("抢占者的绑定被破坏: %q", got)
	}
}

// ── 登录识别 ────────────────────────────────────────────────────────────

func TestResolveLoginAccount(t *testing.T) {
	svc, db, _ := newQQBindSvcFixture(t, "alice", "10038")
	if err := db.BindQQ("2805420962", "alice", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	cases := []struct{ in, want, why string }{
		{"2805420962", "alice", "已绑定的 QQ 号应翻译成账号名"},
		{"alice", "alice", "账号名原样"},
		{"10038", "10038", "纯数字账号名（未绑定过的）原样 —— 老账号不受影响"},
		{"unknown", "unknown", "非数字原样"},
		{"  10038  ", "10038", "首尾空白被裁掉"},
		{"", "", "空原样"},
		// ── 显式前缀 qq: ──
		{"qq:2805420962", "alice", "带前缀的已绑定 QQ 号应翻译"},
		{"QQ:2805420962", "alice", "前缀大小写不敏感"},
		{"Qq:2805420962", "alice", "前缀大小写不敏感（混合）"},
		{"  qq: 2805420962  ", "alice", "前缀后允许空格，整体也裁空白"},
		{"qq:99999999", "qq:99999999", "带前缀但没人绑过 → 原样（登录会报账号不存在）"},
		{"qq:", "qq:", "只有前缀 → 原样"},
		{"qq:abc", "qq:abc", "前缀后不是数字 → 原样"},
		{"qq:alice", "qq:alice", "前缀后是账号名也不认 —— 前缀就是在声明\"这是 QQ 号\""},
		{"qq", "qq", "半截前缀 → 原样"},
	}
	for _, c := range cases {
		if got := svc.ResolveLoginAccount(c.in); got != c.want {
			t.Errorf("%s：ResolveLoginAccount(%q) = %q，期望 %q", c.why, c.in, got, c.want)
		}
	}
}

// ★ 兜底：当"某个数字既被绑成 QQ 号、又存在同名账号"这种冲突态真的出现时，
// 账号名必须优先 —— 否则那个账号的主人会被翻译到别人身上，密码对不上，
// **自己的号永远登不进去**，只能等客服。
//
// 冲突态有两条来路：存量纯数字账号名被后绑的 QQ 号撞上，或者账号名绕过注册
// 接口产生（运维手工建号、导入脚本直连 SQL）。注册接口本身拒绝"注册一个
// 已被人绑定的数字"（先到先得），但那两条绕得过去，所以登录这一步的兜底不能省。
// 这里用 db.BindQQ 直连绕过 service 的检查，精确复现那个状态。
//
// 兜底之后 QQ 号主人并不会被牺牲：他写 `qq:10038` 就能强制翻译（下面第 2 段断言）。
func TestResolveLoginAccountPrefersExistingAccountName(t *testing.T) {
	// 注意需要**两个**账号：绑定是"一账号一 QQ、一 QQ 一账号"的一对一，
	// 一个账号塞不下两条绑定（第二次会被 BindQQ 用"账号已绑定"顶回来）。
	svc, db, _ := newQQBindSvcFixture(t, "alice", "10038", "bob")

	// 绕过 service 的检查，硬造出冲突态：10038 既是账号名，又是 alice 的绑定 QQ 号
	if err := db.BindQQ("10038", "alice", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	if got := svc.ResolveLoginAccount("10038"); got != "10038" {
		t.Fatalf("冲突态下裸输入账号名应优先，ResolveLoginAccount(10038) = %q，期望 10038"+
			"（返回 alice 就意味着那个 10038 账号的主人再也登不进自己的号）", got)
	}
	// ★ 反过来，QQ 号主人带上前缀照样能进自己的号 —— 冲突态下两边都不吃亏的关键。
	if got := svc.ResolveLoginAccount("qq:10038"); got != "alice" {
		t.Fatalf("带前缀应强制翻译，ResolveLoginAccount(qq:10038) = %q，期望 alice", got)
	}
	// 未冲突的 QQ 号翻译不受影响
	if err := db.BindQQ("2805420962", "bob", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}
	if got := svc.ResolveLoginAccount("2805420962"); got != "bob" {
		t.Fatalf("正常绑定仍应翻译，实得 %q", got)
	}
	if got := svc.ResolveLoginAccount("QQ:2805420962"); got != "bob" {
		t.Fatalf("前缀大小写不敏感，QQ:2805420962 应翻译成 bob，实得 %q", got)
	}
}

// 绑定表出错时登录必须照常（按账号名走），不能把登录链路拖垮。
func TestResolveLoginAccountSurvivesQueryError(t *testing.T) {
	svc, db, _ := newQQBindSvcFixture(t, "alice")
	if err := db.BindQQ("2805420962", "alice", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	// 关掉连接，模拟"库读不出来"这种真实事故（表缺失 / 文件被换 / 权限异常）。
	db.Close()

	if got := svc.ResolveLoginAccount("2805420962"); got != "2805420962" {
		t.Fatalf("查库失败时应原样返回，实得 %q", got)
	}
	// 带前缀也要降级原样 —— 它只是"声明这是 QQ 号"，查不到就是查不到，
	// 绝不能因为拿不到绑定表就返回一个假的账号名。
	if got := svc.ResolveLoginAccount("qq:2805420962"); got != "qq:2805420962" {
		t.Fatalf("查库失败时带前缀也应原样返回，实得 %q", got)
	}
	if got := svc.BindingOf("alice"); got != "" {
		t.Fatalf("查库失败时 BindingOf 应返回空串，实得 %q", got)
	}
}

// 绑定后 QQ 号能解析；解绑后立刻失效 —— 这是玩家自助换绑的核心路径。
func TestResolveLoginAccountAfterUnbind(t *testing.T) {
	svc, db, _ := newQQBindSvcFixture(t, "alice")
	if err := db.BindQQ("2805420962", "alice", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}
	if got := svc.ResolveLoginAccount("2805420962"); got != "alice" {
		t.Fatalf("绑定后应解析成 alice，实得 %q", got)
	}

	if code, msg := svc.Unbind("alice"); code != models.Err.Ok {
		t.Fatalf("解绑失败: code=%d msg=%s", code, msg)
	}
	if got := svc.ResolveLoginAccount("2805420962"); got != "2805420962" {
		t.Fatalf("解绑后不该再解析成账号名，实得 %q", got)
	}
}

// ── 解绑 ────────────────────────────────────────────────────────────────

func TestUnbindNotBound(t *testing.T) {
	svc, _, _ := newQQBindSvcFixture(t, "alice")

	if code, _ := svc.Unbind("alice"); code != models.Err.QQNotBound {
		t.Fatalf("未绑定应返回 1035，实得 %d", code)
	}
}

func TestUnbindMessageMasked(t *testing.T) {
	svc, db, _ := newQQBindSvcFixture(t, "alice")
	if err := db.BindQQ("2805420962", "alice", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	code, msg := svc.Unbind("alice")
	if code != models.Err.Ok {
		t.Fatalf("解绑应成功，实得 %d", code)
	}
	if strings.Contains(msg, "2805420962") {
		t.Fatalf("提示消息回显了完整 QQ 号: %q", msg)
	}
}

// ── 辅助函数 ────────────────────────────────────────────────────────────

func TestMaskQQ(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2805420962", "2805***962"},
		{"123456", "1***6"},
		{"12345", "1***5"},
	}
	for _, c := range cases {
		if got := maskQQ(c.in); got != c.want {
			t.Errorf("maskQQ(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestRandomVerifyCodeFormat(t *testing.T) {
	seen := map[string]int{}
	for i := 0; i < 500; i++ {
		code, err := randomVerifyCode()
		if err != nil {
			t.Fatalf("生成失败: %v", err)
		}
		if len(code) != 6 {
			t.Fatalf("验证码长度 = %d，期望 6（%q）", len(code), code)
		}
		if !isAllDigits(code) {
			t.Fatalf("验证码含非数字: %q", code)
		}
		seen[code]++
	}
	// 500 次里如果只出现个位数的不同值，说明随机源坏了。
	if len(seen) < 400 {
		t.Fatalf("随机性不足：500 次只有 %d 个不同值", len(seen))
	}
}

func TestStripQQPrefix(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOk bool
	}{
		{"qq:123456", "123456", true},
		{"QQ:123456", "123456", true},
		{"Qq:123456", "123456", true},
		{"qQ:123456", "123456", true},
		{"qq:  123456", "123456", true},
		{"qq:", "", true},
		{"qq:abc", "abc", true},
		// 以下都不是前缀写法，交回给上层按原样处理
		{"qq", "", false},
		{"qq123456", "", false},
		{"123456", "", false},
		{"", "", false},
		{"  qq:123456", "", false},
		{"xqq:123456", "", false},
	}
	for _, c := range cases {
		got, ok := stripQQPrefix(c.in)
		if ok != c.wantOk || got != c.want {
			t.Errorf("stripQQPrefix(%q) = (%q, %v)，期望 (%q, %v)", c.in, got, ok, c.want, c.wantOk)
		}
	}
}

func TestIsAllDigits(t *testing.T) {
	for _, s := range []string{"0", "123456", "9999999"} {
		if !isAllDigits(s) {
			t.Errorf("%q 应该全是数字", s)
		}
	}
	for _, s := range []string{"", "12a", "1 2", "-1", "12.3"} {
		if isAllDigits(s) {
			t.Errorf("%q 不该被判定为全数字", s)
		}
	}
}

func TestStartOfToday(t *testing.T) {
	start := startOfToday()
	if start <= 0 {
		t.Fatalf("起始时刻异常: %d", start)
	}
	now := time.Now().Unix()
	if start > now {
		t.Fatalf("今日零点（%d）不该晚于当前时刻（%d）", start, now)
	}
	// 与当前时刻的差不能超过 25 小时（跨时区/夏令时也不会差这么多）。
	if now-start > 25*3600 {
		t.Fatalf("今日零点算错了：距今 %d 秒", now-start)
	}
}

// 邮件正文必须写明来意、且不含链接。
func TestBindMailBody(t *testing.T) {
	body := bindMailBody("123456", "2805420962", "alice", 300)
	for _, want := range []string{"123456", "2805420962", "alice", "5 分钟", "忽略"} {
		if !strings.Contains(body, want) {
			t.Errorf("正文缺少 %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "http") || strings.Contains(body, "www.") {
		t.Errorf("正文不该含链接:\n%s", body)
	}
	// 有效期不足 60 秒时也要显示成"1 分钟"，不能显示 0。
	if !strings.Contains(bindMailBody("1", "1", "a", 30), "1 分钟") {
		t.Error("短有效期应兜底成 1 分钟")
	}
}

// ── 注册 vs 绑定：账号名不能撞上别人的 QQ 号 ────────────────────────────

// newAccountSvcFixture 造一个只挂 AccountService 的最小环境。
//
// 不复用 newQQBindSvcFixture：那个夹具把 logger / cfg 都封在内部，
// 而验证"注册时撞上已绑 QQ 号"需要在**同一个 db** 上同时拿到
// AccountService 和数据库句柄 —— 偷懒复用反而要改所有既有测试的签名。
func newAccountSvcFixture(t *testing.T) (*AccountService, *database.Database) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		BusyTimeoutSeconds: 5,
		WalMode:            true,
	})
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("建日志失败: %v", err)
	}
	t.Cleanup(func() { lg.Close() }) // 同 newQQBindSvcFixture：不关会伪装成测试 FAIL
	return NewAccountService(db, config.DefaultConfig(), lg), db
}

// ★ 先绑定、后注册这条路必须被堵住。
//
// 绑定流程只挡了反方向（绑定时拒绝与现有账号名相同的 QQ 号）。
// 不做这道检查的话：玩家注册一个"看起来完全正常、实际是别人绑定的 QQ 号"
// 的账号名，用自己设的密码登录时会被 ResolveLoginAccount 翻译到 QQ 主人的账号 →
// 拿到 1008 密码错误 → 自己还完全不知道发生了什么。
func TestRegisterRejectsAccountNameEqualToBoundQQ(t *testing.T) {
	accSvc, db := newAccountSvcFixture(t)
	if err := db.BindQQ("2805420962", "someone-else", ""); err != nil {
		t.Fatalf("预置绑定失败: %v", err)
	}

	if code := accSvc.Register("2805420962", strings.Repeat("a", 32)); code != models.Err.AccountExists {
		t.Fatalf("注册一个已被绑定的 QQ 号当账号名应被拒（1004），实得 %d", code)
	}

	// 反向对照：没被绑定的数字名照旧能注册 —— 老数字账号名（原生产账号名就是数字）
	// 这条路一点都不能受影响。
	if code := accSvc.Register("10038", strings.Repeat("b", 32)); code != models.Err.Ok {
		t.Fatalf("未被绑定的数字账号名应能注册，实得 %d", code)
	}
	// 英文名也不受影响
	if code := accSvc.Register("alice", strings.Repeat("c", 32)); code != models.Err.Ok {
		t.Fatalf("普通账号名应能注册，实得 %d", code)
	}
}
