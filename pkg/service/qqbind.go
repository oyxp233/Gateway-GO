package service

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/notify"
	"s4a21-gateway/pkg/security"
)

// ────────────────────────────────────────────────────────────────────────
// QQ 号绑定（2026-09-24）
//
// 口径（安南拍板）：**账号名照旧，额外绑一个 QQ 号，登录框两个都能进。**
//
// 所以这套逻辑做两件事，别的一概不碰：
//  1. 让玩家证明"这个 QQ 号是他的"（把 6 位验证码发到 <QQ号>@qq.com）；
//  2. 登录时把输入的数字翻译成账号名（ResolveLoginAccount）。
//
// 它**不改** accounts 表的任何字段：m_id、密码、点券、角色全部原样，
// 游戏库那边的关联一个字节都不动。
//
// 为什么不用官方 QQ 互联：腾讯只返回 openid（不透明字符串，拿不到 QQ 号），
// 且桌面客户端没有可用类目；详见 交付物/登录器绑定QQ登录-准备清单-20260924.md。
// ────────────────────────────────────────────────────────────────────────

// qqNumberRe 是 QQ 号格式：5~11 位、首位不为 0。
//
// 为什么要校验：绑定后的数字会被当成登录框的输入去查绑定表，
// 放任 `0`、`000001`、`1234567890123456` 这类值进来只会把数据搞脏，
// 而脏数据的后果是"登录框输入某个数字，登进了别人的号"。
var qqNumberRe = regexp.MustCompile(`^[1-9][0-9]{4,10}$`)

// loginQQPrefix 是登录框里"显式声明这是 QQ 号"的前缀：`qq:123456`。
//
// 为什么需要它：同一个数字完全可能既是 A 的账号名、又是 B 绑定的 QQ 号
// （存量数字账号名 + 后绑的 QQ 号，写入口堵不全）。裸数字登录只能二选一，
// 于是总有一方登不进自己的号。加上前缀就是让玩家自己说清楚"我说的是 QQ 号"：
//
//	123456      → 账号名优先 → 进 A 的号
//	qq:123456   → 强制翻译   → 进 B 的号
//
// 它不会和任何真实账号名撞车，因为账号名走字符白名单
// （见 AccountService.Register：只允许 a-z / A-Z / 0-9、长度 3~20，冒号进不来）。
const loginQQPrefix = "qq:"

// 单个验证码允许的最大错误尝试次数。超过就直接作废该码（要重新获取）。
const maxVerifyCodeAttempts = 5

// QQBindService 处理账号绑定 QQ 号的业务。
type QQBindService struct {
	db     *database.Database
	sender notify.Sender
	cfg    *config.GatewayConfig
	logger *logger.ConsoleLogger
}

// NewQQBindService 创建绑定服务。
//
// sender 允许为 nil（未配 SMTP 时）—— 这时 SendBindCode 会明确返回
// "邮件服务未开启"，而不是处理空指针崩溃：配置漏了不该让网关挂掉。
func NewQQBindService(
	db *database.Database,
	sender notify.Sender,
	cfg *config.GatewayConfig,
	lg *logger.ConsoleLogger,
) *QQBindService {
	return &QQBindService{db: db, sender: sender, cfg: cfg, logger: lg}
}

// smtpCfg 返回补齐兜底值后的 SMTP 配置。
//
// 配置文件里漏填某一项时不该按 0 处理（0 表示"一个都不许发"或"立刻过期"），
// 这种静默失效最难排查。
func (s *QQBindService) smtpCfg() config.SmtpSection {
	c := s.cfg.Smtp
	if c.CodeTTLSeconds <= 0 {
		c.CodeTTLSeconds = 300
	}
	if c.ResendCooldownSeconds <= 0 {
		c.ResendCooldownSeconds = 60
	}
	if c.DailyLimit <= 0 {
		c.DailyLimit = 80
	}
	if c.PerMinuteLimit <= 0 {
		c.PerMinuteLimit = 20
	}
	return c
}

// Available 报告发信通道是否可用（后台"绑定"功能据此显示状态）。
func (s *QQBindService) Available() bool {
	if s.sender == nil {
		return false
	}
	type enabler interface{ Enabled() bool }
	if e, ok := s.sender.(enabler); ok {
		return e.Enabled()
	}
	return true
}

// ── 登录识别 ────────────────────────────────────────────────────────────

// ResolveLoginAccount 把登录框里输入的内容翻译成真正的账号名。
//
// 三种输入，按优先级：
//  1. `qq:<数字>` —— 玩家**显式**声明这是 QQ 号，强制翻译，不做下面的账号名优先；
//  2. 纯数字 —— 先看这个串本身是不是一个存在的账号名（**账号名优先**），
//     不是才去查绑定表翻译；
//  3. 其余 —— 原样返回。
//
// 第 2 条的"账号名优先"是兜底，不是多余。数字 X 同时是账号名和别人的绑定 QQ 号
// 这种冲突态，光靠写入口的检查堵不全：运维手工建号、导入脚本直连 SQL、
// 存量数据都可能绕过。少了这条，X 的主人输自己的账号名会被翻译成 QQ 主人的账号 →
// 密码对不上 → **自己的号永远登不进去**。有这条则他照常登录，
// 而 QQ 号主人改走第 1 条写 `qq:X` 就行 —— 冲突态下两边都不吃亏。
//
// ⚠️ 查库失败时**必须**原样返回。绑定表读不出来（比如老库没跑迁移）就登不进游戏，
// 那这个功能就成了登录链路的单点故障 —— 它只是可选增强，没资格拖垮登录。
func (s *QQBindService) ResolveLoginAccount(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return input
	}

	// ① 显式前缀：玩家已经说清这是 QQ 号了，直接翻译，跳过账号名优先检查。
	if num, ok := stripQQPrefix(input); ok {
		if num == "" || !isAllDigits(num) {
			return input
		}
		return s.lookupByQQNumber(num, input)
	}

	// ② 裸输入里只有纯数字才可能被当成 QQ 号。
	if !isAllDigits(input) {
		return input
	}
	account := s.lookupByQQNumber(input, "")
	if account == "" {
		return input
	}

	// ③ 账号名优先：这个数字如果本身就是某个账号名，那它属于账号名主人。
	existing, err := s.db.GetAccountByName(input)
	if err != nil {
		// 读不出来时不敢翻译：宁可让这个 QQ 号暂时登不上，
		// 也不能把账号名的主人翻译到别人的号上。
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("查账号名冲突失败（登录按账号名照旧处理）: 输入=%s err=%v", input, err))
		}
		return input
	}
	if existing != nil {
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("数字 %s 同时是账号名和已绑定 QQ 号，按账号名优先处理；QQ 号主人可用 %s%s 登录",
				input, loginQQPrefix, input))
		}
		return input
	}
	return account
}

// lookupByQQNumber 查 QQ 号对应的账号名，查询失败或未绑定都返回 fallback。
//
// 把"没有绑定"和"查询失败"合并成同一个返回值是有意的：登录链路上两者的处理
// 完全一样（原样返回，交给后面的账号名流程去判断），区别只体现在日志上。
func (s *QQBindService) lookupByQQNumber(qqNumber, fallback string) string {
	account, err := s.db.GetAccountByQQNumber(qqNumber)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("查 QQ 绑定失败（登录按账号名照旧处理）: 输入=%s err=%v", qqNumber, err))
		}
		return fallback
	}
	if account == "" {
		return fallback
	}
	return account
}

// stripQQPrefix 识别 `qq:123456` 形式并取出后面的数字部分。
//
// 前缀大小写不敏感（`QQ:` / `Qq:` 都认），冒号后的空格会被吃掉 ——
// 这是玩家手敲的东西，不该为了一个空格把人挡在门外。
func stripQQPrefix(input string) (string, bool) {
	if len(input) < len(loginQQPrefix) {
		return "", false
	}
	if !strings.EqualFold(input[:len(loginQQPrefix)], loginQQPrefix) {
		return "", false
	}
	return strings.TrimSpace(input[len(loginQQPrefix):]), true
}

// qqNumberConflictsWithAccountName 报告这个数字是否同时被用作**别人**的账号名。
//
// 自己绑自己账号名不算冲突 —— 那种情况翻译前后是同一个账号，没有任何歧义。
//
// 查库失败一律按"不冲突"处理：这个判定只决定提示语里要不要多一句前缀说明、
// 以及要不要记一条日志，判错的最坏结果就是少一句提示，
// 绝不能让绑定主流程因此失败。
func (s *QQBindService) qqNumberConflictsWithAccountName(qqNumber, account string) bool {
	existing, err := s.db.GetAccountByName(qqNumber)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("查账号名是否与 QQ 号同名失败（按不冲突处理）: qq=%s err=%v", qqNumber, err))
		}
		return false
	}
	return existing != nil && existing.Name != account
}

// BindingOf 返回账号已绑定的 QQ 号，未绑定返回空串。
//
// 出错时也返回空串：登录响应里少一个"已绑定"标记，
// 总好过因为绑定表读不出来而让登录直接失败。
func (s *QQBindService) BindingOf(account string) string {
	b, err := s.db.GetQQBindingByAccount(strings.TrimSpace(account))
	if err != nil || b == nil {
		return ""
	}
	return b.QQNumber
}

// ── 发码 ────────────────────────────────────────────────────────────────

// SendBindCode 下发绑定验证码，返回 (错误码, 提示消息)。
//
// 顺序是有讲究的，分三段：
//  1. **跟能不能发信无关**的检查（账号名、QQ 号格式、账号是否已绑、QQ 号是否被占、
//     是否与现有账号名冲突）—— 这些是"请求本身不合法"，先给玩家最准确的原因；
//  2. **发信通道**与**频控/额度**（服务未开、重发冷却、日额度、分钟限流）——
//     这些决定"这一封发不发得出去"；
//  3. 最后才真的连 SMTP。
//
// ⚠️ 第 2 段的"服务未开"必须排在第 1 段之后。
// 曾经把它放在 QQ 号格式校验后面（即第 1 段之前），后果有两个：
//   - 线上 SMTP 一关，玩家点绑定只会看到"邮件服务未开启"，
//     哪怕真正的原因是"这个 QQ 号已经被别人绑了"，排障时完全看不出；
//   - 本机 E2E 默认不开 SMTP，于是"已绑定 1032 / 被占 1033 / 撞账号名 1034"
//     这三条最易写错的判定在回归里**一次都没跑到**（全被 1030 挡在前面）。
func (s *QQBindService) SendBindCode(account, qqNumber, clientIP string) (int, string) {
	account = strings.TrimSpace(account)
	qqNumber = strings.TrimSpace(qqNumber)

	if account == "" {
		return models.Err.AccountNotFound, "登录状态无效，请重新登录"
	}
	if !qqNumberRe.MatchString(qqNumber) {
		return models.Err.QQNumberInvalid, "QQ 号格式不正确（5~11 位数字）"
	}

	// 该账号是否已经绑过
	if bound := s.BindingOf(account); bound != "" {
		if bound == qqNumber {
			return models.Err.AccountAlreadyBound, fmt.Sprintf("该账号已绑定 QQ 号 %s", bound)
		}
		return models.Err.AccountAlreadyBound, fmt.Sprintf("该账号已绑定 QQ 号 %s，请先解绑", bound)
	}

	// 该 QQ 号是否已被别人绑
	owner, err := s.db.GetAccountByQQNumber(qqNumber)
	if err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("查 QQ 号归属失败: qq=%s err=%v", qqNumber, err))
		}
		return models.Err.DatabaseError, "系统繁忙，请稍后再试"
	}
	if owner != "" {
		return models.Err.QQNumberTaken, "该 QQ 号已被其他账号绑定"
	}

	// QQ 号与现有账号名撞了 —— 不再拒绝。
	//
	// 早期这里直接返回 1034，理由是"数字 X 既被 B 绑成 QQ 号、又是 A 的账号名"
	// 会让登录识别二选一，总有一方登不进。现在登录侧有了 `qq:<数字>` 显式前缀
	//（见 ResolveLoginAccount），玩家自己就能说清"我说的是 QQ 号"，歧义不存在了：
	//
	//	A 输 123456     → 账号名优先 → 进 A 的号
	//	B 输 qq:123456  → 强制翻译   → 进 B 的号
	//
	// 所以这里只记日志（运营要能一眼看出哪些数字必须带前缀登），不拦人。
	// 顺带把"拿自己的账号名当 QQ 号来绑"也放开了 —— 那种玩家以前是 100% 被
	// 误伤的，而数量不少：存量账号名大量是纯数字，很多人当年就用自己的 QQ 号注册。
	if s.qqNumberConflictsWithAccountName(qqNumber, account) {
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("QQ 号与现有账号名同名，仍允许绑定: qq=%s 绑定账号=%s；该数字裸输入时账号名优先，需用 %s%s 登录",
				qqNumber, account, loginQQPrefix, qqNumber))
		}
	}

	// 发信通道是否可用。放在这里而不是最前面 —— 理由见函数头注释。
	if s.sender == nil || !s.Available() {
		return models.Err.MailServiceDisabled, "邮件服务未开启，请联系管理员"
	}

	c := s.smtpCfg()
	now := time.Now().Unix()

	// 重发冷却
	if last, err := s.db.LastVerifyCodeAt(qqNumber, database.PurposeQQBind); err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("查最近发码时刻失败: qq=%s err=%v", qqNumber, err))
		}
		return models.Err.DatabaseError, "系统繁忙，请稍后再试"
	} else if last > 0 && now-last < int64(c.ResendCooldownSeconds) {
		wait := int64(c.ResendCooldownSeconds) - (now - last)
		return models.Err.SendTooFrequent, fmt.Sprintf("请求过于频繁，请 %d 秒后再试", wait)
	}

	// 日额度自保 + 分钟限流
	// ★ 腾讯侧普通 QQ 邮箱日上限约 100~200 封且随风控浮动，
	// 宁可让玩家看到"今日额度已用完"，也不要让整个通道被风控停掉。
	if n, err := s.db.CountVerifyCodesSince(startOfToday()); err == nil {
		if n >= c.DailyLimit {
			if s.logger != nil {
				s.logger.Warn(fmt.Sprintf("QQ 绑定验证码已达每日上限 %d（今日 %d 封），拒绝继续发送", c.DailyLimit, n))
			}
			return models.Err.SendQuotaExhausted, "今日验证码额度已用完，请联系管理员"
		}
	} else if s.logger != nil {
		s.logger.Warn(fmt.Sprintf("统计今日发码量失败（跳过额度检查）: %v", err))
	}
	if n, err := s.db.CountVerifyCodesSince(now - 60); err == nil && n >= c.PerMinuteLimit {
		return models.Err.SendTooFrequent, "请求过于频繁，请稍后再试"
	}

	code, err := randomVerifyCode()
	if err != nil {
		return models.Err.MailSendFailed, "验证码生成失败，请稍后再试"
	}

	// 先作废旧码：任何时刻只有一个"活"码，否则点两次"获取"就有两个码能用，
	// 等于把 6 位码的爆破难度砍半。
	if err := s.db.InvalidateVerifyCodes(qqNumber, database.PurposeQQBind); err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("作废旧验证码失败: qq=%s err=%v", qqNumber, err))
		}
		return models.Err.DatabaseError, "系统繁忙，请稍后再试"
	}

	expiresAt := now + int64(c.CodeTTLSeconds)
	if err := s.db.SaveVerifyCode(
		qqNumber, database.PurposeQQBind,
		database.HashVerifyCode(qqNumber, database.PurposeQQBind, code),
		expiresAt, clientIP,
	); err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("保存验证码失败: qq=%s err=%v", qqNumber, err))
		}
		return models.Err.DatabaseError, "系统繁忙，请稍后再试"
	}

	to := qqNumber + "@qq.com"
	if err := s.sender.Send(to, bindMailSubject(), bindMailBody(code, qqNumber, account, c.CodeTTLSeconds)); err != nil {
		// ★ 发信失败必须把刚写进去的码作废。
		//
		// 不做这一步的话，会出现"玩家没收到信、但库里躺着一个有效码"的状态：
		// 他只要连点几次就可能撞上那个码绑成功，或者更糟 —— 库泄露时
		// 这个谁都收不到的码成了可用的后门。宁可让他重新走一遍流程。
		if ierr := s.db.InvalidateVerifyCodes(qqNumber, database.PurposeQQBind); ierr != nil && s.logger != nil {
			s.logger.Warn(fmt.Sprintf("发信失败后作废验证码也失败: qq=%s err=%v", qqNumber, ierr))
		}
		if s.logger != nil {
			// ⚠️ 只记账号/QQ 号和错误原因，**绝不记验证码明文和授权码**。
			s.logger.Error(fmt.Sprintf("验证码邮件发送失败: 账号=%s qq=%s err=%v", account, qqNumber, err))
		}
		return models.Err.MailSendFailed, "验证码发送失败，请稍后重试或联系管理员"
	}

	if s.logger != nil {
		s.logger.Info(fmt.Sprintf("已下发绑定验证码: 账号=%s qq=%s IP=%s 有效期=%ds",
			account, qqNumber, clientIP, c.CodeTTLSeconds))
	}
	return models.Err.Ok, "验证码已发送到 " + maskQQ(qqNumber) + " 的邮箱，请查收（含垃圾箱）"
}

// ── 绑定 ────────────────────────────────────────────────────────────────

// Bind 校验验证码并建立绑定。
func (s *QQBindService) Bind(account, qqNumber, code, clientIP string) (int, string) {
	account = strings.TrimSpace(account)
	qqNumber = strings.TrimSpace(qqNumber)
	code = strings.TrimSpace(code)

	if account == "" {
		return models.Err.AccountNotFound, "登录状态无效，请重新登录"
	}
	if !qqNumberRe.MatchString(qqNumber) {
		return models.Err.QQNumberInvalid, "QQ 号格式不正确（5~11 位数字）"
	}
	if code == "" {
		return models.Err.VerifyCodeInvalid, "请填写验证码"
	}

	now := time.Now().Unix()
	vc, hash, err := s.db.GetActiveVerifyCode(qqNumber, database.PurposeQQBind, now)
	if err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("取验证码失败: qq=%s err=%v", qqNumber, err))
		}
		return models.Err.DatabaseError, "系统繁忙，请稍后再试"
	}
	if vc == nil {
		return models.Err.VerifyCodeExpired, "验证码不存在或已过期，请重新获取"
	}
	if vc.Attempts >= maxVerifyCodeAttempts {
		return models.Err.VerifyCodeAttemptsExceed, "验证码错误次数过多，请重新获取"
	}

	// G-17（2026-10-08，审查报告）：改成恒定时间比较。
	// 上面已经有次数上限（maxVerifyCodeAttempts）兜着，单点风险低；但同一份代码里
	// 别处都用 security.ConstantTimeEquals，唯独这里用 `!=` 属口径不统一 ——
	// 哪天有人把次数上限调大或挪走，这条就变成真的时序泄漏了。
	if !security.ConstantTimeEquals(database.HashVerifyCode(qqNumber, database.PurposeQQBind, code), hash) {
		if err := s.db.BumpVerifyCodeAttempts(vc.ID); err != nil && s.logger != nil {
			s.logger.Warn(fmt.Sprintf("累加验证码错误次数失败: id=%d err=%v", vc.ID, err))
		}
		if s.logger != nil {
			s.logger.Warn(fmt.Sprintf("绑定验证码错误: 账号=%s qq=%s IP=%s 第 %d 次",
				account, qqNumber, clientIP, vc.Attempts+1))
		}
		left := maxVerifyCodeAttempts - vc.Attempts - 1
		if left <= 0 {
			return models.Err.VerifyCodeAttemptsExceed, "验证码错误次数过多，请重新获取"
		}
		return models.Err.VerifyCodeInvalid, fmt.Sprintf("验证码不正确，还可尝试 %d 次", left)
	}

	// 一次性消费：并发提交同一个码时，只有第一个能把 used 置 1。
	ok, err := s.db.MarkVerifyCodeUsed(vc.ID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("核销验证码失败: id=%d err=%v", vc.ID, err))
		}
		return models.Err.DatabaseError, "系统繁忙，请稍后再试"
	}
	if !ok {
		return models.Err.VerifyCodeExpired, "该验证码已被使用，请重新获取"
	}

	// 发码之后、提交之前，状态可能已经变了（玩家换了浏览器/被别人绑走）。
	// 唯一性不能只靠发码时的检查 —— 这里是最后一道闸。
	if err := s.db.BindQQ(qqNumber, account, clientIP); err != nil {
		switch {
		case errors.Is(err, database.ErrQQNumberTaken):
			return models.Err.QQNumberTaken, "该 QQ 号已被其他账号绑定"
		case errors.Is(err, database.ErrQQAlreadyBound):
			return models.Err.AccountAlreadyBound, "该账号已绑定 QQ 号，请先解绑"
		default:
			if s.logger != nil {
				s.logger.Error(fmt.Sprintf("写入绑定失败: 账号=%s qq=%s err=%v", account, qqNumber, err))
			}
			return models.Err.DatabaseError, "绑定失败，请稍后再试"
		}
	}

	if s.logger != nil {
		s.logger.Info(fmt.Sprintf("QQ 号绑定成功: 账号=%s qq=%s IP=%s", account, qqNumber, clientIP))
	}

	// 如果这个数字同时也是别人的账号名，就得把"带前缀登录"当场说清楚。
	// 否则他哪天用裸数字登录、进了别人的号、看到"密码错误"，只会来投诉，
	// 而客服那边也未必想得到是撞了账号名。
	//
	// 只在真有冲突时才加这句：没冲突的绝大多数玩家看到"请输入 qq:123456"
	// 反而会以为必须带前缀，于是把一个可选写法当成规定动作。
	if s.qqNumberConflictsWithAccountName(qqNumber, account) {
		return models.Err.Ok, fmt.Sprintf(
			"绑定成功。注意：%s 同时也是某个玩家的账号名，用 QQ 号登录时请输入 %s%s",
			maskQQ(qqNumber), loginQQPrefix, qqNumber)
	}
	return models.Err.Ok, "绑定成功，以后可以用 QQ 号 " + maskQQ(qqNumber) + " 登录"
}

// ── 解绑 ────────────────────────────────────────────────────────────────

// Unbind 解除账号的 QQ 号绑定。
//
// 只校验会话（调用方负责），不要求再收一次验证码：
// 绑定是"加一个登录入口"，解绑是"去掉它"，解绑失败的最坏结果只是
// 玩家继续用老账号名登录，不存在"解绑了别人的号"这种风险。
func (s *QQBindService) Unbind(account string) (int, string) {
	account = strings.TrimSpace(account)
	if account == "" {
		return models.Err.AccountNotFound, "登录状态无效，请重新登录"
	}

	qq, err := s.db.UnbindQQ(account)
	if err != nil {
		if errors.Is(err, database.ErrQQBindNotFound) {
			return models.Err.QQNotBound, "该账号未绑定 QQ 号"
		}
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("解绑失败: 账号=%s err=%v", account, err))
		}
		return models.Err.DatabaseError, "解绑失败，请稍后再试"
	}

	if s.logger != nil {
		s.logger.Info(fmt.Sprintf("QQ 号解绑成功: 账号=%s 原绑定=%s", account, qq))
	}
	return models.Err.Ok, "已解除与 " + maskQQ(qq) + " 的绑定"
}

// ── 辅助 ────────────────────────────────────────────────────────────────

func isAllDigits(s string) bool {
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return len(s) > 0
}

// randomVerifyCode 生成 6 位数字验证码。
//
// 用 crypto/rand 而不是 math/rand：后者由时间种子决定，
// 观察几个码就能推出下一个，等于验证码形同虚设。
func randomVerifyCode() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(b[:]) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

// startOfToday 返回本地时区今天 0 点的 Unix 秒（日额度统计窗口起点）。
func startOfToday() int64 {
	now := time.Now()
	y, m, d := now.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, now.Location()).Unix()
}

// maskQQ 把 QQ 号脱敏成 2805***962 的形式。
//
// 用途：给玩家看的提示里不要把完整 QQ 号回显一遍 ——
// 绑定时输入框里已经有完整的了，回显只会在截图/录屏里多泄露一次。
func maskQQ(qq string) string {
	if len(qq) <= 6 {
		return qq[:1] + "***" + qq[len(qq)-1:]
	}
	return qq[:4] + "***" + qq[len(qq)-3:]
}

func bindMailSubject() string {
	return "S4A21 账号绑定验证码"
}

// bindMailBody 拼验证码邮件正文。
//
// 两个刻意的选择：
//   - **不放链接**。带链接的邮件在 QQ 邮箱里更容易被判成垃圾邮件，
//     而这类邮件唯一的任务就是让玩家看到那 6 个数字。
//   - **写明来意和忽略方式**。玩家收到莫名其妙的验证码会当诈骗举报，
//     邮件里说清"用于把 QQ 号绑定到哪个账号"能省很多客服成本。
func bindMailBody(code, qqNumber, account string, ttlSeconds int) string {
	minutes := ttlSeconds / 60
	if minutes <= 0 {
		minutes = 1
	}
	var b strings.Builder
	b.WriteString("你的验证码是：" + code + "\n\n")
	b.WriteString(fmt.Sprintf("本次操作用于把 QQ 号 %s 绑定到游戏账号 %s。\n", qqNumber, account))
	b.WriteString(fmt.Sprintf("验证码 %d 分钟内有效，请勿转发给任何人。\n\n", minutes))
	b.WriteString("如果这不是你本人的操作，忽略本邮件即可，你的账号不会有任何变化。\n")
	b.WriteString("（本邮件为系统自动发送，请勿直接回复）\n")
	return b.String()
}
