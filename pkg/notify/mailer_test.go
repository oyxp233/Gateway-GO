package notify

import (
	"encoding/base64"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
)

func TestBuildMessageEncodesChineseSubject(t *testing.T) {
	msg := string(buildMessage("S4A21", "sender@qq.com", "123456@qq.com", "S4A21 验证码", "你的验证码是 123456"))

	// 主题必须做 RFC 2047 编码，否则中文在 SMTP 链路上会被毁掉。
	if !strings.Contains(msg, "Subject: =?utf-8?") {
		t.Fatalf("主题未做 RFC2047 编码:\n%s", msg)
	}
	if strings.Contains(msg, "Subject: S4A21 验证码") {
		t.Fatalf("主题里出现了未编码的原始中文:\n%s", msg)
	}
	// 头部必须是 CRLF 分隔（裸 \n 会被严格的 SMTP 服务端拒绝）。
	if !strings.Contains(msg, "\r\n") {
		t.Fatalf("邮件头缺少 CRLF")
	}
	if !strings.Contains(msg, "To: <123456@qq.com>") {
		t.Fatalf("收件人头不正确:\n%s", msg)
	}
	if !strings.Contains(msg, "From: ") || !strings.Contains(msg, "<sender@qq.com>") {
		t.Fatalf("发件人头不正确:\n%s", msg)
	}
}

func TestBuildMessageBodyRoundTrip(t *testing.T) {
	body := "你的验证码是 123456，5 分钟内有效。\n若非本人操作请忽略本邮件。"
	msg := string(buildMessage("测试", "s@qq.com", "r@qq.com", "验证码", body))

	idx := strings.Index(msg, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("找不到头部与正文的分隔")
	}
	raw := msg[idx+4:]

	// 去掉折行后 base64 解码，必须与原文逐字一致 —— 中文不能被转码毁掉。
	joined := strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", ""), "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(joined)
	if err != nil {
		t.Fatalf("正文不是合法 base64: %v", err)
	}
	if string(decoded) != body {
		t.Fatalf("正文往返不一致:\n期望 %q\n实得 %q", body, string(decoded))
	}
}

func TestBuildMessageFoldsLongLines(t *testing.T) {
	// RFC 2045 要求 base64 每行不超过 76 字符，超长正文必须折行。
	body := strings.Repeat("验证码", 200)
	msg := string(buildMessage("S4A21", "s@qq.com", "r@qq.com", "subject", body))

	idx := strings.Index(msg, "\r\n\r\n")
	if idx < 0 {
		t.Fatalf("找不到头部与正文的分隔")
	}
	for _, line := range strings.Split(msg[idx+4:], "\r\n") {
		if len(line) > 76 {
			t.Fatalf("base64 行超长（%d 字符）", len(line))
		}
	}
}

func TestBuildMessageFallsBackToAddressWhenNoName(t *testing.T) {
	msg := string(buildMessage("", "sender@qq.com", "r@qq.com", "s", "b"))
	if !strings.Contains(msg, "<sender@qq.com>") {
		t.Fatalf("FromName 为空时应回退成邮箱地址:\n%s", msg)
	}
}

func TestMailerEnabledRequiresConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.SmtpSection
		want bool
	}{
		{"全空", config.SmtpSection{}, false},
		{"只开开关没主机", config.SmtpSection{Enabled: true, Username: "u@qq.com"}, false},
		{"只开开关没账号", config.SmtpSection{Enabled: true, Host: "smtp.qq.com"}, false},
		{"开关关着但配置齐全", config.SmtpSection{Host: "smtp.qq.com", Username: "u@qq.com"}, false},
		{"配置齐全且开启", config.SmtpSection{Enabled: true, Host: "smtp.qq.com", Username: "u@qq.com"}, true},
	}
	for _, c := range cases {
		if got := NewMailer(c.cfg).Enabled(); got != c.want {
			t.Errorf("%s: Enabled() = %v, 期望 %v", c.name, got, c.want)
		}
	}
}

func TestMailerPasswordConfigured(t *testing.T) {
	if NewMailer(config.SmtpSection{Enabled: true, Host: "smtp.qq.com", Username: "u@qq.com"}).PasswordConfigured() {
		t.Fatal("没配授权码时 PasswordConfigured 应为 false")
	}
	if !NewMailer(config.SmtpSection{Password: "x"}).PasswordConfigured() {
		t.Fatal("配了授权码时 PasswordConfigured 应为 true")
	}
}

func TestNewMailerDefaults(t *testing.T) {
	m := NewMailer(config.SmtpSection{Host: "smtp.qq.com"})
	if m.addr != "smtp.qq.com:465" {
		t.Fatalf("端口兜底失败，addr = %s", m.addr)
	}
	if m.timeout.Seconds() != 15 {
		t.Fatalf("超时兜底失败，timeout = %v", m.timeout)
	}
}

func TestMailerSendRejectsWhenDisabled(t *testing.T) {
	m := NewMailer(config.SmtpSection{})
	if err := m.Send("a@qq.com", "s", "b"); err == nil {
		t.Fatal("未启用时 Send 必须返回错误，不能静默成功")
	}
}

// ★ 授权码绝不能被带进错误信息（错误会进日志、日志可能被贴进工单）。
func TestMailerErrorDoesNotLeakPassword(t *testing.T) {
	const secret = "abcdefghijklmnop"
	m := NewMailer(config.SmtpSection{
		Enabled:  true,
		Host:     "127.0.0.1",
		Port:     1, // 必然连不上
		UseSSL:   false,
		Username: "u@qq.com",
		Password: secret,
	})
	err := m.Send("a@qq.com", "主题", "正文")
	if err == nil {
		t.Skip("127.0.0.1:1 竟然连上了，跳过")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("错误信息泄露了授权码: %v", err)
	}
}
