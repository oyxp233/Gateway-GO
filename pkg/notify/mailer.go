// Package notify 提供网关对外的通知能力（目前只有邮件）。
//
// 为什么单独开一个包：发信是**不可靠的外部依赖** —— SMTP 会超时、会被风控、
// 邮件会被丢进垃圾箱。把它隔离在这里，业务层（service.QQBindService）只依赖
// Sender 接口：单测换成假实现，不碰网络；真机上出问题也只需要看这一个文件。
package notify

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"s4a21-gateway/pkg/config"
)

// Sender 是发信能力的抽象。
//
// 业务层依赖接口而不是 *Mailer，测试才能不连 SMTP 就把「发码 → 校验 → 绑定」
// 整条链路跑完。
type Sender interface {
	Send(to, subject, body string) error
}

// Mailer 是基于 net/smtp 的 Sender 实现。
//
// 支持两种连接方式：
//   - UseSSL=true（端口 465）：握手即 TLS（QQ 邮箱用这个）；
//   - UseSSL=false（端口 587）：先明文再 STARTTLS。
//
// 无共享可变状态，可被多个 goroutine 并发调用 —— 每次发送都新建连接。
type Mailer struct {
	cfg     config.SmtpSection
	auth    smtp.Auth
	addr    string
	timeout time.Duration
}

// NewMailer 按配置构造 Mailer。参数不合法时不做校验、只走兜底默认值，
// 真正能不能发由 Enabled() 决定。
func NewMailer(cfg config.SmtpSection) *Mailer {
	host := strings.TrimSpace(cfg.Host)
	port := cfg.Port
	if port == 0 {
		port = 465
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Mailer{
		cfg:     cfg,
		auth:    smtp.PlainAuth("", cfg.Username, cfg.Password, host),
		addr:    net.JoinHostPort(host, strconv.Itoa(port)),
		timeout: timeout,
	}
}

// Enabled 报告发信能力是否可用：开关打开、且主机与账号都配了。
//
// 未启用时业务层要给出明确提示（"邮件服务未开启，请联系管理员"），
// 而不是让玩家对着一个永远不来的验证码等 5 分钟。
func (m *Mailer) Enabled() bool {
	if m == nil || !m.cfg.Enabled {
		return false
	}
	return strings.TrimSpace(m.cfg.Host) != "" && strings.TrimSpace(m.cfg.Username) != ""
}

// PasswordConfigured 报告授权码是否已注入（只看有没有，不返回内容）。
//
// 用于启动自检：Enabled=true 但授权码为空 = 配置漏了环境变量，
// 这种"看着开了其实发不出去"的状态要能在日志里一眼看出来。
func (m *Mailer) PasswordConfigured() bool {
	return m != nil && strings.TrimSpace(m.cfg.Password) != ""
}

// Send 发送一封纯文本邮件。
//
// 返回的 error 不会包含授权码 —— SMTP 服务端的应答文本里只有状态码与描述。
func (m *Mailer) Send(to, subject, body string) error {
	if !m.Enabled() {
		return fmt.Errorf("邮件服务未启用")
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("收件人为空")
	}
	from := strings.TrimSpace(m.cfg.Username)

	msg := buildMessage(m.cfg.FromName, from, to, subject, body)

	conn, err := m.dial()
	if err != nil {
		return fmt.Errorf("连接邮件服务器失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(m.timeout))

	c, err := smtp.NewClient(conn, strings.TrimSpace(m.cfg.Host))
	if err != nil {
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer c.Close()

	if !m.cfg.UseSSL {
		if err := c.StartTLS(&tls.Config{ServerName: strings.TrimSpace(m.cfg.Host)}); err != nil {
			return fmt.Errorf("STARTTLS 失败: %w", err)
		}
	}
	if err := c.Auth(m.auth); err != nil {
		return fmt.Errorf("SMTP 认证失败: %w", err)
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM 被拒: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO 被拒: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA 被拒: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("写入邮件正文失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("提交邮件失败: %w", err)
	}
	// Quit 的失败不影响"邮件已提交"这个事实，忽略即可。
	_ = c.Quit()
	return nil
}

func (m *Mailer) dial() (net.Conn, error) {
	host := strings.TrimSpace(m.cfg.Host)
	if m.cfg.UseSSL {
		d := &net.Dialer{Timeout: m.timeout}
		return tls.DialWithDialer(d, "tcp", m.addr, &tls.Config{ServerName: host})
	}
	return net.DialTimeout("tcp", m.addr, m.timeout)
}

// buildMessage 拼一封纯文本邮件。
//
// 两个关键点（踩过才知道）：
//   - 主题含中文必须做 RFC 2047 编码，否则被服务端拒或显示成乱码；
//   - 正文用 base64 + UTF-8，避免中文在传输链路上被转码毁掉。
//
// 正文**故意不放链接** —— 带链接的邮件在 QQ 邮箱里更容易被判定为垃圾邮件，
// 而验证码邮件的唯一任务就是让玩家看到那 6 个数字。
func buildMessage(fromName, from, to, subject, body string) []byte {
	var b bytes.Buffer
	name := strings.TrimSpace(fromName)
	if name == "" {
		name = from
	}
	b.WriteString("From: " + mime.QEncoding.Encode("utf-8", name) + " <" + from + ">\r\n")
	b.WriteString("To: <" + to + ">\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")

	// base64 后按 76 字符折行（RFC 2045 要求每行不超过 76）。
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	b.WriteString("\r\n")
	return b.Bytes()
}
