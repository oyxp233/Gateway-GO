package httprouter

import (
	"net/http/httptest"
	"testing"
)

// 本文件钉死 clientIPOf 的两条硬约束（2026-11-01）：
//
//  1. 请求来自**本机反代**（RemoteAddr 是回环）时，必须取转发头里的真实来源 ——
//     否则所有 Web 注册共用 127.0.0.1 一个 IP 配额，当天第二个人就被限额挡住。
//  2. 请求来自**公网直连**时，必须忽略转发头 ——
//     否则客户端伪造 X-Forwarded-For 就能绕过「同 IP 每日注册数」。
//
// 这两条是相反的，任何一边退让都会出事，所以两边都要有断言。
func TestClientIPOfTrustsForwardedHeadersOnlyFromLoopback(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		realIP     string
		xff        string
		want       string
	}{
		{
			name:       "本机反代 + X-Real-IP",
			remoteAddr: "127.0.0.1:54321",
			realIP:     "203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "本机反代 + 只有 XFF（取最后一段）",
			remoteAddr: "127.0.0.1:54321",
			xff:        "1.1.1.1, 203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "本机反代 + XFF 首段是伪造的（仍取最后一段）",
			remoteAddr: "127.0.0.1:54321",
			xff:        "9.9.9.9, 203.0.113.7",
			want:       "203.0.113.7",
		},
		{
			name:       "本机反代 + XFF 带端口",
			remoteAddr: "127.0.0.1:54321",
			xff:        "203.0.113.7:1234",
			want:       "203.0.113.7",
		},
		{
			name:       "本机反代 + IPv6 回环 + X-Real-IP",
			remoteAddr: "[::1]:54321",
			realIP:     "203.0.113.8",
			want:       "203.0.113.8",
		},
		{
			name:       "本机反代但没带转发头 → 退回回环地址",
			remoteAddr: "127.0.0.1:54321",
			want:       "127.0.0.1",
		},
		{
			name:       "★ 公网直连 + 伪造 XFF → 必须忽略，用远端地址",
			remoteAddr: "198.51.100.9:40000",
			xff:        "203.0.113.7",
			realIP:     "203.0.113.7",
			want:       "198.51.100.9",
		},
		{
			name:       "公网直连 + IPv6",
			remoteAddr: "[2001:db8::1]:40000",
			want:       "2001:db8::1",
		},
		{
			name:       "远端地址异常 → unknown",
			remoteAddr: "",
			want:       "unknown",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/register", nil)
			r.RemoteAddr = c.remoteAddr
			if c.realIP != "" {
				r.Header.Set("X-Real-IP", c.realIP)
			}
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := clientIPOf(r); got != c.want {
				t.Fatalf("clientIPOf = %q, want %q", got, c.want)
			}
		})
	}
}

// lastForwardedIP 遇到全垃圾值时返回空串（而不是把垃圾当 IP 写进库）。
func TestLastForwardedIPIgnoresGarbage(t *testing.T) {
	for _, raw := range []string{"", "  ", "not-an-ip", "1.2.3.4.5", "abc, def"} {
		if got := lastForwardedIP(raw); got != "" {
			t.Fatalf("lastForwardedIP(%q) = %q, want empty", raw, got)
		}
	}
	if got := lastForwardedIP("1.2.3.4, 5.6.7.8"); got != "5.6.7.8" {
		t.Fatalf("lastForwardedIP 取最后一段失败: %q", got)
	}
}
