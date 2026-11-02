package service

// ============================================================================
// X-Forwarded-For 透传（2026-10-25 修复的回归防线）
//
// 背景：网关是用户态 HTTP 客户端，S5A3 服务端看到的 TCP 对端恒为 127.0.0.1。
// 网关转发账号 API 时若不设 X-Forwarded-For：
//   ① dnf90_web_accounts.last_login_ip 全记成 127.0.0.1
//      → 后台「账号管理」的 IP 列对所有人都是 127.0.0.1
//   ② 服务端账号 API 的按 IP 限流（allowRate）把所有玩家算成同一个来源
//      → 一个人刷几次就把全服卡住
//
// 服务端侧读取逻辑见 Server-S5A3 的 account_api.go:accountAPIClientIP，
// 优先取 XFF 第一段。本测试钉住"网关侧确实把这行头发出去了"。
// ============================================================================

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"s4a21-gateway/pkg/config"
)

// newXFFProbe 起一个假账号服务，把收到的 XFF 值回传出来。
func newXFFProbe(t *testing.T, gotXFF *string, gotCount *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotCount++
		*gotXFF = r.Header.Get("X-Forwarded-For")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"account_id":"dnf:10001","token":"tok"}`))
	}))
}

func newXFFClient(serverURL string) *s5a3AccountClient {
	enabled := true
	return newS5A3AccountClient(config.GameServerEntry{
		// AccountApiUrl 属于内嵌的 GameServerSection，必须在字面量里显式给出
		// 那一层（Go 1.22 的 -lang 不允许在字面量里直接写 promoted field）。
		GameServerSection: config.GameServerSection{
			AccountApiUrl: serverURL,
		},
		Id:       "s5a3",
		Protocol: "s5a3",
		Enabled:  &enabled,
	})
}

// TestS5A3AccountForwardsClientIP 验证注册与登录都带上真实玩家 IP。
func TestS5A3AccountForwardsClientIP(t *testing.T) {
	var gotXFF string
	var calls int
	server := newXFFProbe(t, &gotXFF, &calls)
	defer server.Close()

	client := newXFFClient(server.URL)

	if code, msg := client.register(context.Background(), "player1", "pw", "203.0.113.7"); code != 0 {
		t.Fatalf("register 失败: code=%d msg=%s", code, msg)
	}
	if gotXFF != "203.0.113.7" {
		t.Fatalf("注册请求的 X-Forwarded-For = %q，期望 203.0.113.7", gotXFF)
	}

	gotXFF = ""
	if _, code, msg := client.login(context.Background(), "player1", "pw", "198.51.100.9"); code != 0 {
		t.Fatalf("login 失败: code=%d msg=%s", code, msg)
	}
	if gotXFF != "198.51.100.9" {
		t.Fatalf("登录请求的 X-Forwarded-For = %q，期望 198.51.100.9", gotXFF)
	}

	if calls != 2 {
		t.Fatalf("假服务端收到 %d 次请求，期望 2 次", calls)
	}
}

// TestS5A3AccountOmitsXFFWhenIPEmpty 验证拿不到 IP 时不发这个头。
//
// 宁可让服务端回落到 RemoteAddr（127.0.0.1），也不要发一个空值 ——
// 空值会被 accountAPIClientIP 当成"有 XFF 但解析不出来"，然后回落，
// 行为一样但日志更容易误导。
func TestS5A3AccountOmitsXFFWhenIPEmpty(t *testing.T) {
	var gotXFF string
	var calls int
	server := newXFFProbe(t, &gotXFF, &calls)
	defer server.Close()

	client := newXFFClient(server.URL)
	if code, msg := client.register(context.Background(), "player2", "pw", ""); code != 0 {
		t.Fatalf("register 失败: code=%d msg=%s", code, msg)
	}
	if gotXFF != "" {
		t.Fatalf("空 IP 时不该发 X-Forwarded-For，实际 = %q", gotXFF)
	}
}
