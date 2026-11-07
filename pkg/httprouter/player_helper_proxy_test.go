package httprouter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// 玩家内辅转发（POST /api/account/helper）
//
// 这层的职责只有三件，用例也就钉这三件：
//  1. 能力值形状不对就**不转发**（它是短期凭证，别拿去做无谓的上游往返）；
//  2. 响应**原样透传**（宿主要求 {"ok":..,"binding":32位,"policy":..}，改写即失效）；
//  3. 失败用对状态码（宿主的 Transient 只看 5xx/408/429 可重试，4xx 是永久失败）。
// ─────────────────────────────────────────────────────────────────────────────

const testHelperCapability = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// helperServerEntry 造一个服条目。
// AccountApiUrl 在嵌入的 GameServerSection 上，复合字面量里不能直接赋值提升字段。
func helperServerEntry(id, accountAPIURL string) config.GameServerEntry {
	return config.GameServerEntry{
		Id:                id,
		GameServerSection: config.GameServerSection{AccountApiUrl: accountAPIURL},
	}
}

// newHelperProxyServer 造一个只带配置的最小 Server。
func newHelperProxyServer(servers ...config.GameServerEntry) *Server {
	return &Server{config: &config.GatewayConfig{GameServers: servers}}
}

func TestPlayerHelperProxyRejectsMalformedCapability(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s := newHelperProxyServer(helperServerEntry("s5a3", upstream.URL))
	for _, capability := range []string{
		"",                      // 缺失
		"abc",                   // 太短
		strings.Repeat("z", 64), // 非十六进制
		strings.Repeat("a", 63), // 差一位
	} {
		request := httptest.NewRequest(http.MethodPost, playerHelperProxyPath, strings.NewReader(`{"version":1}`))
		if capability != "" {
			request.Header.Set("X-DNF-Helper", capability)
		}
		recorder := httptest.NewRecorder()
		s.handlePlayerHelperProxy(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("capability=%q => %d, want 401", capability, recorder.Code)
		}
	}
	if called {
		t.Fatal("能力值不合法时不得访问上游")
	}
}

func TestPlayerHelperProxyWithoutUpstream(t *testing.T) {
	// 有服但没配 AccountApiUrl ⇒ 503（宿主会重试，不会把租约判死）。
	s := newHelperProxyServer(config.GameServerEntry{Id: "s5a3"})
	request := httptest.NewRequest(http.MethodPost, playerHelperProxyPath, strings.NewReader(`{}`))
	request.Header.Set("X-DNF-Helper", testHelperCapability)
	recorder := httptest.NewRecorder()
	s.handlePlayerHelperProxy(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("未配置上游 => %d, want 503", recorder.Code)
	}
}

// 响应必须逐字节透传，且请求头/请求体原样带过去。
func TestPlayerHelperProxyPassesThrough(t *testing.T) {
	const reply = `{"ok":true,"available":true,"binding":"0123456789abcdef0123456789abcdef","policy":{"gold":false}}`
	var gotCapability, gotForwardedFor, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCapability = r.Header.Get("X-DNF-Helper")
		gotForwardedFor = r.Header.Get("X-Forwarded-For")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(reply))
	}))
	defer upstream.Close()

	s := newHelperProxyServer(helperServerEntry("s5a3", upstream.URL))
	const body = `{"version":1,"action":"renew","binding":"0123456789abcdef0123456789abcdef"}`
	request := httptest.NewRequest(http.MethodPost, playerHelperProxyPath, strings.NewReader(body))
	request.RemoteAddr = "203.0.113.7:54321"
	request.Header.Set("X-DNF-Helper", testHelperCapability)
	recorder := httptest.NewRecorder()
	s.handlePlayerHelperProxy(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("状态码=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != reply {
		t.Fatalf("响应被改写了: %q", recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q，凭证类接口必须 no-store", got)
	}
	if gotCapability != testHelperCapability {
		t.Fatalf("能力值没有透传: %q", gotCapability)
	}
	if gotForwardedFor != "203.0.113.7" {
		t.Fatalf("X-Forwarded-For=%q，服务端按它记真实来源", gotForwardedFor)
	}
	if gotBody != body {
		t.Fatalf("请求体被改写: %q", gotBody)
	}
}

// 上游的 4xx/5xx 也必须原样回（含「功能未开启」的 404、「会话不可用」的 401）。
func TestPlayerHelperProxyPassesUpstreamFailure(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable} {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "upstream says no", status)
		}))
		s := newHelperProxyServer(helperServerEntry("s5a3", upstream.URL))
		request := httptest.NewRequest(http.MethodPost, playerHelperProxyPath, strings.NewReader(`{}`))
		request.Header.Set("X-DNF-Helper", testHelperCapability)
		recorder := httptest.NewRecorder()
		s.handlePlayerHelperProxy(recorder, request)
		upstream.Close()
		if recorder.Code != status {
			t.Fatalf("上游 %d 被改成了 %d", status, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "upstream says no") {
			t.Fatalf("上游错误体没透传: %q", recorder.Body.String())
		}
	}
}

func TestPlayerHelperProxyRejectsOversizedBody(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer upstream.Close()

	s := newHelperProxyServer(helperServerEntry("s5a3", upstream.URL))
	big := strings.Repeat("x", playerHelperMaxBodyBytes+1)
	request := httptest.NewRequest(http.MethodPost, playerHelperProxyPath, strings.NewReader(big))
	request.Header.Set("X-DNF-Helper", testHelperCapability)
	recorder := httptest.NewRecorder()
	s.handlePlayerHelperProxy(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限请求 => %d, want 413", recorder.Code)
	}
	if called {
		t.Fatal("超限请求不得转发到上游")
	}
}

// 多服网关靠 X-DNF-Server 选上游；不传则取第一个启用且配了地址的服。
func TestPlayerHelperProxySelectsUpstream(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"from":"first"}`))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"from":"second"}`))
	}))
	defer second.Close()

	s := newHelperProxyServer(
		helperServerEntry("s5a3", first.URL),
		helperServerEntry("s5a3-cn", second.URL),
	)

	call := func(server string) string {
		request := httptest.NewRequest(http.MethodPost, playerHelperProxyPath, strings.NewReader(`{}`))
		request.Header.Set("X-DNF-Helper", testHelperCapability)
		if server != "" {
			request.Header.Set(playerHelperServerHeader, server)
		}
		recorder := httptest.NewRecorder()
		s.handlePlayerHelperProxy(recorder, request)
		return recorder.Body.String()
	}

	if got := call(""); !strings.Contains(got, "first") {
		t.Fatalf("未指定服应取第一个: %q", got)
	}
	if got := call("s5a3-cn"); !strings.Contains(got, "second") {
		t.Fatalf("X-DNF-Server 未生效: %q", got)
	}
	// 指定了不存在的服 ⇒ 不回退到第一个（宁可 503 也不要打到别的服上）。
	request := httptest.NewRequest(http.MethodPost, playerHelperProxyPath, strings.NewReader(`{}`))
	request.Header.Set("X-DNF-Helper", testHelperCapability)
	request.Header.Set(playerHelperServerHeader, "no-such-server")
	recorder := httptest.NewRecorder()
	s.handlePlayerHelperProxy(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("指定不存在的服 => %d, want 503（不得回退）", recorder.Code)
	}
}
