package httprouter

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
)

// ============================================================================
// 服清单下发（三服合一，2026-10-24）
//
// 三条不变量：
//   ① 只下发启用的、非隐藏的服；
//   ② 端点留空时从全局配置推导（不是留空下发）；
//   ③ 签名可被编译期公钥验证，篡改清单必须验签失败。
// ============================================================================

func newServersServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.GatewayConfig{}
	cfg.Gateway.TcpPort = 8000
	cfg.Gateway.HttpPort = 8080
	cfg.GameServers = []config.GameServerEntry{
		{
			Id: "s4a21", Name: "A21", Protocol: config.ProtocolS4A21,
			GameServerSection: config.GameServerSection{PublicIP: "1.1.1.1"},
		},
		{
			Id: "s5a3", Name: "90CN", Protocol: config.ProtocolS5A3,
			GameServerSection: config.GameServerSection{PublicIP: "2.2.2.2"},
		},
	}
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("构造 logger 失败: %v", err)
	}
	// Windows 上日志文件句柄不关会让 TempDir 清理失败（unlinkat 报"正在使用"）
	t.Cleanup(lg.Close)
	return &Server{config: cfg, logger: lg}
}

// TestServerListExcludesDisabledAndHidden 锁定"停用/隐藏的服不出现在清单里"。
func TestServerListExcludesDisabledAndHidden(t *testing.T) {
	s := newServersServer(t)

	// 加一个停用的服和一个隐藏的服
	disabled := false
	s.config.GameServers = append(s.config.GameServers,
		config.GameServerEntry{
			Id: "off", Name: "停用", Protocol: config.ProtocolS4A21, Enabled: &disabled,
		},
		config.GameServerEntry{
			Id: "hidden", Name: "隐藏", Protocol: config.ProtocolS4A21, ListHidden: true,
		})

	m := s.buildServerListManifest()
	if len(m.Servers) != 2 {
		t.Fatalf("应只下发 2 个服，实得 %d: %+v", len(m.Servers), m.Servers)
	}
	for _, e := range m.Servers {
		if e.Id == "off" || e.Id == "hidden" {
			t.Fatalf("停用/隐藏的服不该出现在清单里: %s", e.Id)
		}
	}
}

// TestServerListDerivesEndpoints 锁定"留空时从全局配置推导"。
func TestServerListDerivesEndpoints(t *testing.T) {
	s := newServersServer(t)
	m := s.buildServerListManifest()

	for _, e := range m.Servers {
		if e.AuthPort != 8000 {
			t.Fatalf("服 %s 的 auth_port 应推导为 8000，实得 %d", e.Id, e.AuthPort)
		}
		if e.HttpPort != 8080 {
			t.Fatalf("服 %s 的 http_port 应推导为 8080，实得 %d", e.Id, e.HttpPort)
		}
		if e.Host == "" {
			t.Fatalf("服 %s 的 host 应推导为 PublicIP，实得空", e.Id)
		}
	}
}

// TestServerListExplicitOverridesGlobal 锁定"显式配置优先于全局默认"。
func TestServerListExplicitOverridesGlobal(t *testing.T) {
	s := newServersServer(t)
	tlsOn := true
	s.config.GameServers[1].ListHost = "gw.example.com"
	s.config.GameServers[1].ListAuthPort = 9000
	s.config.GameServers[1].ListHttpPort = 9443
	s.config.GameServers[1].ListTls = &tlsOn
	s.config.GameServers[1].ListPin = "ABCDEF"

	m := s.buildServerListManifest()
	var s5a3 *models.ServerListEntry
	for i := range m.Servers {
		if m.Servers[i].Id == "s5a3" {
			s5a3 = &m.Servers[i]
		}
	}
	if s5a3 == nil {
		t.Fatal("清单里找不到 s5a3")
	}
	if s5a3.Host != "gw.example.com" || s5a3.AuthPort != 9000 || s5a3.HttpPort != 9443 {
		t.Fatalf("显式端点未生效: %+v", s5a3)
	}
	if !s5a3.Tls || s5a3.Pin != "ABCDEF" {
		t.Fatalf("显式 TLS/pin 未生效: %+v", s5a3)
	}
}

// TestServerListCapsByProtocol 锁定 caps 的协议默认值 ——
// S5A3 五项全关（空 caps），S4A21 全开。这条是"门禁按服下发"的基线。
func TestServerListCapsByProtocol(t *testing.T) {
	s := newServersServer(t)
	m := s.buildServerListManifest()

	for _, e := range m.Servers {
		switch e.Protocol {
		case config.ProtocolS5A3:
			if len(e.Caps) != 0 {
				t.Fatalf("S5A3 的 caps 应为空（五项全关），实得 %v", e.Caps)
			}
		case config.ProtocolS4A21:
			for _, want := range []string{"pvf", "plugins", "integrity", "kernel"} {
				found := false
				for _, c := range e.Caps {
					if c == want {
						found = true
					}
				}
				if !found {
					t.Fatalf("S4A21 的 caps 缺 %s，实得 %v", want, e.Caps)
				}
			}
		}
	}
}

// TestServerListSigned 锁定"清单签名可被公钥验证，篡改后验签失败"。
//
// 这是整条信任链的核心：登录器拿到清单后必须能证明它来自网关。
//
// ★ 签名覆盖 ServersJson 的字节（不是 Servers 的再序列化）——
//   这是跨语言验签能成立的关键，见 models.ServerListManifest 的注释。
func TestServerListSigned(t *testing.T) {
	dir := t.TempDir()
	pubHex, err := InitSigning(dir + "/signing.key")
	if err != nil {
		t.Fatalf("InitSigning: %v", err)
	}
	if pubHex == "" {
		t.Fatal("InitSigning 未返回公钥")
	}
	t.Cleanup(func() { signingKey = nil; signingPubHex = "" })

	s := newServersServer(t)
	m := s.buildServerListManifest()

	if m.Signature == "" {
		t.Fatal("清单未签名")
	}
	if m.ServersJson == "" {
		t.Fatal("清单缺 ServersJson（签名原文）—— 登录器将无法验签")
	}
	if m.PublicKey != pubHex {
		t.Fatalf("清单公钥与初始化的公钥不一致")
	}

	// 验签必须通过（用 ServersJson 的字节）
	if !VerifyServerListSignature(m.PublicKey, m.Signature, m.ServersJson) {
		t.Fatal("清单验签失败")
	}

	// ServersJson 必须是合法 JSON 且与 Servers 内容等价
	var fromJSON []models.ServerListEntry
	if err := json.Unmarshal([]byte(m.ServersJson), &fromJSON); err != nil {
		t.Fatalf("ServersJson 不是合法 JSON: %v (%s)", err, m.ServersJson)
	}
	if len(fromJSON) != len(m.Servers) {
		t.Fatalf("ServersJson 与 Servers 条目数不一致: %d vs %d", len(fromJSON), len(m.Servers))
	}

	// 篡改 ServersJson（加一个服）必须验签失败
	tampered := `[{"id":"evil","name":"假服","protocol":"s4a21","host":"6.6.6.6","auth_port":8000,"http_port":8080,"tls":false,"caps":null}]`
	if VerifyServerListSignature(m.PublicKey, m.Signature, tampered) {
		t.Fatal("篡改清单后验签竟然通过 —— 签名链路失效")
	}

	// 篡改某个服的端口也必须失败
	var mod []models.ServerListEntry
	_ = json.Unmarshal([]byte(m.ServersJson), &mod)
	mod[0].AuthPort = 9999
	modJSON, _ := json.Marshal(mod)
	if VerifyServerListSignature(m.PublicKey, m.Signature, string(modJSON)) {
		t.Fatal("篡改端点后验签竟然通过")
	}
}

// TestServerListUnsignedWhenNoKey 锁定"未配置私钥时 signature 为空，清单仍下发"。
//
// 这是刻意的降级：没有签名不等于没有清单，登录器侧按"未签名"处理。
func TestServerListUnsignedWhenNoKey(t *testing.T) {
	signingKey = nil
	signingPubHex = ""

	s := newServersServer(t)
	m := s.buildServerListManifest()

	if len(m.Servers) != 2 {
		t.Fatalf("无签名时清单仍应下发，实得 %d 个服", len(m.Servers))
	}
	if m.Signature != "" {
		t.Fatal("无密钥时不该有签名")
	}
}

// TestServerListHandlerWritesJSON 锁定 HTTP 层能正常序列化（字段名是 snake_case）。
func TestServerListHandlerWritesJSON(t *testing.T) {
	s := newServersServer(t)
	req := httptest.NewRequest("GET", "/api/launcher/servers", nil)
	w := httptest.NewRecorder()

	s.handleLauncherServers(w, req)

	if w.Code != 200 {
		t.Fatalf("状态码应为 200，实得 %d", w.Code)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v (%s)", err, w.Body.String())
	}
	if _, ok := got["servers"]; !ok {
		t.Fatalf("响应缺 servers 字段: %s", w.Body.String())
	}
	if _, ok := got["expires_at"]; !ok {
		t.Fatalf("响应缺 expires_at 字段: %s", w.Body.String())
	}

	// 服条目的字段名必须是 snake_case（登录器按此反序列化）
	servers := got["servers"].([]interface{})
	first := servers[0].(map[string]interface{})
	for _, k := range []string{"id", "name", "protocol", "host", "auth_port", "http_port", "tls", "caps"} {
		if _, ok := first[k]; !ok {
			t.Fatalf("服条目缺字段 %s: %v", k, first)
		}
	}
}
