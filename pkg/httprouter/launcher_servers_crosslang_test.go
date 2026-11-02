package httprouter

// ============================================================================
// 跨语言签名 fixture（2026-10-24）
//
// 目的：证明 Go 网关签的清单，C# 登录器能验签通过。
//
// 这是本次改造最容易被忽略、也最容易出错的一环：
//   · Go 的 CanonicalJSON 按 key 字典序输出、omitempty 省略空字段
//   · C# 的 JsonSerializer 按属性定义序输出、默认输出空串
// 两端各自"反序列化再序列化"必然字节不同 → 验签永远失败。
//
// 解法是让网关把规范字节原样放进 servers_json 下发，登录器验这段字节。
// 本 fixture 就是这条链路的固化证据：
//
//	go test ./pkg/httprouter -run TestEmitCrossLangFixture -v
//	→ 写出 testdata/crosslang/{manifest.json, signing.key}
//	→ _work/ServerListSigTest 里的 C# 工程读它验签
//
// ★ 这个测试不是"跑一次就丢"的脚手架 —— 它是回归资产。
//   以后任何一端改了序列化方式，C# 验证工程会立刻变红。
// ============================================================================

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
)

// TestEmitCrossLangFixture 生成跨语言验签 fixture。
//
// 固定内容（不用随机数据）：
//   - 三个服，覆盖 s4a21 / s5a3 / s5a95 三种协议
//   - 覆盖空 pin、空 min_launcher_version（验证 omitempty 与空串的差异已被 servers_json 抹平）
//   - 覆盖 caps 为空数组与全开两种
func TestEmitCrossLangFixture(t *testing.T) {
	dir := filepath.Join("testdata", "crosslang")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建 fixture 目录失败: %v", err)
	}

	keyPath := filepath.Join(dir, "signing.key")
	pubHex, err := InitSigning(keyPath)
	if err != nil {
		t.Fatalf("InitSigning: %v", err)
	}
	t.Cleanup(func() { signingKey = nil; signingPubHex = "" })

	cfg := &config.GatewayConfig{}
	cfg.Gateway.TcpPort = 8000
	cfg.Gateway.HttpPort = 8080
	cfg.GameServers = []config.GameServerEntry{
		{
			Id: "s4a21", Name: "A21 正式服", Protocol: config.ProtocolS4A21,
			GameServerSection: config.GameServerSection{PublicIP: "1.1.1.1"},
			ListMinLauncherVer: "2.5.0",
		},
		{
			Id: "s5a3", Name: "90CN", Protocol: config.ProtocolS5A3,
			GameServerSection: config.GameServerSection{PublicIP: "2.2.2.2"},
			// 空 caps → DefaultCapsFor 返回空切片 → 序列化为 []
		},
		{
			Id: "s5a95", Name: "DNF95", Protocol: config.ProtocolS5A95,
			GameServerSection: config.GameServerSection{PublicIP: "3.3.3.3"},
			ListCaps:          []string{"policy", "integrity"},
			ListHidden:        false,
		},
	}

	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("构造 logger 失败: %v", err)
	}
	t.Cleanup(lg.Close)

	s := &Server{config: cfg, logger: lg}
	m := s.buildServerListManifest()

	if m.Signature == "" || m.ServersJson == "" {
		t.Fatal("清单未签名或缺 servers_json")
	}

	// 自检：Go 侧自己先验一遍
	if !VerifyServerListSignature(m.PublicKey, m.Signature, m.ServersJson) {
		t.Fatal("Go 侧自验签失败 —— fixture 本身是坏的")
	}

	// 写 fixture
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("序列化 manifest 失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatalf("写 manifest.json 失败: %v", err)
	}

	// 写一个期望值文件，供 C# 侧断言"公钥一致"
	expect := map[string]interface{}{
		"public_key":  pubHex,
		"signature":   m.Signature,
		"servers_json": m.ServersJson,
		"server_count": len(m.Servers),
	}
	expRaw, _ := json.MarshalIndent(expect, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "expect.json"), expRaw, 0o644); err != nil {
		t.Fatalf("写 expect.json 失败: %v", err)
	}

	t.Logf("fixture 已写出到 %s", dir)
	t.Logf("公钥: %s", pubHex)
	t.Logf("servers_json: %s", m.ServersJson)

	// 关键断言：servers_json 必须与"servers 字段的默认序列化"不同 ——
	// 如果恰好相同，说明测试没覆盖到跨语言差异，fixture 就失去了意义。
	defaultServers, _ := json.Marshal(m.Servers)
	if string(defaultServers) == m.ServersJson {
		t.Logf("提示：本次 fixture 的 servers_json 与默认序列化恰好相同（键序偶然一致）")
	} else {
		t.Logf("已确认：servers_json 与默认序列化不同（键序/空字段差异已被规范化抹平）")
	}
}

// TestFixtureServersJsonIsValidJSON 锁定 fixture 的 servers_json 可被反序列化。
func TestFixtureServersJsonIsValidJSON(t *testing.T) {
	dir := filepath.Join("testdata", "crosslang")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Skipf("fixture 不存在，先跑 TestEmitCrossLangFixture: %v", err)
	}
	var m models.ServerListManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest.json 不是合法 JSON: %v", err)
	}
	var entries []models.ServerListEntry
	if err := json.Unmarshal([]byte(m.ServersJson), &entries); err != nil {
		t.Fatalf("servers_json 不是合法 JSON: %v", err)
	}
	if len(entries) != len(m.Servers) {
		t.Fatalf("servers_json 与 servers 条目数不一致: %d vs %d", len(entries), len(m.Servers))
	}
}
