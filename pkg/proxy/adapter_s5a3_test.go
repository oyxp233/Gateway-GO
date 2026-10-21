package proxy

import (
	"bytes"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// S5A3 服的代理侧强制设置
//
// 与 S5A95 的 TestNewProxyServerS5A95ForcedSettings 同一思路：配置里怎么写
// 都不算数，NewProxyServer 里对 S5A3 有两处硬性覆盖，这里把它们钉死。
// ─────────────────────────────────────────────────────────────────────────────

func s5a3TestConfig() *config.GatewayConfig {
	profile := config.GameServerEntry{
		Id:       "s5a3",
		Name:     "S5A3",
		Protocol: config.ProtocolS5A3,
	}
	profile.BackendHost = "127.0.0.1"
	profile.BackendChannelPort = 7001
	profile.ChannelListenerPort = 7001
	profile.GamePorts = []int{10006}
	profile.PartyUDPPorts = []int{30000, 30001}

	cfg := &config.GatewayConfig{}
	cfg.Gateway.ListenAddress = "127.0.0.1"
	cfg.GameServers = []config.GameServerEntry{profile}
	return cfg
}

func TestNewProxyServerS5A3ForcedSettings(t *testing.T) {
	cfg := s5a3TestConfig()
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(lg.Close)

	// 故意把两个开关全打开，验证被强制关掉
	profile := cfg.GameServers[0]
	profile.ProxyProtocol = "v1"
	profile.GamePortAuth.Enabled = true

	srv := NewProxyServer(cfg, profile, nil, lg, nil, nil)

	// 1) PROXY protocol 必须关：S5A3 服务端不认这行头，
	//    发了它会把 PROXY 行当成游戏包头，解析失败 → 玩家立刻掉线。
	if srv.profile.ProxyProtocol != "off" {
		t.Fatalf("S5A3 的 ProxyProtocol 应被强制为 off，实际 %q", srv.profile.ProxyProtocol)
	}

	// 2) 方案 D（游戏口首包凭证）必须关：S5A3 的游戏口是**服务端先说话**
	//    （先下发频道 greeting），网关等首包准入会与客户端互相干等到超时。
	if srv.profile.GamePortAuth.Enabled {
		t.Fatal("S5A3 的 GamePortAuth.Enabled 应被强制为 false")
	}

	// 3) 频道口必须绑透传适配器（不能是 nil，nil 与"显式透传"在
	//    copyDownlink 里行为相同，但 nil 会让人误以为"忘了配适配器"）。
	if srv.channelAdapter == nil {
		t.Fatal("S5A3 应绑定频道口透传适配器")
	}
	if _, ok := srv.channelAdapter.(s5a3PassthroughAdapter); !ok {
		t.Fatalf("S5A3 频道口适配器类型应为 s5a3PassthroughAdapter，实际 %T", srv.channelAdapter)
	}
}

// TestS5A3PassthroughAdapterKeepsBytes 透传适配器必须**逐字节**返回输入。
//
// 这条断言看着废话，但它守的是本分支的核心承诺：网关不理解也不改写
// S5A3 的频道帧。任何"顺手做个 trim/切帧"的改动都会让 CHANNELINFO 里的
// IP / 端口与服务端配置对不上，表现为客户端连不上频道。
func TestS5A3PassthroughAdapterKeepsBytes(t *testing.T) {
	adapter := NewS5A3PassthroughAdapter()

	cases := [][]byte{
		nil,
		{},
		{0x00},
		bytes.Repeat([]byte{0xFF}, 1500),
		[]byte("class0/op1 CHANNELINFO \x00\xb5\xb5"),
	}
	for index, input := range cases {
		got := adapter.ProcessDownlink(input, nil)
		if !bytes.Equal(got, input) {
			t.Fatalf("用例 %d：透传后字节不一致\n输入 %x\n输出 %x", index, input, got)
		}
	}
}

// TestStartUDPRelaysSkipsNonS5A3 非 S5A3 服不应开任何 UDP 监听。
func TestStartUDPRelaysSkipsNonS5A3(t *testing.T) {
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(lg.Close)

	cfg := &config.GatewayConfig{}
	profile := config.GameServerEntry{Id: "s4a21", Protocol: config.ProtocolS4A21}
	profile.BackendHost = "127.0.0.1"
	profile.PartyUDPPorts = []int{30000} // 即便配了端口，非 s5a3 也不该启用
	cfg.GameServers = []config.GameServerEntry{profile}

	mgr := StartUDPRelays(cfg, lg)
	t.Cleanup(mgr.Stop)
	if mgr.Count() != 0 {
		t.Fatalf("非 S5A3 服不应启用 UDP 中继，实际启用 %d 个", mgr.Count())
	}
}
