package config

import "testing"

// ────────────────────────────────────────────────────────────────────────
// 多服端口校验（2026-10-16 修的自指缺陷）
//
// 缺陷形态：单服配置里 ChannelListenerPort=0 表示"沿用 Gateway.ProxyPort"，
// 而校验拿这个继承来的值去和 ProxyPort 比 → 必然判成碰撞 →
// **配置加载 Fatal，进程拒绝启动**。
//
// 危害面是所有"只有旧 GameServer 段"的存量配置（161 线上就是这种），
// 而且只在**换二进制/重启**那一刻才炸 —— 平时完全看不出来。
// 这两条断言正是"能不能启动"这件事本身，不是某个功能好不好用。
// ────────────────────────────────────────────────────────────────────────

// legacyServerConfig 造一份「只有旧 GameServer 段」的配置 ——
// 与 161 线上 appsettings.json 的形态一致（GameServers 键压根不存在）。
func legacyServerConfig() *GatewayConfig {
	c := DefaultConfig()
	c.Gateway.TcpPort = 8000
	c.Gateway.HttpPort = 8080
	c.Gateway.ProxyPort = 8001
	c.Gateway.AdminHttpPort = 8443
	c.Gateway.InternalPort = 18080
	c.GameServers = nil
	c.GameServer = GameServerSection{
		PublicIP:           "1.2.3.4",
		BackendHost:        "127.0.0.1",
		BackendChannelPort: 7001,
	}
	return c
}

// TestLegacySingleServerConfigLoads 存量单服配置必须能正常加载（能启动）。
//
// 这条是本次修复的**核心断言**：改回"继承值参与碰撞判定"它必须立刻红。
func TestLegacySingleServerConfigLoads(t *testing.T) {
	c := legacyServerConfig()
	if err := c.NormalizeGameServers(); err != nil {
		t.Fatalf("只有旧 GameServer 段的配置必须能加载，实际报错: %v", err)
	}
	if len(c.GameServers) != 1 {
		t.Fatalf("应合成 1 个服条目，实得 %d", len(c.GameServers))
	}
	// 继承口径不能变：单服时频道口 == ProxyPort
	e := c.GameServers[0]
	channel := e.ChannelListenerPort
	if channel == 0 {
		channel = c.Gateway.ProxyPort
	}
	if channel != c.Gateway.ProxyPort {
		t.Errorf("单服频道口应沿用 ProxyPort(%d)，实得 %d", c.Gateway.ProxyPort, channel)
	}
	// 派生镜像要回写到 GameServer（老读取方靠它工作）
	if c.GameServer.BackendHost != "127.0.0.1" {
		t.Errorf("派生镜像未回写: %+v", c.GameServer)
	}
}

// TestChannelPortRealCollisionStillRejected 真的撞上别的端口时照样要拒
// （修自指缺陷不能顺手把真碰撞也放开）。
func TestChannelPortRealCollisionStillRejected(t *testing.T) {
	// 显式把频道口配成 TCP 端口 —— 真碰撞
	c := legacyServerConfig()
	enabled := true
	c.GameServers = []GameServerEntry{{
		Id: "s4a21", Protocol: ProtocolS4A21, Enabled: &enabled,
		ChannelListenerPort: c.Gateway.TcpPort,
	}}
	if err := c.NormalizeGameServers(); err == nil {
		t.Fatal("频道口撞 Gateway.TcpPort 必须被拒，实际通过了")
	}

	// 多服撞同一个频道口 —— 真碰撞
	c2 := legacyServerConfig()
	c2.GameServers = []GameServerEntry{
		{Id: "a", Protocol: ProtocolS4A21, Enabled: &enabled, ChannelListenerPort: 9001},
		{Id: "b", Protocol: ProtocolS4A21, Enabled: &enabled, ChannelListenerPort: 9001},
	}
	if err := c2.NormalizeGameServers(); err == nil {
		t.Fatal("两个服共用一个频道口必须被拒，实际通过了")
	}

	// 撞内部 API 端口 —— 真碰撞
	c3 := legacyServerConfig()
	c3.GameServers = []GameServerEntry{{
		Id: "s4a21", Protocol: ProtocolS4A21, Enabled: &enabled,
		ChannelListenerPort: c3.Gateway.InternalPort,
	}}
	if err := c3.NormalizeGameServers(); err == nil {
		t.Fatal("频道口撞 Gateway.InternalPort 必须被拒，实际通过了")
	}
}

// TestMultiServerExplicitChannelPortsOk 多服各自显式配了不同频道口 → 正常通过。
func TestMultiServerExplicitChannelPortsOk(t *testing.T) {
	c := legacyServerConfig()
	enabled := true
	c.GameServers = []GameServerEntry{
		{Id: "a", Protocol: ProtocolS4A21, Enabled: &enabled, ChannelListenerPort: 9001},
		{Id: "b", Protocol: ProtocolS5A95, Enabled: &enabled, ChannelListenerPort: 9002},
	}
	if err := c.NormalizeGameServers(); err != nil {
		t.Fatalf("多服各自独立频道口不该报错，实得: %v", err)
	}
}
