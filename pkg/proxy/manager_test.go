package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/session"
)

// ─────────────────────────────────────────────────────────────────────────────
// ProxyManager 多服装配测试（2026-10-16 双服改造）
//
// 钉住三件事：
//   1. 每个服一份端口表文件：默认服 proxy_ports.json（历史零迁移），
//      其余服 proxy_ports-<id>.json；
//   2. 合并视图（ActivePorts / PortConnections）跨服不互相覆盖；
//   3. 端口表热更新按 profileId 路由到对应服，不串服。
// ─────────────────────────────────────────────────────────────────────────────

func boolPtr(b bool) *bool { return &b }

// twoProfileConfig 构造一个最小双服配置：
//
//	s4a21（默认服）：显式频道口 18001（多服配置不允许 0）
//	s5a95          ：显式频道口 18002，游戏口 23101/23102 → 公网 24001/24002
func twoProfileConfig(t *testing.T) *config.GatewayConfig {
	t.Helper()
	cfg := &config.GatewayConfig{
		Gateway: config.GatewaySection{
			ListenAddress: "127.0.0.1",
			ProxyPort:     0, // 两服都显式指定了频道口，不使用它
		},
		GameServers: []config.GameServerEntry{
			{
				Id:                  "s4a21",
				Name:                "S4A21 正式服",
				Protocol:            config.ProtocolS4A21,
				Enabled:             boolPtr(true),
				ChannelListenerPort: 18001,
				GameServerSection: config.GameServerSection{
					PublicIP:           "203.0.113.7",
					BackendHost:        "127.0.0.1",
					BackendChannelPort: 7001,
					GamePorts:          []int{20001, 20002},
				},
			},
			{
				Id:                  "s5a95",
				Name:                "S5A9 DNF95",
				Protocol:            config.ProtocolS5A95,
				Enabled:             boolPtr(true),
				ChannelListenerPort: 18002,
				GameServerSection: config.GameServerSection{
					PublicIP:           "203.0.113.7",
					BackendHost:        "127.0.0.1",
					BackendChannelPort: 23100,
					GamePorts:          []int{24001, 24002},
				},
			},
		},
	}
	if err := cfg.NormalizeGameServers(); err != nil {
		t.Fatalf("NormalizeGameServers: %v", err)
	}
	return cfg
}

func newTestManager(t *testing.T, cfg *config.GatewayConfig, dir string) *ProxyManager {
	t.Helper()
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(lg.Close)
	sm := session.NewSessionManager(func() {}, func() {})
	return NewProxyManager(cfg, dir, sm, lg, nil)
}

func TestProxyManagerPerProfilePortFiles(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManager(t, twoProfileConfig(t), dir)

	report := mgr.Start()
	t.Cleanup(mgr.Stop)

	if len(report.ChannelFailed) != 0 {
		t.Fatalf("两个服的频道口都应起来，失败: %v", report.ChannelFailed)
	}
	if ids := mgr.ProfileIDs(); len(ids) != 2 || ids[0] != "s4a21" || ids[1] != "s5a95" {
		t.Fatalf("ProfileIDs = %v, want [s4a21 s5a95]", ids)
	}

	// 端口表文件拆分：默认服沿用历史文件名，第二服按 Id 拆
	for _, name := range []string{PortConfigFileName, PortConfigFileNameFor("s5a95")} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("端口表文件 %s 应存在: %v", path, err)
		}
	}
	// 且内容是按各自服派生的（ChannelPort/BackendPort 不同）
	def := mgr.DefaultPortStore()
	if def == nil {
		t.Fatalf("DefaultPortStore 不应为 nil")
	}
	if !strings.HasSuffix(def.ConfigPath(), PortConfigFileName) {
		t.Fatalf("默认服端口表 = %s, want 后缀 %s", def.ConfigPath(), PortConfigFileName)
	}
	if got := def.GetConfig().BackendPort; got != 7001 {
		t.Fatalf("默认服 BackendPort = %d, want 7001", got)
	}
	s5 := mgr.stores["s5a95"]
	if s5 == nil {
		t.Fatalf("s5a95 的端口表存储缺失")
	}
	if got := s5.GetConfig().BackendPort; got != 23100 {
		t.Fatalf("s5a95 BackendPort = %d, want 23100", got)
	}
	if got := s5.GetConfig().ChannelPort; got != 18002 {
		t.Fatalf("s5a95 ChannelPort = %d, want 18002", got)
	}
}

func TestProxyManagerMergedViews(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManager(t, twoProfileConfig(t), dir)
	mgr.Start()
	t.Cleanup(mgr.Stop)

	// 给两个服各灌一份端口表（含启用端口），验证合并视图
	mgr.ReloadPorts("s4a21", &ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: 20001, Backend: 10001, Enabled: true},
	}})
	mgr.ReloadPorts("s5a95", &ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: 24001, Backend: 23101, Enabled: true},
	}})

	ports := mgr.ActivePorts()
	// 20001 只属于 s4a21、24001 只属于 s5a95：合并不能互相覆盖
	if ports[20001] != 10001 {
		t.Fatalf("合并视图缺 s4a21 的 20001→10001，实际 %v", ports)
	}
	if ports[24001] != 23101 {
		t.Fatalf("合并视图缺 s5a95 的 24001→23101，实际 %v", ports)
	}
	if len(ports) != 2 {
		t.Fatalf("合并视图应恰有 2 个端口，实际 %v", ports)
	}

	// 停用一个端口后从合并视图消失
	mgr.ReloadPorts("s4a21", &ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: 20001, Backend: 10001, Enabled: false},
	}})
	if _, ok := mgr.ActivePorts()[20001]; ok {
		t.Fatalf("停用后 20001 不应出现在合并视图")
	}
	if _, ok := mgr.ActivePorts()[24001]; !ok {
		t.Fatalf("s5a95 的 24001 不应受 s4a21  reload 影响")
	}
}

func TestProxyManagerReloadRoutesByProfile(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManager(t, twoProfileConfig(t), dir)
	mgr.Start()
	t.Cleanup(mgr.Stop)

	// 只路由给 s5a95：s4a21 的内部端口表必须原样不动
	// （它启动时已按 appsettings 的 GamePorts 初始化成同端口转发）。
	mgr.mu.RLock()
	s5 := mgr.servers["s5a95"]
	s4 := mgr.servers["s4a21"]
	mgr.mu.RUnlock()

	s4.mu.RLock()
	before := make(map[int]int, len(s4.gamePortMap))
	for k, v := range s4.gamePortMap {
		before[k] = v
	}
	s4.mu.RUnlock()

	mgr.ReloadPorts("s5a95", &ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: 24001, Backend: 23101, Enabled: true},
	}})

	s5.mu.RLock()
	defer s5.mu.RUnlock()
	if s5.gamePortMap[24001] != 23101 {
		t.Fatalf("s5a95 端口表未生效: %v", s5.gamePortMap)
	}
	s4.mu.RLock()
	defer s4.mu.RUnlock()
	if len(s4.gamePortMap) != len(before) {
		t.Fatalf("s4a21 端口表被串改: before=%v after=%v", before, s4.gamePortMap)
	}
	for k, v := range before {
		if s4.gamePortMap[k] != v {
			t.Fatalf("s4a21 端口表被串改: 端口 %d before=%d after=%d", k, v, s4.gamePortMap[k])
		}
	}

	// 不存在的服：返回空结果、不 panic
	if res := mgr.ReloadPorts("no-such-server", &ProxyPortConfig{}); len(res.Failed) != 0 {
		t.Fatalf("未知服的 reload 应返回空结果，实际 %v", res)
	}
}

func TestProxyManagerSkipsDisabledProfile(t *testing.T) {
	cfg := twoProfileConfig(t)
	cfg.GameServers[0].Enabled = boolPtr(false) // 停用默认服
	if err := cfg.NormalizeGameServers(); err != nil {
		t.Fatalf("NormalizeGameServers: %v", err)
	}

	dir := t.TempDir()
	mgr := newTestManager(t, cfg, dir)
	report := mgr.Start()
	t.Cleanup(mgr.Stop)

	if ids := mgr.ProfileIDs(); len(ids) != 1 || ids[0] != "s5a95" {
		t.Fatalf("只应启动 s5a95，实际 %v", ids)
	}
	if len(report.Started) != 1 {
		t.Fatalf("Started = %v, want 1 项", report.Started)
	}
	// 停用服不建端口表文件
	if _, err := os.Stat(filepath.Join(dir, PortConfigFileNameFor("s4a21"))); err == nil {
		t.Fatalf("停用服不应有端口表文件")
	}
	// 启用服的频道口必须起来（它拿的是显式 18002）
	if len(report.ChannelFailed) != 0 {
		t.Fatalf("s5a95 频道口应起来，失败: %v", report.ChannelFailed)
	}
}

// TestNewProxyServerS5A95ForcedSettings 钉住 S5A9 的两个服务端侧强制项：
// PROXY protocol 强制关（DfoServer 不认这行头）+ 方案 D 首包凭证强制关
// （首包布局不同且后端自校验 digest）。配置里怎么写都不算数。
func TestNewProxyServerS5A95ForcedSettings(t *testing.T) {
	cfg := twoProfileConfig(t)
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(lg.Close)

	// 故意把两个开关全打开，验证被强制关掉
	profile := cfg.GameServers[1] // s5a95
	profile.ProxyProtocol = "v1"
	profile.GamePortAuth.Enabled = true

	srv := NewProxyServer(cfg, profile, nil, lg, nil, nil)
	if srv.profile.ProxyProtocol != "off" {
		t.Fatalf("S5A95 的 ProxyProtocol 应被强制为 off，实际 %q", srv.profile.ProxyProtocol)
	}
	if srv.profile.GamePortAuth.Enabled {
		t.Fatalf("S5A95 的 GamePortAuth.Enabled 应被强制为 false")
	}
	// 两个下行适配器都必须绑定
	if srv.channelAdapter == nil || srv.gameAdapter == nil {
		t.Fatalf("S5A95 应绑定频道口+游戏口两个适配器")
	}

	// 对照组：非 S5A95 协议不绑任何适配器（只透传），且不被强制改写 ProxyProtocol。
	// S4A21 的频道列适配器已从本分支删除，配置里出现别的协议时行为是"能连但地址不改写"。
	other := cfg.GameServers[0]
	other.ProxyProtocol = "v1"
	srvOther := NewProxyServer(cfg, other, nil, lg, nil, nil)
	if srvOther.profile.ProxyProtocol != "v1" {
		t.Fatalf("非 S5A95 服的 ProxyProtocol 不应被改动，实际 %q", srvOther.profile.ProxyProtocol)
	}
	if srvOther.channelAdapter != nil {
		t.Fatalf("非 S5A95 服不应绑频道适配器")
	}
	if srvOther.gameAdapter != nil {
		t.Fatalf("非 S5A95 服不应绑游戏口适配器")
	}
}

// TestProxyManagerLegacySingleConfig 存量单服配置（无 GameServers 段）
// 走 Manager 也必须工作：合成默认服、沿用 proxy_ports.json。
func TestProxyManagerLegacySingleConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Gateway.ListenAddress = "127.0.0.1"
	cfg.Gateway.ProxyPort = 0
	// 注意：不调用 NormalizeGameServers —— 模拟老读取路径直接喂字面量

	dir := t.TempDir()
	mgr := newTestManager(t, cfg, dir)
	report := mgr.Start()
	t.Cleanup(mgr.Stop)

	if ids := mgr.ProfileIDs(); len(ids) != 1 {
		t.Fatalf("存量配置应合成单服，实际 %v", ids)
	}
	if len(report.ChannelFailed) != 0 {
		t.Fatalf("单服频道口应起来，失败: %v", report.ChannelFailed)
	}
	if _, err := os.Stat(filepath.Join(dir, PortConfigFileName)); err != nil {
		t.Fatalf("存量配置应仍生成 proxy_ports.json: %v", err)
	}
}
