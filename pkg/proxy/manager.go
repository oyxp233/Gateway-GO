package proxy

import (
	"fmt"
	"sync"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/session"
)

// ProxyManager 多游戏服代理管理器（2026-10-16 双服改造）。
//
// 一个网关进程同时带多个游戏服（S4A21 / S5A9）：每个 config.GameServers
// 条目对应一个独立的 ProxyServer，各自监听自己的频道口与游戏口段，
// 各自持有一份端口表（proxy_ports.json / proxy_ports-<id>.json）。
//
// 对外（main.go / 管理后台本地后端）仍呈现"一个代理"的合并视图：
// ActivePorts / PortConnections 把所有服的数据合并。各服公网端口
// 由 config.ValidateGameServers 保证互不碰撞，合并不会互相覆盖。
type ProxyManager struct {
	cfg       *config.GatewayConfig
	configDir string
	sm        *session.SessionManager
	logger    *logger.ConsoleLogger
	gameAuth  GameCredentialVerifier

	mu      sync.RWMutex
	servers map[string]*ProxyServer     // profileId → server
	stores  map[string]*PortConfigStore // profileId → 端口表存储
	order   []string                    // 按配置顺序排列的 profileId
}

// NewProxyManager 创建多服代理管理器（尚未启动任何监听）。
//
// configDir 是端口表文件所在目录（与 appsettings.json 同目录）。
// gameAuth 是游戏口首包凭证校验器（方案 D），对 S5A95 服由
// NewProxyServer 内部强制关闭，传 nil 只影响 S4A21 服的口令路径。
func NewProxyManager(
	cfg *config.GatewayConfig,
	configDir string,
	sm *session.SessionManager,
	logger *logger.ConsoleLogger,
	gameAuth GameCredentialVerifier,
) *ProxyManager {
	return &ProxyManager{
		cfg:       cfg,
		configDir: configDir,
		sm:        sm,
		logger:    logger,
		gameAuth:  gameAuth,
		servers:   make(map[string]*ProxyServer),
		stores:    make(map[string]*PortConfigStore),
	}
}

// profiles 返回规范化后的启用服列表（保持配置顺序）。
//
// 配置在 LoadConfig 时已经过 NormalizeGameServers；这里再兜底一次，
// 保证测试里直接构造的字面量 cfg 也能工作。
func (m *ProxyManager) profiles() []config.GameServerEntry {
	if m.cfg == nil {
		return nil
	}
	if len(m.cfg.GameServers) == 0 {
		return []config.GameServerEntry{m.cfg.DefaultGameServerEntry()}
	}
	out := make([]config.GameServerEntry, 0, len(m.cfg.GameServers))
	for _, e := range m.cfg.GameServers {
		if e.IsEnabled() {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		// 全部显式停用：退回默认服口径，避免网关一个服都不带
		// （那是明显的误配，但静默零监听比带默认服更难排查）。
		return []config.GameServerEntry{m.cfg.DefaultGameServerEntry()}
	}
	return out
}

// StartReport 描述一次 Start 的结果，供启动日志汇总。
type StartReport struct {
	Started        []string // 正常启动的服（profileId）
	ChannelFailed  []string // 频道口监听失败的服
	GamePortFailed map[string]map[int]string
}

// Start 启动所有启用服：先建端口表存储，再逐个启动代理。
//
// 单个服启动失败不拖死其它服（频道口 bind 失败只记日志的传统在这里
// 保留），但会全部收进 StartReport 由调用方显式播报。
func (m *ProxyManager) Start() StartReport {
	report := StartReport{GamePortFailed: map[string]map[int]string{}}

	profiles := m.profiles()
	for _, profile := range profiles {
		// 第一个启用服沿用历史文件名 proxy_ports.json（零迁移），
		// 其余服按 Id 拆文件。
		fileName := PortConfigFileName
		if len(m.order) > 0 {
			fileName = PortConfigFileNameFor(profile.Id)
		}

		channelPort := profile.ChannelListenerPort
		if channelPort <= 0 {
			channelPort = m.cfg.Gateway.ProxyPort
		}
		bootstrap := BuildBootstrapPortConfigForProfile(profile, channelPort)

		profileID := profile.Id
		store := NewPortConfigStoreNamedBootstrap(m.configDir, fileName,
			func(newConfig *ProxyPortConfig) ReloadResult {
				return m.ReloadPorts(profileID, newConfig)
			}, bootstrap)
		// 落盘即生效：文件被改（后台保存 / 手改）时回调 ReloadPorts。
		// 必须先 StartWatching 再建 server，避免启动后到监听建立之间
		// 的改动窗口丢事件。
		store.StartWatching()

		srv := NewProxyServer(m.cfg, profile, m.sm, m.logger, store, m.gameAuth)

		m.mu.Lock()
		m.servers[profileID] = srv
		m.stores[profileID] = store
		m.order = append(m.order, profileID)
		m.mu.Unlock()

		res := srv.Start()

		report.Started = append(report.Started, profileID)
		if !srv.ChannelListenerUp() {
			report.ChannelFailed = append(report.ChannelFailed, profileID)
		}
		// Start 内部按端口表加载过游戏口；把启动时就没起来的端口
		// （如被占用）收进报告，由调用方显式播报。
		if len(res.Failed) > 0 {
			report.GamePortFailed[profileID] = res.Failed
		}
	}
	return report
}

// Stop 关闭所有服的代理与端口表监听。
func (m *ProxyManager) Stop() {
	m.mu.Lock()
	servers := make([]*ProxyServer, 0, len(m.servers))
	stores := make([]*PortConfigStore, 0, len(m.stores))
	for _, id := range m.order {
		if srv, ok := m.servers[id]; ok {
			servers = append(servers, srv)
		}
		if st, ok := m.stores[id]; ok {
			stores = append(stores, st)
		}
	}
	m.mu.Unlock()

	for _, st := range stores {
		st.StopWatching()
	}
	for _, srv := range servers {
		srv.Stop()
	}
}

// ReloadPorts 把某个服的端口表变更路由到它的 ProxyServer。
//
// 由 PortConfigStore 的 onChange 回调调用（文件热更新 / 后台保存两条路）。
// 服不存在（已停用）时返回空结果，不报错 —— 停用服的端口表文件还在被
// 监听是允许的，重启后自然生效。
func (m *ProxyManager) ReloadPorts(profileID string, newConfig *ProxyPortConfig) ReloadResult {
	m.mu.RLock()
	srv, ok := m.servers[profileID]
	m.mu.RUnlock()
	if !ok || srv == nil {
		return ReloadResult{}
	}
	return srv.ReloadPorts(newConfig)
}

// ActivePorts 合并所有服的活跃端口（public → backend）。
func (m *ProxyManager) ActivePorts() map[int]int {
	m.mu.RLock()
	servers := make([]*ProxyServer, 0, len(m.servers))
	for _, id := range m.order {
		if srv, ok := m.servers[id]; ok {
			servers = append(servers, srv)
		}
	}
	m.mu.RUnlock()

	merged := make(map[int]int)
	for _, srv := range servers {
		for port, backend := range srv.GetActivePorts() {
			merged[port] = backend
		}
	}
	return merged
}

// PortConnections 合并所有服各公网端口的在线连接数。
func (m *ProxyManager) PortConnections() map[int]int {
	m.mu.RLock()
	servers := make([]*ProxyServer, 0, len(m.servers))
	for _, id := range m.order {
		if srv, ok := m.servers[id]; ok {
			servers = append(servers, srv)
		}
	}
	m.mu.RUnlock()

	merged := make(map[int]int)
	for _, srv := range servers {
		for port, n := range srv.PortConnections() {
			merged[port] += n
		}
	}
	return merged
}

// DefaultPortStore 返回默认服（第一个启用服）的端口表存储。
//
// 管理后台的端口页 P0 仍只管理默认服；多服端口管理在 P1+ 按服拆分。
func (m *ProxyManager) DefaultPortStore() *PortConfigStore {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.order) == 0 {
		return nil
	}
	return m.stores[m.order[0]]
}

// ProfileIDs 返回按配置顺序排列的服标识（管理后台 / 日志用）。
func (m *ProxyManager) ProfileIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.order))
	copy(out, m.order)
	return out
}

// Summary 生成一行人类可读的启动摘要（每个服一行）。
func (m *ProxyManager) Summary() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.order) == 0 {
		return "无启用游戏服"
	}
	lines := make([]string, 0, len(m.order))
	for _, id := range m.order {
		srv := m.servers[id]
		st := m.stores[id]
		if srv == nil {
			continue
		}
		ports := srv.GetActivePorts()
		line := fmt.Sprintf("服 %s（协议 %s）频道口 %d，游戏口 %d 个",
			id, srv.profile.Protocol, srv.channelPort(), len(ports))
		if st != nil {
			line += fmt.Sprintf("，端口表 %s", st.ConfigPath())
		}
		lines = append(lines, line)
	}
	return joinLines(lines)
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "；"
		}
		out += l
	}
	return out
}
