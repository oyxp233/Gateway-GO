package proxy

import (
	"fmt"
	"strings"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
)

// UDPRelayManager 是多服 UDP 中继的集合（每服一个 *UDPRelay）。
//
// 只有 Protocol == s5a3 且 PartyUDPPorts 非空的服才会被纳入；其余服
// 一条监听都不开（S4A21 / S5A95 的组队不走 UDP 中继，或由服务端自处理）。
//
// 生命周期跟 ProxyManager 平行：启动时 Start，进程退出时 Stop。
// 与 TCP 代理不同，UDP 端口表**不做热加载** —— 改 PartyUDPPorts 需要
// 重启网关，因为换端口意味着已经在服务端注册过的端点全部失效，
// 热切只会让在线玩家静默失去组队，不如显式重启。
type UDPRelayManager struct {
	relays []*UDPRelay
	logger *logger.ConsoleLogger
}

// StartUDPRelays 按配置为每个 S5A3 服起 UDP 中继。
//
// 返回的 manager 永不为 nil（没有可启用的服时 relays 为空），
// 调用方可以无条件 Stop()。
func StartUDPRelays(cfg *config.GatewayConfig, log *logger.ConsoleLogger) *UDPRelayManager {
	mgr := &UDPRelayManager{logger: log}
	if cfg == nil {
		return mgr
	}
	for _, entry := range cfg.GameServers {
		if entry.Protocol != config.ProtocolS5A3 {
			continue
		}
		if !entry.IsEnabled() {
			continue
		}
		ports := entry.PartyUDPPorts
		if len(ports) == 0 {
			continue
		}
		backend := strings.TrimSpace(entry.BackendHost)
		if backend == "" {
			log.Error(fmt.Sprintf("[UDP] 服 %s 配了 PartyUDPPorts 但 BackendHost 为空，跳过 UDP 中继", entry.Id))
			continue
		}
		relay := NewUDPRelay(entry.Id, backend, ports)
		if relay == nil {
			continue
		}
		failures := relay.Start()
		for _, err := range failures {
			log.Error(fmt.Sprintf("[UDP] %v", err))
		}
		started := len(ports) - len(failures)
		if started <= 0 {
			log.Error(fmt.Sprintf("[UDP] 服 %s 的 UDP 端口全部监听失败，组队将不可用", entry.Id))
			continue
		}
		log.Info(fmt.Sprintf("[UDP] 服 %s 组队中继已启动: %d/%d 个端口 → %s（1:1 透传，每客户端独立后端源端口）",
			entry.Id, started, len(ports), backend))
		mgr.relays = append(mgr.relays, relay)
	}
	return mgr
}

// Stop 关闭所有中继。
func (m *UDPRelayManager) Stop() {
	if m == nil {
		return
	}
	for _, relay := range m.relays {
		relay.Stop()
	}
	m.relays = nil
}

// Count 返回启用的服数（运维日志用）。
func (m *UDPRelayManager) Count() int {
	if m == nil {
		return 0
	}
	return len(m.relays)
}

// Sessions 返回所有中继的活跃会话总数（管理后台 / 排查用）。
func (m *UDPRelayManager) Sessions() int {
	if m == nil {
		return 0
	}
	total := 0
	for _, relay := range m.relays {
		total += relay.SessionCount()
	}
	return total
}
