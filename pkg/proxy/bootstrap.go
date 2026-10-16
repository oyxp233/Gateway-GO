package proxy

import (
	"strings"

	"s4a21-gateway/pkg/config"
)

// BuildBootstrapPortConfig 从 appsettings 的 GameServer 段派生初始端口配置。
//
// 用途：`proxy_ports.json` 缺失时（首次运行 / 被删）用它生成初始文件。
// 文件一旦存在就**以文件为准** —— 管理后台改的端口不会因为重启被 appsettings 覆盖。
//
// 两个进程都要用它：网关进程创建 PortConfigStore 时作为 bootstrap，
// admin 进程同样（否则两个进程对"文件缺失时该是什么"的理解会不一致）。
func BuildBootstrapPortConfig(cfg *config.GatewayConfig) *ProxyPortConfig {
	if cfg == nil {
		return &ProxyPortConfig{
			ChannelPort: 8001,
			BackendHost: "127.0.0.1",
			BackendPort: 10001,
			PortRange:   PortRange{Start: 20001, End: 20201},
		}
	}
	return buildBootstrapFromSection(&cfg.GameServer, cfg.Gateway.ProxyPort)
}

// BuildBootstrapPortConfigForProfile 从某个游戏服的配置段派生初始端口配置。
//
// 多服模型（2026-10-16）：每个服有自己的 proxy_ports-<id>.json，
// 文件缺失时由该服自己的 GamePorts/GamePortMap 派生生成。
// channelPort 是该服频道口的公网监听端口（0 时回落 Gateway.ProxyPort，
// 由调用方按 config.GameServerEntry.ChannelListenerPort 规则算好传入）。
func BuildBootstrapPortConfigForProfile(profile config.GameServerEntry, channelPort int) *ProxyPortConfig {
	return buildBootstrapFromSection(&profile.GameServerSection, channelPort)
}

func buildBootstrapFromSection(section *config.GameServerSection, channelPort int) *ProxyPortConfig {
	boot := &ProxyPortConfig{
		ChannelPort: channelPort,
		BackendHost: section.BackendHost,
		BackendPort: section.BackendChannelPort,
	}

	seen := map[int]bool{}
	for _, entry := range section.GamePortMap {
		parts := strings.Split(entry, ":")
		if len(parts) != 2 {
			continue
		}
		pub := ParsePortString(parts[0])
		back := ParsePortString(parts[1])
		if pub > 0 && back > 0 && !seen[pub] {
			seen[pub] = true
			boot.GamePorts = append(boot.GamePorts, GamePortMapping{Public: pub, Backend: back, Enabled: true})
		}
	}

	// GamePorts 里没被映射覆盖的端口按同端口转发
	for _, port := range section.GamePorts {
		if !seen[port] {
			seen[port] = true
			boot.GamePorts = append(boot.GamePorts, GamePortMapping{Public: port, Backend: port, Enabled: true})
		}
	}

	lo, hi := 20001, 20201
	if len(boot.GamePorts) > 0 {
		lo = boot.GamePorts[0].Public
		for _, m := range boot.GamePorts {
			if m.Public < lo {
				lo = m.Public
			}
			if m.Public > hi {
				hi = m.Public
			}
		}
	}
	boot.PortRange = PortRange{Start: lo, End: hi}
	return boot
}

// ParsePortString 解析十进制端口字符串，非法返回 0。
func ParsePortString(s string) int {
	n := 0
	for _, ch := range strings.TrimSpace(s) {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
