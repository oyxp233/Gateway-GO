package httprouter

// ============================================================================
// 服清单下发（三服合一，2026-10-24）
//
// 见 评估-三服合一登录器-20261023.md 第三章：
//
//	GET /api/launcher/servers  免鉴权，返回 Ed25519 签名后的服清单
//
// 登录器启动时先连编译期 bootstrap 地址调此接口，拿到服清单后：
//  - 填充选服下拉框
//  - 按选中的服解析所有 API 端点（替代编译期写死）
//  - 按选中的服的 caps[] 决定启用哪些门禁
//
// 安全链：编译期 bootstrap(host + TLS pin + Ed25519 公钥) → TLS+pin 保护传输 →
// Ed25519 签名保护清单完整性 → 本地缓存带签名断网可用。
// 玩家改 launcher-config.json 改不动编译期三样 → 拿不到绕过收益。
// ============================================================================

import (
	"net/http"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/signing"
)

// signingKey 是网关启动时加载/生成的 Ed25519 私钥。
// nil = 未配置签名（清单仍可下发，signature 字段为空）。
var signingKey []byte // ed25519.PrivateKey, 但用 []byte 避免循环依赖

// signingPubHex 是公钥的 hex 编码（随清单一起下发，登录器可校验）。
var signingPubHex string

// InitSigning 在网关启动时调用，加载或生成 Ed25519 密钥对。
//
// keyPath 为空 = 不启用签名（清单仍返回，signature 为空串）。
// keyPath 非空但文件不存在 = 自动生成新密钥并保存（0600 权限）。
// 文件存在 = 加载已有密钥（保证登录器 exe 里编译的公钥不变）。
//
// 返回公钥 hex 字符串（用于日志展示，方便运维复制到登录器编译配置）。
func InitSigning(keyPath string) (string, error) {
	if keyPath == "" {
		return "", nil
	}

	pk, pubHex, err := signing.EnsurePrivateKey(keyPath)
	if err != nil {
		return "", err
	}
	signingKey = pk
	signingPubHex = pubHex
	return pubHex, nil
}

// handleLauncherServers 下发签名后的服清单。
//
// 免鉴权（公开接口），已纳入 GroupLauncher 限流分组。
// 响应体见 models.ServerListManifest。
func (s *Server) handleLauncherServers(w http.ResponseWriter, r *http.Request) {
	manifest := s.buildServerListManifest()
	writeJSON(w, http.StatusOK, manifest)
}

// buildServerListManifest 从当前配置构建服清单并签名。
//
// 设计要点：
//  - 只列出 IsEnabled() && !ListHidden 的服
//  - 每个服的端点从 GameServerEntry + GatewaySection 推导（留空 = 用全局默认）
//  - caps 从 ListCaps 推导，nil 时按 Protocol 默认能力位（见 gates.go）
//  - 签名只签 servers 数组的 CanonicalJSON，不签 generated_at/expires_at
//    （时间戳是"本次响应的元信息"，不是清单内容，每次都会变）
func (s *Server) buildServerListManifest() models.ServerListManifest {
	cfg := s.config
	gw := cfg.Gateway
	tlsEnabled := cfg.Tls.Enabled
	lz := cfg.LauncherSnapshot()
	expirySec := cfg.Signing.KeyExpirySeconds
	if expirySec <= 0 {
		expirySec = 300 // 默认 5 分钟
	}
	now := time.Now().Unix()

	entries := make([]models.ServerListEntry, 0, len(cfg.GameServers))
	for _, gs := range cfg.GameServers {
		if !gs.IsEnabled() || gs.ListHidden {
			continue
		}

		// 端点推导：留空 = 用全局默认
		host := gs.ListHost
		if host == "" {
			host = gs.PublicIP
		}
		authPort := gs.ListAuthPort
		if authPort == 0 {
			authPort = gw.TcpPort
		}
		httpPort := gs.ListHttpPort
		if httpPort == 0 {
			httpPort = gw.HttpPort
		}
		useTls := tlsEnabled
		if gs.ListTls != nil {
			useTls = *gs.ListTls
		}
		pin := gs.ListPin // 留空 = 登录器用编译期 PinnedFingerprint

		// 能力位推导：nil = 按 Protocol 默认（见 config.DefaultCapsFor）
		caps := gs.ListCaps
		if caps == nil {
			caps = config.DefaultCapsFor(gs.Protocol)
		}

		// 最低版本
		minVer := gs.ListMinLauncherVer
		if minVer == "" {
			minVer = lz.MinVersion
		}

		entries = append(entries, models.ServerListEntry{
			Id:             gs.Id,
			Name:           gs.Name,
			Protocol:       gs.Protocol,
			Host:           host,
			AuthPort:       authPort,
			HttpPort:       httpPort,
			Tls:            useTls,
			Pin:            pin,
			Caps:           caps,
			MinLauncherVer: minVer,
		})
	}

	manifest := models.ServerListManifest{
		Servers:     entries,
		GeneratedAt: now,
		ExpiresAt:   now + int64(expirySec),
		PublicKey:   signingPubHex,
	}

	// 规范化序列化 —— 这段字节就是签名覆盖的内容，也是登录器验签的对象。
	//
	// ★ 必须原样下发（ServersJson），不能让登录器"反序列化再重新序列化"：
	//   两端序列化规则不同（见 models.ServerListManifest 的注释），
	//   各自重序列化必然字节不同 → 验签永远失败。
	canonical, err := signing.CanonicalJSON(entries)
	if err != nil {
		// 序列化失败 = 清单不可用。返回空清单 + 无签名，让登录器走降级路径。
		s.logger.Error("[ServerList] 清单规范化序列化失败: " + err.Error())
		return models.ServerListManifest{GeneratedAt: now, ExpiresAt: now + int64(expirySec)}
	}
	manifest.ServersJson = string(canonical)

	// 签名（覆盖 ServersJson 的字节）
	if signingKey != nil {
		manifest.Signature = signing.Sign(signingKey, canonical)
	}

	return manifest
}

// VerifyServerListSignature 验签辅助函数（测试与登录器侧对照用）。
//
// ★ 签名覆盖的是 ServersJson 的 UTF-8 字节，不是 Servers 的再序列化结果。
// 传 Servers 进来是错的 —— 那会引入跨语言序列化差异（见 models 的注释）。
func VerifyServerListSignature(pubKeyHex, sigHex, serversJSON string) bool {
	return signing.VerifyHex(pubKeyHex, sigHex, []byte(serversJSON))
}
