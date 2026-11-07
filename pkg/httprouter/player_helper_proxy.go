package httprouter

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"s4a21-gateway/pkg/config"
)

// ============================================================================
// 玩家内辅（player helper）转发：POST /api/account/helper → 服务端账号 API
//
// 背景：上游 PR #71 在**服务端**加了 `/api/account/helper`（见
// Server-S5A3 的 player_helper_api.go），但它只绑 127.0.0.1:17002，
// 玩家机器上的内辅宿主连不到。这一层就是那条"既有 HTTPS 网关转发"：
//
//	内辅宿主 --HTTPS:8080--> 网关 --HTTP:17002--> 服务端账号 API
//
// ★ 为什么复用 8080 而不是新开端口：8080 已经是登录器在用的那个 HTTPS 监听
// （`Gateway.HttpPort`，90CN 已开 TLS，证书 CN 为网关公网 IP），
// 复用它的路由器即可 —— 不用新端口、不用新证书、不动防火墙。
//
// ★ 鉴权不在网关做。能力值（`X-DNF-Helper`）是登录器用登录 token 派生的
// 单向摘要，服务端在消费令牌时保存同一摘要并据此绑定**已登录角色**。
// 网关只做格式校验（64 位十六进制）后原样透传，**不解析、不记录**这个值 ——
// 它等价于一份短期凭证，写进日志就等于泄露。
//
// ★ 响应必须原样透传。宿主要求响应体是 `{"ok":..,"binding":32位,"policy":..}`，
// 网关任何改写都会让它判成"拾取响应无效"。
//
// ★ **刻意不进 HTTP 限流分组**（`ratelimiter.PathGroup` 对它返回空 = 不限流）。
// 理由：内辅每 5 秒续一次租约（12 次/分/人），而限流是"按 IP 分桶、全局 120/分"——
// 一旦有多个玩家处在同一个运营商 NAT 后面，就会互相挤占，症状是"内辅偶尔停一下"
// 这种极难归因的问题。这条接口本身很便宜（内存里扫一遍会话 + 一次 JSON 解码），
// 且没有能力值一律 401 立刻返回，靠能力值鉴权比靠 IP 限流更合适。
// 真要限流，也应该按能力值（= 角色）而不是按 IP 分桶。
// ============================================================================

const (
	// playerHelperProxyPath 与服务端 `mux.HandleFunc("/api/account/helper")` 一致。
	playerHelperProxyPath = "/api/account/helper"

	// playerHelperCapabilityLen 是能力值长度（SHA-256 十六进制）。
	playerHelperCapabilityLen = 64

	// playerHelperMaxBodyBytes 是请求体上限。服务端自己只收 4096 字节，
	// 这里留一倍余量，超了直接 413 —— 不要让它先跑到服务端再被拒。
	playerHelperMaxBodyBytes = 8 << 10

	// playerHelperMaxReplyBytes 是响应体上限。便捷接口（utility）的
	// warehouse 列表实测可达 128 KiB，宿主自己也按 131072 截断，这里对齐。
	playerHelperMaxReplyBytes = 128 << 10

	// playerHelperDefaultTimeout 是兜底超时。
	// 宿主侧：拾取请求 2 秒、便捷请求 15 秒（SessionBroker.cs），所以这里取 14 秒，
	// 让它略小于便捷接口的 15 秒 —— 超时由网关先给出 503（宿主会重试），
	// 而不是让宿主自己取消、看到"连接被中断"。
	// 拾取那条 2 秒的路径靠 r.Context() 传导取消：宿主断开 ⇒ 上游请求立刻中止。
	playerHelperDefaultTimeout = 14 * time.Second

	// playerHelperServerHeader 是可选的上游选择头（多服网关用）。
	// 单服网关不用传，默认取第一个启用且配了 AccountApiUrl 的服。
	playerHelperServerHeader = "X-DNF-Server"
)

// handlePlayerHelperProxy 把内辅请求转发到服务端账号 API。
//
// 状态码约定（与宿主的 Transient 判定对齐：5xx/408/429 可重试，其余 4xx 是永久失败）：
//
//	401  能力值缺失/格式不对 —— 宿主提示"等待角色登录；如已进城，请重登关联会话"
//	413  请求体超限
//	503  该服没配 AccountApiUrl，或上游不可达/超时 —— 宿主重试
//	其它 服务端返回什么就回什么（含 404「功能未开启」、401「会话不可用」）
func (s *Server) handlePlayerHelperProxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	capability := strings.TrimSpace(r.Header.Get("X-DNF-Helper"))
	if !validPlayerHelperCapability(capability) {
		// 不回显收到的值，也不记日志：它是一份短期凭证。
		http.Error(w, "game session unavailable", http.StatusUnauthorized)
		return
	}

	entry, ok := s.playerHelperUpstream(r.Header.Get(playerHelperServerHeader))
	if !ok {
		// 服务端侧同样回 503（账号 API 未接入），语义一致。
		http.Error(w, "helper upstream unavailable", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, playerHelperMaxBodyBytes))
	if err != nil {
		http.Error(w, "helper request too large", http.StatusRequestEntityTooLarge)
		return
	}

	timeout := time.Duration(entry.AccountApiTimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > playerHelperDefaultTimeout {
		timeout = playerHelperDefaultTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	target := strings.TrimRight(strings.TrimSpace(entry.AccountApiUrl), "/") + playerHelperProxyPath
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "helper upstream unavailable", http.StatusServiceUnavailable)
		return
	}
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("X-DNF-Helper", capability)
	// 与服务端账号 API 的既有口径一致：网关是用户态客户端，服务端看到的对端恒为
	// 127.0.0.1，真实来源只能靠这个头带过去（服务端按 XFF 第一段取）。
	if ip := clientIPOf(r); ip != "" && ip != "unknown" {
		upstream.Header.Set("X-Forwarded-For", ip)
	}

	response, err := playerHelperHTTPClient.Do(upstream)
	if err != nil {
		// 超时/连接失败都归 503：宿主据此重试，不会把租约判死。
		if s.logger != nil {
			s.logger.Warn("内辅转发失败: " + entry.Id + ": " + err.Error())
		}
		http.Error(w, "helper upstream unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = response.Body.Close() }()

	reply, err := io.ReadAll(io.LimitReader(response.Body, playerHelperMaxReplyBytes))
	if err != nil {
		http.Error(w, "helper upstream unavailable", http.StatusServiceUnavailable)
		return
	}

	if ct := response.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(reply)
}

// playerHelperUpstream 选出这次转发要用的服条目。
//
// 显式给了 `X-DNF-Server` 就按 Id 精确匹配；否则取**第一个启用且配了
// AccountApiUrl** 的服。我们每台网关只服务一个服（216 / 90CN 各自独立），
// 所以单服场景不需要这个头；多服网关由登录器把服 id 带上即可。
func (s *Server) playerHelperUpstream(requested string) (config.GameServerEntry, bool) {
	if s == nil || s.config == nil {
		return config.GameServerEntry{}, false
	}
	requested = strings.TrimSpace(requested)
	for index := range s.config.GameServers {
		entry := &s.config.GameServers[index]
		if !entry.IsEnabled() {
			continue
		}
		if requested != "" && !strings.EqualFold(strings.TrimSpace(entry.Id), requested) {
			continue
		}
		if strings.TrimSpace(entry.AccountApiUrl) == "" {
			continue
		}
		return *entry, true
	}
	return config.GameServerEntry{}, false
}

// playerHelperHTTPClient 是转发专用客户端（进程级单例）。
//
// 不复用账号登录那个 client：那条链路带 bcrypt、超时 8 秒，而这里要 14 秒；
// 也不复用公告那个（公告是低频小请求，超时 5 秒）。三条链路的超时口径不同，
// 混用只会让其中一条被另一条的口径拖死。
//
// 不跟随重定向：内辅请求带着能力值，跟随重定向等于把凭证发给配置之外的主机。
var playerHelperHTTPClient = &http.Client{
	Timeout: playerHelperDefaultTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// validPlayerHelperCapability 只校验形状（64 位十六进制），不校验真伪 ——
// 真伪由服务端比对登录令牌派生的摘要。
func validPlayerHelperCapability(value string) bool {
	if len(value) != playerHelperCapabilityLen {
		return false
	}
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
		case char >= 'a' && char <= 'f':
		case char >= 'A' && char <= 'F':
		default:
			return false
		}
	}
	return true
}
