package httprouter

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"s4a21-gateway/pkg/config"
)

// launcherDiagnosticsMaxBody 是 POST /api/diagnostics/context 的请求体上限。
//
// 正常请求只有三个短字段（read_token / correlation_id / after），几百字节。
// 4 KiB 足够覆盖异常长的令牌，再大就是攻击或客户端 bug。
const launcherDiagnosticsMaxBody = 4 << 10

// launcherDiagnosticsTimeout 是转发到服务端账号 API 的超时。
//
// 这个接口是**旁路**：登录器约每 2 秒拉一次，拉不到就保持 last_known 继续跑。
// 所以超时要短、失败要快 —— 绝不能让它拖住登录器或网关的连接池。
const launcherDiagnosticsTimeout = 6 * time.Second

// handleLauncherDiagnostics 把登录器的增强诊断上下文请求转发到 S5A3 账号 API。
//
//	POST /api/diagnostics/context?game=s5a3
//
// 为什么必须由网关转发：账号 API 只绑 127.0.0.1（DNFBRIDGE_ACCOUNT_API_LISTEN），
// 玩家直连不到。参考实现（PurpleMagic）同样只给网关加这一条 POST 白名单，
// 管理接口继续隔离。
//
// 安全边界：
//   - 不做鉴权以外的判断 —— 鉴权就是 body 里的 read_token，由服务端校验；
//     网关不解析、不记录、不落盘该令牌。
//   - 只允许 POST，且只转发到**该服配置的 AccountApiUrl**，不接受任意目标。
//   - 透传玩家真实 IP（X-Forwarded-For），与服务端限流口径一致。
//
// 失败语义：上游不可达/超时一律返回 503 + JSON，登录器按"上下文暂不可用"降级，
// 不影响游戏本身（这条链路上没有任何游戏数据）。
func (s *Server) handleLauncherDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"ok":      false,
			"message": "仅支持 POST",
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, launcherDiagnosticsMaxBody))
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": "请求体为空或读取失败",
		})
		return
	}

	// 先做一次结构校验：只认 read_token + correlation_id 这两个必填键。
	// 这样做不是为了鉴权（那是服务端的事），而是避免把明显的垃圾流量转给账号 API。
	var probe struct {
		ReadToken     string `json:"read_token"`
		CorrelationID string `json:"correlation_id"`
	}
	if err := json.Unmarshal(body, &probe); err != nil ||
		strings.TrimSpace(probe.ReadToken) == "" || strings.TrimSpace(probe.CorrelationID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": "缺少 read_token 或 correlation_id",
		})
		return
	}

	base := s.diagnosticsAccountBase(r.URL.Query().Get("game"))
	if base == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok":      false,
			"message": "该服未配置诊断上下文服务",
		})
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		strings.TrimRight(base, "/")+"/api/diagnostics/context", bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok":      false,
			"message": "构造上游请求失败",
		})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// 与服务端账号 API 的限流/审计口径一致：它只看 XFF 第一段。
	if ip := clientIPOf(r); ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}

	client := &http.Client{Timeout: launcherDiagnosticsTimeout}
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Warn("诊断上下文转发失败: " + err.Error())
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok":      false,
			"message": "诊断上下文服务暂不可用",
		})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 原样回传上游状态码与 JSON：登录器据 code 区分"令牌过期(404)"与"服务不可用"。
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok":      false,
			"message": "读取上游响应失败",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(payload)
}

// diagnosticsAccountBase 返回指定服的账号 API 基址。
//
// game 为空 = 默认服（与登录/启动串同一口径：空串取第一个启用的服）。
// 只在该服 Protocol == s5a3 且配了 AccountApiUrl 时返回非空。
func (s *Server) diagnosticsAccountBase(game string) string {
	if s.config == nil {
		return ""
	}

	want := strings.TrimSpace(game)
	for _, entry := range s.config.GameServers {
		if !entry.IsEnabled() {
			continue
		}
		if want != "" && !strings.EqualFold(entry.Id, want) {
			continue
		}
		if entry.Protocol != config.ProtocolS5A3 {
			continue
		}
		return strings.TrimSpace(entry.AccountApiUrl)
	}

	// 单服旧配置走 GameServer 段（没有 GameServers 列表时）。
	// 该段没有 Protocol 字段，用 AccountApiUrl 是否配置来判定 ——
	// 只有 S5A3 服会配账号 API 基址，其它协议不会走到这条转发。
	if want == "" {
		return strings.TrimSpace(s.config.GameServer.AccountApiUrl)
	}
	return ""
}
