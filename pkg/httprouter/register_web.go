package httprouter

// ============================================================================
// Web 注册页（三服合一，2026-10-24）
//
// 背景：注册入口必须唯一（只在主网关）。登录器已固定走主网关，
// 但有两个场景需要 Web 兜底：
//   - 主网关连不上（登录器注册失败）时，玩家可以从浏览器注册
//   - 手机/平板等没有登录器的场景
//
// 路由：
//
//	GET  /api/register   返回注册页 HTML（从网关返回"请到主网关注册"说明页）
//	POST /api/register   JSON {account, password} → 建平台账号 + 转发 S5A3
//
// ★ 为什么挂在 /api 下而不是 /register：
//   usePublicOnlyMiddleware 会把所有非 /api 路径 404（玩家端口不暴露页面）。
//   想放根路径就得放宽那个中间件，而它的存在是刻意的安全边界。
//
// ★ 注册逻辑与登录器共用 service.AccountService.RegisterPlatform：
//   一份实现两个入口，避免"Web 能注册但登录器注册失败"这种漂移。
//
// 安全边界：
//   - 只绑主网关（从网关一律 403 / 说明页）
//   - IP 限流：走 usePublicOnlyMiddleware 的 httpRateLimitMiddleware + RegisterLimit
//   - body 上限 4 KiB（注册请求只有账号密码，超过就是异常）
//   - 同源检查：拒绝跨站 POST（CSRF），注册虽不涉登录态，但不该被第三方代填
//   - 密码不写日志、不回显
// ============================================================================

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/security"
)

//go:embed static/register.html
var registerPageHTML []byte

// webRegisterMaxBody 是 POST /api/register 的 body 上限。
//
// 正常请求 ~100 字节（账号 + 密码）。4 KiB 足够覆盖异常长的密码，
// 再大就是攻击或客户端 bug。
const webRegisterMaxBody = 4 << 10

// webRegisterRequest 是 POST /api/register 的请求体。
//
// ★ 只收明文密码，不收 MD5：MD5 由网关算。
//   理由是浏览器端算 MD5 需要额外 JS 库，而不同实现的编码处理
//   （UTF-8 / 大小写）容易不一致，导致"Web 注册的号登录器登不进"。
type webRegisterRequest struct {
	Account  string `json:"account"`
	Password string `json:"password"`
	// InviteCode 是邀请码（2026-10-24）。开启 Register.RequireInvite 时必填。
	// 归一化（去空格/连字符、转大写）由服务端做，前端传原始输入即可。
	InviteCode string `json:"invite_code"`
}

// isSlaveGateway 判断本机是不是从网关（与 auth.Handler 同一判据）。
func (s *Server) isSlaveGateway() bool {
	return s.config != nil && strings.TrimSpace(s.config.Signing.PeerInternalUrl) != ""
}

// handleWebRegisterPage 返回注册页。
//
// 从网关不提供注册页，改为返回一段说明 + 主网关地址（若配了 PeerBaseUrl）。
func (s *Server) handleWebRegisterPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 注册页含表单，禁止被嵌入 iframe（防点击劫持）
	w.Header().Set("X-Frame-Options", "DENY")

	if s.isSlaveGateway() {
		_, _ = w.Write(buildSlaveRegisterPage(s.config.Signing.PeerBaseUrl))
		return
	}

	_, _ = w.Write(registerPageHTML)
}

// handleWebRegister 处理 Web 注册。
func (s *Server) handleWebRegister(w http.ResponseWriter, r *http.Request) {
	// 从网关拒绝（注册入口必须唯一）
	if s.isSlaveGateway() {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"ok":      false,
			"message": "请在主网关注册账号（本服不提供注册入口）",
		})
		return
	}

	// 同源检查（CSRF）：浏览器跨站 POST 会带别的 Origin。
	//
	// 没有 Origin 头的请求放行 —— 那是非浏览器客户端（curl / 脚本），
	// 它们本来就能随便改 Origin，拦它没有意义；真正的防线是 IP 限额。
	if origin := r.Header.Get("Origin"); origin != "" {
		if !sameOriginAs(origin, r.Host) {
			writeJSON(w, http.StatusForbidden, map[string]interface{}{
				"ok":      false,
				"message": "非法来源",
			})
			return
		}
	}

	var req webRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, webRegisterMaxBody)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": "请求格式不正确",
		})
		return
	}

	account := strings.TrimSpace(req.Account)
	password := req.Password

	// 与登录器/网关同一套校验口径（见 service.Register 的注释）。
	// 这里先做一遍是为了给出**可操作**的文案，service 内部还会再校验一次。
	if account == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "请输入账号",
		})
		return
	}
	if len(account) < 3 || len(account) > 20 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "账号长度需为 3–20 位",
		})
		return
	}
	for _, ch := range account {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"ok": false, "message": "账号只能是字母或数字",
			})
			return
		}
	}
	if len(password) < 6 || len(password) > 32 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "密码长度需为 6–32 位",
		})
		return
	}

	// 客户端 IP：与 TCP 链路同口径（远端地址，不是自填）
	clientIP := clientIPOf(r)

	code, msg := s.accountSvc.RegisterPlatform(
		account, security.HashMD5(password), password, req.InviteCode, clientIP, "")

	if code != models.Err.Ok {
		if msg == "" {
			msg = webRegisterMessage(code)
		}
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": msg, "code": code,
		})
		return
	}

	// 成功：msg 非空时是"部分成功"的说明（S5A3 建号未完成）
	if msg == "" {
		msg = "注册成功，请到登录器登录"
	}

	// ★ 注册奖励登记（2026-11-01）。
	//
	// 两个注册入口必须都登记：登录器入口在 auth.Handler.registerPlatform 里登记，
	// 本入口原来**漏了** —— 网页注册的玩家连 pending 行都没有，
	// 后面 ProcessOnLogin 再正确也无从发。
	if s.registerBonusSvc != nil {
		s.registerBonusSvc.Register(account)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "message": msg,
	})
}

// webRegisterMessage 把错误码转成给网页看的文案。
//
// 与 auth 包的 errorMessages 分开维护是刻意的：网页和登录器的措辞场景不同
// （网页可以更详细、能带"请换个账号名"这种指导）。
// 但**判据必须一致** —— 都来自 service 返回的同一个 code。
func webRegisterMessage(code int) string {
	switch code {
	case models.Err.AccountExists:
		return "该账号名已被注册，请换一个"
	case models.Err.InviteRequired:
		return "请输入邀请码"
	case models.Err.InviteInvalid:
		return "邀请码无效或已被使用，请向管理员索取新的邀请码"
	case models.Err.RegisterIpLimit:
		return "同一网络今日注册账号已达上限，请明天再试或联系管理员"
	case models.Err.RegisterMachineLimit:
		return "该设备注册账号已达上限，请联系管理员"
	case models.Err.IllegalChars:
		return "账号只能包含字母或数字"
	case models.Err.AccountLength:
		return "账号长度需为 3–20 位"
	case models.Err.PasswordLength:
		return "密码长度需为 6–32 位"
	case models.Err.AccountUpstream:
		return "账号服务暂时不可用，请稍后重试"
	case models.Err.DatabaseError:
		return "服务器繁忙，请稍后重试"
	default:
		return fmt.Sprintf("注册失败（错误码 %d）", code)
	}
}

// sameOriginAs 判断 Origin 是否与请求 Host 同源。
//
// Origin 形如 "https://host:port"（或 "null"），Host 是 "host:port"。
// 只比较 host:port，忽略 scheme —— 网关可能在 TLS 终止代理后面，
// 那时 Origin 是 https 而 Host 是 http，比较 scheme 会误杀。
func sameOriginAs(origin, host string) bool {
	if origin == "null" {
		return false // sandboxed iframe / file:// 等，一律拒绝
	}
	// 去掉 scheme
	rest := origin
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	// 去掉路径（Origin 通常没有，但容错）
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return strings.EqualFold(rest, host)
}

// clientIPOf 取客户端 IP。
//
// ★ 2026-11-01 修正：网关前面挂了 fn-knock 反向代理
// （re.cn.dof.us.ci → 127.0.0.1:8080，见 /etc/fn-knock/gateway/config.json）。
// 只取 TCP 远端地址的话，Web 注册全部记成 127.0.0.1 ——
// 后果是所有 Web 注册共用同一个「同 IP 每日限额」，当天第二个人就被挡住，
// 后台注册流水里也全是 127.0.0.1，没法按 IP 排查。
//
// 口径：
//   - 远端是**回环**（说明请求来自本机反代，不是公网直连）
//     → 取 X-Real-IP；没有就取 X-Forwarded-For 的**最后一段**；
//   - 其它情况 → 仍用远端地址，**绝不**信任转发头。
//
// 为什么只在回环时信任：转发头谁都能写，但能连到 127.0.0.1:8080 的只有本机进程
// （反代或运维自己的 curl）。公网直连请求带的 XFF 一律忽略，否则限额可被伪造头绕过。
//
// 为什么取 XFF 的**最后**一段而不是第一段：反代通常把真实来源**追加**到末尾，
// 第一段可能是客户端自己伪造的。末尾才是「离我们最近的那一跳」给出的值。
func clientIPOf(r *http.Request) string {
	remote := remoteHostOf(r.RemoteAddr)
	if isLoopbackHost(remote) {
		if ip := normalizeIPHeader(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
		if ip := lastForwardedIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
	}
	if remote == "" {
		return "unknown"
	}
	return remote
}

// remoteHostOf 从 "host:port" / "[v6]:port" 里取主机部分；无端口时原样返回。
func remoteHostOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// isLoopbackHost 判断是否回环地址（127.0.0.0/8、::1、localhost）。
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

// normalizeIPHeader 把一个转发头值规整成合法 IP 字面量；不合法一律当没有。
// 兼容 "1.2.3.4"、"1.2.3.4:5678"、"[::1]:80" 三种写法。
func normalizeIPHeader(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host := remoteHostOf(raw); host != raw {
		raw = host
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	return ""
}

// lastForwardedIP 取 X-Forwarded-For 里**最后**一段合法 IP。
func lastForwardedIP(raw string) string {
	parts := strings.Split(raw, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if ip := normalizeIPHeader(parts[i]); ip != "" {
			return ip
		}
	}
	return ""
}

// buildSlaveRegisterPage 生成从网关的"请到主网关注册"说明页。
func buildSlaveRegisterPage(primaryBase string) []byte {
	link := ""
	if strings.TrimSpace(primaryBase) != "" {
		u := strings.TrimRight(strings.TrimSpace(primaryBase), "/") + "/api/register"
		link = fmt.Sprintf(`<p><a href="%s">%s</a></p>`, u, u)
	} else {
		link = `<p class="dim">请联系服务器管理员获取主网关地址。</p>`
	}
	html := `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>请在主网关注册</title>
<style>
 body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
      background:#0f1620;color:#e8eef6;font-family:"Microsoft YaHei",system-ui,sans-serif;padding:24px}
 .card{max-width:420px;background:#18202c;border:1px solid #2a3646;border-radius:14px;padding:28px}
 h1{margin:0 0 12px;font-size:19px}
 p{font-size:13px;line-height:1.8;color:#c3d0de}
 .dim{color:#8fa8c0}
 a{color:#3f8cff;word-break:break-all}
</style></head><body><div class="card">
<h1>请在主网关注册</h1>
<p>账号注册统一由主网关处理，本服不提供注册入口。</p>
<p>注册一次后，所有服务器通用。</p>
` + link + `
</div></body></html>`
	return []byte(html)
}
