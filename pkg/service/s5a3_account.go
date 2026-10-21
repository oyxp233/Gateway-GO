// S5A3 账号提供方：把网关的账号动作转成 S5A3 服务端的 HTTP 账号 API。
//
// ── 为什么需要这一层 ─────────────────────────────────────────────────────
//
// 网关原本是账号主权方：账号、密码哈希、salt、m_id、会话令牌全部由网关
// 自己的 SQLite 掌管（pkg/service/services.go 的 Register/Login）。
// S5A3 不是这样：账号在服务端的 MySQL（dnf90_web_accounts），密码 bcrypt，
// 登录成功后由**服务端签发**一个 `de509f65` + 24 位小写的令牌，客户端拿它
// 连游戏；网关自己随机构造的令牌会被服务端直接拒绝。
//
// 所以 S5A3 模式下网关降级成"翻译层"：
//
//	登录器 --TCP8000 JSON帧--> 网关 --HTTP--> S5A3 /api/account/login
//	                              <-- token --┘
//	登录器 <-- launch_args(含该 token) --
//
// 会话令牌仍是网关自己签的（心跳/后台在线统计用），与启动串里的
// S5A3 令牌**是两回事** —— 这一点与 S4A21 的现状一致，不要合并。
//
// ── 密码是明文 ───────────────────────────────────────────────────────────
//
// S5A3 的接口收 `{"account","password"}` 明文（服务端自己 bcrypt）。
// 登录器在 S5A3 模式下必须发明文而不是 password_md5，见
// pkg/auth/handler.go 与登录器分支的说明。
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/utils"
)

const (
	// s5a3DefaultAccountTimeout 是账号接口默认超时。S5A3 侧每个请求
	// 只有一次 bcrypt（约 50~80ms）+ 一次 MySQL 往返，8 秒足够宽松。
	s5a3DefaultAccountTimeout = 8 * time.Second
	// s5a3AccountMaxBodyBytes 限制响应体，避免上游异常时把网关内存吃满。
	s5a3AccountMaxBodyBytes = 8 << 10
)

// s5a3AccountClient 是 S5A3 账号 API 的 HTTP 客户端。
type s5a3AccountClient struct {
	baseURL string
	http    *http.Client
}

// newS5A3AccountClient 按服配置构造客户端。baseURL 为空返回 nil，
// 调用方据此回报"该服没配账号上游"，而不是发一个必然失败的请求。
func newS5A3AccountClient(profile config.GameServerEntry) *s5a3AccountClient {
	base := strings.TrimRight(strings.TrimSpace(profile.AccountApiUrl), "/")
	if base == "" {
		return nil
	}
	timeout := time.Duration(profile.AccountApiTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = s5a3DefaultAccountTimeout
	}
	return &s5a3AccountClient{
		baseURL: base,
		http: &http.Client{
			Timeout: timeout,
			// 账号 API 是服务端自己的 HTTP 端点，不跟随重定向：
			// 跟随会让密码被发到配置之外的主机。
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type s5a3CredentialRequest struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

type s5a3AccountResponse struct {
	OK        bool   `json:"ok"`
	AccountID string `json:"account_id"`
	Token     string `json:"token"`
	Message   string `json:"message"`
}

// s5a3Call 是三个接口共用的调用骨架，返回 (响应, HTTP 状态码, error)。
// error 只表示"没拿到可解析的响应"（网络/超时/坏 JSON），业务失败走响应体。
func (c *s5a3AccountClient) call(ctx context.Context, path string, body any) (s5a3AccountResponse, int, error) {
	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return s5a3AccountResponse{}, 0, err
		}
		payload = encoded
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return s5a3AccountResponse{}, 0, err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return s5a3AccountResponse{}, 0, err
	}
	defer func() { _ = response.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(response.Body, s5a3AccountMaxBodyBytes))
	if err != nil {
		return s5a3AccountResponse{}, response.StatusCode, err
	}

	var decoded s5a3AccountResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return s5a3AccountResponse{}, response.StatusCode,
			fmt.Errorf("解析 S5A3 账号响应失败: %w（body=%q）", err, truncateForLog(raw))
	}
	return decoded, response.StatusCode, nil
}

// register 在 S5A3 侧建号。成功返回 models.Err.Ok。
func (c *s5a3AccountClient) register(ctx context.Context, account, password string) (int, string) {
	result, status, err := c.call(ctx, "/api/account/register", s5a3CredentialRequest{Account: account, Password: password})
	if err != nil {
		return models.Err.AccountUpstream, "账号服务暂时不可用，请稍后重试"
	}
	if result.OK {
		return models.Err.Ok, ""
	}
	switch status {
	case http.StatusConflict:
		return models.Err.AccountExists, "该账号名已被注册"
	case http.StatusForbidden:
		// S5A3 关掉了自助注册（DNFBRIDGE_ACCOUNT_API_ALLOW_REGISTER=false）。
		// 这不是玩家的错，文案要指向管理员，否则会被当成"网关坏了"。
		return models.Err.AccountUpstream, "本服务器当前关闭了自助注册，请联系管理员开号"
	case http.StatusBadRequest:
		// S5A3 的 400 只有两种：缺字段、账号名/密码长度不合规。
		return models.Err.PasswordLength, messageOr(result.Message, "账号或密码不符合要求")
	default:
		return models.Err.AccountUpstream, messageOr(result.Message, "注册失败，请稍后重试")
	}
}

// login 在 S5A3 侧校验账号并取回令牌。
//
// 返回的 token 是**服务端签发**的启动串令牌，必须原样写进 launch_args；
// 网关不得用 security.GenerateToken() 替换它。
func (c *s5a3AccountClient) login(ctx context.Context, account, password string) (s5a3AccountResponse, int, string) {
	result, status, err := c.call(ctx, "/api/account/login", s5a3CredentialRequest{Account: account, Password: password})
	if err != nil {
		return result, models.Err.AccountUpstream, "账号服务暂时不可用，请稍后重试"
	}
	if result.OK && strings.TrimSpace(result.Token) != "" {
		return result, models.Err.Ok, ""
	}
	if result.OK && strings.TrimSpace(result.Token) == "" {
		// 上游说成功却没给令牌：拼进启动串会让客户端带着空凭证进游戏，
		// 现场表现是"登录成功但连不上"，必须在这里拦掉。
		return result, models.Err.AccountUpstream, "账号服务未返回登录令牌，请联系管理员"
	}
	switch status {
	case http.StatusUnauthorized:
		return result, models.Err.WrongPassword, "账号不存在或密码错误"
	case http.StatusBadRequest:
		return result, models.Err.AccountEmpty, messageOr(result.Message, "请填写账号和密码")
	default:
		return result, models.Err.AccountUpstream, messageOr(result.Message, "登录失败，请稍后重试")
	}
}

// status 探活，只用于启动自检与后台展示。
func (c *s5a3AccountClient) status(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/status", nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("S5A3 /api/status 返回 %d", response.StatusCode)
	}
	return nil
}

func messageOr(message, fallback string) string {
	if strings.TrimSpace(message) == "" {
		return fallback
	}
	return message
}

// truncateForLog 截断响应体，避免把整页 HTML 错误页打进日志。
func truncateForLog(raw []byte) string {
	const limit = 200
	text := strings.TrimSpace(string(raw))
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}

// ─────────────────────────────────────────────────────────────────────────────
// AccountService 上的 S5A3 入口
//
// 这两个方法只在「所选服 Protocol == s5a3」时被 pkg/auth 调用，
// 不改变 S4A21 / S5A95 的任何既有路径。
// ─────────────────────────────────────────────────────────────────────────────

// s5a3Profile 解析选服并确认它确实是 S5A3 服。
//
// 返回 (profile, 错误码)。错误码为 models.Err.Ok 表示可以继续。
func (s *AccountService) s5a3Profile(gameId string) (config.GameServerEntry, int, string) {
	profile, found := s.config.FindGameServer(gameId)
	if !found {
		return config.GameServerEntry{}, models.Err.GameNotFound, ""
	}
	if !profile.IsEnabled() {
		return config.GameServerEntry{}, models.Err.GameDisabled, ""
	}
	if profile.Protocol != config.ProtocolS5A3 {
		// 调用方本不该走到这里（它先判了协议）。真走到说明选服与分支判断
		// 不一致，宁可报错也不要悄悄按 S5A3 处理另一个服的账号。
		return config.GameServerEntry{}, models.Err.GameNotFound, "该服不是 S5A3 服"
	}
	return profile, models.Err.Ok, ""
}

// RegisterS5A3 在 S5A3 服务端建号。
//
// 与本地注册的差别：
//   - 密码是**明文**（S5A3 自己 bcrypt），不是 32 位 MD5；
//   - 不在网关 SQLite 里留行 —— S5A3 的账号表是唯一真源，
//     网关再存一份必然不同步（改密、封禁、删号都在服务端）；
//   - 不做网关侧的 IP/机器码限额：S5A3 账号 API 自己有限流
//     （defaultAccountAPIRatePerMin=30），两套限额叠加只会让玩家
//     在两处都撞墙且文案互相矛盾。
func (s *AccountService) RegisterS5A3(name, password, gameId string) (int, string) {
	name = utils.TrimSpace(name)
	password = strings.TrimSpace(password)

	profile, code, msg := s.s5a3Profile(gameId)
	if code != models.Err.Ok {
		return code, msg
	}
	client := newS5A3AccountClient(profile)
	if client == nil {
		return models.Err.AccountUpstream, "该服未配置 S5A3 账号服务地址（AccountApiUrl）"
	}
	if name == "" {
		return models.Err.AccountEmpty, ""
	}
	if password == "" {
		return models.Err.PasswordEmpty, ""
	}

	code, msg = client.register(context.Background(), name, password)
	if code == models.Err.Ok {
		s.logger.Info(fmt.Sprintf("S5A3 注册: 服=%s 账号=%s", profile.Id, name))
	}
	return code, msg
}

// LoginS5A3 在 S5A3 服务端校验账号并取回启动令牌。
//
// ★ 关键差异：launch_args 里的 {token} 必须是 S5A3 返回的那个令牌。
// 网关自己的 security.GenerateToken() 生成的是会话令牌（心跳/在线用），
// 拼进启动串会被 S5A3 直接拒绝 —— 表现是"登录成功但游戏连不上"。
func (s *AccountService) LoginS5A3(name, password, gameId string) *models.LoginResult {
	name = utils.TrimSpace(name)
	password = strings.TrimSpace(password)

	profile, code, msg := s.s5a3Profile(gameId)
	if code != models.Err.Ok {
		result := &models.LoginResult{ErrorCode: code}
		if msg != "" {
			result.Message = &msg
		}
		return result
	}
	client := newS5A3AccountClient(profile)
	if client == nil {
		text := "该服未配置 S5A3 账号服务地址（AccountApiUrl）"
		return &models.LoginResult{ErrorCode: models.Err.AccountUpstream, Message: &text}
	}
	if name == "" {
		return &models.LoginResult{ErrorCode: models.Err.AccountEmpty}
	}
	if password == "" {
		return &models.LoginResult{ErrorCode: models.Err.PasswordEmpty}
	}

	response, code, msg := client.login(context.Background(), name, password)
	if code != models.Err.Ok {
		result := &models.LoginResult{ErrorCode: code}
		if msg != "" {
			result.Message = &msg
		}
		return result
	}

	// MId 取 S5A3 的 account_id（形如 dnf:10002）。它不进启动串
	// （S5A3 模板没有 {m_id}），只用于网关侧会话与后台在线展示。
	identity := response.AccountID
	if strings.TrimSpace(identity) == "" {
		identity = name
	}
	launchArgs := s.buildLaunchArgs(profile, identity, response.Token, "")

	s.logger.Info(fmt.Sprintf("S5A3 登录: 服=%s 账号=%s account_id=%s", profile.Id, name, identity))

	return &models.LoginResult{
		ErrorCode:  models.Err.Ok,
		Token:      response.Token,
		MId:        identity,
		LaunchArgs: launchArgs,
	}
}
