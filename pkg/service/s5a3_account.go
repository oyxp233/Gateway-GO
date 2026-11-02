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
	"s4a21-gateway/pkg/database"
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
//
// ★ clientIP 必须传**玩家真实 IP**，通过 X-Forwarded-For 交给服务端
// （2026-10-25 修复）：网关是用户态 HTTP 客户端，服务端看到的 TCP 对端恒为
// 127.0.0.1。不传 XFF 会导致：
//   - dnf90_web_accounts.last_login_ip 全记成 127.0.0.1（后台"账号管理"看不到真 IP）
//   - 服务端账号 API 的按 IP 限流（allowRate）把所有玩家算成同一个来源，
//     一个人刷几次就把全服卡住
//
// 服务端侧读取见 account_api.go 的 accountAPIClientIP：优先取 XFF 第一段。
// 安全前提：账号 API 只绑 127.0.0.1（DNFBRIDGE_ACCOUNT_API_LISTEN），
// 只有网关能连，所以这里的 XFF 不可能被玩家伪造。
func (c *s5a3AccountClient) call(ctx context.Context, path string, body any, clientIP string) (s5a3AccountResponse, int, error) {
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
	if ip := strings.TrimSpace(clientIP); ip != "" {
		request.Header.Set("X-Forwarded-For", ip)
	}

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
func (c *s5a3AccountClient) register(ctx context.Context, account, password, clientIP string) (int, string) {
	result, status, err := c.call(ctx, "/api/account/register", s5a3CredentialRequest{Account: account, Password: password}, clientIP)
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
func (c *s5a3AccountClient) login(ctx context.Context, account, password, clientIP string) (s5a3AccountResponse, int, string) {
	result, status, err := c.call(ctx, "/api/account/login", s5a3CredentialRequest{Account: account, Password: password}, clientIP)
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
//   - 不在网关 SQLite 里留密码行 —— S5A3 的账号表是唯一真源，
//     网关再存一份必然不同步（改密、封禁、删号都在服务端）。
//     但**会留一条身份镜像行**（m_id + name，密码列为空），见 EnsureAccountMirror；
//   - 注册限额**与本地注册同一套判据**（见下）。
//
// ── 关于注册限额（2026-10-29 修复）────────────────────────────────────────
//
// 原先这里不做网关侧限额，注释理由是"S5A3 账号 API 自己有限流
// （defaultAccountAPIRatePerMin=30），两套限额叠加只会让玩家在两处撞墙"。
// 这个理由**不成立**：服务端那个限流是"每分钟 30 次请求"（防暴力破解），
// 不是"每 IP 每天能注册几个号"（防刷号）。两者维度完全不同，
// 不叠加的后果是 S5A3 服可以无限刷号。
//
// 现在与 RegisterWithLimit 完全同构：先 CheckRegisterLimit，成功后落 register_logs
// （流水是限额的计数依据，漏写等于限额失效）。
//
// clientIP 是玩家真实 IP，经 X-Forwarded-For 交给服务端（见 call 的说明）。
// machineID 是登录器上报的机器码，可伪造，只用于"提高批量注册成本"。
func (s *AccountService) RegisterS5A3(name, password, gameId, clientIP, machineID string) (int, string) {
	name = utils.TrimSpace(name)
	password = strings.TrimSpace(password)
	clientIP = utils.TrimSpace(clientIP)
	machineID = utils.TrimSpace(machineID)

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

	// ★ 与本地注册共用同一把锁与同一套限额判据。
	//   用 s.registerMu 是为了让"S5A3 注册"和"本地注册"在同一条临界区里 ——
	//   否则两个入口各判各的，刷号的人只要交替打两个入口就能绕过单入口的计数。
	s.registerMu.Lock()
	defer s.registerMu.Unlock()

	if code, msg := s.CheckRegisterLimit(clientIP, machineID); code != models.Err.Ok {
		s.logger.Warn(fmt.Sprintf("拒绝 S5A3 注册: 账号=%s 服=%s IP=%s machine=%s 原因码=%d",
			name, profile.Id, clientIP, maskMachineID(machineID), code))
		return code, msg
	}

	code, msg = s.registerS5A3Upstream(client, profile.Id, name, password, clientIP)
	if code != models.Err.Ok {
		return code, msg
	}
	s.logger.Info(fmt.Sprintf("S5A3 注册: 服=%s 账号=%s IP=%s", profile.Id, name, clientIP))

	// 落注册流水（限额的计数依据）。★ 写失败**不改判注册结果**：
	// 账号已经在服务端建好了，把玩家挡回去只会让他重试、然后撞上"账号已存在"。
	// 代价是这一条不占后续配额（限额被小幅放松），与 RegisterWithLimit 同一取舍。
	mId, _ := s.db.S5A3AccountIDByName(name)
	if err := s.db.InsertRegistrationLog(name, mId, clientIP, machineID, utils.NowUnix()); err != nil {
		s.logger.Error(fmt.Sprintf("写 S5A3 注册流水失败（不影响注册成功）: account=%s ip=%s err=%v", name, clientIP, err))
	}
	// 顺手补一条身份镜像，让后台列表/账号事件立刻能看到这个新号。
	if mId != "" {
		if _, err := s.db.EnsureAccountMirror(mId, name); err != nil {
			// 镜像只是便利，建不出来不影响玩家登录（登录会再懒建一次）。
			s.logger.Warn(fmt.Sprintf("S5A3 注册后补身份镜像失败（不影响注册）: account=%s m_id=%s err=%v", name, mId, err))
		}
	}

	// 记录账号事件（三服合一）：供从网关增量同步。
	// 与本地注册（Register）同一口径 —— 事件按账号名工作，与账号行在哪个库无关。
	// 写流水失败不影响注册本身。
	if err := s.db.RecordAccountEvent(database.AccountEventRegister, name, "", database.BanScopeGlobal); err != nil {
		s.logger.Warn(fmt.Sprintf("记录 S5A3 账号事件(register)失败: %v", err))
	}

	return models.Err.Ok, ""
}

// RegisterS5A3Upstream 只做「转发到 S5A3 账号 API + 补身份镜像」，**不判限额、不落流水**。
//
// 专供 RegisterPlatform 用：那条路径已经在平台账号那一步用 RegisterWithLimit
// 判过限额并落了流水，再判一次会让一次注册吃掉 N+1 个配额（N = S5A3 服数量），
// 表现为"玩家注册一个号，同 IP 当天就再也注册不了"。
//
// 单服入口（RegisterS5A3）用的是带限额的版本，两者不要混用。
func (s *AccountService) RegisterS5A3Upstream(name, password, gameId, clientIP string) (int, string) {
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

	code, msg = s.registerS5A3Upstream(client, profile.Id, name, password, clientIP)
	if code != models.Err.Ok {
		return code, msg
	}
	// 补身份镜像（失败不影响注册，登录时会再懒建一次）。
	if mId, _ := s.db.S5A3AccountIDByName(name); mId != "" {
		if _, err := s.db.EnsureAccountMirror(mId, name); err != nil {
			s.logger.Warn(fmt.Sprintf("S5A3 注册后补身份镜像失败（不影响注册）: account=%s m_id=%s err=%v", name, mId, err))
		}
	}
	return models.Err.Ok, ""
}

// registerS5A3Upstream 是最内层的纯转发（不带任何限额/流水/镜像副作用）。
func (s *AccountService) registerS5A3Upstream(client *s5a3AccountClient, gameID, name, password, clientIP string) (int, string) {
	code, msg := client.register(context.Background(), name, password, clientIP)
	if code == models.Err.Ok {
		s.logger.Info(fmt.Sprintf("S5A3 注册: 服=%s 账号=%s IP=%s", gameID, name, clientIP))
	}
	return code, msg
}

// LoginS5A3 在 S5A3 服务端校验账号并取回启动令牌。
//
// ★ 关键差异：launch_args 里的 {token} 必须是 S5A3 返回的那个令牌。
// 网关自己的 security.GenerateToken() 生成的是会话令牌（心跳/在线用），
// 拼进启动串会被 S5A3 直接拒绝 —— 表现是"登录成功但游戏连不上"。
// clientIP 是玩家真实 IP，经 X-Forwarded-For 交给服务端 ——
// 服务端用它写 last_login_ip（后台"账号管理"显示的那一列）并按 IP 限流。
func (s *AccountService) LoginS5A3(name, password, gameId, clientIP string) *models.LoginResult {
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

	response, code, msg := client.login(context.Background(), name, password, clientIP)
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

	// ★ 把最后登录信息写回**网关库**（2026-10-25 修复）。
	//
	// 后台「账号管理」读的是网关 SQLite 的 accounts 表，不是服务端 MariaDB。
	// S5A3 登录走的是本函数，与本地账号的 Login() 是两条路 ——
	// 原先这里不写库，于是：
	//   · 后台 IP 列永远停在早期值（多数是 127.0.0.1）
	//   · 最后登录时间也不更新
	// 服务端那份由 XFF 记真 IP（见 call），网关这份同步写同一份事实。
	//
	// ★ 2026-10-29 改成「先懒建镜像行，再写登录信息」：
	//   原来只 UPDATE，而 S5A3 账号在网关库通常一行都没有 ⇒ 影响 0 行、
	//   静默什么都不做。镜像行只存身份（m_id + name），密码列留空
	//   —— 见 database.EnsureAccountMirror 的说明（不允许成为绕过服务端的登录路径）。
	if strings.TrimSpace(identity) != "" && strings.TrimSpace(name) != "" {
		if _, err := s.db.EnsureAccountMirror(identity, name); err != nil {
			// 同名冲突是迁移期正常现象（S4A21 与 S5A3 有同名号），只告警不阻断。
			s.logger.Warn(fmt.Sprintf("S5A3 登录补身份镜像失败（不影响登录）: 账号=%s m_id=%s err=%v",
				name, identity, err))
		}
	}
	if strings.TrimSpace(clientIP) != "" {
		if err := s.db.UpdateAccountLogin(name, clientIP, 0, 0); err != nil {
			// 写库失败不能影响登录本身：玩家已经拿到令牌了。
			s.logger.Warn(fmt.Sprintf("S5A3 登录成功但写回网关库失败（不影响登录）: 账号=%s err=%v", name, err))
		}
	}

	s.logger.Info(fmt.Sprintf("S5A3 登录: 服=%s 账号=%s account_id=%s IP=%s", profile.Id, name, identity, clientIP))

	return &models.LoginResult{
		ErrorCode:  models.Err.Ok,
		Token:      response.Token,
		MId:        identity,
		LaunchArgs: launchArgs,
	}
}

// ValidateS5A3Password 校验 S5A3 密码规则（6~64 位，与服务端同口径）。
//
// 暴露给 auth 层在**连库之前**先挡掉明显不合规的输入 ——
// auth 包不 import database（分层约束），所以由这里转一层。
func (s *AccountService) ValidateS5A3Password(password string) error {
	return database.ValidateS5A3Password(password)
}

// ChangePasswordS5A3 是玩家自助改密（S5A3 版）。
//
// 必须**先验旧密码**：这是玩家自己的账号，不是管理员重置。
// 返回 (是否成功, 账号是否存在, error)。
//
// ★ 调用方对外不应区分"账号不存在"与"旧密码错" —— 区分了就是账号枚举接口。
func (s *AccountService) ChangePasswordS5A3(account, oldPassword, newPassword string) (bool, bool, error) {
	account = utils.TrimSpace(account)
	if account == "" {
		return false, false, nil
	}
	ok, exists, err := s.db.S5A3VerifyPassword(account, oldPassword)
	if err != nil {
		return false, exists, err
	}
	if !ok {
		if exists {
			s.logger.Warn(fmt.Sprintf("S5A3 改密被拒（原密码错）: 账号=%s", account))
		}
		return false, exists, nil
	}
	hit, err := s.db.S5A3ChangePassword(account, newPassword)
	if err != nil {
		return false, exists, err
	}
	if !hit {
		// 验证通过但写不进去：账号刚被删（并发），按不存在处理。
		return false, false, nil
	}
	return true, true, nil
}
