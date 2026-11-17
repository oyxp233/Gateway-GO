package auth

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/service"
	"s4a21-gateway/pkg/session"
)

// Handler 实现 CommandHandler 接口，处理 TCP 命令。
type Handler struct {
	accountSvc    *service.AccountService
	adminSvc      *service.AdminService
	sessionMgr    *session.SessionManager
	registerBonus *service.RegisterBonusService
	// qqBindSvc 负责「账号绑定 QQ 号」（2026-09-24）。
	//
	// 允许为 nil：绑定是**可选增强**，没配 SMTP 时相关命令明确返回
	// "邮件服务未开启"，而不是让整个网关起不来 —— 也没资格拖垮登录链路。
	qqBindSvc *service.QQBindService
	config    *config.GatewayConfig
	logger    *logger.ConsoleLogger
}

// NewHandler 创建命令处理器。
func NewHandler(
	accountSvc *service.AccountService,
	adminSvc *service.AdminService,
	sessionMgr *session.SessionManager,
	registerBonus *service.RegisterBonusService,
	qqBindSvc *service.QQBindService,
	cfg *config.GatewayConfig,
	logger *logger.ConsoleLogger,
) *Handler {
	return &Handler{
		accountSvc:    accountSvc,
		adminSvc:      adminSvc,
		sessionMgr:    sessionMgr,
		registerBonus: registerBonus,
		qqBindSvc:     qqBindSvc,
		config:        cfg,
		logger:        logger,
	}
}

// Handle 处理 TCP 命令。
func (h *Handler) Handle(req *models.GatewayRequest, clientIP string) (*models.GatewayResponse, error) {
	// 版本门禁 + 维护模式门禁
	if req.Cmd == models.Cmd.Login || req.Cmd == models.Cmd.Register || req.Cmd == models.Cmd.ChangePassword {
		if gate := h.checkLauncherVersion(req); gate != nil {
			return gate, nil
		}
		if gate := h.checkMaintenanceMode(req); gate != nil {
			return gate, nil
		}
	}

	switch req.Cmd {
	case models.Cmd.Register:
		return h.handleRegister(req, clientIP), nil
	case models.Cmd.Login:
		return h.handleLogin(req, clientIP), nil
	case models.Cmd.ChangePassword:
		return h.handleChangePassword(req), nil
	case models.Cmd.Health:
		return h.handleHealth(req), nil
	case models.Cmd.AccountInfo:
		return h.handleAccountInfo(req), nil
	case models.Cmd.AccountReset:
		return h.handleAccountReset(req), nil
	case models.Cmd.SendItems:
		return h.handleSendItems(req), nil
	case models.Cmd.GetRoles:
		return h.handleGetRoles(req), nil
	case models.Cmd.ClearMailbox:
		return h.handleClearMailbox(req), nil
	// ── QQ 号绑定（2026-09-24）─────────────────────────────────────────
	// 三个命令都要求**已登录**：它们校验会话 token 而不是 auth_key。
	// 理由：绑定是玩家自己的动作，不该由后台密钥代劳；
	// 而且 token 已经把"是谁"绑定在会话上，玩家没法替别人绑。
	case models.Cmd.SendBindCode:
		return h.handleSendBindCode(req, clientIP), nil
	case models.Cmd.BindQQ:
		return h.handleBindQQ(req, clientIP), nil
	case models.Cmd.UnbindQQ:
		return h.handleUnbindQQ(req), nil
	case models.Cmd.Version:
		return h.handleVersion(), nil
	default:
		return failureResponse(req.Cmd, models.Err.UnknownCommand, "未知命令"), nil
	}
}

func (h *Handler) handleRegister(req *models.GatewayRequest, clientIP string) *models.GatewayResponse {
	account := deref(req.Account, "")
	passwordMd5 := deref(req.PasswordMd5, "")
	gameId := strings.TrimSpace(deref(req.Game, ""))

	if clientIP == "" {
		clientIP = "unknown"
	}

	// ── 从网关拒绝注册（三服合一，2026-10-24）─────────────────────────
	//
	// 注册入口必须唯一：如果从网关也能注册，就会产生"只在 B 服有的号"，
	// 玩家去 A 服登不进，又要靠反向同步补 —— 那条路要明文密码，代价太大。
	//
	// 判定：配了 Signing.PeerInternalUrl 的就是从网关（主网关不需要配这一项）。
	// 从网关的登录器侧已经固定把注册发往主网关，正常玩家碰不到这条；
	// 这里是防御"绕过登录器直接调从网关注册接口"。
	if h.isSlaveGateway() {
		h.logger.Warn(fmt.Sprintf("拒绝注册: 账号=%s 本机是从网关（请到主网关注册） IP=%s", account, clientIP))
		return failureResponse(req.Cmd, models.Err.AccountUpstream,
			"请在主网关注册账号（本服不提供注册入口）")
	}

	// ── 平台账号注册（默认路径，三服合一）──────────────────────────────
	//
	// 建"平台账号"（网关 accounts 表，MD5），再把明文密码转发给所有 S5A3 服。
	// 这样"注册一次，三服都能登"（含 S5A3）。
	//
	// Register.PlatformOnly=false 时保留改造前的行为（按 game 分流）。
	if h.config == nil || h.config.Register.PlatformOnlyEnabled() {
		return h.registerPlatform(req, account, passwordMd5, clientIP)
	}

	// ── 改造前行为：按 game 分流到 S5A3 ────────────────────────────────
	// S5A3 服：账号在服务端 MySQL，注册直接转给它的 HTTP 账号 API。
	// 见 pkg/service/s5a3_account.go 的 RegisterS5A3。
	if h.isS5A3Server(gameId) {
		password := deref(req.Password, "")
		// 明文密码字段只有认识 S5A3 的登录器才会填（见 launcher 的
		// ServerProtocols）。空值说明是旧登录器，给出可执行的提示，
		// 而不是让它带着空密码去撞服务端、最后回报"密码错误"。
		if password == "" {
			return failureResponse(req.Cmd, models.Err.AccountUpstream,
				"该服要求登录器上报明文密码，请使用支持 S5A3 的登录器版本")
		}
		// 机器码用于注册限额的机器维度（老登录器不带 ⇒ 空串 ⇒ 只按 IP 判）。
		machineID := deref(req.MachineId, "")
		code, msg := h.accountSvc.RegisterS5A3(account, password, gameId, clientIP, machineID)
		if code == models.Err.Ok {
			// 注册奖励由 S5A3 自己在同一事务里落库
			// （signupbenefits.CaptureSignup），网关再发一份就是双发。
			return successResponse(req.Cmd, "注册成功")
		}
		if msg == "" {
			msg = errorMessages[code]
		}
		return failureResponse(req.Cmd, code, msg)
	}

	// 机器码来自登录器上报（首个物理网卡 MAC）。老登录器不带 ⇒ 空串 ⇒
	// 注册限额跳过机器维度，只按 IP 判。见 models.GatewayRequest.MachineId。
	machineID := deref(req.MachineId, "")

	// 走带限额的注册：判定与建号在同一临界区内（service.RegisterWithLimit）。
	code, msg := h.accountSvc.RegisterWithLimit(account, passwordMd5, clientIP, machineID)
	if code == models.Err.Ok {
		h.registerBonus.Register(account)
		return successResponse(req.Cmd, "注册成功")
	}
	if msg == "" {
		msg = errorMessages[code]
	}
	return failureResponse(req.Cmd, code, msg)
}

// isSlaveGateway 判断本机是不是从网关。
//
// 判定依据：配了 Signing.PeerInternalUrl = 本机从主网关同步 = 从网关。
// 主网关不需要配这一项（它自己就是权威）。
//
// ★ 与 httprouter 的 Web 注册共用同一个判据 —— 两个入口必须都拒绝，
//
//	否则玩家可以从 Web 端绕到从网关注册。
func (h *Handler) isSlaveGateway() bool {
	return h.config != nil && strings.TrimSpace(h.config.Signing.PeerInternalUrl) != ""
}

// registerPlatform 建平台账号并把明文密码转发给所有 S5A3 服。
//
// 真正的实现在 service.AccountService.RegisterPlatform ——
// 与 Web 注册（GET/POST /api/register）共用同一份，避免两个入口行为漂移。
//
// 这里只负责协议层：取 machineID、把 service 返回的 message 转成响应。
func (h *Handler) registerPlatform(
	req *models.GatewayRequest, account, passwordMd5, clientIP string,
) *models.GatewayResponse {
	machineID := deref(req.MachineId, "")
	password := deref(req.Password, "")
	inviteCode := deref(req.InviteCode, "")

	code, msg := h.accountSvc.RegisterPlatform(account, passwordMd5, password, inviteCode, clientIP, machineID)
	if code != models.Err.Ok {
		if msg == "" {
			msg = errorMessages[code]
		}
		return failureResponse(req.Cmd, code, msg)
	}

	// 平台账号建成后才发注册奖励（与改造前一致：奖励只给真正注册成功的人）
	h.registerBonus.Register(account)

	if msg != "" {
		// 部分成功（S5A3 建号未完成）——把 service 的说明透给玩家
		return successResponse(req.Cmd, msg)
	}
	return successResponse(req.Cmd, "注册成功")
}

// isS5A3Server 判断选中的服是不是 S5A3（Protocol == s5a3）。
//
// 空 gameId = 默认服，所以单服部署时把唯一那个服配成 s5a3 即可，
// 老登录器不带 game 字段也能正确路由。
func (h *Handler) isS5A3Server(gameId string) bool {
	if h.config == nil {
		return false
	}
	profile, found := h.config.FindGameServer(gameId)
	return found && profile.Protocol == config.ProtocolS5A3
}

func (h *Handler) handleLogin(req *models.GatewayRequest, clientIP string) *models.GatewayResponse {
	account := deref(req.Account, "")
	passwordMd5 := deref(req.PasswordMd5, "")
	deviceSecret := deref(req.DeviceSecret, "")
	// gameId：选服字段（2026-10-17 双服）。老登录器不带 ⇒ 空串 ⇒ 默认服。
	gameId := strings.TrimSpace(deref(req.Game, ""))

	if clientIP == "" {
		clientIP = "unknown"
	}

	// ★ 封禁检查必须放在 S5A3 分支**之前**（2026-10-29 修复）。
	//
	// 原来这段在 S5A3 分支之后，而 S5A3 走独立分支直接 return ——
	// 于是后台「封禁」对 S5A3 服**完全无效**：库里写进去了，玩家照样能登。
	// 症状极具欺骗性：后台列表显示"已封禁"，游戏里人还在跑。
	//
	// 三服合一（2026-10-24）：按服判断 —— scope='global' 命中任何服，
	// scope='<gameId>' 只命中该服。gameId 为空时只判全局（老登录器行为不变）。
	//
	// S5A3 的账号名就是登录名（服务端 dnf90_web_accounts.account），
	// 与网关库 banned_accounts 的键一致，所以这里不需要额外翻译。
	if banned, _ := h.accountSvc.IsBannedForServer(account, gameId); banned {
		h.logger.Warn(fmt.Sprintf("拒绝登录: 账号=%s 已封禁 game=%q IP=%s", account, gameId, clientIP))
		return failureResponse(req.Cmd, models.Err.Banned, errorMessages[models.Err.Banned])
	}

	// S5A3 服走独立分支：账号校验与启动令牌都由服务端负责，
	// 网关只做翻译与会话登记。见 handleLoginS5A3。
	if h.isS5A3Server(gameId) {
		return h.handleLoginS5A3(req, clientIP, gameId)
	}

	// ★ QQ 号识别（2026-09-24）：登录框「账号名 / QQ 号」两个都能进。
	//
	// 只有「纯数字 + 绑定表命中」才翻译，其余原样返回 ——
	// 所以账号名本身就是数字的老账号（游戏库迁移来的）行为完全不变。
	// 歧义在绑定时就堵死了：绑定时会拒绝与现有账号名相同的 QQ 号。
	//
	// ⚠️ 必须在封禁检查**之前**翻译。否则被封的是账号 X、玩家用 QQ 号登录时，
	// 封禁查的是"那个 QQ 号"这个根本不存在的账号名，封禁形同虚设。
	if h.qqBindSvc != nil {
		account = h.qqBindSvc.ResolveLoginAccount(account)
	}

	// 选服校验前移到封禁检查之后、密码校验之前没有意义 —— game 字段的
	// 拒绝码与密码无关，放在 accountSvc.Login 内部统一判定（见 service.Login）。
	// 这里只负责把字段透传到底，错误码由 Login 返回。
	result := h.accountSvc.Login(account, passwordMd5, deviceSecret, clientIP, gameId)
	if result.ErrorCode != models.Err.Ok {
		// 选服类失败不记"登录失败"警告（那会把排障引向密码方向），
		// 单独一条 Info 级别日志，带上 game 字段原值。
		if result.ErrorCode == models.Err.GameNotFound || result.ErrorCode == models.Err.GameDisabled {
			h.logger.Info(fmt.Sprintf("拒绝登录: 账号=%s game=%q 错误码=%d", account, gameId, result.ErrorCode))
		} else {
			h.logger.Warn(fmt.Sprintf("登录失败: 账号=%s 错误码=%d IP=%s", account, result.ErrorCode, clientIP))
		}
		msg := errorMessages[result.ErrorCode]
		if result.Message != nil {
			msg = *result.Message
		}
		return failureResponse(req.Cmd, result.ErrorCode, msg)
	}

	h.registerBonus.ProcessOnLogin(account)

	// 单账号单令牌：同一账号同时只存在一个会话。
	// 未带 force_login 的重复登录返回 1023，由登录器弹窗让玩家选择
	// 「踢掉之前的会话并继续」；带 force 的重复登录会踢旧会话（真断开）
	// 并把在线时长/泡点进度结转到新会话，时长不再因重复登录清零。
	_, alreadyOnline := h.sessionMgr.FindSessionByAccount(account)
	staleReconnect := false
	if alreadyOnline {
		// ★ 掉线重连自动放行（2026-10-10）。
		//
		// 玩家掉线后重开登录器登录时，旧会话往往还没到心跳超时就被判"已在线"，
		// 弹窗要人点确认 —— 人不在电脑前就一直进不去，几秒的网络抖动被放大成
		// 几十秒掉线。旧会话已经"心跳停滞 + 来自同一端"时判定为掉线重连，
		// 直接踢掉旧会话放行，不再弹窗。异地顶号（IP/设备都不同）不在此列，
		// 仍然走 1023 弹窗，顶号保护不受影响。
		if stale, ok := h.sessionMgr.FindStaleSessionForReconnect(
			account, clientIP, deviceSecret, h.config.Heartbeat.StaleForceSeconds); ok {
			staleReconnect = true
			h.logger.Warn(fmt.Sprintf(
				"自动放行掉线重连: 账号=%s IP=%s 旧会话心跳停滞=%ds 旧IP=%s 阈值=%ds",
				account, clientIP, time.Now().Unix()-stale.LastHeartbeat, stale.ClientIP,
				h.config.Heartbeat.StaleForceSeconds))
		}
	}
	reject, carryOver := duplicateLoginDecision(alreadyOnline, deref(req.ForceLogin, false), staleReconnect)
	if reject {
		h.logger.Warn(fmt.Sprintf("拒绝重复登录: 账号=%s 已在线 IP=%s", account, clientIP))
		return failureResponse(req.Cmd, models.Err.AccountOnline,
			"该账号已登录，如需继续将断开之前的会话")
	}

	// G-13（2026-10-04 审查）：原先写成 `token, _ := ...` 吞掉错误。
	// ReplaceAccountSessions 内部第一步就是 GenerateToken()，失败时返回 ("", err) ⇒
	// 登录响应 200 但 token 为空，玩家心跳与游戏连接全部鉴权失败，而服务端日志
	// 却显示"登录成功"，极难定位。这里显式判错并回报服务端错误。
	// gameId 一并写进会话：在线统计/后台展示按服分流（2026-10-17 双服）。
	token, err := h.sessionMgr.ReplaceAccountSessions(account, result.MId, clientIP, result.DeviceSecret, gameId, carryOver)
	if err != nil {
		h.logger.Error(fmt.Sprintf("创建会话失败: 账号=%s IP=%s: %v", account, clientIP, err))
		return failureResponse(req.Cmd, models.Err.DatabaseError, "服务器内部错误，请稍后重试")
	}

	resp := successResponse(req.Cmd)
	resp.Token = strPtr(token)
	resp.Cera = int64Ptr(result.Cera)
	resp.MId = strPtr(result.MId)
	resp.DeviceSecret = strPtr(result.DeviceSecret)
	resp.DeviceChanged = boolPtr(result.DeviceChanged)
	resp.LaunchArgs = strPtr(result.LaunchArgs)
	resp.Gates = h.gatesFor(gameId)
	// 已绑定的 QQ 号一并下发：登录器据此直接显示绑定状态，不用多一次往返。
	// 注意这里的 account 已经是翻译后的**真实账号名**。
	if h.qqBindSvc != nil {
		if qq := h.qqBindSvc.BindingOf(account); qq != "" {
			resp.QQNumber = strPtr(qq)
		}
	}
	return resp
}

// handleLoginS5A3 是 S5A3 服的登录分支。
//
// 与 S4A21 路径的三点差别：
//
//  1. 密码走**明文** `password` 字段（S5A3 账号 API 收明文），不是 password_md5；
//  2. 启动令牌由 S5A3 签发，原样进 launch_args —— 网关自己的
//     GenerateToken() 结果不能替代（服务端会拒）；
//  3. 不做 QQ 号翻译、设备绑定、封禁检查：这些数据都在网关 SQLite 里，
//     S5A3 账号在那边没有行。S5A3 侧的封禁/限流由服务端自己负责。
//
// 会话仍然登记在网关内存里（心跳、后台在线统计要用），但用的是网关自己的
// 会话令牌，与启动串里的 S5A3 令牌是两个东西 —— 与 S4A21 的现状一致。
func (h *Handler) handleLoginS5A3(req *models.GatewayRequest, clientIP, gameId string) *models.GatewayResponse {
	account := deref(req.Account, "")
	password := deref(req.Password, "")

	// 与注册同理：空明文密码 = 旧登录器。直接说清原因，别让玩家以为号被盗了。
	if password == "" {
		return failureResponse(req.Cmd, models.Err.AccountUpstream,
			"该服要求登录器上报明文密码，请使用支持 S5A3 的登录器版本")
	}

	result := h.accountSvc.LoginS5A3(account, password, gameId, clientIP)
	if result.ErrorCode != models.Err.Ok {
		msg := errorMessages[result.ErrorCode]
		if result.Message != nil && *result.Message != "" {
			msg = *result.Message
		}
		return failureResponse(req.Cmd, result.ErrorCode, msg)
	}

	// ★ 审查 H2（2026-11-17）：S5A3 路径此前直接 ReplaceAccountSessions(..., false)，
	// 缺 S4A21 路径那套「1023 / ForceLogin / 掉线重连放行 / carryOver」判定 ——
	// 异地二次登录静默踢掉第一个玩家、无「账号已在线」提示，且在线时长/泡点清零。
	// 这里补齐，与 S4A21 共用同一判定（duplicateLoginDecision），保证三服行为一致。
	_, alreadyOnline := h.sessionMgr.FindSessionByAccount(account)
	staleReconnect := false
	if alreadyOnline {
		if stale, ok := h.sessionMgr.FindStaleSessionForReconnect(
			account, clientIP, "", h.config.Heartbeat.StaleForceSeconds); ok {
			staleReconnect = true
			h.logger.Warn(fmt.Sprintf(
				"S5A3 自动放行掉线重连: 账号=%s IP=%s 旧会话心跳停滞=%ds 旧IP=%s 阈值=%ds",
				account, clientIP, time.Now().Unix()-stale.LastHeartbeat, stale.ClientIP,
				h.config.Heartbeat.StaleForceSeconds))
		}
	}
	reject, carryOver := duplicateLoginDecision(alreadyOnline, deref(req.ForceLogin, false), staleReconnect)
	if reject {
		h.logger.Warn(fmt.Sprintf("S5A3 拒绝重复登录: 账号=%s 已在线 IP=%s", account, clientIP))
		return failureResponse(req.Cmd, models.Err.AccountOnline,
			"该账号已登录，如需继续将断开之前的会话")
	}

	token, err := h.sessionMgr.ReplaceAccountSessions(account, result.MId, clientIP, "", gameId, carryOver)
	if err != nil {
		h.logger.Error(fmt.Sprintf("S5A3 登录创建会话失败: 账号=%s IP=%s: %v", account, clientIP, err))
		return failureResponse(req.Cmd, models.Err.DatabaseError, "服务器内部错误，请稍后重试")
	}
	// ★ 把 S5A3 令牌挂到网关会话上（2026-10-29）。
	//
	// 客户端连游戏口的首包带的就是这个令牌，Game 连接靠它做精确归属。
	// 不挂的话只能按 IP 猜，同 IP 双开时会把 A 的连接挂到 B 的会话上，
	// B 一登录 closeConns 就把 A 踢下线（实测现象：第二个账号一登录，
	// 第一个账号「网络连接中断」）。
	// 注意这是 S5A3 服务端签发的令牌，与上面网关自己的 token 不是一个东西。
	h.sessionMgr.SetS5A3Token(token, result.Token)

	// ★ 注册奖励（2026-11-01）。
	//
	// 原来只有 S4A21 登录路径会调 ProcessOnLogin（见 handleLogin 里那句），
	// S5A3 走的是本函数、在这里就 return 了 —— 结果 S5A3 玩家注册后
	// pending 行永远滞留，奖励一次都发不出去。
	//
	// 放在会话建好之后：登录已经成功了，发奖是附加动作，不该影响登录结果
	// （ProcessOnLogin 内部吞掉所有错误，只打日志）。
	//
	// 注意时序：S5A3 的 dnf_accounts 行由服务端在**玩家首次进游戏**时创建，
	// 所以第一次登录通常还没得发，会保持 pending，下次登录时补发。
	h.registerBonus.ProcessOnLogin(account)

	resp := successResponse(req.Cmd)
	resp.Token = strPtr(token)
	resp.MId = strPtr(result.MId)
	resp.LaunchArgs = strPtr(result.LaunchArgs)
	resp.Gates = h.gatesFor(gameId)
	return resp
}

// duplicateLoginDecision 给出「账号已在线时这次登录该怎么办」的统一判定。
//
// ★ 为什么抽出来（审查 H2，2026-11-17）：
// 原 S4A21 路径有完整的 1023 / ForceLogin / 掉线重连放行 / carryOver 逻辑，
// 但 S5A3 路径直接 ReplaceAccountSessions(..., false) —— 异地二次登录静默踢号、
// 在线时长与泡点清零。两条路径必须共用同一判定，否则三服行为再次漂移。
//
// 参数：
//   - alreadyOnline：FindSessionByAccount 的结果（该账号当前是否已有会话）
//   - forceLogin：请求里的 force_login（登录器弹窗确认后带上来）
//   - staleReconnect：同端 + 心跳停滞，判定为掉线重连（免弹窗自动放行）
//
// 返回：
//   - reject=true  → 回 1023，让登录器弹「是否断开之前的会话」
//   - carryOver    → 传给 ReplaceAccountSessions：已在线（被顶/重连）时结转
//     在线时长与泡点，避免重复登录清零。
func duplicateLoginDecision(alreadyOnline, forceLogin, staleReconnect bool) (reject bool, carryOver bool) {
	if !alreadyOnline {
		return false, false
	}
	// 已在线：带 force 或判定为同端掉线重连才放行，否则弹窗确认。
	if !forceLogin && !staleReconnect {
		return true, true
	}
	// 无论是 force 顶号还是掉线重连，旧会话的在线事实都要结转。
	return false, true
}

// gatesFor 返回本服该跑哪几道门禁（随登录响应下发）。
//
// 判定本体在 config.GateSwitchesFor，与 /api/launcher/policy 共用 ——
// 两个出口给出不同答案会让登录器行为随"先拉到哪个"而变。
func (h *Handler) gatesFor(gameId string) *models.GateBlock {
	profile, found := h.config.FindGameServer(gameId)
	gates := config.GateSwitchesFor(profile, found)
	return &gates
}

func (h *Handler) handleChangePassword(req *models.GatewayRequest) *models.GatewayResponse {
	account := deref(req.Account, "")
	oldPwdMd5 := deref(req.OldPwdMd5, "")
	newPwdMd5 := deref(req.NewPwdMd5, "")

	// ── S5A3 分支（2026-10-29 修复）──────────────────────────────────────
	//
	// S5A3 的密码是服务端 bcrypt，校验用明文。网关只有 MD5 就没法生成
	// 能被服务端接受的哈希（MD5 不可逆），所以这条路径必须走明文。
	//
	// 登录器支持情况：认识 S5A3 的版本会发 old_password / new_password
	// （见 models.GatewayRequest 的说明）。不发的老版本给出可执行的提示，
	// 而不是笼统的"服务端管理密码"（那句话会让人以为功能不存在）。
	if h.isS5A3Server(strings.TrimSpace(deref(req.Game, ""))) {
		oldPlain := deref(req.OldPassword, "")
		newPlain := deref(req.NewPassword, "")
		if oldPlain == "" || newPlain == "" {
			return failureResponse(req.Cmd, models.Err.AccountUpstream,
				"改密需要登录器上报明文密码，请更新到支持 S5A3 改密的登录器版本")
		}
		if err := h.accountSvc.ValidateS5A3Password(newPlain); err != nil {
			return failureResponse(req.Cmd, models.Err.PasswordLength, err.Error())
		}
		ok, exists, err := h.accountSvc.ChangePasswordS5A3(account, oldPlain, newPlain)
		if err != nil {
			h.logger.Error(fmt.Sprintf("S5A3 改密失败: 账号=%s err=%v", account, err))
			return failureResponse(req.Cmd, models.Err.DatabaseError, "改密失败，请稍后重试")
		}
		if !ok {
			// ★ 不区分"账号不存在"和"旧密码错" —— 区分了就是账号枚举接口。
			_ = exists
			return failureResponse(req.Cmd, models.Err.WrongPassword, "账号或原密码错误")
		}
		h.logger.Info(fmt.Sprintf("S5A3 改密成功: 账号=%s", account))
		return successResponse(req.Cmd, "密码修改成功")
	}

	code := h.accountSvc.ChangePassword(account, oldPwdMd5, newPwdMd5)
	if code == models.Err.Ok {
		return successResponse(req.Cmd, "密码修改成功")
	}
	return failureResponse(req.Cmd, code, errorMessages[code])
}

func (h *Handler) handleHealth(req *models.GatewayRequest) *models.GatewayResponse {
	token := deref(req.Token, "")
	if token == "" {
		return successResponse(req.Cmd)
	}

	sess, ok := h.sessionMgr.ValidateToken(token)
	if !ok {
		return failureResponse(req.Cmd, models.Err.SessionExpired, errorMessages[models.Err.SessionExpired])
	}

	// 三服合一（2026-10-24）：按会话所在的服判封禁
	// （sess.GameId 为空的会话 = 默认服，只判全局）。
	banned, _ := h.accountSvc.IsBannedForServer(sess.Account, sess.GameId)
	if banned {
		h.sessionMgr.RemoveSession(token)
		return failureResponse(req.Cmd, models.Err.Banned, errorMessages[models.Err.Banned])
	}

	return successResponse(req.Cmd)
}

func (h *Handler) handleAccountInfo(req *models.GatewayRequest) *models.GatewayResponse {
	authKey := deref(req.AuthKey, "")
	if !h.adminSvc.ValidateAuthKey(authKey) {
		return failureResponse(req.Cmd, models.Err.InvalidAuthKey, "授权无效")
	}

	account := deref(req.Account, "")
	info, err := h.accountSvc.GetAccountInfo(account)
	if err != nil || info == nil {
		return failureResponse(req.Cmd, models.Err.AccountNotFound, "账号不存在")
	}

	resp := successResponse(req.Cmd)
	resp.MId = strPtr(info.MId)
	resp.Cera = int64Ptr(info.Cera)
	resp.TokenCera = int64Ptr(info.TokenCera)
	resp.HappyTokenCera = int64Ptr(info.HappyTokenCera)
	return resp
}

func (h *Handler) handleAccountReset(req *models.GatewayRequest) *models.GatewayResponse {
	authKey := deref(req.AuthKey, "")
	if !h.adminSvc.ValidateAuthKey(authKey) {
		return failureResponse(req.Cmd, models.Err.InvalidAuthKey, "授权无效")
	}

	account := deref(req.Account, "")
	newPwdMd5 := deref(req.NewPwdMd5, "")

	code := h.adminSvc.ResetPassword(account, newPwdMd5)
	if code == models.Err.Ok {
		return successResponse(req.Cmd, "密码已重置")
	}
	return failureResponse(req.Cmd, code, errorMessages[code])
}

func (h *Handler) handleSendItems(req *models.GatewayRequest) *models.GatewayResponse {
	authKey := deref(req.AuthKey, "")
	if !h.adminSvc.ValidateAuthKey(authKey) {
		return failureResponse(req.Cmd, models.Err.InvalidAuthKey, "授权无效")
	}

	characterId := int64PtrZero(req.CharacterId)
	items := req.Items

	if characterId <= 0 {
		return failureResponse(req.Cmd, models.Err.InvalidCharacterId, errorMessages[models.Err.InvalidCharacterId])
	}
	if len(items) == 0 {
		return failureResponse(req.Cmd, models.Err.EmptyAttachments, errorMessages[models.Err.EmptyAttachments])
	}

	result := h.adminSvc.SendItems(characterId, items)
	if result.ErrorCode == models.Err.Ok {
		return successResponse(req.Cmd, "邮件已投递")
	}
	return failureResponse(req.Cmd, result.ErrorCode, result.Message)
}

func (h *Handler) handleGetRoles(req *models.GatewayRequest) *models.GatewayResponse {
	authKey := deref(req.AuthKey, "")
	if !h.adminSvc.ValidateAuthKey(authKey) {
		return failureResponse(req.Cmd, models.Err.InvalidAuthKey, "授权无效")
	}

	account := deref(req.Account, "")

	result, _ := h.adminSvc.GetRoles(account)
	if result.ErrorCode != models.Err.Ok {
		return failureResponse(req.Cmd, result.ErrorCode, result.Message)
	}

	resp := successResponse(req.Cmd)
	roles := make([]models.RoleInfo, len(result.Roles))
	for i, r := range result.Roles {
		roles[i] = models.RoleInfo{
			CharacterId: r.CharacterId,
			Name:        r.Name,
			Level:       r.Level,
			Job:         r.Job,
			GrowType:    r.GrowType,
			JobName:     r.JobName,
			Exp:         r.Exp,
		}
	}
	resp.Roles = roles
	return resp
}

func (h *Handler) handleClearMailbox(req *models.GatewayRequest) *models.GatewayResponse {
	authKey := deref(req.AuthKey, "")
	if !h.adminSvc.ValidateAuthKey(authKey) {
		return failureResponse(req.Cmd, models.Err.InvalidAuthKey, "授权无效")
	}

	characterId := int64PtrZero(req.CharacterId)
	code, count := h.adminSvc.ClearMailbox(characterId)
	if code != models.Err.Ok {
		return failureResponse(req.Cmd, code, errorMessages[code])
	}

	resp := successResponse(req.Cmd, "邮箱已清空")
	resp.DeletedCount = intPtr(count)
	return resp
}

// ── QQ 号绑定（2026-09-24）──────────────────────────────────────────────

// bindContext 从请求里取出「已登录账号」。返回空串表示会话无效。
//
// 三个绑定命令共用，走**会话 token** 校验而不是 auth_key：
// token 已经把"是谁"绑在会话上，玩家没法拿一把后台密钥去绑别人的号；
// 而 auth_key 是运营侧凭据，不该出现在玩家的登录器里。
func (h *Handler) bindContext(req *models.GatewayRequest) string {
	if h.qqBindSvc == nil {
		return ""
	}
	token := deref(req.Token, "")
	if token == "" {
		return ""
	}
	sess, ok := h.sessionMgr.ValidateToken(token)
	if !ok || sess == nil {
		return ""
	}
	return sess.Account
}

// handleSendBindCode 下发绑定验证码。
func (h *Handler) handleSendBindCode(req *models.GatewayRequest, clientIP string) *models.GatewayResponse {
	if h.qqBindSvc == nil {
		return failureResponse(req.Cmd, models.Err.MailServiceDisabled, "邮件服务未开启，请联系管理员")
	}
	account := h.bindContext(req)
	if account == "" {
		return failureResponse(req.Cmd, models.Err.SessionExpired, errorMessages[models.Err.SessionExpired])
	}

	code, msg := h.qqBindSvc.SendBindCode(account, deref(req.QQNumber, ""), clientIP)
	if code == models.Err.Ok {
		return successResponse(req.Cmd, msg)
	}
	return failureResponse(req.Cmd, code, msg)
}

// handleBindQQ 校验验证码并建立绑定。
func (h *Handler) handleBindQQ(req *models.GatewayRequest, clientIP string) *models.GatewayResponse {
	if h.qqBindSvc == nil {
		return failureResponse(req.Cmd, models.Err.MailServiceDisabled, "邮件服务未开启，请联系管理员")
	}
	account := h.bindContext(req)
	if account == "" {
		return failureResponse(req.Cmd, models.Err.SessionExpired, errorMessages[models.Err.SessionExpired])
	}

	qqNumber := deref(req.QQNumber, "")
	code, msg := h.qqBindSvc.Bind(account, qqNumber, deref(req.VerifyCode, ""), clientIP)
	if code != models.Err.Ok {
		return failureResponse(req.Cmd, code, msg)
	}

	resp := successResponse(req.Cmd, msg)
	resp.QQNumber = strPtr(qqNumber)
	return resp
}

// handleUnbindQQ 解除绑定。
func (h *Handler) handleUnbindQQ(req *models.GatewayRequest) *models.GatewayResponse {
	if h.qqBindSvc == nil {
		return failureResponse(req.Cmd, models.Err.MailServiceDisabled, "邮件服务未开启，请联系管理员")
	}
	account := h.bindContext(req)
	if account == "" {
		return failureResponse(req.Cmd, models.Err.SessionExpired, errorMessages[models.Err.SessionExpired])
	}

	code, msg := h.qqBindSvc.Unbind(account)
	if code != models.Err.Ok {
		return failureResponse(req.Cmd, code, msg)
	}
	return successResponse(req.Cmd, msg)
}

func (h *Handler) handleVersion() *models.GatewayResponse {
	// G-5：Launcher 段会被管理后台在运行中改写，读一律走快照（锁内拷贝）。
	snap := h.config.LauncherSnapshot()
	minVersion := strings.TrimSpace(snap.MinVersion)
	if minVersion == "" {
		minVersion = "1.0.0"
	}
	resp := successResponse(models.Cmd.Version)
	resp.Version = strPtr(minVersion)
	resp.DownloadUrl = strPtr(snap.DownloadUrl)
	return resp
}

// 版本门禁
func (h *Handler) checkLauncherVersion(req *models.GatewayRequest) *models.GatewayResponse {
	snap := h.config.LauncherSnapshot() // G-5：快照读取
	minText := strings.TrimSpace(snap.MinVersion)
	if minText == "" {
		return nil
	}

	minVer := parseVersion(minText)
	if minVer == nil {
		h.logger.Warn(fmt.Sprintf("[Launcher] MinVersion 配置无效: %s", minText))
		return nil
	}

	reportedText := deref(req.LauncherVersion, "")
	if reportedText == "" {
		resp := failureResponse(req.Cmd, models.Err.LauncherVersionTooOld,
			fmt.Sprintf("登录器版本过低，请更新至 v%s 以上", minText))
		resp.Version = strPtr(minText)
		resp.DownloadUrl = strPtr(snap.DownloadUrl)
		return resp
	}

	reportedVer := parseVersion(reportedText)
	if reportedVer == nil || reportedVer.Less(*minVer) {
		resp := failureResponse(req.Cmd, models.Err.LauncherVersionTooOld,
			fmt.Sprintf("登录器版本过低，请更新至 v%s 以上", minText))
		resp.Version = strPtr(minText)
		resp.DownloadUrl = strPtr(snap.DownloadUrl)
		return resp
	}

	return nil
}

// 维护模式门禁
func (h *Handler) checkMaintenanceMode(req *models.GatewayRequest) *models.GatewayResponse {
	// G-5：Administrator 在管理后台开维护模式时会整体替换 Maintenance 段
	// （含 AdminAccounts 切片头），这里必须走快照读，否则可能读到撕裂的值。
	m := h.config.MaintenanceSnapshot()
	if !m.Enabled {
		return nil
	}

	account := deref(req.Account, "")
	if isMaintenanceAdmin(account, m.AdminAccounts) {
		return nil
	}

	message := strings.TrimSpace(m.Message)
	if message == "" {
		message = "服务器维护中，请稍后再试"
	}

	return failureResponse(req.Cmd, models.Err.MaintenanceMode, message)
}

func isMaintenanceAdmin(account string, adminAccounts []string) bool {
	if account == "" {
		return false
	}
	for _, a := range adminAccounts {
		if strings.EqualFold(strings.TrimSpace(a), account) {
			return true
		}
	}
	return false
}

// 辅助函数

func successResponse(cmd string, msg ...string) *models.GatewayResponse {
	resp := &models.GatewayResponse{Cmd: cmd, Ok: true, ErrorCode: models.Err.Ok}
	if len(msg) > 0 {
		resp.Message = strPtr(msg[0])
	}
	return resp
}

func failureResponse(cmd string, code int, msg string) *models.GatewayResponse {
	return &models.GatewayResponse{Cmd: cmd, Ok: false, ErrorCode: code, Message: strPtr(msg)}
}

func int64Ptr(i int64) *int64 {
	return &i
}

func int64PtrZero(p *int64) int64 {
	if p != nil {
		return *p
	}
	return 0
}

func intPtr(i int) *int {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

func deref[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

func parseVersion(s string) *Version {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return nil
	}
	patch := 0
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return &Version{Major: major, Minor: minor, Patch: patch}
}

// Version 语义化版本号。
type Version struct {
	Major int
	Minor int
	Patch int
}

func (v Version) Less(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

// errorMessages 错误码到消息的映射。
var errorMessages = map[int]string{
	models.Err.AccountEmpty:           "账号不能为空",
	models.Err.AccountLength:          "账号长度不符合要求",
	models.Err.AccountExists:          "账号已存在",
	models.Err.PasswordEmpty:          "密码不能为空",
	models.Err.PasswordLength:         "密码长度不符合要求",
	models.Err.PasswordMismatch:       "两次密码输入不一致",
	models.Err.AccountNotFound:        "账号不存在",
	models.Err.WrongPassword:          "密码错误",
	models.Err.SamePassword:           "新密码不能与旧密码相同",
	models.Err.InvalidAuthKey:         "授权 auth_key 无效",
	models.Err.IllegalChars:           "账号包含非法字符",
	models.Err.AccountLocked:          "账号已被临时锁定，请稍后再试",
	models.Err.InvalidCharacterId:     "收件角色ID无效",
	models.Err.EmptyAttachments:       "邮件附件不能为空",
	models.Err.LauncherVersionTooOld:  "登录器版本过低，请更新后重试",
	models.Err.MaintenanceMode:        "服务器维护中，请稍后再试",
	models.Err.RateLimited:            "请求过于频繁",
	models.Err.UnknownCommand:         "未知命令",
	models.Err.DecodeFailed:           "请求解码失败",
	models.Err.BodyTooLarge:           "请求体过大",
	models.Err.DatabaseError:          "数据库操作失败",
	models.Err.SessionExpired:         "会话已失效",
	models.Err.Banned:                 "账号已被封禁，请联系管理员",
	models.Err.AccountOnline:          "该账号已登录，如需继续将断开之前的会话",
	models.Err.DeviceChanged:          "设备已变更，无法登录",
	models.Err.DeviceRotationCooldown: "设备密钥轮换冷却中，请稍后再试",
	// ── QQ 号绑定（1024~1035）──────────────────────────────────────────
	models.Err.QQNumberInvalid:          "QQ 号格式不正确（5~11 位数字）",
	models.Err.VerifyCodeInvalid:        "验证码不正确",
	models.Err.VerifyCodeExpired:        "验证码不存在或已过期，请重新获取",
	models.Err.VerifyCodeAttemptsExceed: "验证码错误次数过多，请重新获取",
	models.Err.SendTooFrequent:          "请求过于频繁，请稍后再试",
	models.Err.MailSendFailed:           "验证码发送失败，请稍后重试或联系管理员",
	models.Err.MailServiceDisabled:      "邮件服务未开启，请联系管理员",
	models.Err.SendQuotaExhausted:       "今日验证码额度已用完，请联系管理员",
	models.Err.AccountAlreadyBound:      "该账号已绑定 QQ 号，请先解绑",
	models.Err.QQNumberTaken:            "该 QQ 号已被其他账号绑定",
	models.Err.QQNumberConflict:         "该数字已被用作账号名，存在冲突，请联系管理员",
	models.Err.QQNotBound:               "该账号未绑定 QQ 号",
	// ── 注册限额（1036~1037）────────────────────────────────────────
	// 这两个码的实际文案由 service.CheckRegisterLimit 动态拼（带上限数值），
	// 这里是兜底：万一走了不带的路径，玩家至少能看懂发生了什么。
	models.Err.RegisterIpLimit:      "同一网络今日注册账号已达上限，请明天再试或联系管理员",
	models.Err.RegisterMachineLimit: "该设备注册账号数已达上限，请联系管理员",
	// ── 双服选服（2026-10-17）────────────────────────────────────────
	models.Err.GameNotFound: "所选游戏不存在，请更新登录器或联系管理员",
	models.Err.GameDisabled: "该游戏暂未开放，请稍后再试或选择其它游戏",
	// ── 邀请码（1040~1041，2026-10-24）──────────────────────────────
	//
	// 两个码分开：没填 vs 填了但不可用。文案必须能指导玩家下一步做什么 ——
	// 混成一句"邀请码错误"会让人以为是自己输错了格式。
	models.Err.InviteRequired: "请输入邀请码（可向管理员索取）",
	models.Err.InviteInvalid:  "邀请码无效或已被使用，请向管理员索取新的邀请码",
}
