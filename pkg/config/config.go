package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// OverrideFileName 是热更新配置文件的名称，优先于 appsettings.json。
const OverrideFileName = "appsettings.override.json"

// SmtpSection 是「QQ 号绑定」用的发信配置（2026-09-24）。
//
// 授权码属于敏感凭据，与 Admin.AuthKey 同级处理：
//   - appsettings.json 里默认留空；
//   - 生产用环境变量 S4A21_SMTP_PASS 注入（见 applyEnvOverrides）。
//
// 为什么必须这样：配置目录会被整体打包分发，授权码泄露等于别人能用这个
// 邮箱以你的名义发信；而 QQ 邮箱被判定异常发信会**直接禁用 SMTP 权限**，
// 连带把玩家注册/绑定的验证码通道打死。
type SmtpSection struct {
	Enabled  bool   `json:"Enabled"`
	Host     string `json:"Host"`
	Port     int    `json:"Port"`
	UseSSL   bool   `json:"UseSSL"`
	Username string `json:"Username"`
	// Password 是邮箱的 SMTP 授权码（不是登录密码）。
	Password string `json:"Password"`
	// FromName 是收件人看到的发件人显示名。
	FromName string `json:"FromName"`

	// DailyLimit 是网关自己卡的发信上限，用于自保。
	// ★ 腾讯侧普通 QQ 邮箱的实际日上限约 100~200 封（非公开数字，随风控浮动），
	// 这里默认 80 留出余量：宁可让玩家看到"今日额度已用完"，
	// 也不要让整个通道被风控停掉。
	DailyLimit int `json:"DailyLimit"`
	// PerMinuteLimit 是分钟级上限。腾讯侧同账号约 30 封/分钟，
	// 这里默认 20 —— 正常业务量下永远打不到，只在被刷时兜底。
	PerMinuteLimit int `json:"PerMinuteLimit"`

	// CodeTTLSeconds 是验证码有效期（默认 300 秒 = 5 分钟）。
	CodeTTLSeconds int `json:"CodeTTLSeconds"`
	// ResendCooldownSeconds 是同一目标的重新获取冷却（默认 60 秒）。
	ResendCooldownSeconds int `json:"ResendCooldownSeconds"`
	// TimeoutSeconds 是单封邮件的整体超时（默认 15 秒）。
	TimeoutSeconds int `json:"TimeoutSeconds"`
}

// GatewayConfig 是网关的全部配置。
type GatewayConfig struct {
	Smtp       SmtpSection       `json:"Smtp"`
	Gateway    GatewaySection    `json:"Gateway"`
	Database   DatabaseSection   `json:"Database"`
	GameServer GameServerSection `json:"GameServer"`
	// GameServers 是多服模型（2026-10-16 双服改造）：一个网关同时带多个
	// 游戏服（S4A21 / S5A9-DNF95 …），每个服一套后端地址、端口表、
	// 频道列改写协议与启动参数模板。
	//
	// ★ 与旧 GameServer 段的关系：加载时规范化（见 NormalizeGameServers）——
	//   只有旧段时合成单元素列表；两段都在时以 GameServers 为准。
	//   规范化后 GameServer 被置为「默认服（第一个启用服）」的内嵌段，
	//   作为**派生镜像**供老读取方（LaunchArgs 模板等）无缝工作。
	//   新代码一律用 GameServers，不要读 GameServer。
	GameServers    []GameServerEntry     `json:"GameServers"`
	Pvf            PvfSection            `json:"Pvf"`
	Launcher       LauncherSection       `json:"Launcher"`
	Admin          AdminSection          `json:"Admin"`
	RateLimit      RateLimitSection      `json:"RateLimit"`
	Token          TokenSection          `json:"Token"`
	Tls            TlsSection            `json:"Tls"`
	Heartbeat      HeartbeatSection      `json:"Heartbeat"`
	Device         DeviceSection         `json:"Device"`
	RegisterLimit  RegisterLimitSection  `json:"RegisterLimit"`
	Server         ServerSection         `json:"Server"`
	GatewayControl GatewayControlSection `json:"GatewayControl"`
	Maintenance    MaintenanceSection    `json:"Maintenance"`

	// runtimeMu 保护**运行时可变**的配置段（Launcher / Maintenance / RegisterLimit / Heartbeat）——
	// 这几段会被管理后台在运行中改写（httprouter 的 runtimeConfigBackend），
	// 而认证侧（auth 的版本门禁、注册限额判定）、HTTP 侧（policy/notice/update 端点）
	// 与清理协程（cmd/gateway 的巡检 ticker 读 Heartbeat.TimeoutSeconds）在并发读。
	//
	// G-5（2026-10-04 审查）：原先全程无锁 —— 管理员开维护模式的同时有玩家登录，
	// 可能读到**撕裂的切片头**（Maintenance.AdminAccounts）而崩溃，或读到半改的门禁值。
	// 只对这几个字段加锁；其余字段是启动时定型、之后只读，不进锁。
	//
	// 注意：本结构体因此**不可按值拷贝**（vet copylocks）。全仓均以 *GatewayConfig 传递。
	runtimeMu sync.RWMutex
}

// LauncherSnapshot 返回 Launcher 段的运行时快照（并发安全）。
func (c *GatewayConfig) LauncherSnapshot() LauncherSection {
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	return c.Launcher
}

// MaintenanceSnapshot 返回 Maintenance 段的运行时快照（并发安全）。
//
// AdminAccounts 额外做一次切片拷贝：它会被后台整体替换（SetMaintenanceRuntime），
// 直接返回共享底层会让调用方在遍历时读到被替换后的元素 —— 正是 G-5 说的"撕裂"。
func (c *GatewayConfig) MaintenanceSnapshot() MaintenanceSection {
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	out := c.Maintenance
	if c.Maintenance.AdminAccounts != nil {
		out.AdminAccounts = append([]string(nil), c.Maintenance.AdminAccounts...)
	}
	return out
}

// SetLauncherRuntime 在锁内更新 Launcher 段的运行时可变字段（传 nil = 不改该项）。
func (c *GatewayConfig) SetLauncherRuntime(minVersion, downloadURL, updateNotice *string, maxInstances *int) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	if minVersion != nil {
		c.Launcher.MinVersion = *minVersion
	}
	if downloadURL != nil {
		c.Launcher.DownloadUrl = *downloadURL
	}
	if updateNotice != nil {
		c.Launcher.UpdateNotice = *updateNotice
	}
	if maxInstances != nil {
		c.Launcher.MaxInstances = *maxInstances
	}
}

// SetMaintenanceRuntime 在锁内更新 Maintenance 段的运行时可变字段（传 nil = 不改该项）。
// admins 落库时做一次拷贝：调用方可能复用该切片。
func (c *GatewayConfig) SetMaintenanceRuntime(enabled *bool, message *string, admins []string) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	if enabled != nil {
		c.Maintenance.Enabled = *enabled
	}
	if message != nil {
		c.Maintenance.Message = *message
	}
	if admins != nil {
		c.Maintenance.AdminAccounts = append([]string(nil), admins...)
	}
}

// RegisterLimitSnapshot 返回注册限额段的运行时快照（并发安全）。
//
// 注册是 TCP 侧高频路径（每次登录器点「注册」都会读一次），必须走快照而不是
// 直接摸 c.RegisterLimit.* —— 管理员在后台改限额的同时有玩家注册，无锁读会
// 读到半改的值（-race 下直接报数据竞争）。
func (c *GatewayConfig) RegisterLimitSnapshot() RegisterLimitSection {
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	return c.RegisterLimit
}

// SetRegisterLimitRuntime 在锁内更新注册限额段的运行时可变字段（传 nil = 不改该项）。
//
// 顺序约定与 SetLauncher 一致：由调用方**先落盘 override、成功后再调本函数**，
// 避免落盘失败时留下"内存已改、重启还原"的不一致。
func (c *GatewayConfig) SetRegisterLimitRuntime(enabled *bool, perIPPerDay, perMachine *int) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	if enabled != nil {
		c.RegisterLimit.Enabled = *enabled
	}
	if perIPPerDay != nil {
		c.RegisterLimit.PerIPPerDay = *perIPPerDay
	}
	if perMachine != nil {
		c.RegisterLimit.PerMachine = *perMachine
	}
}

// HeartbeatSnapshot 返回心跳段的运行时快照（并发安全）。
//
// 会话超时清理协程每 CheckIntervalSeconds 读一次 TimeoutSeconds
// （cmd/gateway/main.go 的巡检 ticker）—— 管理员在后台改超时的同时它正在跑，
// 无锁读会读到半改的值（-race 下直接报数据竞争），所以统一走快照。
func (c *GatewayConfig) HeartbeatSnapshot() HeartbeatSection {
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	return c.Heartbeat
}

// SetHeartbeatRuntime 在锁内更新心跳段的运行时可变字段（传 nil = 不改该项）。
//
// 目前**只暴露 TimeoutSeconds**：CheckIntervalSeconds 在启动时就决定了巡检 ticker
// 的周期（newHeartbeatTicker），改它需要重建 ticker，不在本接口范围内。
//
// 顺序约定与 SetLauncher 一致：由调用方**先落盘 override、成功后再调本函数**，
// 避免落盘失败时留下"内存已改、重启还原"的不一致。
//
// 取值边界（由调用方校验）：必须**大于登录器心跳周期**（161/193/216 上都是 30s），
// 否则每一次正常心跳之间都会判超时；又不宜过大，否则玩家客户端崩溃后会话长期挂着。
func (c *GatewayConfig) SetHeartbeatRuntime(timeoutSeconds *int) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	if timeoutSeconds != nil {
		c.Heartbeat.TimeoutSeconds = *timeoutSeconds
	}
}

type GatewaySection struct {
	TcpPort                int    `json:"TcpPort"`
	HttpPort               int    `json:"HttpPort"`
	ProxyPort              int    `json:"ProxyPort"`
	ListenAddress          string `json:"ListenAddress"`
	HttpListenAddress      string `json:"HttpListenAddress"`
	AdminHttpPort          int    `json:"AdminHttpPort"`
	AdminHttpListenAddress string `json:"AdminHttpListenAddress"`
	DisableAdminHttp       bool   `json:"DisableAdminHttp"`
	TcpIdleTimeoutSeconds  int    `json:"TcpIdleTimeoutSeconds"`
	// TcpHandshakeTimeoutSeconds 是 TLS 握手专属超时（秒），默认 10。
	//
	// 为什么必须独立于 TcpIdleTimeoutSeconds：握手复用 idle 超时时，
	// 一个"连上但不发 ClientHello"的连接能把 acceptLoop 卡住整个 idle 时长
	// （线上 600s）。期间新玩家 TCP 连得上（内核 backlog 照常接纳），
	// 却永远等不到 ServerHello —— 登录器 20s 超时后报 L4002，批量掉登录。
	// 2026-10-15 正式服2（193）实测：一晚三次，每次一批玩家同秒 EO F 潮。
	TcpHandshakeTimeoutSeconds int `json:"TcpHandshakeTimeoutSeconds"`
	TcpMaxConnections          int `json:"TcpMaxConnections"`

	// InternalPort / InternalListenAddress 是"进程分离"用的内部 API 地址。
	// ⚠️ 只应绑 loopback —— 它能让调用者读在线名单、踢人、重载端口表。
	InternalPort          int    `json:"InternalPort"`
	InternalListenAddress string `json:"InternalListenAddress"`

	// ServeAdminInProcess 是**回滚开关**。
	//
	//   false（默认，双进程）：网关起 StartPublic + StartInternal；
	//                          管理后台由独立的 s4a21-admin 进程提供（8443）。
	//   true（单进程/回滚）  ：网关自己把管理后台也起了（8080 + AdminHttpPort），
	//                          停掉 s4a21-admin 即可回到分离前的形态。
	//
	// 回滚步骤：置 true → 给 AdminHttpPort 配回 8443 → 重启 gateway → 停用 gateway-admin。
	ServeAdminInProcess bool `json:"ServeAdminInProcess"`
}

type DatabaseSection struct {
	Path               string `json:"Path"`
	GamePath           string `json:"GamePath"`
	WalMode            bool   `json:"WalMode"`
	BusyTimeoutSeconds int    `json:"BusyTimeoutSeconds"`
}

type GameServerSection struct {
	PublicIP                     string   `json:"PublicIP"`
	BackendHost                  string   `json:"BackendHost"`
	BackendChannelPort           int      `json:"BackendChannelPort"`
	GamePorts                    []int    `json:"GamePorts"`
	GamePortMap                  []string `json:"GamePortMap"`
	KeyTimeZoneOffsetHours       int      `json:"KeyTimeZoneOffsetHours"`
	MaxConnectionsPerIP          int      `json:"MaxConnectionsPerIP"`
	FirstReadTimeoutSeconds      int      `json:"FirstReadTimeoutSeconds"`
	IdleTimeoutSeconds           int      `json:"IdleTimeoutSeconds"`
	BackendConnectTimeoutSeconds int      `json:"BackendConnectTimeoutSeconds"`

	// TcpKeepAliveSeconds 是 Game/Channel 代理两端 TCP 连接的保活探测周期（秒）。
	// 0 或负数 = 不开 SO_KEEPALIVE（保持历史行为）。
	//
	// ★ 为什么必须有：IdleTimeoutSeconds 只看「有没有应用层数据」，
	// 而客户端被强杀 / 崩溃 / 断网时 TCP 不会收到 FIN —— 那条半开连接会
	// 一直占着 MaxConnectionsPerIP 的槽位，直到 IdleTimeoutSeconds（默认 1800s
	// = 30 分钟）用尽才释放。实测症状：玩家关掉游戏后重开，仍然被
	// 「单 IP 并发已达上限」拒之门外（2026-10-13 新机双开测试）。
	//
	// keepalive 是**传输层**探活：只要对端主机还在、网络还通就会回 ACK，
	// 所以纯挂机（不发游戏包）的玩家不会被误踢 —— 这正是它比「直接调小
	// IdleTimeoutSeconds」安全的地方。探测失败后 socket 被置错，
	// copyWithTimeout 的读会返回错误 ⇒ 连接关闭 ⇒ 槽位立刻释放。
	//
	// 实际判死耗时 = TcpKeepAliveSeconds × (1 + net.ipv4.tcp_keepalive_probes)。
	// Go 的 SetKeepAlivePeriod 会同时设置 TCP_KEEPIDLE 与 TCP_KEEPINTVL，
	// 探测次数仍取系统默认（通常 9）。部署脚本把该值调到 3 ⇒ 60s 时约 4 分钟。
	TcpKeepAliveSeconds int `json:"TcpKeepAliveSeconds"`

	LaunchArgsFormat string `json:"LaunchArgsFormat"`

	// ── 以下四项只对 ProtocolS5A3 有意义，其余协议忽略 ──────────────────

	// InitialGamePort 是 S5A3 启动串第 4 段（客户端首个游戏口）。
	// 0 = 让客户端自己从 CHANNELINFO 里挑，与 S5A3 本地一键端
	// （deploy/windows/local_client.py 填 0）口径一致。建议保持 0。
	InitialGamePort int `json:"InitialGamePort"`

	// AccountApiUrl 是 S5A3 服务端账号 API 的基址，形如
	// `http://127.0.0.1:17002`（DNFBRIDGE_ACCOUNT_API_LISTEN 的地址）。
	//
	// 该 API 由服务端提供（internal/services/dnfbridge/account_api.go）：
	//   POST /api/account/register {"account","password"}
	//   POST /api/account/login    {"account","password"} → {"ok","account_id","token","message"}
	//   GET  /api/status
	// 密码是**明文**（服务端自己 bcrypt），不是 MD5 —— 所以 S5A3 模式下
	// 登录器必须发明文，见 pkg/service/s5a3_account.go。
	AccountApiUrl string `json:"AccountApiUrl"`
	// AccountApiTimeoutSeconds 是调用上面三个接口的超时，0 = 8 秒。
	AccountApiTimeoutSeconds int `json:"AccountApiTimeoutSeconds"`

	// PartyUDPPorts 是 S5A3 组队 UDP 中继端口段（服务端
	// party_udp_relay_port_start/count，默认 30000 起 64 个）。
	//
	// 留空 = 不做 UDP 中继（组队时客户端会尝试直连服务端 UDP 端口，
	// 只有服务端 UDP 端口对外可达时才可用）。填了才启用 1:1 UDP 透传，
	// 见 pkg/proxy/udp_relay.go。
	PartyUDPPorts []int `json:"PartyUDPPorts"`

	// ProxyProtocol 控制是否在转发任何客户端字节**之前**，先向后端写一行
	// PROXY protocol v1 头：
	//
	//	PROXY TCP4 <真实客户端IP> <本机IP> <源端口> <目的端口>\r\n
	//
	// 为什么需要：网关是用户态 TCP 代理，服务端看到的 TCP 对端恒为 127.0.0.1。
	// 而 PvP 的 UDP 中继强制「UDP 源 IP == TCP 源 IP」，PK 场数据报会被全部判
	// rejected source tuple；组队/副本下发给队友的 P2P 地址也会变成 127.0.0.1。
	// 把真实地址用 PROXY 头声明给服务端，两边就一致了。
	//
	// 取值："" 或 "off" = 不发送（缺省）；"v1" = 发送 v1 头。
	//
	// ★ 缺省**关闭**是有意的：服务端不认识这行头时会把它当成游戏包头，
	// 结果是所有玩家立刻掉线。必须先在服务端具备识别能力（缺省已开，
	// 见 GameNetworkConfig.ProxyProtocolEnabled），再在这里打开。
	ProxyProtocol string `json:"ProxyProtocol"`

	// GamePortAuth 游戏口准入控制（方案 D：首包 m_id + 凭证认证）。
	//
	// 背景：后端游戏登录**不校验密码**（LoginHandler 只 GetByMid、陌生 m_id
	// 自动建号），频道口后端零鉴权 ⇒ 游戏口准入是账号安全唯一闸门。
	// 旧形态只有「IP 白名单」一道，带来两个问题：
	//  1. 加速器/跨网段玩家登录 IP ≠ 游戏出口 IP 时被误伤（正式服2 事件二实盘）；
	//  2. 已登录用户可伪造首包 m_id 冒充任意账号（网关不校验首包与来源 IP 的
	//     一致性，后端又不验密码）。
	// 方案 D 用首包凭证同时解决两者，详见 pkg/proxy 的 admitGameClient。
	GamePortAuth GamePortAuthSection `json:"GamePortAuth"`
}

// ─────────────────────────────────────────────────────────────────────────────
// 多服模型（2026-10-16 双服改造）
//
// 一个网关同时带 S4A21 与 S5A9（DNF95）两个服：登录器让玩家自选进哪个，
// 网关按「服」隔离后端地址、公网端口段、频道列改写协议与启动参数模板。
//
// 协议差异全部收在 pkg/proxy 的下行适配层里（S4A21ChannelAdapter /
// S5A95ChannelAdapter / S5A95GameAdapter），转发热路径不加任何 if/else。
// ─────────────────────────────────────────────────────────────────────────────

// 协议标识。Protocol 决定该服绑定哪组下行适配器。
const (
	// ProtocolS4A21 是 S4A21（86 版本）游戏协议：频道列 0x12 明文布局
	// （条目 48B、IP@28、端口@44、zlib + AES 日密钥）。
	ProtocolS4A21 = "s4a21"
	// ProtocolS5A95 是 S5A9（DNF95）游戏协议：频道口 op18 Directory
	// （AES-ECB 固定密钥 + zlib，条目 64B、IP@28、端口@60），
	// 游戏口 LOGIN 回复内嵌 Endpoint(地址, 端口)。
	ProtocolS5A95 = "s5a95"
	// ProtocolS5A3 是 S5A3（DNF90 / ServerS5A3）游戏协议。
	//
	// 与上面两个**根本不同**：S5A3 的频道表不是"网关改写出来的"，而是
	// 服务端自己在 class0/op1 CHANNELINFO 里下发的（body 经 rotr2^0xB5 编码的
	// protobuf，字段 12 = serverIP、各频道条目自带端口）。客户端拿到的地址
	// 完全由服务端的 DNFBRIDGE_SERVER_IP 决定，网关**没有可改写的中间层**。
	//
	// 因此 S5A3 的代理形态是**1:1 端口透传**：网关监听与后端相同的端口号，
	// 服务端把 DNFBRIDGE_SERVER_IP 配成网关的对外地址，CHANNELINFO 里就
	// 天然是网关地址，不需要任何下行改写。见 pkg/proxy/adapter_s5a3.go。
	ProtocolS5A3 = "s5a3"
)

// GameServerEntry 是一个游戏服的完整配置。
//
// 内嵌 GameServerSection（JSON 字段扁平提升），额外多出五个「服」维度字段。
type GameServerEntry struct {
	// Id 是服的唯一标识，同时是登录器 CMD_LOGIN 的 game 字段值。
	// 只允许 [a-z0-9-]（会进文件名 proxy_ports-<id>.json）。
	Id string `json:"Id"`
	// Name 是展示名（管理后台 / 日志用）。
	Name string `json:"Name"`
	// Protocol 见 ProtocolS4A21 / ProtocolS5A95。
	Protocol string `json:"Protocol"`
	// Enabled 缺省（键缺失）= 启用；显式 false = 停用（不开任何监听）。
	// 用指针而不是 bool：运营加一个服时忘了写 Enabled 也不至于把它停掉。
	Enabled *bool `json:"Enabled"`
	// ChannelListenerPort 是该服频道口（频道列表）的公网监听端口。
	// 0 = 用 Gateway.ProxyPort —— 仅「只有一个启用服」时允许，
	// 多服必须显式配置且互不碰撞（见 ValidateGameServers）。
	ChannelListenerPort int `json:"ChannelListenerPort"`

	GameServerSection
}

// IsEnabled 键缺失视为启用（见 Enabled 注释）。
func (e *GameServerEntry) IsEnabled() bool {
	return e.Enabled == nil || *e.Enabled
}

// FindGameServer 按 Id 找服（CMD_LOGIN 的 game 字段解析用，2026-10-17）。
//
// 返回 (entry, true) 表示找到；第二返回值表达"存在但停用"与"根本没有"
// 两种失败，让调用方回报不同的错误码（停用=维护中，不存在=配置/客户端问题）。
// 配置未经规范化时（测试直构字面量）按 Id 直比也能工作。
func (c *GatewayConfig) FindGameServer(id string) (GameServerEntry, bool) {
	if id == "" {
		// 空 = 默认服（第一个启用服；没有就按旧 GameServer 段合成）。
		// 永远返回 true：老登录器不带 game 字段必须照旧能登录。
		return c.DefaultGameServerEntry(), true
	}
	for i := range c.GameServers {
		if c.GameServers[i].Id == id {
			return c.GameServers[i], true
		}
	}
	// 未规范化且只配了旧 GameServer 段：默认服 Id 是 s4a21。
	if len(c.GameServers) == 0 && id == ProtocolS4A21 {
		return c.DefaultGameServerEntry(), true
	}
	return GameServerEntry{}, false
}

// DefaultGameServerEntry 返回规范后的默认服（第一个启用服）。
//
// 配置未经 NormalizeGameServers 规范化时（测试直接构造字面量等），
// 这里按旧 GameServer 段合成一个等价条目 —— 保证任何调用路径
// 都能拿到一个可用的服配置。
func (c *GatewayConfig) DefaultGameServerEntry() GameServerEntry {
	for i := range c.GameServers {
		if c.GameServers[i].IsEnabled() {
			return c.GameServers[i]
		}
	}
	// 未规范化：按旧段合成（Id/Protocol 取 legacy 口径）。
	entry := GameServerEntry{
		Id:                ProtocolS4A21,
		Name:              "S4A21",
		Protocol:          ProtocolS4A21,
		GameServerSection: c.GameServer,
	}
	enabled := true
	entry.Enabled = &enabled
	return entry
}

// NormalizeGameServers 把配置规范成多服模型（幂等）：
//   - GameServers 非空：以其为准，逐条补默认值；
//   - 只有旧 GameServer 段：合成单元素列表（等价改造前行为）；
//   - 规范化后把 GameServer 置为默认服的内嵌段（派生镜像，见字段注释）。
//
// 返回 error 表示配置存在硬冲突（端口碰撞等）—— 调用方应拒绝启动，
// 而不是让某个服静默不工作。
func (c *GatewayConfig) NormalizeGameServers() error {
	if len(c.GameServers) == 0 {
		// 旧配置：合成单服。Id 用 s4a21，端口 0 = 沿用 Gateway.ProxyPort，
		// 与改造前逐字节等价。
		enabled := true
		c.GameServers = []GameServerEntry{{
			Id:                ProtocolS4A21,
			Name:              "S4A21",
			Protocol:          ProtocolS4A21,
			Enabled:           &enabled,
			GameServerSection: c.GameServer,
		}}
	} else {
		for i := range c.GameServers {
			e := &c.GameServers[i]
			if e.Id == "" {
				e.Id = ProtocolS4A21
			}
			if e.Name == "" {
				e.Name = e.Id
			}
			if e.Protocol == "" {
				e.Protocol = ProtocolS4A21
			}
			// LaunchArgsFormat 缺省按协议补权威模板（2026-10-17 双服）：
			// S5A95 的 99?…{digest}… 与 S4A21 的 9?…{token}… 是两套格式，
			// 运营只加 Id/Protocol 就应得到能用的模板，而不是空串 ——
			// 空串会让登录器拿到空 LaunchArgs，表现为"登录成功但游戏起不来"。
			if strings.TrimSpace(e.LaunchArgsFormat) == "" {
				switch e.Protocol {
				case ProtocolS5A95:
					e.LaunchArgsFormat = DefaultS5A95LaunchArgsFormat
				case ProtocolS5A3:
					e.LaunchArgsFormat = DefaultS5A3LaunchArgsFormat
				default:
					e.LaunchArgsFormat = DefaultLaunchArgsFormat
				}
			}
		}
	}

	if err := c.ValidateGameServers(); err != nil {
		return err
	}

	// 派生镜像：默认服（第一个启用服）的内嵌段回写到 GameServer，
	// 老读取方（如 service.buildLaunchArgs 读 GameServer.LaunchArgsFormat）
	// 无需改动即继续工作在默认服上。
	def := c.DefaultGameServerEntry()
	c.GameServer = def.GameServerSection
	return nil
}

// ValidateGameServers 校验多服配置的硬冲突。
//
// 全部是「不校验就会静默坏一个服」的问题：公网端口碰撞 = 监听失败、
// 频道口碰撞 = 两个服抢同一个口、协议未知 = 适配器绑不上。
func (c *GatewayConfig) ValidateGameServers() error {
	seenId := map[string]bool{}
	seenPublic := map[int]string{}  // 公网 Game 端口 -> 占用服 Id
	seenChannel := map[int]string{} // 频道口 -> 占用服 Id
	enabledCount := 0

	// skipProxyPort 的来历（2026-10-16 修的自指缺陷）：
	//
	// 频道口在**单服**模式下本来就是 Gateway.ProxyPort —— 配置写 0 表示"沿用
	// ProxyPort"（见 ChannelListenerPort 字段注释），此时拿它去和 ProxyPort
	// 比，等于拿一个端口撞它自己，必然报错。
	//
	// 后果不是"功能不可用"，是**进程 Fatal 拒绝启动**：所有"只有旧 GameServer
	// 段、没显式配 ChannelListenerPort"的存量配置（161 就是这种）一加载就炸。
	// 其余四个端口的碰撞判定照旧 —— 那些是真的撞别人。
	reserve := func(port int, what string, skipProxyPort bool) error {
		switch {
		case port == c.Gateway.TcpPort:
			return fmt.Errorf("%s 与 Gateway.TcpPort(%d) 碰撞", what, port)
		case port == c.Gateway.HttpPort:
			return fmt.Errorf("%s 与 Gateway.HttpPort(%d) 碰撞", what, port)
		case !skipProxyPort && port == c.Gateway.ProxyPort:
			return fmt.Errorf("%s 与 Gateway.ProxyPort(%d) 碰撞", what, port)
		case c.Gateway.AdminHttpPort > 0 && port == c.Gateway.AdminHttpPort:
			return fmt.Errorf("%s 与 Gateway.AdminHttpPort(%d) 碰撞", what, port)
		case c.Gateway.InternalPort > 0 && port == c.Gateway.InternalPort:
			return fmt.Errorf("%s 与 Gateway.InternalPort(%d) 碰撞", what, port)
		}
		return nil
	}

	for i := range c.GameServers {
		e := &c.GameServers[i]
		if !e.IsEnabled() {
			continue
		}
		enabledCount++

		if seenId[e.Id] {
			return fmt.Errorf("GameServers: Id %q 重复", e.Id)
		}
		seenId[e.Id] = true

		for _, r := range e.Id {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("GameServers: Id %q 含非法字符（只允许小写字母/数字/连字符）", e.Id)
			}
		}

		switch e.Protocol {
		case ProtocolS4A21, ProtocolS5A95, ProtocolS5A3:
		default:
			return fmt.Errorf("GameServers[%s]: 未知 Protocol %q（可选 %s / %s / %s）",
				e.Id, e.Protocol, ProtocolS4A21, ProtocolS5A95, ProtocolS5A3)
		}

		channelPort := e.ChannelListenerPort
		if channelPort == 0 {
			if enabledCount > 1 {
				return fmt.Errorf("GameServers[%s]: 多服配置必须显式指定 ChannelListenerPort（0 只允许单服）", e.Id)
			}
			channelPort = c.Gateway.ProxyPort
		}
		if channelPort < 1 || channelPort > 65535 {
			return fmt.Errorf("GameServers[%s]: ChannelListenerPort %d 非法", e.Id, e.ChannelListenerPort)
		}
		// 频道口跳过与 ProxyPort 的比对：单服时它就是 ProxyPort 本身
		// （见上方 reserve 的 skipProxyPort 注释）。
		if err := reserve(channelPort,
			fmt.Sprintf("GameServers[%s].ChannelListenerPort", e.Id), true); err != nil {
			return err
		}
		if other, ok := seenChannel[channelPort]; ok {
			return fmt.Errorf("GameServers[%s] 与 [%s] 的频道口 %d 碰撞", e.Id, other, channelPort)
		}
		seenChannel[channelPort] = e.Id

		for pub := range e.GamePortMapResolved() {
			if other, ok := seenPublic[pub]; ok {
				return fmt.Errorf("GameServers[%s] 与 [%s] 的公网 Game 端口 %d 碰撞", e.Id, other, pub)
			}
			seenPublic[pub] = e.Id
		}
	}
	return nil
}

// GamePortAuthSection 是游戏口准入（方案 D）的配置段。
type GamePortAuthSection struct {
	// Enabled 总开关。false = 完全回到旧行为：IP 白名单先行，
	// 首包只用于会话归属（双开同 IP 精确归属那一套）。
	Enabled bool `json:"Enabled"`

	// RequireCredential 决定「首包凭证不匹配」时的处置：
	//   false（缺省）= 回退 IP 白名单 —— 与旧行为一致的零新拒绝路径，
	//     用于观察期：先确认真实客户端首包凭证形态，再收紧；
	//   true = 一律拒绝 —— 堵住「已登录用户伪造首包冒充任意账号」。
	//
	// ★ 收紧前必须确认客户端首包密码字段的形态（网关日志会打 准入=token/pwd），
	//   否则会把正常玩家当冒充者拒掉。
	RequireCredential bool `json:"RequireCredential"`
}

type PvfSection struct {
	// FilePath 是**客户端基准 PVF** 的路径 —— 网关侧保存的那份，客户端校验与
	// 增量更新全部以它为准（`/api/pvf/info` 的指纹、`/api/launcher/policy` 下发
	// 的 hash、增量包、版本历史）。
	//
	// ★★ 它**不是**服务端 DfoServer 读的那份。服务端 PVF 由 Server.PvfPath /
	// Server.WorkDir 推导（见 ServerManager.resolvePvfPath），两者必须是**不同文件**：
	//   · 客户端基准（本字段）：将来可换成加密版，随整包/增量发给玩家
	//   · 服务端 PVF（Server 段）：始终明文，只在本机使用
	// 两者指向同一文件时，「替换服务端 PVF」会覆盖客户端的增量基线 .bak，
	// 生成「新版→新版」的自差分，导致旧版客户端全部进不去
	//（2026-09-30 线上事故；handleAdminServerPvf 已加硬守卫拒绝该配置下的写入）。
	FilePath string `json:"FilePath"`

	// DeltaDir 是 PVF 增量包目录，相对网关运行目录（默认 "./pvf_delta"）。
	//
	// 上传新 PVF 时自动生成「上一版 → 当前版」的 delta 放在这里，
	// 由 /api/launcher/pvf/delta 下发给登录器做增量更新。
	// 固定增量只保留最新一份（current.delta）；「更老版本 → 当前版」的
	// 按需增量按 from_<HASH>.delta 缓存在同一目录，上传新版时全部作废清除。
	DeltaDir string `json:"DeltaDir"`

	// HistoryDir 是 PVF 历史版本目录（默认 "./pvf_history"）。
	//
	// 内容寻址存储：每个出现过的版本一份 <大写SHA-256>.pvf + index.json 元数据
	//（显示名 / 上传时间 / 原文件名）。两处用途：
	//  1. 管理后台「版本历史」表 + 回退功能（回退走完整 ReplacePvf 链路）
	//  2. /api/launcher/pvf/delta?from=<hash> 按需生成「任意历史版 → 当前版」增量
	HistoryDir string `json:"HistoryDir"`

	// HistoryKeep 是历史保留版数上限（默认 20，约 1.5 GB）。超出删最老；
	// 当前版与 .bak（固定 delta 基线）永不删。0 取默认。
	HistoryKeep int `json:"HistoryKeep"`
}

type LauncherSection struct {
	MinVersion  string `json:"MinVersion"`
	DownloadUrl string `json:"DownloadUrl"`

	// UpdateNotice 是登录器「更新内容」区展示的公告正文，由管理后台
	// 「客户端配置」页维护。多行文本，空串表示不下发公告（登录器显示「暂无公告」）。
	//
	// 与 MinVersion/DownloadUrl 共用同一条下发链路：存在网关进程内存 →
	// /api/launcher/notice 公开只读 → 改完立刻生效，不用重启网关或登录器。
	UpdateNotice string `json:"UpdateNotice"`

	// PluginDir 是插件下发目录，相对网关运行目录（默认 "./plugins"）。
	//
	// 目录里放插件文件（*.dll 及其伴随 *.ini / *.xui），外加一份可选的
	// plugins.json 元数据清单。网关按目录签名 (name,size,mtime) 判断是否变化，
	// 变了就重算 sha256 —— 所以**丢文件进去即生效，不用重启网关**。
	//
	// 元数据的权威源是 plugins.json（哪个是核心插件、默认开关、显示名、顺序）。
	// 它缺失时退化为"按 *.dll 文件名推导"，并在清单响应里置 degraded=true，
	// 登录器据此可以拒绝继续 —— 这是刻意的失败方向：清单必须由网关控制。
	PluginDir string `json:"PluginDir"`

	// PluginBaseUrl 是下发给登录器的插件下载基址前缀（可留空）。
	//
	// 留空时登录器用「自己连的那个网关地址 + /api/launcher/plugins/file/」拼。
	// 非空时可用于把插件字节的分发挪到 CDN / 对象存储：**网关只出清单（权威），
	// 字节从别处来**，服务器出网带宽为零。清单里的 sha256 始终由网关算，改不了。
	PluginBaseUrl string `json:"PluginBaseUrl"`

	// PluginEnabled 是插件下发的总开关。**缺省（nil）视为开。**
	//
	// 置 false 时 /api/launcher/plugins 仍返回 200，但带 enabled=false，
	// 登录器据此退回内置插件、完全不下载 —— 这是插件下发出问题时的
	// **一键回滚开关**，不必回滚登录器 exe。
	//
	// 用 *bool 而不是 bool：现网 appsettings.json 里没有这个键，
	// 用 bool 会把"没配"读成 false，等于把功能默认关掉。
	PluginEnabled *bool `json:"PluginEnabled"`

	// UpdateDir 是登录器更新分发目录，相对网关运行目录（默认 "./launcher_update"）。
	//
	// 布局（2026-10-01 自更新）：
	//
	//	launcher_update/current.exe            当前版本全量（按需 delta 的 to 源）
	//	launcher_update/history/<HASH>.exe     历史版本（内容寻址）
	//	launcher_update/history/index.json     版本记录（version/name/filename）
	//	launcher_update/delta/from_<HASH>.delta 按需增量缓存（换版即清）
	//
	// 与插件目录同模式：纯文件系统、无网关内存态，gateway(8080 下发) 与
	// admin(8443 上传) 两个进程共用同一目录，不需要 backends 抽象。
	UpdateDir string `json:"UpdateDir"`

	// UpdateKeep 是登录器历史保留版数上限（默认 4）。
	//
	// ★ 与 PVF 的 HistoryKeep=20 不同量级：登录器一版约 134 MB，20 版 = 2.7 GB，
	// 会把磁盘吃穿。4 版 ≈ 540 MB，覆盖「当前 + 最近三版」—— 比最老历史还老的
	// 客户端自动回退全量下载，功能不丢，只是慢一次。
	UpdateKeep int `json:"UpdateKeep"`

	// UpdateEnabled 是登录器自更新总开关。**缺省（nil）视为开。**
	//
	// 置 false 时 /api/launcher/update 仍返回 200，但带 enabled=false，
	// 登录器据此跳过全部检查逻辑 —— 自更新出问题时的**一键回滚开关**，
	// 改 appsettings.json + 重启即可，不动任何已分发文件。
	UpdateEnabled *bool `json:"UpdateEnabled"`

	// MaxInstances 是单台机器允许同时运行的登录器实例数上限（2026-10-19）。
	//
	// 执行方在**登录器侧**：每个实例启动时抢占一个命名互斥体槽位
	// （Global\S4A21-Launcher-Slot-1..N），抢不到即弹窗退出。
	//
	// 语义边界（改动前务必读）：
	//   - **0（缺省）= 不限制**。老 appsettings.json 没有这个键，Go 零值
	//     就是 0 —— 未配置时行为与改造前完全一致，不误伤现有双开玩家；
	//     管理员在后台填 N（1~32）才对之后启动的实例生效。
	//   - 调大立即生效；**调小只对之后启动的实例生效**，运行中的实例不追溯
	//     （实例数已在旧上限内合法启动，强退会误伤玩家）。
	//   - 「单台机器」= 本机所有 Windows 会话/用户（Global\ 命名空间），
	//     同机换用户再开一个也计数。
	//   - 定位是**提高多开成本**，不是绝对封死：槽位机制对重命名 exe 无效
	//     （槽名编译在登录器里），但改动过的登录器不在本文档覆盖范围内。
	MaxInstances int `json:"MaxInstances"`
}

// LauncherUpdateEnabled 返回登录器自更新总开关的生效值（缺省视为开）。
func (c *GatewayConfig) LauncherUpdateEnabled() bool {
	if c.Launcher.UpdateEnabled == nil {
		return true
	}
	return *c.Launcher.UpdateEnabled
}

// LauncherPluginEnabled 返回插件下发总开关的生效值（缺省视为开）。
//
// 收敛成一处方法而不是各处判 nil：这个值有 3 个调用点
// （清单 handler、管理后台、自检），两处口径不一致就会出现
// 「后台显示关闭、登录器照旧下载」这类静默错位。
func (c *GatewayConfig) LauncherPluginEnabled() bool {
	if c.Launcher.PluginEnabled == nil {
		return true
	}
	return *c.Launcher.PluginEnabled
}

type AdminSection struct {
	AuthKey                      string `json:"AuthKey"`
	BroadcastTotalCharacterLimit int    `json:"BroadcastTotalCharacterLimit"`

	// InternalKey 是内部 API（网关 ↔ admin 进程）的独立密钥，与 AuthKey **分开**。
	//
	// 为什么要分开：AuthKey 交给运营/后台使用者，InternalKey 只存在两台进程的配置里。
	// 两者复用会让"改后台密码"变成"必须同时重启两个进程"，也会把内部能力的凭据
	// 扩散到更多地方。为空时内部 API 端口不启动（安全默认，需要显式配置）。
	InternalKey string `json:"InternalKey"`
}

type RateLimitSection struct {
	Enabled               bool `json:"Enabled"`
	RequestsPerMinute     int  `json:"RequestsPerMinute"`
	HttpRequestsPerMinute int  `json:"HttpRequestsPerMinute"`
}

type TokenSection struct {
	ExpirySeconds int `json:"ExpirySeconds"`
}

type HeartbeatSection struct {
	TimeoutSeconds       int `json:"TimeoutSeconds"`
	CheckIntervalSeconds int `json:"CheckIntervalSeconds"`
	// StaleForceSeconds 掉线重连自动放行阈值（2026-10-10）。
	//
	// 玩家掉线后重开登录器登录，旧会话往往还没到 TimeoutSeconds，于是撞 1023
	// 被弹窗拦住 —— 人不在电脑前就一直进不去。这里给一个**更短的**判据：
	// 旧会话心跳已停滞超过本值，且新登录来自**同一台机器**（同 IP 或同
	// device_secret）⇒ 判定为掉线重连，直接踢旧会话放行，不再弹窗。
	//
	// 语义边界（改动前务必读）：
	//  - 必须**同时**满足"心跳停滞"与"同端"，缺一不可。只满足前者而 IP/设备
	//    不同 = 异地顶号，仍然走 1023 弹窗，顶号保护不受影响。
	//  - 取值必须 **小于 TimeoutSeconds**（否则会话早被清理轮清掉了，这条
	//    逻辑永远跑不到），又必须 **大于登录器心跳周期**（161/216 上都是
	//    30 秒）才不会把"丢了一次心跳的活人"误判成僵尸。
	//  - **0 或负数 = 关闭**，退回原来的"一律弹窗"行为。
	StaleForceSeconds int `json:"StaleForceSeconds"`
}

type DeviceSection struct {
	MaxHistory              int    `json:"MaxHistory"`
	AlertThreshold          int    `json:"AlertThreshold"`
	RotationCooldownMinutes int    `json:"RotationCooldownMinutes"`
	EnforceBinding          bool   `json:"EnforceBinding"`
	AlertWebhook            string `json:"AlertWebhook"`
}

// RegisterLimitSection 是注册限额（反批量注册）配置段（2026-10-13）。
//
// 目的：挡掉"一个人用脚本批量刷号"这类行为，不追求不可绕过 —— 客户端上报的
// 机器码一律可伪造，这里定位是**提高成本**而不是绝对封死。
//
// 三条判据各自独立、命中即拒：
//   - PerIPPerDay：同一来源 IP 每个自然日最多注册几个（0 = 不限制这一维）。
//   - PerMachine：同一机器码累计最多注册几个（0 = 不限制这一维）。
//   - Enabled：总开关，false 时两条判据都不生效（一键回滚用）。
//
// 语义边界（改动前务必读）：
//   - 「当日」按**网关进程所在时区**的零点切分（与 QQ 绑定验证码日额度同一口径，
//     见 service.startOfToday），不是 UTC —— 否则限流会在北京时间早上 8 点重置。
//   - 机器码**缺失**（老登录器不带该字段）时只按 IP 判，**不参与机器计数**。
//     绝不能把缺失值当成同一个空机器码去计数，那会让所有老登录器共用一个配额，
//     全服瞬间注册不了。
//   - 只统计**本次上线之后**的注册流水（register_logs）。存量账号没有历史 IP/机器码，
//     不回溯，也不占配额。
type RegisterLimitSection struct {
	Enabled     bool `json:"Enabled"`
	PerIPPerDay int  `json:"PerIPPerDay"`
	PerMachine  int  `json:"PerMachine"`
}

// DefaultPerIPPerDay / DefaultPerMachine 是注册限额的默认值。
//
// 抽成常量而不是只写在 DefaultConfig 里：service 层判定时要在"配置里写了 0 /
// 没写"之间给出一致口径，散落的字面量迟早对不上。
const (
	DefaultPerIPPerDay = 2
	DefaultPerMachine  = 5
)

type TlsSection struct {
	Enabled      bool   `json:"Enabled"`
	CertFormat   string `json:"CertFormat"`
	CertPath     string `json:"CertPath"`
	CertKeyPath  string `json:"CertKeyPath"`
	CertPassword string `json:"CertPassword"`
}

type ServerSection struct {
	Unit    string `json:"Unit"`
	WorkDir string `json:"WorkDir"`
	PvfPath string `json:"PvfPath"`
	// ★ PvfPath 是**服务端使用的** PVF（明文，DfoServer 读的那份），与
	// Pvf.FilePath（网关侧的客户端基准）是两件事，必须指向不同文件。
	// 留空时按 WorkDir 推导（见 ServerManager.resolvePvfPath）。
	LogPath                string `json:"LogPath"`
	AuctionBotDataDir      string `json:"AuctionBotDataDir"`
	BackupDir              string `json:"BackupDir"`
	LogTailLines           int    `json:"LogTailLines"`
	BackupMaxFileSizeBytes int64  `json:"BackupMaxFileSizeBytes"`
	ControlEnabled         bool   `json:"ControlEnabled"`

	// BackupRetainCount 每个类别（db / pvf / logs）保留最近多少份 .tar.gz。
	//
	// 0 或负数 = 不清理（**默认值**，与改造前一样只增不减）——
	// 自动删备份是破坏性动作，必须显式配置才生效，绝不能靠缺省打开。
	//
	// ★ 只清理「本次产出涉及的类别」，且只认 <类别>-<时间戳>.tar.gz 这一个命名族：
	//   改造前散装的 inventory-*.db / gateway-*.db / Script-*.pvf 一个都不动
	//   —— 那些文件是运维在没有"保留 N 份"这套约定时留下来的，自动删掉属于越权。
	BackupRetainCount int `json:"BackupRetainCount"`

	// BackupPurgeAuditLog 控制「备份完成后是否清理游戏库的背包审计日志并收缩库文件」。
	//
	// 用 *bool 而不是 bool：现网 appsettings.json 里**没有**这个键，
	// 若用 bool，反序列化得到零值 false，功能会静默失效（改完没生效最难查）。
	// nil = 未配置 = 按默认值 true 处理；要关掉必须显式写 false。
	// 判断统一走 PurgeAuditLogEnabled()，不要在调用点直接读字段。
	BackupPurgeAuditLog *bool `json:"BackupPurgeAuditLog"`
}

// PurgeAuditLogEnabled 备份后是否清理审计日志。未配置（nil）按 true。
func (s ServerSection) PurgeAuditLogEnabled() bool {
	if s.BackupPurgeAuditLog == nil {
		return true
	}
	return *s.BackupPurgeAuditLog
}

type GatewayControlSection struct {
	Unit           string `json:"Unit"`
	ControlEnabled bool   `json:"ControlEnabled"`
	LogTailLines   int    `json:"LogTailLines"`
}

type MaintenanceSection struct {
	Enabled       bool     `json:"Enabled"`
	Message       string   `json:"Message"`
	AdminAccounts []string `json:"AdminAccounts"`
}

// DefaultLaunchArgsFormat 启动参数模板的**权威默认值**。
//
// 取值口径为原网关的**生产部署**版本 —— `{token}` 落在第 5 段（紧随 `{m_id}`，其后是常量组 `1?0?6?0?2?1`）。
// 依据（三方一致）：
//  1. `参考文件/S4A21Gateway/README.md` 并列的两版模板，标注「生产 8.138.9.216 实际使用」
//     的是第 5 段那版：
//     代码初始值   ：...{m_id}?1?0?6?0?2?{token}?1?...   ← {token} 在第 10 段
//     生产实际使用 ：...{m_id}?{token}?1?0?6?0?2?1?...   ← {token} 在第 5 段
//  2. `参考文件/S4A21Gateway/appsettings.json`（第 5 段）
//  3. 192.168.1.202 现网 `appsettings.json`（第 5 段）
//
// ⚠️ 本常量**故意不与**原网关 `Models/GatewayConfig.cs:241` 的初始值一致 ——
// 那个初始值把 `{token}` 排到了常量组 `1?0?6?0?2` 之后（第 10 段），是历史缺陷，
// 不要照抄。写反的后果是游戏端拿到写死的常量当 token，
// 表现为玩家「能登录但连不上游戏」，排查成本极高。改动前务必核对生产口径。
const DefaultLaunchArgsFormat = "9?{ip}?{port}?{m_id}?{token}?1?0?6?0?2?1???0?0?0?9n2b1c8r3w7y?0?0?0?0?0?2?0?0?0?0?0?0?0?0?0?0?0?4D87"

// DefaultS5A95LaunchArgsFormat 是 S5A9（DNF95 / ARAD.exe）启动参数模板的
// **权威默认值**，与 S4A21 模板是两个世界的格式，不要混用：
//
//   - 首段是 99（S4A21 是 9）；
//   - 第 5 段是 {digest} 而不是 {token} —— DNF95 客户端把这一段当登录凭证
//     发给游戏服务端，服务端拿它与账号绑定的一次性 digest 比对
//     （AuthenticationService.VerifyOrCreateLogin，PBKDF2）。
//     网关为每个账号签发固定 32 位 hex digest（见 database.EnsureS5A9Digest），
//     玩家改网关密码不会影响它 —— 透传密码 MD5 会让改过密码的账号被
//     S5A9 后端永久拒登。
//   - 尾部常量组 1?0?0?0?0?0?2?0?0?0?0 来自 `E:\DNF95\一键登录.cmd` 实测。
//
// ⚠️ {port} 段填的是**频道口**（GameServerEntry.ChannelListenerPort）：
// DNF95 客户端先连频道口拿 Directory（频道 IP+端口表），与 S4A21 的
// {port}=Gateway.ProxyPort 语义相同但值来自服的频道口配置。
const DefaultS5A95LaunchArgsFormat = "99?{ip}?{port}?{m_id}?{digest}?1?0?0?0?0?0?2?0?0?0?0"

// DefaultS5A3LaunchArgsFormat 是 S5A3（DNF90 / ServerS5A3）启动参数模板。
//
// 权威来源是服务端自己的控制面：`cmd/server/control/controller.go`
// 的 clientLaunchArgument()，逐段含义：
//
//	99 ? {ip} ? {port} ? {initial_game_port} ? {token} ? 01 ? 1 ? 0 ? 0 ? 0 ? 0 ? 1
//	   ? 9n2b1c8r3w7y ? 0 ? 0 ? 19847
//
//   - 首段 99（S4A21 是 9，S5A9 也是 99）；
//   - 第 2 段是频道引导地址（服务端 ChannelListen 的 host）；
//   - 第 3 段是频道引导端口（服务端 ChannelListen 的 port，默认 7001）；
//   - 第 4 段是 Client.InitialGamePort。S5A3 的本地一键端把它填 0
//     （见 deploy/windows/local_client.py），客户端会自行从 CHANNELINFO
//     里取频道端口，所以这里默认也用 0；
//   - 第 5 段 {token} 是**服务端签发**的登录令牌，必须是
//     `de509f65` + 24 位小写十六进制（Protocol.GameOuterToken 的形态）。
//     网关不能自己随机生成 —— 见 pkg/service/s5a3_account.go 的说明；
//   - 尾部 `9n2b1c8r3w7y?0?0?19847` 是客户端校验用的常量组，原样照抄。
//
// ⚠️ 与 S4A21 模板的关键差异：这里没有 {m_id}。S5A3 的账号由服务端
// MySQL 管理、令牌即身份，客户端启动串里根本不带 m_id。
const DefaultS5A3LaunchArgsFormat = "99?{ip}?{port}?{initial_game_port}?{token}?01?1?0?0?0?0?1?9n2b1c8r3w7y?0?0?19847"

// DefaultConfig 返回带有生产环境默认值的配置。
func DefaultConfig() *GatewayConfig {
	return &GatewayConfig{
		Gateway: GatewaySection{
			TcpPort:                    8000,
			HttpPort:                   8080,
			ProxyPort:                  8001,
			ListenAddress:              "0.0.0.0",
			HttpListenAddress:          "",
			AdminHttpPort:              0,
			AdminHttpListenAddress:     "127.0.0.1",
			TcpIdleTimeoutSeconds:      600,
			TcpHandshakeTimeoutSeconds: 10,
			TcpMaxConnections:          512,
			InternalPort:               18080,
			InternalListenAddress:      "127.0.0.1",
			ServeAdminInProcess:        false,
		},
		Database: DatabaseSection{
			Path:               "./Data/gateway.db",
			GamePath:           "",
			WalMode:            true,
			BusyTimeoutSeconds: 30,
		},
		GameServer: GameServerSection{
			PublicIP:                     "127.0.0.1",
			BackendHost:                  "127.0.0.1",
			BackendChannelPort:           7001,
			GamePorts:                    []int{},
			GamePortMap:                  []string{},
			KeyTimeZoneOffsetHours:       0,
			MaxConnectionsPerIP:          4,
			FirstReadTimeoutSeconds:      30,
			IdleTimeoutSeconds:           1800,
			BackendConnectTimeoutSeconds: 10,
			TcpKeepAliveSeconds:          60,
			LaunchArgsFormat:             DefaultLaunchArgsFormat,
			// 缺省关：服务端先具备识别能力后再显式改成 "v1"。
			ProxyProtocol: "off",
			// 方案 D 缺省开启、观察模式（凭证不符回退白名单，不新增拒绝路径）。
			// 确认真实客户端凭证形态后，再把 RequireCredential 置 true 收紧。
			GamePortAuth: GamePortAuthSection{
				Enabled:           true,
				RequireCredential: false,
			},
		},
		Pvf: PvfSection{
			// 客户端基准（网关侧保存），相对网关运行目录 ⇒ 默认 /opt/gateway/Data/Pvf/Script.pvf。
			// ★ 服务端那份在 Server.WorkDir 下（默认识别不到就由运维配 Server.PvfPath），
			//   两者必须不同文件 —— 见 PvfSection.FilePath 的注释。
			FilePath: "./Data/Pvf/Script.pvf",
			// 相对网关运行目录。/opt/gateway/s4a21-gateway 的 CWD 是 /opt/gateway，
			// 所以默认目录是 /opt/gateway/pvf_delta（与 ./plugins 同级）。
			DeltaDir: "./pvf_delta",
			// 历史版本目录与保留数，同上按网关运行目录解析。
			HistoryDir:  "./pvf_history",
			HistoryKeep: 20,
		},
		Launcher: LauncherSection{
			MinVersion:  "2.0.0",
			DownloadUrl: "",
			// 相对网关运行目录。/opt/gateway/s4a21-gateway 的 CWD 是 /opt/gateway，
			// 所以默认目录是 /opt/gateway/plugins。
			PluginDir: "./plugins",
			// 登录器更新分发目录，与 ./plugins 同级。HistoryKeep=4 的磁盘理由
			// 见 LauncherSection.UpdateKeep 注释（每版约 134 MB）。
			UpdateDir:  "./launcher_update",
			UpdateKeep: 4,
		},
		// SMTP 默认关。开启需要同时满足：Enabled=true + Host + Username + 授权码
		// （授权码走环境变量 S4A21_SMTP_PASS）。默认关是刻意的 ——
		// 没有授权码却"看着开了"，只会让玩家对着收不到的验证码干等。
		Smtp: SmtpSection{
			Enabled:               false,
			Host:                  "smtp.qq.com",
			Port:                  465,
			UseSSL:                true,
			Username:              "",
			Password:              "",
			FromName:              "S4A21",
			DailyLimit:            80,
			PerMinuteLimit:        20,
			CodeTTLSeconds:        300,
			ResendCooldownSeconds: 60,
			TimeoutSeconds:        15,
		},
		Admin: AdminSection{
			AuthKey:                      "CHANGE-ME-NOW",
			BroadcastTotalCharacterLimit: 10000,
		},
		RateLimit: RateLimitSection{
			Enabled:               true,
			RequestsPerMinute:     60,
			HttpRequestsPerMinute: 120,
		},
		Token: TokenSection{
			ExpirySeconds: 300,
		},
		Heartbeat: HeartbeatSection{
			TimeoutSeconds:       60,
			CheckIntervalSeconds: 30,
			// 35 秒：> 登录器心跳周期 30s（容忍丢一次心跳）、< 会话超时 60s。
			StaleForceSeconds: 35,
		},
		Device: DeviceSection{
			MaxHistory:              10,
			AlertThreshold:          5,
			RotationCooldownMinutes: 10,
			EnforceBinding:          false,
			AlertWebhook:            "",
		},
		RegisterLimit: RegisterLimitSection{
			Enabled:     true,
			PerIPPerDay: DefaultPerIPPerDay,
			PerMachine:  DefaultPerMachine,
		},
		Tls: TlsSection{
			Enabled:      false,
			CertFormat:   "Pfx",
			CertPath:     "",
			CertKeyPath:  "",
			CertPassword: "",
		},
		Server: ServerSection{
			Unit:                   "dfo-server",
			WorkDir:                "/opt/S4A21Server",
			PvfPath:                "",
			LogPath:                "",
			AuctionBotDataDir:      "",
			BackupDir:              "/opt/backups",
			LogTailLines:           300,
			BackupMaxFileSizeBytes: 536870912,
			ControlEnabled:         true,
		},
		GatewayControl: GatewayControlSection{
			Unit:           "gateway",
			ControlEnabled: true,
			LogTailLines:   300,
		},
		Maintenance: MaintenanceSection{
			Enabled:       false,
			Message:       "服务器维护中，请稍后再试",
			AdminAccounts: []string{},
		},
	}
}

// LoadConfig 从指定的 JSON/JSONC 文件加载配置，缺失的字段使用默认值。
func LoadConfig(path string) (*GatewayConfig, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	cleaned := StripJsoncComments(string(data))
	if err := json.Unmarshal([]byte(cleaned), cfg); err != nil {
		return nil, err
	}

	// 检查 override 文件
	overridePath := filepath.Join(filepath.Dir(path), OverrideFileName)
	if data, err := os.ReadFile(overridePath); err == nil {
		cleaned := StripJsoncComments(string(data))
		if err := json.Unmarshal([]byte(cleaned), cfg); err != nil {
			// override 解析失败不影响启动，只记录日志
			_ = err
		}
	}

	applyEnvOverrides(cfg)

	// 多服规范化 + 硬冲突校验。冲突时拒绝启动 —— 端口碰撞的后果是
	// 某个服静默不监听，比启动失败难查得多。
	if err := cfg.NormalizeGameServers(); err != nil {
		return nil, fmt.Errorf("GameServers 配置无效: %w", err)
	}

	return cfg, nil
}

// 管理密钥的环境变量名。生产环境建议用环境变量注入，
// 不要把真实密钥写进 appsettings.json（该文件通常会进版本库或被一起分发，
// 而管理密钥等于后台最高权限，泄露即可重置任意账号密码、踢人、封号）。
const EnvAdminAuthKey = "S4A21_ADMIN_AUTH_KEY"

// 内部 API 密钥的环境变量名（进程分离用，与 EnvAdminAuthKey 相互独立）。
const EnvAdminInternalKey = "S4A21_ADMIN_INTERNAL_KEY"

// EnvSmtpPassword 是邮箱 SMTP 授权码的环境变量名。
//
// ⚠️ 与 EnvAdminAuthKey 同级处理：**不要写进 appsettings.json**。
// 配置目录会被整体打包分发（202 的部署目录、交付包），一旦跟着发出去，
// 拿到的人就能用这个邮箱以你的名义发信；而 QQ 邮箱判定异常发信会
// **直接停用该账号的 SMTP 权限**，连带把玩家注册/绑定的验证码通道打死，
// 且解封要人工申诉。写进文件省的那点事，不值得赌这条通道。
const EnvSmtpPassword = "S4A21_SMTP_PASS"

// applyEnvOverrides 用环境变量覆盖敏感配置。
// 优先级：环境变量 > appsettings.override.json > appsettings.json > DefaultConfig。
func applyEnvOverrides(cfg *GatewayConfig) {
	if v := strings.TrimSpace(os.Getenv(EnvAdminAuthKey)); v != "" {
		cfg.Admin.AuthKey = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvAdminInternalKey)); v != "" {
		cfg.Admin.InternalKey = v
	}
	// SMTP 授权码只从环境变量取，不读配置文件里的值 ——
	// 配置文件里那一栏留着是为了让结构可读（能一眼看出要配什么），
	// 而不是让人往里填。填了也会被这里的空值判断跳过。
	if v := strings.TrimSpace(os.Getenv(EnvSmtpPassword)); v != "" {
		cfg.Smtp.Password = v
	}
}

// ResolveInternalListenAddress 返回内部 API 的有效监听地址（默认 loopback）。
func (c *GatewayConfig) ResolveInternalListenAddress() string {
	if addr := strings.TrimSpace(c.Gateway.InternalListenAddress); addr != "" {
		return addr
	}
	return "127.0.0.1"
}

// InternalAPIEnabled 判断内部 API 是否具备启动条件（端口 > 0 且配了密钥）。
func (c *GatewayConfig) InternalAPIEnabled() bool {
	return c.Gateway.InternalPort > 0 && strings.TrimSpace(c.Admin.InternalKey) != ""
}

// ServeAdminInProcess 判断网关是否要自己把管理后台也起了（单进程/回滚模式）。
//
// 注意它同时要求 AdminHttpPort 有效 —— 只置 ServeAdminInProcess=true 而没有管理端口，
// 等于"以为回到单进程了，其实后台没人提供"，这种配置要能一眼看出来。
func (c *GatewayConfig) ShouldServeAdminInProcess() bool {
	return c.Gateway.ServeAdminInProcess && c.AdminSplitEnabled()
}

// SaveOverride 将变更的配置写入 appsettings.override.json。
// 使用"读 -> 深度合并 -> 写临时文件 -> 原子替换"策略。
//
// ★★ 必须是**深度**合并（2026-10-19 193 线上事故修复）：
// 原实现只做顶层键替换（existing[k] = v），于是 updates={"Launcher":{MaxInstances:0}}
// 会把整个 Launcher 段替换成只剩 MaxInstances —— 同段里这次没有提交的
// MinVersion / DownloadUrl / UpdateNotice 被静默抹掉。193 生产因此在后台改一次
// 多开限制后，override 变成 {"Launcher":{"MaxInstances":0}}；网关下次重启读回时
// min_version 从 2.5.8 掉回主配置 2.0.5、公告被清空 —— 强制更新门槛被无声放松。
//
// 段内字段"各自可选"的后台接口（Launcher、RegisterLimit）全都依赖这条合并语义：
// 后台只提交一个字段时，其余字段必须原样保留。
func SaveOverride(dir string, updates map[string]interface{}) error {
	overridePath := filepath.Join(dir, OverrideFileName)

	// 读取现有内容
	var existing map[string]interface{}
	if data, err := os.ReadFile(overridePath); err == nil {
		cleaned := StripJsoncComments(string(data))
		if err := json.Unmarshal([]byte(cleaned), &existing); err != nil {
			existing = make(map[string]interface{})
		}
	} else {
		existing = make(map[string]interface{})
	}

	// 深度合并（段内字段保留，只有本次提交的键被覆盖）
	mergeOverrideMap(existing, updates)

	// 写临时文件
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := overridePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	// 原子替换
	return os.Rename(tmpPath, overridePath)
}

// mergeOverrideMap 把 src 深度合并进 dst：两边同为 map 的键递归合并，
// 其余情况（新增键 / 类型不同 / 标量 / null）一律取 src 的值。
//
// 不处理数组的元素级合并（当前 override 没有这种用法，需要语义时由调用方
// 传完整数组，等价于整体替换 —— 这正是期望行为）。
func mergeOverrideMap(dst, src map[string]interface{}) {
	for k, v := range src {
		if sv, ok := v.(map[string]interface{}); ok {
			if dv, ok := dst[k].(map[string]interface{}); ok {
				mergeOverrideMap(dv, sv)
				continue
			}
		}
		dst[k] = v
	}
}

// ResolveHttpListenAddress 返回 HTTP 端口的有效监听地址。
func (c *GatewayConfig) ResolveHttpListenAddress() string {
	if c.Gateway.HttpListenAddress == "" {
		return c.Gateway.ListenAddress
	}
	return c.Gateway.HttpListenAddress
}

// AdminSplitEnabled 检查后台端口是否拆分。
func (c *GatewayConfig) AdminSplitEnabled() bool {
	if c.Gateway.DisableAdminHttp {
		return false
	}
	return c.Gateway.AdminHttpPort > 0 && c.Gateway.AdminHttpPort != c.Gateway.HttpPort
}

// GamePortMapResolved 解析 GamePortMap 配置为 map[publicPort]backendPort。
func (c *GatewayConfig) GamePortMapResolved() map[int]int {
	return c.GameServer.GamePortMapResolved()
}

// GamePortMapResolved 服级口径（多服模型：每个服有自己的端口表）。
func (s *GameServerSection) GamePortMapResolved() map[int]int {
	result := make(map[int]int)
	for _, entry := range s.GamePortMap {
		parts := strings.Split(entry, ":")
		if len(parts) == 2 {
			pub := parsePort(strings.TrimSpace(parts[0]))
			back := parsePort(strings.TrimSpace(parts[1]))
			if pub > 0 && back > 0 {
				result[pub] = back
			}
		}
	}
	return result
}

func parsePort(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// StripJsoncComments 移除 JSON 文件中的 // 行注释和 /* */ 块注释，
// 同时正确处理字符串内的 // 和 /* 序列，并去掉**尾随逗号**。
//
// 尾随逗号也要吃：配置的生产者是 .NET 侧的 System.Text.Json
// （默认开了 AllowTrailingCommas），它写出来 / 人工写出来的配置里带尾随逗号
// 是常态 —— 生产 8.138.9.216 的 appsettings.json 与 bonus.json 都是这样。
// 只去注释不去尾随逗号，解析照样失败（2026-09-28 在 161 用生产配置演练踩到：
// 网关日志「泡点配置解析失败: invalid character '/' ...」）。
// 去掉尾随逗号是**纯放宽**：原本能解析的内容一律不受影响。
func StripJsoncComments(input string) string {
	return stripJSONTrailingCommas(stripJsoncCommentLines(input))
}

// stripJsoncCommentLines 只去注释（字符串内部一个字节都不动）。
func stripJsoncCommentLines(input string) string {
	var result []byte
	i := 0
	for i < len(input) {
		// 字符串处理
		if input[i] == '"' {
			result = append(result, input[i])
			i++
			for i < len(input) {
				result = append(result, input[i])
				if input[i] == '\\' && i+1 < len(input) {
					i++
					result = append(result, input[i])
				} else if input[i] == '"' {
					break
				}
				i++
			}
			i++
			continue
		}

		// 块注释
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '*' {
			i += 2
			for i+1 < len(input) && !(input[i] == '*' && input[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}

		// 行注释
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '/' {
			for i < len(input) && input[i] != '\n' {
				i++
			}
			continue
		}

		result = append(result, input[i])
		i++
	}
	return string(result)
}

// stripJSONTrailingCommas 去掉 `}` 或 `]` 之前的尾随逗号（字符串内部不动）。
func stripJSONTrailingCommas(s string) string {
	var out []byte
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(s) {
				i++
				out = append(out, s[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
				j++
			}
			if j < len(s) && (s[j] == '}' || s[j] == ']') {
				continue // 尾随逗号：丢掉
			}
		}
		out = append(out, c)
	}
	return string(out)
}
