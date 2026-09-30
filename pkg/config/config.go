package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	Smtp           SmtpSection           `json:"Smtp"`
	Gateway        GatewaySection        `json:"Gateway"`
	Database       DatabaseSection       `json:"Database"`
	GameServer     GameServerSection     `json:"GameServer"`
	Pvf            PvfSection            `json:"Pvf"`
	Launcher       LauncherSection       `json:"Launcher"`
	Admin          AdminSection          `json:"Admin"`
	RateLimit      RateLimitSection      `json:"RateLimit"`
	Token          TokenSection          `json:"Token"`
	Tls            TlsSection            `json:"Tls"`
	Heartbeat      HeartbeatSection      `json:"Heartbeat"`
	Device         DeviceSection         `json:"Device"`
	Server         ServerSection         `json:"Server"`
	GatewayControl GatewayControlSection `json:"GatewayControl"`
	Maintenance    MaintenanceSection    `json:"Maintenance"`
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
	TcpMaxConnections      int    `json:"TcpMaxConnections"`

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
	RewriteChannelList           bool     `json:"RewriteChannelList"`
	KeyTimeZoneOffsetHours       int      `json:"KeyTimeZoneOffsetHours"`
	MaxConnectionsPerIP          int      `json:"MaxConnectionsPerIP"`
	FirstReadTimeoutSeconds      int      `json:"FirstReadTimeoutSeconds"`
	IdleTimeoutSeconds           int      `json:"IdleTimeoutSeconds"`
	BackendConnectTimeoutSeconds int      `json:"BackendConnectTimeoutSeconds"`
	LaunchArgsFormat             string   `json:"LaunchArgsFormat"`

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
}

type PvfSection struct {
	FilePath string `json:"FilePath"`
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
}

type DeviceSection struct {
	MaxHistory              int    `json:"MaxHistory"`
	AlertThreshold          int    `json:"AlertThreshold"`
	RotationCooldownMinutes int    `json:"RotationCooldownMinutes"`
	EnforceBinding          bool   `json:"EnforceBinding"`
	AlertWebhook            string `json:"AlertWebhook"`
}

type TlsSection struct {
	Enabled      bool   `json:"Enabled"`
	CertFormat   string `json:"CertFormat"`
	CertPath     string `json:"CertPath"`
	CertKeyPath  string `json:"CertKeyPath"`
	CertPassword string `json:"CertPassword"`
}

type ServerSection struct {
	Unit                   string `json:"Unit"`
	WorkDir                string `json:"WorkDir"`
	PvfPath                string `json:"PvfPath"`
	LogPath                string `json:"LogPath"`
	AuctionBotDataDir      string `json:"AuctionBotDataDir"`
	BackupDir              string `json:"BackupDir"`
	LogTailLines           int    `json:"LogTailLines"`
	BackupMaxFileSizeBytes int64  `json:"BackupMaxFileSizeBytes"`
	ControlEnabled         bool   `json:"ControlEnabled"`

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

// DefaultConfig 返回带有生产环境默认值的配置。
func DefaultConfig() *GatewayConfig {
	return &GatewayConfig{
		Gateway: GatewaySection{
			TcpPort:                8000,
			HttpPort:               8080,
			ProxyPort:              8001,
			ListenAddress:          "0.0.0.0",
			HttpListenAddress:      "",
			AdminHttpPort:          0,
			AdminHttpListenAddress: "127.0.0.1",
			TcpIdleTimeoutSeconds:  600,
			TcpMaxConnections:      512,
			InternalPort:           18080,
			InternalListenAddress:  "127.0.0.1",
			ServeAdminInProcess:    false,
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
			RewriteChannelList:           true,
			KeyTimeZoneOffsetHours:       0,
			MaxConnectionsPerIP:          4,
			FirstReadTimeoutSeconds:      30,
			IdleTimeoutSeconds:           1800,
			BackendConnectTimeoutSeconds: 10,
			LaunchArgsFormat:             DefaultLaunchArgsFormat,
			// 缺省关：服务端先具备识别能力后再显式改成 "v1"。
			ProxyProtocol: "off",
		},
		Pvf: PvfSection{
			FilePath: "./Data/Pvf/Script.pvf",
		},
		Launcher: LauncherSection{
			MinVersion:  "2.0.0",
			DownloadUrl: "",
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
		},
		Device: DeviceSection{
			MaxHistory:              10,
			AlertThreshold:          5,
			RotationCooldownMinutes: 10,
			EnforceBinding:          false,
			AlertWebhook:            "",
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
// 使用"读 -> 合并 -> 写临时文件 -> 原子替换"策略。
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

	// 合并
	for k, v := range updates {
		existing[k] = v
	}

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
	result := make(map[int]int)
	for _, entry := range c.GameServer.GamePortMap {
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
