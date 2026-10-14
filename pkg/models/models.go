package models

import "net"

// Commands 定义 TCP 帧协议中的命令名常量。
type Commands struct {
	Register       string
	Login          string
	ChangePassword string
	Health         string
	AccountInfo    string
	AccountReset   string
	SendItems      string
	GetRoles       string
	ClearMailbox   string
	Version        string
	// ── QQ 号绑定（2026-09-24）─────────────────────────────────────────
	//
	// 三个命令都要求**已登录**（走会话 token 校验，不是 auth_key）——
	// 绑定是玩家自己的动作，不该由后台密钥代劳。
	// 未绑定 QQ 的账号完全不受影响，这三个命令不发也没关系。
	SendBindCode string
	BindQQ       string
	UnbindQQ     string
}

var Cmd = Commands{
	Register:       "CMD_REGISTER",
	Login:          "CMD_LOGIN",
	ChangePassword: "CMD_CHANGE_PASSWORD",
	Health:         "CMD_HEALTH",
	AccountInfo:    "CMD_ACCOUNT_INFO",
	AccountReset:   "CMD_ACCOUNT_RESET",
	SendItems:      "CMD_SEND_ITEMS",
	GetRoles:       "CMD_GET_ROLES",
	ClearMailbox:   "CMD_CLEAR_MAILBOX",
	Version:        "CMD_VERSION",
	SendBindCode:   "CMD_SEND_BIND_CODE",
	BindQQ:         "CMD_BIND_QQ",
	UnbindQQ:       "CMD_UNBIND_QQ",
}

// ErrorCode 定义网关返回给客户端的错误码。
//
// 分段（P2-3 补注，避免被误读成"1001~1020 全是账号类"）：
//
//	1001~1016  账号类：注册 / 登录 / 密码 / 设备绑定 / 版本门禁
//	1017~1020  设备轮换 / 物品附件 / 会话 —— 都是「已登录之后」才可能出现的码，
//	           与账号本身无关，改这一段时不要顺手并进上面那组
//	1021~1023  封禁 / 维护模式 / 单点登录占用
//	1024~1035  QQ 号绑定
//	3xxx       协议层（限流 / 未知命令 / 解码失败 / 包体过大）
//	5xxx       服务端内部（数据库）
type ErrorCode struct {
	Ok                     int
	AccountEmpty           int
	AccountLength          int
	AccountExists          int
	PasswordEmpty          int
	PasswordLength         int
	PasswordMismatch       int
	AccountNotFound        int
	WrongPassword          int
	SamePassword           int
	InvalidAuthKey         int
	IllegalChars           int
	AccountLocked          int
	InvalidCharacterId     int
	EmptyAttachments       int
	DeviceChanged          int
	LauncherVersionTooOld  int
	DeviceRotationCooldown int
	TooManyAttachments     int
	InvalidItemParams      int
	SessionExpired         int
	Banned                 int
	MaintenanceMode        int
	AccountOnline          int
	RateLimited            int
	UnknownCommand         int
	DecodeFailed           int
	BodyTooLarge           int
	DatabaseError          int
	// ── QQ 号绑定（1024~1035，2026-09-24）─────────────────────────────
	//
	// 为什么分这么细：这些码是后台排查这类问题时的**唯一线索**。
	// 全塞进一个"绑定失败"里，玩家报"绑不上"时只能靠猜 ——
	// 是收不到信、码过期、还是 QQ 号被别人绑了？每种的处理方式完全不同。
	//
	// QQNumberConflict(1034) 当前**不再主动返回**，仅保留协议位：它原本用来拒绝
	// 「与现有账号名同名」的绑定。2026-09-24 登录侧引入 `qq:<数字>` 显式前缀后，
	// 同名不再导致登错号（A 输裸数字、B 输前缀各归各家），绑定于是不必再拦 ——
	// 改成记日志放行，见 service.SendBindCode。
	QQNumberInvalid          int
	VerifyCodeInvalid        int
	VerifyCodeExpired        int
	VerifyCodeAttemptsExceed int
	SendTooFrequent          int
	MailSendFailed           int
	MailServiceDisabled      int
	SendQuotaExhausted       int
	AccountAlreadyBound      int
	QQNumberTaken            int
	QQNumberConflict         int
	QQNotBound               int
	// ── 注册限额（1036~1037，2026-10-13）─────────────────────────────
	RegisterIpLimit      int
	RegisterMachineLimit int
}

var Err = ErrorCode{
	Ok:                       0,
	AccountEmpty:             1001,
	AccountLength:            1002,
	AccountExists:            1003,
	PasswordEmpty:            1004,
	PasswordLength:           1005,
	PasswordMismatch:         1006,
	AccountNotFound:          1007,
	WrongPassword:            1008,
	SamePassword:             1009,
	InvalidAuthKey:           1010,
	IllegalChars:             1011,
	AccountLocked:            1012,
	InvalidCharacterId:       1013,
	EmptyAttachments:         1014,
	DeviceChanged:            1015,
	LauncherVersionTooOld:    1016,
	DeviceRotationCooldown:   1017,
	TooManyAttachments:       1018,
	InvalidItemParams:        1019,
	SessionExpired:           1020,
	Banned:                   1021,
	MaintenanceMode:          1022,
	AccountOnline:            1023,
	QQNumberInvalid:          1024,
	VerifyCodeInvalid:        1025,
	VerifyCodeExpired:        1026,
	VerifyCodeAttemptsExceed: 1027,
	SendTooFrequent:          1028,
	MailSendFailed:           1029,
	MailServiceDisabled:      1030,
	SendQuotaExhausted:       1031,
	AccountAlreadyBound:      1032,
	QQNumberTaken:            1033,
	QQNumberConflict:         1034,
	QQNotBound:               1035,
	// 注册限额。两个码分开而不是共用一个：登录器/后台排障时要能一眼看出
	// 是被"同一 IP 当日刷太多"还是"同一台机器号太多"挡下的。
	RegisterIpLimit:      1036,
	RegisterMachineLimit: 1037,
	RateLimited:          3002,
	UnknownCommand:           3003,
	DecodeFailed:             3005,
	BodyTooLarge:             3009,
	DatabaseError:            5001,
}

// GatewayRequest 是 TCP 帧协议中的请求体。
type GatewayRequest struct {
	Cmd             string  `json:"cmd"`
	Account         *string `json:"account,omitempty"`
	PasswordMd5     *string `json:"password_md5,omitempty"`
	OldPwdMd5       *string `json:"old_pwd_md5,omitempty"`
	NewPwdMd5       *string `json:"new_pwd_md5,omitempty"`
	Token           *string `json:"token,omitempty"`
	AuthKey         *string `json:"auth_key,omitempty"`
	DeviceSecret    *string `json:"device_secret,omitempty"`
	LauncherVersion *string `json:"launcher_version,omitempty"`
	// MachineId 是登录器上报的机器码（2026-10-13）。
	//
	// 用途**仅限**注册限额计数（同一台机器累计注册几个号），不参与登录鉴权。
	// 取值由登录器推导（首个物理网卡 MAC），因此**可伪造** —— 这是刻意接受的：
	// 网关在公网上物理看不到玩家 MAC（那是二层地址），要按机器限就只能相信客户端。
	// 定位是"提高批量注册的成本"，不是不可绕过的封禁。
	//
	// 老登录器不带此字段 ⇒ 为空串 ⇒ 注册限额**跳过机器维度**、只按 IP 判。
	// 绝不能把空值当成同一个机器计数（那会全服注册不了）。
	MachineId *string `json:"machine_id,omitempty"`
	// ForceLogin 强制登录：账号已在线时踢掉旧会话并登录。
	// 未携带（false）时若账号已在线，登录返回 AccountOnline(1023)。
	ForceLogin  *bool             `json:"force_login,omitempty"`
	CharacterId *int64            `json:"character_id,omitempty"`
	Items       []MailItemRequest `json:"items,omitempty"`

	// ── QQ 号绑定（2026-09-24）────────────────────────────────────────
	// QQNumber 是玩家填的 QQ 号（纯数字，5~11 位）。
	QQNumber *string `json:"qq_number,omitempty"`
	// VerifyCode 是发到 <QQ号>@qq.com 的 6 位数字验证码。
	VerifyCode *string `json:"verify_code,omitempty"`
}

// MailItemRequest 表示邮件附件中的物品。
type MailItemRequest struct {
	ItemTemplateId int  `json:"item_template_id"`
	Count          int  `json:"count"`
	Kind           *int `json:"kind,omitempty"`
	ItemType       *int `json:"item_type,omitempty"`
}

// GatewayResponse 是 TCP 帧协议中的响应体。
type GatewayResponse struct {
	Cmd            string     `json:"cmd"`
	Ok             bool       `json:"ok"`
	ErrorCode      int        `json:"error_code"`
	Message        *string    `json:"message,omitempty"`
	Token          *string    `json:"token,omitempty"`
	Cera           *int64     `json:"cera,omitempty"`
	MId            *string    `json:"m_id,omitempty"`
	DeviceSecret   *string    `json:"device_secret,omitempty"`
	LaunchArgs     *string    `json:"launch_args,omitempty"`
	TokenCera      *int64     `json:"token_cera,omitempty"`
	HappyTokenCera *int64     `json:"happy_token_cera,omitempty"`
	Roles          []RoleInfo `json:"roles,omitempty"`
	DeletedCount   *int       `json:"deleted_count,omitempty"`
	Version        *string    `json:"version,omitempty"`
	DownloadUrl    *string    `json:"download_url,omitempty"`
	DeviceChanged  *bool      `json:"device_changed,omitempty"`
	// QQNumber 是当前账号已绑定的 QQ 号（未绑定时不返回）。
	//
	// 登录成功时一并下发：登录器据此直接显示绑定状态，
	// 不用为"查有没有绑"多发一次往返。
	QQNumber *string `json:"qq_number,omitempty"`
}

// RoleInfo 表示游戏角色的简要信息。
type RoleInfo struct {
	CharacterId int64  `json:"character_id"`
	Name        string `json:"name"`
	Level       int    `json:"level"`
	Job         int    `json:"job"`
	// GrowType 转职/觉醒编码：低 4 位 = 转职，高 4 位 = 觉醒。
	GrowType int `json:"grow_type"`
	// JobName 职业中文名（转职/觉醒名优先）。由 database.JobDisplayName 解析。
	JobName string `json:"job_name"`
	Exp     int64  `json:"exp"`
}

// FingerprintEntry 表示客户端完整性策略中的文件指纹条目。
type FingerprintEntry struct {
	FileName  string `json:"file"`
	Hash      string `json:"hash"`
	Algorithm string `json:"algo"`
	Size      int64  `json:"size"`
	Display   string `json:"display"`
}

// IntegritySnapshot 是完整性策略的不可变快照。
type IntegritySnapshot struct {
	Revision       int                `json:"revision"`
	UpdatedAt      string             `json:"updated_at"`
	WhiteList      []FingerprintEntry `json:"white_list"`
	BlackList      []FingerprintEntry `json:"black_list"`
	AllowedModules []string           `json:"allowed_modules"`
}

// PvfInfo 表示 PVF 文件的权威指纹信息。
type PvfInfo struct {
	Path        string
	Hash        string
	Algo        string
	Size        int64
	ModifiedUtc string
}

// PvfDeltaInfo 描述一份「上一版 → 当前版」的 PVF 增量包。
//
// ★ ToHash 必须恒等于当前 PvfInfo.Hash —— 网关只在两者一致时才把它写进 policy，
// 否则登录器会拿一份合成完对不上的包去替换本地 PVF（虽然最终有整文件 SHA-256 兜底，
// 但那是浪费玩家一次 200 KB~11 MB 的下载 + 一次失败重试）。
type PvfDeltaInfo struct {
	FromHash   string // 客户端必须持有的旧版 SHA-256（大写）
	ToHash     string // 目标版本 SHA-256（大写）
	ToSize     int64  // 目标版本字节数
	Size       int64  // delta 包字节数
	Path       string // delta 文件路径
	CreatedUtc string
}

// PvfHistoryEntry 是一条 PVF 历史版本记录（pvf_history/index.json 的一行）。
//
// 历史文件本体按内容寻址存为 <Hash>.pvf，同 hash 重复上传只留一条记录 ——
// Name/Filename 只在**首次**入史时写入，之后不覆盖（用户给旧版起的备注不该被
// 后续同名上传顶掉）。
type PvfHistoryEntry struct {
	Hash      string `json:"hash"`                 // 大写 SHA-256（= 文件名）
	Size      int64  `json:"size"`                 // 字节数
	Name      string `json:"name,omitempty"`       // 显示名（上传时填的备注，如「神器进深渊池」）
	Filename  string `json:"filename,omitempty"`   // 上传时的原文件名
	StoredUtc string `json:"stored_utc"`           // 首次入史时间（RFC3339）
}

// ============================================================================
// 登录器自更新（2026-10-01）
// ============================================================================

// LauncherDeltaInfo 与 PvfDeltaInfo 字段完全同构（A21D 是通用文件差分），
// 独立命名避免「登录器在下 PVF」的语义混淆。
type LauncherDeltaInfo = PvfDeltaInfo

// LauncherBuildEntry 是一条登录器构建记录（launcher_update/history/index.json 的一行）。
//
// 与 PVF 历史的区别：多一个 Version（登录器版本号，上传时必填、格式 x.y.z）——
// 强更判据（本地 version < 网关 MinVersion）与管理页展示都要用它。
type LauncherBuildEntry struct {
	Hash      string `json:"hash"`               // 大写 SHA-256（= 文件名）
	Version   string `json:"version"`            // 登录器版本号（x.y.z，上传时必填）
	Size      int64  `json:"size"`               // 字节数
	Name      string `json:"name,omitempty"`     // 显示名（上传备注）
	Filename  string `json:"filename,omitempty"` // 上传时的原文件名
	StoredUtc string `json:"stored_utc"`         // 首次入史时间（毫秒精度 RFC3339）
}

// LauncherUpdateManifest 是 GET /api/launcher/update 的响应体（snake_case，
// 与插件清单/policy 的既有口径一致，登录器 System.Text.Json 直接反序列化）。
//
// 判据约定（登录器侧）：
//   - enabled=false        → 服务端关闭自更新，客户端跳过检查（一键回滚开关）；
//   - version/hash 为空    → 服务端从未上传过任何版本，客户端跳过检查；
//   - 本地 exe hash == hash → 已是最新（唯一硬判据，版本号仅用于展示与强更阈值）；
//   - 其余                  → 有新版：本地 version < min_version 时强制更新，
//                            否则弹窗可跳过。
type LauncherUpdateManifest struct {
	OK         bool   `json:"ok"`
	Enabled    bool   `json:"enabled"`
	Version    string `json:"version,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Size       int64  `json:"size,omitempty"`
	StoredUtc  string `json:"stored_utc,omitempty"`
	MinVersion string `json:"min_version"` // 网关内存态 Launcher.MinVersion（强更阈值）
	FullURL    string `json:"full_url"`    // 全量 exe 下载（相对路径）
	DeltaURL   string `json:"delta_url"`   // 按需 delta 基址（登录器拼 ?from=<本地hash>）
}


// BroadcastRequest 表示全服发放请求。
type BroadcastRequest struct {
	TargetCharacterId *int64            `json:"target_character_id,omitempty"`
	TargetAccountId   *int64            `json:"target_account_id,omitempty"`
	Subject           string            `json:"subject,omitempty"`
	Body              string            `json:"body,omitempty"`
	Items             []MailItemRequest `json:"items"`
	ExpireHours       *int              `json:"expire_hours,omitempty"`
}

// ResetPasswordBody 表示后台重置密码请求体。
type ResetPasswordBody struct {
	Account        string  `json:"account"`
	NewPasswordMd5 *string `json:"newPasswordMd5,omitempty"`
	NewPassword    *string `json:"newPassword,omitempty"`
}

// BanBody 表示后台封禁/解封请求体。
type BanBody struct {
	Account string `json:"account"`
	Reason  string `json:"reason"`
}

// SendItemsBody 表示后台定向发物品请求体。
type SendItemsBody struct {
	CharacterId int64             `json:"characterId"`
	Items       []MailItemRequest `json:"items"`
}

// KickBody 表示踢下线请求体。
type KickBody struct {
	Account string `json:"account"`
}

// ServerControlBody 表示服务端/网关启停控制请求体。
type ServerControlBody struct {
	Action string `json:"action"`
}

// RegisterBonusConfig 注册奖励配置（磁盘文件 register_bonus.json）。
type RegisterBonusConfig struct {
	Enabled                bool                `json:"enabled"`
	Cera                   int64               `json:"cera"`
	TokenCera              int64               `json:"token_cera"`
	HappyTokenCera         int64               `json:"happy_token_cera"`
	Gold                   int64               `json:"gold"`
	Title                  string              `json:"title"`
	Body                   string              `json:"body"`
	ItemExpireHours        int                 `json:"item_expire_hours"`
	ItemSplitCount         int                 `json:"item_split_count"`
	ItemStackLimit         int                 `json:"item_stack_limit"`
	ItemDeliverLimit       int                 `json:"item_deliver_limit"`
	ItemAttachmentsPerMail int                 `json:"item_attachments_per_mail"`
	Items                  []RegisterBonusItem `json:"items"`
}

// RegisterBonusItem 注册奖励物品项。
type RegisterBonusItem struct {
	ItemId   int    `json:"item_id"`
	Name     string `json:"name"`
	Count    int64  `json:"count"`
	Kind     int    `json:"kind"`
	ItemType int    `json:"item_type"`
}

// RegisterBonusLogRow 注册奖励日志查询行。
type RegisterBonusLogRow struct {
	ID            int64  `json:"id"`
	Account       string `json:"account"`
	AccountID     int64  `json:"account_id"`
	CharacterID   int64  `json:"character_id"`
	CharacterName string `json:"character_name"`
	RewardType    string `json:"reward_type"`
	ItemID        int64  `json:"item_id"`
	ItemName      string `json:"item_name"`
	Kind          int    `json:"kind"`
	Quantity      int64  `json:"quantity"`
	Status        string `json:"status"`
	Message       string `json:"message"`
	CreatedAt     string `json:"created_at"`
}

// RegisterBonusKinds 注册奖励日志 reward_type / status 常量。
var RegisterBonusKinds = struct {
	Registered     string
	Cera           string
	TokenCera      string
	HappyTokenCera string
	Gold           string
	Item           string

	StatusPending    string
	StatusProcessing string
	StatusDone       string
	StatusDelivered  string
	StatusExpired    string
	StatusFailed     string
	StatusSkipped    string
}{
	Registered:     "registered",
	Cera:           "cera",
	TokenCera:      "token_cera",
	HappyTokenCera: "happy_token_cera",
	Gold:           "gold",
	Item:           "item",

	StatusPending:    "pending",
	StatusProcessing: "processing",
	StatusDone:       "done",
	StatusDelivered:  "delivered",
	StatusExpired:    "expired",
	StatusFailed:     "failed",
	StatusSkipped:    "skipped",
}

// MailItemSpec 表示邮件中的物品规格。
type MailItemSpec struct {
	ItemTemplateId int  `json:"item_template_id"`
	Count          int  `json:"count"`
	Kind           int  `json:"kind"`
	ItemType       *int `json:"item_type,omitempty"`
}

// AccountInfo 表示账号的账户信息。
type AccountInfo struct {
	MId            string
	Cera           int64
	TokenCera      int64
	HappyTokenCera int64
}

// LoginResult 表示登录操作的结果。
type LoginResult struct {
	ErrorCode     int
	Message       *string
	Token         string
	Cera          int64
	MId           string
	DeviceSecret  string
	DeviceChanged bool
	LaunchArgs    string
}

// Session 表示一个在线会话。
type Session struct {
	Token         string
	Account       string
	MId           string
	ClientIP      string
	DeviceSecret  string
	CreatedAt     int64
	LastHeartbeat int64
	BonusGranted  int64
	// ── 泡点计费状态（2026-09-23 调整）──────────────────────────────
	//
	// 计费口径从旧的「最近 N 分钟内有过 HTTP 心跳就发」改成「按玩家**真实
	// 在游戏频道内的时长**发」。依据是会话上挂着的 GameProxyConnections：
	// 只有当玩家真的连上了游戏频道（代理端口 20001+）才计时，
	// 停在登录器/频道选择界面不计时；退出游戏（连接断开）或会话被清理、
	// 被踢下线时立刻停表 —— 会话都不在表里了，就再也遍历不到。
	//
	// GameOnlineSeconds 是「已攒够但还没发满一个计费周期」的秒数余数，
	// 跨轮保留（结算时点与进入时刻错位也不会少发）；重复登录结转不清零。
	//
	// BonusTickAt 是**计费基准时刻**（Unix 秒）：连上游戏频道时置为当时时间
	// （起表），退出游戏时把最后一段结算掉并置为当时时间（停表），
	// 结算时把"基准→现在"这一段在游戏内的秒数累进 GameOnlineSeconds。
	// 0 表示从未进过游戏。
	GameOnlineSeconds int64
	BonusTickAt       int64
	// 代理连接的**真连接对象**（客户端侧）。踢下线 / 维护模式 / 封禁即踢
	// 靠逐个 Close 这些连接真正断开玩家 —— 历史版本只存 fd 句柄数，
	// 踢人只删会话表不断连接，玩家照常游戏（2026-09-23 修复）。
	ProxyConnections     map[net.Conn]struct{}
	GameProxyConnections map[net.Conn]struct{}
}
