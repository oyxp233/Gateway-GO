package httprouter

import (
	"fmt"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/proxy"
	"s4a21-gateway/pkg/service"
	"s4a21-gateway/pkg/session"
)

// ============================================================================
// 后端抽象层：管理后台进程分离用
//
// 背景：管理后台与网关核心原先同进程，改后台后端代码必须重启网关 → 在线玩家掉线。
// 分离后 admin 进程只保留「纯 db / 纯 systemctl / 纯文件」能力，
// 凡是依赖**网关进程内存**的东西，一律通过下面 4 个接口抽象出去：
//
//   SessionBackend        会话表（在线列表 / 踢人）
//   PvfBackend            PVF 内存缓存（指纹 / 重算）
//   PortsBackend          代理**实际监听**的端口与连接数、端口表的应用
//   RuntimeConfigBackend  运行时配置（登录器版本门禁 / 维护模式）
//
// 两个进程各注入一份实现，handler 代码因此不需要知道自己跑在哪个进程：
//   - 网关进程：local* 实现，直接操作内存（即原逻辑原样搬家）
//   - admin 进程：remote* 实现（在 pkg/backends 里），HTTP 调网关内部 API
//
// ⚠️ RuntimeConfigBackend 是原设计方案漏掉的一组。它必须走网关，原因：
//   - `/api/launcher/policy` 读的是**网关进程内存**里的 cfg.Launcher.MinVersion，
//     admin 进程改自己的内存不会影响登录器版本门禁；
//   - 维护模式同理，且它只存在于内存（`handleAdminMaintenancePost` 原本就不落盘）。
//   若让 admin 自己改，会出现「后台显示已开维护模式，玩家照常登录」。
// ============================================================================

// Backends 把 5 组后端打成一个包，避免 NewServer 参数继续膨胀。
//
// 任何一项为 nil 时，NewServer 会用"不可用"实现兜底（报错但不 panic），
// 这样单进程模式（ServeAdminInProcess=true）与双进程模式可以共用同一个构造函数。
type Backends struct {
	Sessions SessionBackend
	Pvf      PvfBackend
	Ports    PortsBackend
	Runtime  RuntimeConfigBackend
	// Announce 公告配置读写 + 弹窗入队（依赖网关内存快照，必须经网关）。
	// 事件列表 / 弹窗历史 / 排行榜是纯历史数据，不在这层，handler 直连 s.db。
	Announce AnnounceBackend
}

// withDefaults 为未提供的项填上"不可用"实现。
func (b Backends) withDefaults() Backends {
	if b.Sessions == nil {
		b.Sessions = NewUnavailableSessionBackend("未注入会话后端")
	}
	if b.Pvf == nil {
		b.Pvf = NewUnavailablePvfBackend("未注入 PVF 后端")
	}
	if b.Ports == nil {
		b.Ports = NewUnavailablePortsBackend("未注入端口后端")
	}
	if b.Runtime == nil {
		b.Runtime = NewUnavailableRuntimeConfigBackend("未注入运行时配置后端")
	}
	if b.Announce == nil {
		b.Announce = NewUnavailableAnnounceBackend("未注入公告后端")
	}
	return b
}

// OnlinePlayer 一条在线玩家记录。既是管理页的展示结构，也是内部 API 的传输结构。
// 字段类型刻意与 models.Session 一致（BonusGranted 是 int64 而非 bool），
// 保证管理页拿到的 JSON 值形态不变。
type OnlinePlayer struct {
	Account       string `json:"account"`
	IP            string `json:"ip"`
	OnlineMinutes int    `json:"online_minutes"`
	LastHeartbeat int64  `json:"last_heartbeat"`
	BonusGranted  int64  `json:"bonus_granted"`
	Cera          int64  `json:"cera"`
	// GameId 是该会话选服的 Id（2026-10-17 双服）。
	// 老会话为空串 = 默认服。空串在展示层归入默认服而不是"未知服"。
	GameId string `json:"game_id"`
}

// SessionBackend 抽象网关内存里的会话表。
type SessionBackend interface {
	// List 返回在线玩家明细。
	List() ([]OnlinePlayer, error)
	// Kick 踢掉指定账号的全部会话；account 为空表示踢全体。
	Kick(account string) (int, error)
	// KickNonAdmin 踢掉所有非管理员会话（维护模式用），返回被踢数量。
	KickNonAdmin(admins []string) (int, error)
	// Count 返回当前会话数。
	Count() (int, error)
}

// PvfView PVF 缓存的对外视图。
type PvfView struct {
	Mode        string `json:"mode"`
	Path        string `json:"path"`
	Hash        string `json:"hash"`
	Algo        string `json:"algo"`
	Size        int64  `json:"size"`
	ModifiedUtc string `json:"modified_utc"`
}

// PvfBackend 抽象 PVF 内存缓存。
type PvfBackend interface {
	Info() (PvfView, error)
	Refresh() error
}

// PortsBackend 抽象"代理实际监听的端口"。
//
// 注意与 PortConfigStore 的分工：
//   - PortConfigStore 管**配置**（读写 proxy_ports.json），admin 进程也能直接持有；
//   - PortsBackend 管**运行时状态**（哪些端口真的在 listen、各有多少连接、
//     以及"保存后立即生效"这个动作），只有网关进程知道。
type PortsBackend interface {
	// Active 返回 公网端口 -> 后端端口 的映射（只含正在监听的）。
	Active() (map[int]int, error)
	// Connections 返回 公网端口 -> 当前连接数。
	Connections() (map[int]int, error)
	// Apply 保存端口配置并立即生效，返回新开/关闭/失败的明细。
	Apply(cfg *proxy.ProxyPortConfig) (proxy.ReloadResult, error)
}

// MaintenanceView 维护模式的当前状态。
type MaintenanceView struct {
	Enabled       bool     `json:"enabled"`
	Message       string   `json:"message"`
	AdminAccounts []string `json:"admin_accounts"`
}

// LauncherView 客户端（登录器）侧可变配置的当前状态。
//
// 这三个字段的**权威值都在网关进程内存里**：
//   - MinVersion / DownloadUrl → 登录时的版本门禁（/api/launcher/policy 由网关执行）
//   - UpdateNotice             → 登录器「更新内容」区展示的公告（/api/launcher/notice）
//
// 双进程模式下 admin 进程只能经 /internal/runtime-config 读写它们。
// json tag 同时被内部 API 与远端后端复用，改这里等于改协议。
type LauncherView struct {
	MinVersion   string `json:"min_version"`
	DownloadURL  string `json:"download_url"`
	UpdateNotice string `json:"update_notice"`
}

// RegisterLimitView 注册限额的当前状态（2026-10-13）。
//
// 权威值同样在**网关进程内存里**：判定发生在 TCP 侧的注册命令处理路径上。
// 双进程模式下 admin 进程只能经 /internal/runtime-config 读写它。
//
// json tag 同时被内部 API 与远端后端复用，改这里等于改协议。
// 用指针表示"该项不改"（与 SetLauncher 同一约定），所以读出来的是值、
// 下发的是指针。
type RegisterLimitView struct {
	Enabled     bool `json:"enabled"`
	PerIPPerDay int  `json:"per_ip_per_day"`
	PerMachine  int  `json:"per_machine"`
}

// HeartbeatView 心跳超时的当前状态（2026-10-14）。
//
// 权威值在**网关进程内存里**：会话超时清理由网关的巡检协程执行
// （cmd/gateway 每 CheckIntervalSeconds 读一次 TimeoutSeconds）。双进程模式下
// admin 进程只能经 /internal/runtime-config 读写它。
//
// 为什么必须做成运行时可变：超时是"和登录器心跳周期配套"的参数，定得太紧
// （60s 对 30s 心跳 = 只容忍丢 1 拍）时误清会话表现为"玩家在游戏里被踢"，
// 而改它原先必须重启网关（= 全体掉线）—— 于是"为修掉线而重启"本身就制造掉线。
//
// json tag 同时被内部 API 与远端后端复用，改这里等于改协议。
// 用指针表示"该项不改"（与 SetLauncher 同一约定），所以读出来的是值、下发的是指针。
type HeartbeatView struct {
	TimeoutSeconds int `json:"timeout_seconds"`
}

// RuntimeConfigBackend 抽象网关进程内存里的可变配置。
type RuntimeConfigBackend interface {
	Launcher() (LauncherView, error)
	// SetLauncher 更新登录器配置（nil 表示该字段不动），返回是否有变更。
	SetLauncher(minVersion, downloadURL, updateNotice *string) (changed bool, err error)

	Maintenance() (MaintenanceView, error)
	// SetMaintenance 更新维护模式；开启时踢掉非管理员会话并返回被踢数量。
	SetMaintenance(enabled *bool, message *string, admins []string) (kicked int, err error)

	RegisterLimit() (RegisterLimitView, error)
	// SetRegisterLimit 更新注册限额（nil 表示该字段不动），返回是否有变更。
	SetRegisterLimit(enabled *bool, perIPPerDay, perMachine *int) (changed bool, err error)

	Heartbeat() (HeartbeatView, error)
	// SetHeartbeat 更新心跳超时（nil 表示不动），返回是否有变更。
	SetHeartbeat(timeoutSeconds *int) (changed bool, err error)
}

// ============================================================================
// 网关进程内的 local 实现
// ============================================================================

type localSessionBackend struct {
	mgr *session.SessionManager
	db  *database.Database
}

// NewLocalSessionBackend 构造网关进程内的会话后端。
//
// 刻意**不在这里写踢人日志**：原实现里只有部分调用方写（kick / delete-account 写，
// reset-device 不写），把日志留给调用方才能保持行为不变。
func NewLocalSessionBackend(mgr *session.SessionManager, db *database.Database) SessionBackend {
	return &localSessionBackend{mgr: mgr, db: db}
}

func (b *localSessionBackend) List() ([]OnlinePlayer, error) {
	if b.mgr == nil {
		return nil, fmt.Errorf("会话管理器未初始化")
	}
	sessions := b.mgr.GetAllSessions()

	ceraMap := map[string]int64{}
	if b.db != nil {
		if m, err := b.db.GetCeraMap(extractAccountNames(sessions)); err == nil {
			ceraMap = m
		}
	}

	now := time.Now().Unix()
	players := make([]OnlinePlayer, 0, len(sessions))
	for _, s := range sessions {
		players = append(players, OnlinePlayer{
			Account:       s.Account,
			IP:            s.ClientIP,
			OnlineMinutes: int((now - s.CreatedAt) / 60),
			LastHeartbeat: s.LastHeartbeat,
			BonusGranted:  s.BonusGranted,
			Cera:          ceraMap[s.Account],
			GameId:        s.GameId,
		})
	}
	return players, nil
}

func (b *localSessionBackend) Kick(account string) (int, error) {
	if b.mgr == nil {
		return 0, fmt.Errorf("会话管理器未初始化")
	}
	if account == "" {
		kicked, _ := b.mgr.KickAll()
		return kicked, nil
	}
	kicked, _ := b.mgr.KickAccount(account)
	return kicked, nil
}

func (b *localSessionBackend) KickNonAdmin(admins []string) (int, error) {
	if b.mgr == nil {
		return 0, fmt.Errorf("会话管理器未初始化")
	}
	return b.mgr.KickNonAdminAccounts(admins), nil
}

func (b *localSessionBackend) Count() (int, error) {
	if b.mgr == nil {
		return 0, fmt.Errorf("会话管理器未初始化")
	}
	return b.mgr.SessionCount(), nil
}

type localPvfBackend struct {
	svc *service.PvfService
}

// NewLocalPvfBackend 构造网关进程内的 PVF 后端。
func NewLocalPvfBackend(svc *service.PvfService) PvfBackend {
	return &localPvfBackend{svc: svc}
}

func (b *localPvfBackend) Info() (PvfView, error) {
	if b.svc == nil {
		return PvfView{}, fmt.Errorf("PVF 服务未初始化")
	}
	info := b.svc.GetPvfInfo()
	view := PvfView{Mode: b.svc.GetSourceMode()}
	if info != nil {
		view.Path = info.Path
		view.Hash = info.Hash
		view.Algo = info.Algo
		view.Size = info.Size
		view.ModifiedUtc = info.ModifiedUtc
	}
	return view, nil
}

func (b *localPvfBackend) Refresh() error {
	if b.svc == nil {
		return fmt.Errorf("PVF 服务未初始化")
	}
	return b.svc.RefreshCache()
}

type localPortsBackend struct {
	active func() map[int]int
	conns  func() map[int]int
	store  *proxy.PortConfigStore
}

// NewLocalPortsBackend 构造网关进程内的端口后端。
//
// active/conns 传 nil 时按"无监听"处理（代理未启动的降级场景）。
// store 用于 Apply —— 它内部会同步回调 ReloadPorts 完成监听的开/关。
func NewLocalPortsBackend(
	active func() map[int]int,
	conns func() map[int]int,
	store *proxy.PortConfigStore,
) PortsBackend {
	return &localPortsBackend{active: active, conns: conns, store: store}
}

func (b *localPortsBackend) Active() (map[int]int, error) {
	if b.active == nil {
		return map[int]int{}, nil
	}
	m := b.active()
	if m == nil {
		return map[int]int{}, nil
	}
	return m, nil
}

func (b *localPortsBackend) Connections() (map[int]int, error) {
	if b.conns == nil {
		return map[int]int{}, nil
	}
	m := b.conns()
	if m == nil {
		return map[int]int{}, nil
	}
	return m, nil
}

func (b *localPortsBackend) Apply(cfg *proxy.ProxyPortConfig) (proxy.ReloadResult, error) {
	if b.store == nil {
		return proxy.ReloadResult{}, fmt.Errorf("端口配置未加载")
	}
	return b.store.Save(cfg)
}

type localRuntimeConfigBackend struct {
	cfg      *config.GatewayConfig
	editor   *service.AppSettingsEditor
	sessions SessionBackend
}

// NewLocalRuntimeConfigBackend 构造网关进程内的运行时配置后端。
func NewLocalRuntimeConfigBackend(cfg *config.GatewayConfig, editor *service.AppSettingsEditor, sessions SessionBackend) RuntimeConfigBackend {
	return &localRuntimeConfigBackend{cfg: cfg, editor: editor, sessions: sessions}
}

func (b *localRuntimeConfigBackend) Launcher() (LauncherView, error) {
	if b.cfg == nil {
		return LauncherView{}, fmt.Errorf("配置未加载")
	}
	// G-5：读运行时可变段一律走快照（锁内拷贝），别直接摸 b.cfg.Launcher.*。
	snap := b.cfg.LauncherSnapshot()
	return LauncherView{
		MinVersion:   snap.MinVersion,
		DownloadURL:  snap.DownloadUrl,
		UpdateNotice: snap.UpdateNotice,
	}, nil
}

func (b *localRuntimeConfigBackend) SetLauncher(minVersion, downloadURL, updateNotice *string) (bool, error) {
	if b.cfg == nil {
		return false, fmt.Errorf("配置未加载")
	}
	// Launcher 段必须一次性合并成一个 map，
	// 否则先后两次赋值 updates["Launcher"] 会导致前一个字段的落盘被覆盖。
	launcherUpdates := make(map[string]interface{})
	if minVersion != nil {
		launcherUpdates["MinVersion"] = *minVersion
	}
	if downloadURL != nil {
		launcherUpdates["DownloadUrl"] = *downloadURL
	}
	if updateNotice != nil {
		launcherUpdates["UpdateNotice"] = *updateNotice
	}
	if len(launcherUpdates) == 0 {
		return false, nil
	}

	updates := map[string]interface{}{"Launcher": launcherUpdates}
	if b.editor != nil {
		if err := b.editor.SaveOverride(updates); err != nil {
			return false, err
		}
	}
	// G-5（2026-10-04 审查）：原先这里直接改 b.cfg.Launcher.*，与认证侧（版本门禁）
	// 和 HTTP 侧（policy/notice）的并发读构成数据竞争。改走锁内原语。
	// 顺序也调整为「先落盘、成功后再更新内存」—— 落盘失败时不留下"内存已改、
	// 重启还原"的不一致状态。
	b.cfg.SetLauncherRuntime(minVersion, downloadURL, updateNotice)
	return true, nil
}

func (b *localRuntimeConfigBackend) Maintenance() (MaintenanceView, error) {
	if b.cfg == nil {
		return MaintenanceView{}, fmt.Errorf("配置未加载")
	}
	// G-5：快照读取（AdminAccounts 已做切片拷贝，可安全遍历）。
	snap := b.cfg.MaintenanceSnapshot()
	return MaintenanceView{
		Enabled:       snap.Enabled,
		Message:       snap.Message,
		AdminAccounts: snap.AdminAccounts,
	}, nil
}

func (b *localRuntimeConfigBackend) SetMaintenance(enabled *bool, message *string, admins []string) (int, error) {
	if b.cfg == nil {
		return 0, fmt.Errorf("配置未加载")
	}
	// G-5（2026-10-04 审查）：原先直接改 b.cfg.Maintenance.*，且紧接着
	// `if b.cfg.Maintenance.Enabled` 是**未加锁读同一批字段**。这里改为
	// 锁内写入 + 锁后快照判定，踢人用的是与判定一致的那份值。
	b.cfg.SetMaintenanceRuntime(enabled, message, admins)
	snap := b.cfg.MaintenanceSnapshot()

	// 开启维护模式时踢掉非管理员会话
	if snap.Enabled && b.sessions != nil {
		kicked, _ := b.sessions.KickNonAdmin(snap.AdminAccounts)
		return kicked, nil
	}
	return 0, nil
}

func (b *localRuntimeConfigBackend) RegisterLimit() (RegisterLimitView, error) {
	if b.cfg == nil {
		return RegisterLimitView{}, fmt.Errorf("配置未加载")
	}
	// 与 Launcher 同款：读运行时可变段一律走快照（锁内拷贝）。
	snap := b.cfg.RegisterLimitSnapshot()
	return RegisterLimitView{
		Enabled:     snap.Enabled,
		PerIPPerDay: snap.PerIPPerDay,
		PerMachine:  snap.PerMachine,
	}, nil
}

func (b *localRuntimeConfigBackend) SetRegisterLimit(enabled *bool, perIPPerDay, perMachine *int) (bool, error) {
	if b.cfg == nil {
		return false, fmt.Errorf("配置未加载")
	}
	if enabled == nil && perIPPerDay == nil && perMachine == nil {
		return false, nil
	}

	// 值域校验放在落盘**之前**：负数或荒谬的大数一旦写进 override 文件，
	// 下次启动会被原样读回，重启也修不好，只能手改文件。
	// 0 是合法值（= 该维度不限制），负数是笔误，超过 10000 显然不是本意。
	for _, v := range []struct {
		name string
		p    *int
	}{{"PerIPPerDay", perIPPerDay}, {"PerMachine", perMachine}} {
		if v.p == nil {
			continue
		}
		if *v.p < 0 || *v.p > 10000 {
			return false, fmt.Errorf("%s 取值必须在 0~10000 之间（0 = 不限制该维度）", v.name)
		}
	}

	// 与 SetLauncher 同序：先落盘 override，成功后再改内存 ——
	// 落盘失败时不留下"内存已改、重启还原"的不一致。
	limitUpdates := make(map[string]interface{})
	if enabled != nil {
		limitUpdates["Enabled"] = *enabled
	}
	if perIPPerDay != nil {
		limitUpdates["PerIPPerDay"] = *perIPPerDay
	}
	if perMachine != nil {
		limitUpdates["PerMachine"] = *perMachine
	}
	if b.editor != nil {
		if err := b.editor.SaveOverride(map[string]interface{}{"RegisterLimit": limitUpdates}); err != nil {
			return false, err
		}
	}
	b.cfg.SetRegisterLimitRuntime(enabled, perIPPerDay, perMachine)
	return true, nil
}

func (b *localRuntimeConfigBackend) Heartbeat() (HeartbeatView, error) {
	if b.cfg == nil {
		return HeartbeatView{}, fmt.Errorf("配置未加载")
	}
	// 与 Launcher/RegisterLimit 同款：读运行时可变段一律走快照（锁内拷贝）。
	snap := b.cfg.HeartbeatSnapshot()
	return HeartbeatView{TimeoutSeconds: snap.TimeoutSeconds}, nil
}

func (b *localRuntimeConfigBackend) SetHeartbeat(timeoutSeconds *int) (bool, error) {
	if b.cfg == nil {
		return false, fmt.Errorf("配置未加载")
	}
	if timeoutSeconds == nil {
		return false, nil
	}

	// ★★ 值域校验必须在落盘**之前**：离谱的值一旦写进 override 文件，
	// 下次启动会被原样读回，重启也修不好，只能手改文件（同 SetRegisterLimit 的理由）。
	//
	// 下限 30 = 登录器心跳周期（161/193/216 上都是 30s）—— 小于它等于把
	// "每个正常心跳之间"都判成超时，会把所有在线玩家清掉，是灾难级误配。
	// 上限 3600 是"客户端崩溃后会话最多挂多久"的容忍度；再大只是更久地占着
	// 单账号单令牌的坑，没有收益。
	const minTimeout, maxTimeout = 30, 3600
	if *timeoutSeconds < minTimeout || *timeoutSeconds > maxTimeout {
		return false, fmt.Errorf("TimeoutSeconds 取值必须在 %d~%d 之间（须大于登录器心跳周期 30s）",
			minTimeout, maxTimeout)
	}

	// 与 SetLauncher 同序：先落盘 override，成功后再改内存 ——
	// 落盘失败时不留下"内存已改、重启还原"的不一致。
	if b.editor != nil {
		if err := b.editor.SaveOverride(map[string]interface{}{
			"Heartbeat": map[string]interface{}{"TimeoutSeconds": *timeoutSeconds},
		}); err != nil {
			return false, err
		}
	}
	b.cfg.SetHeartbeatRuntime(timeoutSeconds)
	return true, nil
}

// ============================================================================
// 空实现：用于"该能力在当前进程不可用"的场景（例如 admin 进程未配置内部地址）
// ============================================================================

// unavailableSessionBackend 在无法访问网关内部 API 时使用：报错但不 panic。
type unavailableSessionBackend struct{ reason string }

// NewUnavailableSessionBackend 构造一个总是返回错误的会话后端。
func NewUnavailableSessionBackend(reason string) SessionBackend {
	return &unavailableSessionBackend{reason: reason}
}

func (b *unavailableSessionBackend) err() error {
	return fmt.Errorf("在线会话功能不可用：%s", b.reason)
}
func (b *unavailableSessionBackend) List() ([]OnlinePlayer, error)      { return nil, b.err() }
func (b *unavailableSessionBackend) Kick(string) (int, error)           { return 0, b.err() }
func (b *unavailableSessionBackend) KickNonAdmin([]string) (int, error) { return 0, b.err() }
func (b *unavailableSessionBackend) Count() (int, error)                { return 0, b.err() }

type unavailablePvfBackend struct{ reason string }

// NewUnavailablePvfBackend 构造一个总是返回错误的 PVF 后端。
func NewUnavailablePvfBackend(reason string) PvfBackend {
	return &unavailablePvfBackend{reason: reason}
}

func (b *unavailablePvfBackend) Info() (PvfView, error) {
	return PvfView{}, fmt.Errorf("PVF 缓存不可用：%s", b.reason)
}
func (b *unavailablePvfBackend) Refresh() error {
	return fmt.Errorf("PVF 缓存不可用：%s", b.reason)
}

type unavailablePortsBackend struct{ reason string }

// NewUnavailablePortsBackend 构造一个总是返回错误的端口后端。
func NewUnavailablePortsBackend(reason string) PortsBackend {
	return &unavailablePortsBackend{reason: reason}
}

func (b *unavailablePortsBackend) err() error {
	return fmt.Errorf("代理端口状态不可用：%s", b.reason)
}
func (b *unavailablePortsBackend) Active() (map[int]int, error)      { return map[int]int{}, nil }
func (b *unavailablePortsBackend) Connections() (map[int]int, error) { return map[int]int{}, nil }
func (b *unavailablePortsBackend) Apply(*proxy.ProxyPortConfig) (proxy.ReloadResult, error) {
	return proxy.ReloadResult{}, b.err()
}

type unavailableRuntimeConfigBackend struct{ reason string }

// NewUnavailableRuntimeConfigBackend 构造一个总是返回错误的运行时配置后端。
func NewUnavailableRuntimeConfigBackend(reason string) RuntimeConfigBackend {
	return &unavailableRuntimeConfigBackend{reason: reason}
}

func (b *unavailableRuntimeConfigBackend) Launcher() (LauncherView, error) {
	return LauncherView{}, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
func (b *unavailableRuntimeConfigBackend) SetLauncher(*string, *string, *string) (bool, error) {
	return false, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
func (b *unavailableRuntimeConfigBackend) Maintenance() (MaintenanceView, error) {
	return MaintenanceView{}, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
func (b *unavailableRuntimeConfigBackend) SetMaintenance(*bool, *string, []string) (int, error) {
	return 0, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
func (b *unavailableRuntimeConfigBackend) RegisterLimit() (RegisterLimitView, error) {
	return RegisterLimitView{}, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
func (b *unavailableRuntimeConfigBackend) SetRegisterLimit(*bool, *int, *int) (bool, error) {
	return false, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
func (b *unavailableRuntimeConfigBackend) Heartbeat() (HeartbeatView, error) {
	return HeartbeatView{}, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
func (b *unavailableRuntimeConfigBackend) SetHeartbeat(*int) (bool, error) {
	return false, fmt.Errorf("运行时配置不可用：%s", b.reason)
}
