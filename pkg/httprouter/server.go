package httprouter

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/proxy"
	"s4a21-gateway/pkg/ratelimiter"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/service"
	"s4a21-gateway/pkg/session"
	"s4a21-gateway/pkg/utils"
)

// Server HTTP 服务器。
type Server struct {
	config           *config.GatewayConfig
	logger           *logger.ConsoleLogger
	db               *database.Database
	sessionMgr       *session.SessionManager
	accountSvc       *service.AccountService
	adminSvc         *service.AdminService
	banSvc           *service.BanService
	pvfSvc           *service.PvfService
	integritySvc     *service.IntegrityStore
	registerBonusSvc *service.RegisterBonusService
	bonusSvc         *service.BonusService
	deviceSvc        *service.DeviceCredentialService
	serverMgr        *service.ServerManager
	gatewayMgr       *service.GatewayManager
	settingsEditor   *service.AppSettingsEditor
	// qqBindSvc 处理「账号绑定 QQ 号」（2026-09-24）。
	//
	// 两个进程都注入：网关侧给玩家发码/绑定，admin 侧只用它来解绑
	//（admin 的 sender 传 nil —— 后台不发信，只做关系维护）。
	qqBindSvc   *service.QQBindService
	httpLimiter *ratelimiter.HttpRateLimiter
	cert        *tls.Certificate
	portStore   *proxy.PortConfigStore

	// plugins 是插件下发目录的扫描器 + sha256 缓存（见 launcher_plugins.go）。
	//
	// 纯文件系统，**不依赖网关进程内存**，所以两个进程各持一份、共用同一个目录即可：
	// admin 进程(8443) 负责上传/删除文件，网关进程(8080) 负责按签名重扫后下发。
	// 不存在"改后台内存不影响玩家"那类错位，因此**不需要**走 backends 抽象。
	plugins *pluginStore

	// 公告服务：**只在网关进程**非 nil。
	// admin 进程不注册 /api/launcher/item-ranking（公开路由），
	// 也不需要它 —— 事件查询/弹窗历史在 admin 侧直读 db。
	announceSvc *service.AnnounceService

	// 后端抽象：跨进程能力（见 backends.go）。
	// 网关进程注入 local* 实现，admin 进程注入 remote* 实现，
	// 因此下面的 handleAdmin* 代码不需要知道自己在哪个进程里跑。
	sessions SessionBackend
	pvf      PvfBackend
	ports    PortsBackend
	runtime  RuntimeConfigBackend
	announce AnnounceBackend

	// 在线角色公开接口的短缓存。
	// 该接口免鉴权，且每次要 join 游戏库查角色；做成缓存是为了——
	//   ① 登录器每次切到「在线角色」页都打一次，没有缓存会把游戏库打成热点；
	//   ② 缓存 5 秒对「谁在线」足够新鲜，同时把突发请求压成一次查询。
	// 存的是已序列化好的 JSON 字节，命中时直接 Write，连再编码都省了。
	onlineCacheMu   sync.Mutex
	onlineCacheAt   time.Time
	onlineCacheBody []byte
}

// NewServer 创建 HTTP 服务器。
func NewServer(
	cfg *config.GatewayConfig,
	logger *logger.ConsoleLogger,
	db *database.Database,
	sessionMgr *session.SessionManager,
	accountSvc *service.AccountService,
	adminSvc *service.AdminService,
	banSvc *service.BanService,
	pvfSvc *service.PvfService,
	integritySvc *service.IntegrityStore,
	registerBonusSvc *service.RegisterBonusService,
	bonusSvc *service.BonusService,
	deviceSvc *service.DeviceCredentialService,
	serverMgr *service.ServerManager,
	gatewayMgr *service.GatewayManager,
	settingsEditor *service.AppSettingsEditor,
	qqBindSvc *service.QQBindService,
	announceSvc *service.AnnounceService,
	cert *tls.Certificate,
	portStore *proxy.PortConfigStore,
	backends Backends,
) *Server {
	b := backends.withDefaults()
	return &Server{
		config:           cfg,
		logger:           logger,
		db:               db,
		sessionMgr:       sessionMgr,
		accountSvc:       accountSvc,
		adminSvc:         adminSvc,
		banSvc:           banSvc,
		pvfSvc:           pvfSvc,
		integritySvc:     integritySvc,
		registerBonusSvc: registerBonusSvc,
		bonusSvc:         bonusSvc,
		deviceSvc:        deviceSvc,
		serverMgr:        serverMgr,
		gatewayMgr:       gatewayMgr,
		settingsEditor:   settingsEditor,
		qqBindSvc:        qqBindSvc,
		announceSvc:      announceSvc,
		httpLimiter: ratelimiter.NewHttpRateLimiter(
			cfg.RateLimit.Enabled, cfg.RateLimit.HttpRequestsPerMinute),
		cert:      cert,
		portStore: portStore,
		plugins:   newPluginStore(cfg.Launcher.PluginDir),
		sessions:  b.Sessions,
		pvf:       b.Pvf,
		ports:     b.Ports,
		runtime:   b.Runtime,
		announce:  b.Announce,
	}
}

// Start 启动 HTTP 服务器（单进程模式：管理后台与核心同进程，支持端口拆分）。
//
// ⚠️ 单进程模式下改后端代码必须重启网关 → 在线玩家掉线（原本的问题）。
// 这是"回滚开关" Gateway.ServeAdminInProcess 的目标形态：
// 置 true 时网关自持 8080 + 管理端口，停掉 gateway-admin 服务即可回到分离前。
// 正常部署请用 StartPublic（网关）+ StartAdmin（admin 进程）。
func (s *Server) Start() {
	r := mux.NewRouter()
	s.registerPublicRoutes(r)
	s.registerAdminRoutes(r)

	// 端口拆分中间件：8080 与 8443 共用一个 router，按本地端口分流
	if s.config.AdminSplitEnabled() {
		r.Use(s.portSplitMiddleware)
	}
	s.useCommonMiddleware(r)

	s.serveHTTPOn(r, s.config.ResolveHttpListenAddress(), s.config.Gateway.HttpPort, "HTTP")

	if s.config.AdminSplitEnabled() {
		s.serveHTTPOn(r, s.config.Gateway.AdminHttpListenAddress, s.config.Gateway.AdminHttpPort, "后台 HTTP")
	}
}

// StartPublic 只启动面向玩家/登录器的 HTTP 端口（双进程模式下的网关进程）。
//
// 玩家链路（TCP 8000 / 8001 / 20001+ / 本端口）完全不经 admin 进程，
// 所以 admin 重启、升级都不影响在线玩家 —— 这是本次改造的核心目的。
func (s *Server) StartPublic() {
	r := mux.NewRouter()
	s.registerPublicRoutes(r)
	s.usePublicOnlyMiddleware(r)
	s.serveHTTPOn(r, s.config.ResolveHttpListenAddress(), s.config.Gateway.HttpPort, "HTTP")
}

// usePublicOnlyMiddleware 挂上玩家端口的中间件：限流 + 非 /api 路径一律 404。
//
// 刻意**不挂静态页**：分离前 8080 上 portSplitMiddleware 会把非 /api 请求全部 404，
// 管理后台页面只在管理端口可见。这里保持完全一致 —— 玩家端口不该暴露后台页面。
func (s *Server) usePublicOnlyMiddleware(r *mux.Router) {
	r.Use(s.httpRateLimitMiddleware)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !strings.HasPrefix(req.URL.Path, "/api") {
				http.NotFound(w, req)
				return
			}
			next.ServeHTTP(w, req)
		})
	})
}

// StartAdmin 只启动管理后台端口 + 静态页（双进程模式下的 admin 进程）。
func (s *Server) StartAdmin() {
	r := mux.NewRouter()
	s.registerAdminRoutes(r)
	s.useCommonMiddleware(r)
	s.serveHTTPOn(r, s.config.Gateway.AdminHttpListenAddress, s.config.Gateway.AdminHttpPort, "后台 HTTP")
}

// StartInternal 启动内部 API 端口（网关进程专用，供 admin 进程调用）。
//
// 安全约束：只绑 loopback（Gateway.InternalListenAddress，默认 127.0.0.1）；
// Admin.InternalKey 未配置时**不启动** —— 宁可让 admin 进程报"能力不可用"，
// 也不开一个无鉴权的内部端口。
func (s *Server) StartInternal() {
	if strings.TrimSpace(s.config.Admin.InternalKey) == "" {
		s.logger.Warn("[Internal] Admin.InternalKey 未配置，内部 API 端口不启动")
		return
	}
	addr := s.config.ResolveInternalListenAddress()

	// 内部 API 能让调用者读在线名单、踢人、改端口表 —— 绝不能暴露到局域网。
	// 这里宁可拒绝启动（admin 进程会明确报"能力不可用"），也不冒险绑 0.0.0.0。
	if !isLoopbackAddr(addr) {
		s.logger.Error(fmt.Sprintf(
			"[Internal] 拒绝启动内部 API：Gateway.InternalListenAddress=%q 不是回环地址。"+
				"只允许 127.0.0.1 / localhost / ::1。", addr))
		return
	}

	r := mux.NewRouter()
	s.registerInternalRoutes(r)
	// ★ 强制明文：这条通道两端都写死 http（admin 进程的 backends 客户端、
	//   服务端公告插件），而它只绑回环 + 有 InternalKey 鉴权。详见 servePlainHTTPOn。
	s.servePlainHTTPOn(r, addr, s.config.Gateway.InternalPort, "内部 API")
}

// isLoopbackAddr 判断监听地址是否为本机回环。
func isLoopbackAddr(addr string) bool {
	a := strings.TrimSpace(addr)
	if a == "" {
		return false
	}
	if a == "localhost" {
		return true
	}
	if ip := net.ParseIP(strings.Trim(a, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// useCommonMiddleware 挂上限流与静态页。
//
// 内部 API 刻意**不挂**这两样：它只服务本机 admin 进程（限流会误伤自家人），
// 静态页也不该从内部端口暴露出去。
func (s *Server) useCommonMiddleware(r *mux.Router) {
	r.Use(s.httpRateLimitMiddleware)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("wwwroot")))
}

// serveHTTPOn 在指定地址起一个 HTTP(S) 服务（非阻塞）。port<=0 表示不启动。
//
// label 只影响日志文案，保持与历史日志一致（"HTTP 服务…" / "后台 HTTP 服务…"），
// 便于沿用既有的日志检索习惯。
//
// TLS 由 s.cert 决定（Tls.Enabled=true 时非空）。
func (s *Server) serveHTTPOn(r *mux.Router, listenAddr string, port int, label string) {
	s.serveOn(r, listenAddr, port, label, s.cert)
}

// servePlainHTTPOn 与 serveHTTPOn 相同，但**强制明文**（忽略 Tls.Enabled）。
//
// 内部 API（Gateway.InternalPort，默认 18080）专用。它必须明文，理由不是"图省事"：
// 这条通道的两端都是**本机进程**，且两端都写死了 http ——
//   · s4a21-admin：pkg/backends.NewClient 里 baseURL = "http://" + host:port；
//   · 服务端公告插件：DungeonBroadcastPlugin 里拼 "http://" + 网关地址 + ":" + 端口
//     （plugin.ini 的「网关地址=127.0.0.1」不带 scheme，走的就是这一支）。
// 给一个只绑回环的进程间通道套 TLS 不增加任何安全性（能连上 127.0.0.1 的对手
// 已经在本机了），却会把上面两条链路一起打断：
//   · admin 启动自检失败 → 在线列表 / 踢人 / PVF / 端口表 全部报错；
//   · 公告插件降级 → 不热重载、不写库、不收弹窗。
// 生产 8.138.9.216 的 appsettings 是 Tls.Enabled=true，切过去当天就会踩到
// （2026-09-28 在 161 用生产配置演练实测）。真正的保护是
// 「只绑回环（ResolveInternalListenAddress）+ Admin.InternalKey 鉴权」，
// 两者都不依赖 TLS。
func (s *Server) servePlainHTTPOn(r *mux.Router, listenAddr string, port int, label string) {
	s.serveOn(r, listenAddr, port, label, nil)
}

// serveOn 是上面两个的公共实现。cert 为 nil 时走明文，非 nil 时走 HTTPS。
func (s *Server) serveOn(r *mux.Router, listenAddr string, port int, label string,
	cert *tls.Certificate) {
	if port <= 0 {
		return
	}
	addr := net.JoinHostPort(listenAddr, strconv.Itoa(port))
	// withBodyDrain：拒绝类响应（401/404/405/限流…）写响应前先读掉请求体，
	// 否则连接关闭时内核会回 RST，客户端看到的是"连接被重置"而不是状态码。
	// withBodyLimit：请求体上限（8 MiB），覆盖全部 30 处 json.NewDecoder(r.Body)。
	// 三个文件上传端点（upload-pvf / server/pvf / integrity/upload）另有 512 MiB 放宽，
	// 见 bodylimit.go 的 uploadPaths —— PVF 实测 58 MiB，8 MiB 会把它们整条打死。
	// 顺序：limit 在外、drain 在内（理由见 bodylimit.go 的注释）。
	handler := withBodyLimit(withBodyDrain(r), maxRequestBodyBytes)
	go func() {
		server := &http.Server{Addr: addr, Handler: handler}
		if cert != nil {
			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			}
		}
		s.logger.Info(fmt.Sprintf("%s服务(%s)已启动: %s", label, tlsLabel(cert), addr))
		s.listenAndServe(server, cert)
	}()
}

func tlsLabel(cert *tls.Certificate) string {
	if cert != nil {
		return "HTTPS"
	}
	return "HTTP明文"
}

func (s *Server) listenAndServe(server *http.Server, cert *tls.Certificate) {
	if cert != nil {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			s.logger.Fatal(fmt.Sprintf("HTTPS 服务启动失败: %v", err))
		}
		return
	}
	if err := server.ListenAndServe(); err != nil {
		s.logger.Fatal(fmt.Sprintf("HTTP 服务启动失败: %v", err))
	}
}

func (s *Server) portSplitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		port := getLocalPort(r)
		path := r.URL.Path
		adminPort := s.config.Gateway.AdminHttpPort

		isAdminApi := strings.HasPrefix(path, "/api/admin") ||
			strings.HasPrefix(path, "/api/pvf/info")
		isLauncherOnly := strings.HasPrefix(path, "/api/launcher") ||
			strings.HasPrefix(path, "/api/heartbeat")

		blocked := false
		if port == adminPort {
			blocked = isLauncherOnly
		} else {
			blocked = isAdminApi || !strings.HasPrefix(path, "/api")
		}

		if blocked {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) httpRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		group := ratelimiter.PathGroup(path)
		if group == "" {
			next.ServeHTTP(w, r)
			return
		}

		ip := getClientIP(r)
		// 按 IP + 分组限流：管理后台、心跳、登录器策略各自独立计数，
		// 避免玩家客户端的高频心跳把管理后台的额度挤掉。
		if s.httpLimiter.TryAcquireGroup(ip, group) {
			next.ServeHTTP(w, r)
			return
		}

		s.logger.Warn(fmt.Sprintf("[RATE_LIMIT] HTTP 限流: %s %s %s group=%s", r.Method, ip, path, group))
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      false,
			"message": "请求过于频繁，请稍后再试",
		})
	})
}

// registerPublicRoutes 注册面向玩家/登录器的路由。
//
// 双进程模式下只有网关进程注册它们 —— 玩家链路完全不经 admin 进程，
// 这是"升管理后台不掉线"的根本原因。
func (s *Server) registerPublicRoutes(r *mux.Router) {
	// 健康检查
	r.HandleFunc("/api/health", s.handleHealth).Methods("GET")

	// 登录器版本
	r.HandleFunc("/api/launcher/version", s.handleLauncherVersion).Methods("GET")

	// 登录器策略
	r.HandleFunc("/api/launcher/policy", s.handleLauncherPolicy).Methods("GET")

	// 登录器物品榜单（史诗/传说/神器三榜，公开只读）
	r.HandleFunc("/api/launcher/item-ranking", s.handleLauncherItemRanking).Methods("GET")

	// 登录器更新公告（公开只读）：内容 = config.Launcher.UpdateNotice，
	// 由管理后台「客户端配置」页维护，改完立刻生效。
	r.HandleFunc("/api/launcher/notice", s.handleLauncherNotice).Methods("GET")

	// 登录器在线角色（公开只读）：网关会话 + 游戏库当前角色推定。
	// 免鉴权，因此已挂 GroupLauncher 限流，且响应里不含账号名/IP。
	r.HandleFunc("/api/launcher/online", s.handleLauncherOnline).Methods("GET")

	// 插件下发（2026-09-30 插件增量更新，公开只读）。
	//
	// ★ 必须走 /api 路由：玩家端口(8080) 由 usePublicOnlyMiddleware 把非 /api 路径
	//   一律 404，wwwroot 静态文件在玩家端口上根本不可达。详见 launcher_plugins.go 抬头。
	//
	// {name} 用 [^/]+ 收窄（URL.Path 已解码，所以 ..%2Fxx 会含 / 而不匹配），
	// handler 里另有 validPluginFileName + 目录前缀双重校验。查的是清单准入表，
	// 目录里的未登记文件不会经此接口外泄。
	r.HandleFunc("/api/launcher/plugins", s.handleLauncherPlugins).Methods("GET")
	r.HandleFunc("/api/launcher/plugins/file/{name:[^/]+}", s.handleLauncherPluginFile).Methods("GET")

	// 心跳
	r.HandleFunc("/api/heartbeat", s.handleHeartbeat).Methods("POST")

	// 外挂检测上报（玩家客户端调用）
	r.HandleFunc("/api/anticheat/report", s.handleAntiCheatReport).Methods("POST")
}

// registerAdminRoutes 注册管理后台路由。
//
// 这些 handler 依赖的运行时状态已全部走 Backends 抽象，
// 因此同一个函数体在网关进程（单进程/回滚模式）与 admin 进程（双进程模式）下都能工作。
func (s *Server) registerAdminRoutes(r *mux.Router) {
	// 健康检查：分离前 8443 上 /api/health 是通的（portSplitMiddleware 只拦登录器路径），
	// 这里保留，避免运维脚本按老习惯探测 8443 时误判"服务挂了"。纯静态响应，不依赖任何 backend。
	r.HandleFunc("/api/health", s.handleHealth).Methods("GET")

	// 在线玩家
	r.HandleFunc("/api/admin/online", s.handleAdminOnline).Methods("GET")
	r.HandleFunc("/api/admin/online/kick", s.handleAdminKick).Methods("POST")

	// 全服发放
	r.HandleFunc("/api/admin/broadcast", s.handleAdminBroadcast).Methods("POST")

	// PVF 管理
	r.HandleFunc("/api/admin/refresh-pvf", s.handleAdminRefreshPvf).Methods("POST")
	r.HandleFunc("/api/pvf/info", s.handlePvfInfo).Methods("GET")
	r.HandleFunc("/api/admin/upload-pvf", s.handleAdminUploadPvf).Methods("POST")
	r.HandleFunc("/api/admin/pvf/register", s.handlePvfRegister).Methods("POST")
	r.HandleFunc("/api/admin/pvf/unregister", s.handlePvfUnregister).Methods("POST")

	// 完整性策略
	r.HandleFunc("/api/admin/integrity", s.handleAdminIntegrity).Methods("GET")
	r.HandleFunc("/api/admin/integrity/upload", s.handleAdminIntegrityUpload).Methods("POST")
	r.HandleFunc("/api/admin/integrity/add", s.handleAdminIntegrityAdd).Methods("POST")
	r.HandleFunc("/api/admin/integrity/remove", s.handleAdminIntegrityRemove).Methods("POST")
	r.HandleFunc("/api/admin/integrity/allow", s.handleAdminIntegrityAllow).Methods("POST")

	// 账号管理
	r.HandleFunc("/api/admin/accounts", s.handleAdminAccounts).Methods("GET")
	r.HandleFunc("/api/admin/sync-game-accounts", s.handleAdminSyncAccounts).Methods("POST")
	r.HandleFunc("/api/admin/roles", s.handleAdminRoles).Methods("GET")
	r.HandleFunc("/api/admin/reset-password", s.handleAdminResetPassword).Methods("POST")
	r.HandleFunc("/api/admin/reset-device", s.handleAdminResetDevice).Methods("POST")
	r.HandleFunc("/api/admin/unlock", s.handleAdminUnlock).Methods("POST")
	r.HandleFunc("/api/admin/reset-all-passwords", s.handleAdminResetAllPasswords).Methods("POST")
	r.HandleFunc("/api/admin/send-items", s.handleAdminSendItems).Methods("POST")
	r.HandleFunc("/api/admin/delete-account", s.handleAdminDeleteAccount).Methods("POST")
	r.HandleFunc("/api/admin/delete-accounts", s.handleAdminDeleteAccounts).Methods("POST")

	// 封禁
	r.HandleFunc("/api/admin/bans", s.handleAdminBans).Methods("GET")
	r.HandleFunc("/api/admin/ban", s.handleAdminBan).Methods("POST")
	// 解除账号与 QQ 号的绑定（2026-09-24）。
	// 与「解绑设备」是两件事：那个清 device_secret，这个删 qq_bindings 一行。
	r.HandleFunc("/api/admin/qq/unbind", s.handleAdminQQUnbind).Methods("POST")
	r.HandleFunc("/api/admin/unban", s.handleAdminUnban).Methods("POST")

	// 注册奖励
	r.HandleFunc("/api/admin/register-bonus/config", s.handleAdminRegisterBonusConfigGet).Methods("GET")
	r.HandleFunc("/api/admin/register-bonus/config", s.handleAdminRegisterBonusConfigPost).Methods("POST")
	r.HandleFunc("/api/admin/register-bonus/logs", s.handleAdminRegisterBonusLogs).Methods("GET")

	// 泡点计费设置（Data/bonus.json）。
	// 放在服务端管理页下：泡点影响的是"服务端在发什么钱"，和注册奖励同一类。
	// 两个进程都能直接读写这个文件（主循环每轮重读盘），所以不需要走内部 API。
	r.HandleFunc("/api/admin/bonus/config", s.handleAdminBonusConfigGet).Methods("GET")
	r.HandleFunc("/api/admin/bonus/config", s.handleAdminBonusConfigPost).Methods("POST")

	// 活动管理（服务端管理页）。
	//
	// 读写的是**游戏库**的 game_event_state / game_event_info_details。
	// 不走内部 API 直接改，理由与账号/封禁/注册奖励一致：数据在共享的 SQLite 里，
	// 不在网关进程的内存里 —— 拿本进程的 db 句柄写就够了。
	// 反过来说，凡是"改的其实是网关内存态"的（维护模式、端口表、公告快照）
	// 都必须走网关；这里不是。
	r.HandleFunc("/api/admin/game-events", s.handleAdminGameEvents).Methods("GET")
	r.HandleFunc("/api/admin/game-event/toggle", s.handleAdminGameEventToggle).Methods("POST")
	r.HandleFunc("/api/admin/game-event/update", s.handleAdminGameEventUpdate).Methods("POST")

	// 服务端配置

	// 全服公告（配置热重载 / 事件分类查询 / 弹窗公告）
	r.HandleFunc("/api/admin/announce/config", s.handleAdminAnnounceConfigGet).Methods("GET")
	r.HandleFunc("/api/admin/announce/config", s.handleAdminAnnounceConfigPost).Methods("POST")
	r.HandleFunc("/api/admin/announce/stats", s.handleAdminAnnounceStats).Methods("GET")
	r.HandleFunc("/api/admin/announce/events", s.handleAdminAnnounceEvents).Methods("GET")
	r.HandleFunc("/api/admin/announce/popups", s.handleAdminAnnouncePopups).Methods("GET")
	r.HandleFunc("/api/admin/announce/popup", s.handleAdminAnnouncePopupSend).Methods("POST")
	r.HandleFunc("/api/admin/announce/popup", s.handleAdminAnnouncePopupDelete).Methods("DELETE")

	// 客户端插件下发（登录器插件增量更新，2026-09-30）。
	//
	// 管理的是**网关运行目录下的插件目录**（Launcher.PluginDir，默认 ./plugins）。
	// 纯文件系统操作、两个进程共用同一目录，所以不走内部 API：
	// admin 写完文件，网关进程下次收到清单请求时按目录签名自动重扫。
	//
	// ★ 部署前提：两个进程的 WorkingDirectory 必须一致，否则 "./plugins"
	//   会解析到两个不同目录（admin 传的文件网关看不见）。与 Pvf.FilePath 同一前提。
	r.HandleFunc("/api/admin/plugins", s.handleAdminPluginsList).Methods("GET")
	r.HandleFunc("/api/admin/plugins/upload", s.handleAdminPluginUpload).Methods("POST")
	r.HandleFunc("/api/admin/plugins/delete", s.handleAdminPluginDelete).Methods("POST")
	r.HandleFunc("/api/admin/plugins/meta", s.handleAdminPluginMetaSave).Methods("POST")
	// 按目录里的 *.dll 生成一份清单草稿（首次部署省得手写）。
	// 草稿全部是"非核心 + 默认关闭"，必须人工改对核心插件与顺序。
	r.HandleFunc("/api/admin/plugins/meta/draft", s.handleAdminPluginMetaDraft).Methods("POST")

	// 服务端管理
	r.HandleFunc("/api/admin/server/status", s.handleAdminServerStatus).Methods("GET")
	r.HandleFunc("/api/admin/server/control", s.handleAdminServerControl).Methods("POST")
	r.HandleFunc("/api/admin/server/logs", s.handleAdminServerLogs).Methods("GET")
	r.HandleFunc("/api/admin/server/pvf", s.handleAdminServerPvf).Methods("POST")
	r.HandleFunc("/api/admin/server/backup", s.handleAdminServerBackup).Methods("POST")
	r.HandleFunc("/api/admin/server/backups", s.handleAdminServerBackups).Methods("GET")

	// 网关管理
	r.HandleFunc("/api/admin/gateway/status", s.handleAdminGatewayStatus).Methods("GET")
	r.HandleFunc("/api/admin/gateway/control", s.handleAdminGatewayControl).Methods("POST")
	r.HandleFunc("/api/admin/gateway/logs", s.handleAdminGatewayLogs).Methods("GET")

	// 游戏代理端口管理
	r.HandleFunc("/api/admin/game-ports", s.handleAdminGamePorts).Methods("GET")
	r.HandleFunc("/api/admin/game-ports", s.handleAdminGamePortsPost).Methods("POST")

	// 登录器配置
	r.HandleFunc("/api/admin/launcher-config", s.handleAdminLauncherConfigGet).Methods("GET")
	r.HandleFunc("/api/admin/launcher-config", s.handleAdminLauncherConfigPost).Methods("POST")

	// 维护模式
	r.HandleFunc("/api/admin/maintenance", s.handleAdminMaintenanceGet).Methods("GET")
	r.HandleFunc("/api/admin/maintenance", s.handleAdminMaintenancePost).Methods("POST")

	// 外挂检测查询
	r.HandleFunc("/api/admin/anticheat/detections", s.handleAdminAntiCheatDetections).Methods("GET")
	r.HandleFunc("/api/admin/anticheat/players", s.handleAdminAntiCheatPlayers).Methods("GET")
	r.HandleFunc("/api/admin/anticheat/players/{account}/details", s.handleAdminAntiCheatPlayerDetails).Methods("GET")
}

// ==================== 内部 API（只绑 loopback，供 admin 进程调用） ====================
//
// 这组接口是进程分离的"脐带"：admin 进程需要网关进程内存里的状态时调它们。
// 安全约束：① 只监听 Gateway.InternalListenAddress（默认 127.0.0.1）；
// ② 独立密钥 Admin.InternalKey，与前台管理密钥 Admin.AuthKey **分开**；
// ③ 密钥为空则内部端口根本不启动。
func (s *Server) registerInternalRoutes(r *mux.Router) {
	r.HandleFunc("/internal/online", s.checkInternal(s.handleInternalOnline)).Methods("GET")
	r.HandleFunc("/internal/kick", s.checkInternal(s.handleInternalKick)).Methods("POST")
	r.HandleFunc("/internal/pvf-info", s.checkInternal(s.handleInternalPvfInfo)).Methods("GET")
	r.HandleFunc("/internal/refresh-pvf", s.checkInternal(s.handleInternalRefreshPvf)).Methods("POST")
	r.HandleFunc("/internal/active-ports", s.checkInternal(s.handleInternalActivePorts)).Methods("GET")
	r.HandleFunc("/internal/apply-ports", s.checkInternal(s.handleInternalApplyPorts)).Methods("POST")
	r.HandleFunc("/internal/runtime-config", s.checkInternal(s.handleInternalRuntimeConfigGet)).Methods("GET")
	r.HandleFunc("/internal/runtime-config", s.checkInternal(s.handleInternalRuntimeConfigSet)).Methods("POST")

	// 全服公告：前两条给游戏服务端插件（热重载 + 事件上报），
	// 后三条给 admin 进程转发写操作（配置有内存快照，必须由网关落）。
	r.HandleFunc("/internal/announce/pull", s.checkInternal(s.handleInternalAnnouncePull)).Methods("GET")
	r.HandleFunc("/internal/announce/events", s.checkInternal(s.handleInternalAnnounceEvents)).Methods("POST")
	r.HandleFunc("/internal/announce/config", s.checkInternal(s.handleInternalAnnounceConfigGet)).Methods("GET")
	r.HandleFunc("/internal/announce/config", s.checkInternal(s.handleInternalAnnounceConfigSet)).Methods("POST")
	r.HandleFunc("/internal/announce/popup", s.checkInternal(s.handleInternalAnnouncePopup)).Methods("POST")
}

// checkInternal 校验内部调用密钥。用常量时间比较，避免时序侧信道。
func (s *Server) checkInternal(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		want := s.config.Admin.InternalKey
		got := r.Header.Get("X-Internal-Key")
		if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"ok": false, "message": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleInternalOnline(w http.ResponseWriter, r *http.Request) {
	players, err := s.sessions.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	// 维护页只要一个数字，别为它序列化整份在线名单
	if r.URL.Query().Get("count_only") == "1" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "count": len(players)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "count": len(players), "players": players,
	})
}

func (s *Server) handleInternalKick(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Account  *string  `json:"account"`
		NonAdmin bool     `json:"non_admin"`
		Admins   []string `json:"admins"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}

	if body.NonAdmin {
		kicked, err := s.sessions.KickNonAdmin(body.Admins)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		session.LogKickAll(s.logger)
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "kicked": kicked})
		return
	}

	account := ""
	if body.Account != nil {
		account = strings.TrimSpace(*body.Account)
	}
	kicked, err := s.sessions.Kick(account)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	if account == "" {
		session.LogKickAll(s.logger)
	} else {
		session.LogKickAccount(account, s.logger)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "kicked": kicked})
}

func (s *Server) handleInternalPvfInfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.pvf.Info()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleInternalRefreshPvf(w http.ResponseWriter, r *http.Request) {
	if err := s.pvf.Refresh(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *Server) handleInternalActivePorts(w http.ResponseWriter, r *http.Request) {
	active, err := s.ports.Active()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	conns, err := s.ports.Connections()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "active": active, "connections": conns,
	})
}

func (s *Server) handleInternalApplyPorts(w http.ResponseWriter, r *http.Request) {
	var cfg proxy.ProxyPortConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}
	result, err := s.ports.Apply(&cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	s.logger.Info(fmt.Sprintf("[GamePort] 端口表已更新: %d 条（新开 %d，关闭 %d，失败 %d）",
		len(cfg.GamePorts), len(result.Opened), len(result.Closed), len(result.Failed)))
	writeJSON(w, http.StatusOK, result)
}

// internalRuntimeConfig 是内部 API 的运行时配置视图。
type internalRuntimeConfig struct {
	Launcher    LauncherView    `json:"launcher"`
	Maintenance MaintenanceView `json:"maintenance"`
	Online      int             `json:"online"`
}

func (s *Server) buildInternalRuntimeConfig() (internalRuntimeConfig, error) {
	var out internalRuntimeConfig

	lv, err := s.runtime.Launcher()
	if err != nil {
		return out, err
	}
	out.Launcher = lv

	mv, err := s.runtime.Maintenance()
	if err != nil {
		return out, err
	}
	out.Maintenance = mv

	online, _ := s.sessions.Count()
	out.Online = online
	return out, nil
}

func (s *Server) handleInternalRuntimeConfigGet(w http.ResponseWriter, r *http.Request) {
	out, err := s.buildInternalRuntimeConfig()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":          true,
		"launcher":    out.Launcher,
		"maintenance": out.Maintenance,
		"online":      out.Online,
	})
}

func (s *Server) handleInternalRuntimeConfigSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Launcher *struct {
			MinVersion   *string `json:"min_version"`
			DownloadURL  *string `json:"download_url"`
			UpdateNotice *string `json:"update_notice"`
		} `json:"launcher"`
		Maintenance *struct {
			Enabled       *bool    `json:"enabled"`
			Message       *string  `json:"message"`
			AdminAccounts []string `json:"admin_accounts"`
		} `json:"maintenance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}

	changed := false
	if body.Launcher != nil {
		c, err := s.runtime.SetLauncher(body.Launcher.MinVersion, body.Launcher.DownloadURL, body.Launcher.UpdateNotice)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		changed = changed || c
	}

	kicked := 0
	if body.Maintenance != nil {
		k, err := s.runtime.SetMaintenance(body.Maintenance.Enabled, body.Maintenance.Message, body.Maintenance.AdminAccounts)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		kicked = k
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "changed": changed, "kicked": kicked,
	})
}

// ==================== 游戏代理端口管理 ====================

func (s *Server) handleAdminGamePorts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	if s.portStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "端口配置未加载"})
		return
	}

	conf := s.portStore.GetConfig()
	if conf == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "端口配置未加载"})
		return
	}

	// "实际监听"与"连接数"来自代理运行时状态（双进程模式下走内部 API）
	listening := map[int]bool{}
	if active, err := s.ports.Active(); err == nil {
		for p := range active {
			listening[p] = true
		}
	}

	conns, _ := s.ports.Connections()

	entries := make([]map[string]interface{}, 0, len(conf.GamePorts))
	enabledCount := 0
	for _, e := range conf.GamePorts {
		if e.Enabled {
			enabledCount++
		}
		entries = append(entries, map[string]interface{}{
			"public_port":  e.Public,
			"backend_port": e.Backend,
			"enabled":      e.Enabled,
			"listening":    listening[e.Public],
			"connections":  conns[e.Public],
			"note":         e.Note,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":            true,
		"need_restart":  false,
		"total":         len(entries),
		"enabled_count": enabledCount,
		"entries":       entries,
		"config_file":   s.portStore.ConfigPath(),
	})
}

type gamePortEntryBody struct {
	PublicPort  int    `json:"public_port"`
	BackendPort int    `json:"backend_port"`
	Enabled     bool   `json:"enabled"`
	Note        string `json:"note"`
}

func (s *Server) handleAdminGamePortsPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.portStore == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "端口配置未加载"})
		return
	}

	var body struct {
		Entries []gamePortEntryBody `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Entries == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	// 网关自身占用端口：禁止被复用为游戏代理端口
	reserved := map[int]bool{}
	for _, p := range []int{
		s.config.Gateway.TcpPort,
		s.config.Gateway.HttpPort,
		s.config.Gateway.ProxyPort,
		s.config.Gateway.AdminHttpPort,
	} {
		if p > 0 {
			reserved[p] = true
		}
	}

	seen := map[int]bool{}
	newConfig := &proxy.ProxyPortConfig{
		BackendHost: s.config.GameServer.BackendHost,
		BackendPort: s.config.GameServer.BackendChannelPort,
	}

	for _, e := range body.Entries {
		if e.PublicPort <= 0 || e.PublicPort > 65535 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": fmt.Sprintf("非法公网端口: %d", e.PublicPort)})
			return
		}
		if e.BackendPort <= 0 || e.BackendPort > 65535 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": fmt.Sprintf("非法后端端口: %d", e.BackendPort)})
			return
		}
		if reserved[e.PublicPort] {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": fmt.Sprintf("端口 %d 已被网关自身占用，不能作为游戏代理端口", e.PublicPort)})
			return
		}
		if seen[e.PublicPort] {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": fmt.Sprintf("公网端口重复: %d", e.PublicPort)})
			return
		}
		seen[e.PublicPort] = true
		newConfig.GamePorts = append(newConfig.GamePorts, proxy.GamePortMapping{
			Public:  e.PublicPort,
			Backend: e.BackendPort,
			Enabled: e.Enabled,
			Note:    strings.TrimSpace(e.Note),
		})
	}

	// 保存即生效：Apply 内部同步回调 ReloadPorts 完成监听的开/关，
	// 并回传实际生效内容（新开的、关闭的、启动失败的端口）。
	// 双进程模式下 admin 进程把这一步整体转给网关执行（见 pkg/backends/remote.go）。
	apply, err := s.ports.Apply(newConfig)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	enabledCount := 0
	for _, e := range newConfig.GamePorts {
		if e.Enabled {
			enabledCount++
		}
	}

	s.logger.Info(fmt.Sprintf("[GamePort] 端口表已更新: %d 条（新开 %d，关闭 %d，失败 %d）",
		len(newConfig.GamePorts), len(apply.Opened), len(apply.Closed), len(apply.Failed)))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":            true,
		"changed":       true,
		"need_restart":  false,
		"total":         len(newConfig.GamePorts),
		"enabled_count": enabledCount,
		"apply":         apply,
		"message":       "已保存并立即生效",
	})
}

// ==================== 处理函数 ====================

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleLauncherVersion(w http.ResponseWriter, r *http.Request) {
	minVer := strings.TrimSpace(s.config.Launcher.MinVersion)
	if minVer == "" {
		minVer = "1.0.0"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":      minVer,
		"download_url": s.config.Launcher.DownloadUrl,
	})
}

func (s *Server) handleLauncherPolicy(w http.ResponseWriter, r *http.Request) {
	rev := r.URL.Query().Get("rev")
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"

	pvfInfo := s.pvfSvc.GetPvfInfo()
	snap := s.integritySvc.Snapshot()

	whiteDigest := listDigest(snap.WhiteList)
	blackDigest := listDigest(snap.BlackList)
	allowedDigest := namesDigest(snap.AllowedModules)
	fingerprint := composeFingerprint(snap.Revision, pvfInfo, whiteDigest, blackDigest, allowedDigest)

	changed := force || rev != fingerprint

	var pvfUtc interface{} = pvfInfo.ModifiedUtc
	if pvfInfo.ModifiedUtc == "" {
		pvfUtc = nil
	}
	resp := map[string]interface{}{
		"ok":             true,
		"changed":        changed,
		"fingerprint":    fingerprint,
		"revision":       snap.Revision,
		"pvf":            map[string]interface{}{"hash": pvfInfo.Hash, "algo": pvfInfo.Algo, "size": pvfInfo.Size, "modified_utc": pvfUtc},
		"white_digest":   whiteDigest,
		"black_digest":   blackDigest,
		"allowed_digest": allowedDigest,
		"white_count":    len(snap.WhiteList),
		"black_count":    len(snap.BlackList),
		"allowed_count":  len(snap.AllowedModules),
	}
	if changed {
		resp["white"] = snap.WhiteList
		resp["black"] = snap.BlackList
		resp["allowed"] = snap.AllowedModules
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token   *string `json:"token"`
		Account *string `json:"account"`
	}
	// 公开端点：除全局 8 MiB 上限外再收紧到 1 MiB。
	// 限流（120/分/IP）挡的是"次数"，挡不住单次巨量 body —— 不设上限时
	// 任何一个登录用户都能用一次 POST 让网关把任意大的 body 缓冲进内存。
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "Invalid request"})
		return
	}

	if req.Token == nil || *req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "Invalid request"})
		return
	}

	sess, ok := s.sessionMgr.ValidateToken(*req.Token)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"ok": false})
		return
	}

	// 封禁检查
	banned, _ := s.db.IsBanned(sess.Account)
	if banned {
		s.sessionMgr.RemoveSession(*req.Token)
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"ok": false, "banned": true, "message": "账号已被封禁"})
		return
	}

	s.sessionMgr.UpdateHeartbeat(*req.Token)
	s.db.UpdateAccountHeartbeat(sess.Account)

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *Server) handleAdminOnline(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	// 会话表在网关进程内存里；双进程模式下由 remote 后端经内部 API 取
	online, err := s.sessions.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"count":   0,
			"players": []interface{}{},
			"error":   err.Error(),
		})
		return
	}

	// 刻意保留原来的 camelCase 键名，前端按这些键取值
	players := make([]map[string]interface{}, 0, len(online))
	for _, p := range online {
		players = append(players, map[string]interface{}{
			"account":       p.Account,
			"ip":            p.IP,
			"onlineMinutes": p.OnlineMinutes,
			"lastHeartbeat": p.LastHeartbeat,
			"bonusGranted":  p.BonusGranted,
			"cera":          p.Cera,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":   len(players),
		"players": players,
	})
}

func (s *Server) handleAdminKick(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Account *string `json:"account"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Account == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	account := strings.TrimSpace(*body.Account)
	kicked, err := s.sessions.Kick(account)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "kicked": 0, "error": err.Error(),
		})
		return
	}
	if account == "" {
		session.LogKickAll(s.logger)
	} else {
		session.LogKickAccount(account, s.logger)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "kicked": kicked})
}

func (s *Server) handleAdminBroadcast(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req models.BroadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "message": "Invalid request"})
		return
	}

	result := s.adminSvc.BroadcastItems(&req)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAdminRefreshPvf(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	if err := s.pvf.Refresh(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *Server) handlePvfInfo(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	// PVF 缓存属于网关进程内存（登录器策略要用它），双进程模式下经内部 API 取
	info, err := s.pvf.Info()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"mode":         info.Mode,
		"path":         info.Path,
		"hash":         info.Hash,
		"algo":         info.Algo,
		"size":         info.Size,
		"modified_utc": info.ModifiedUtc,
	})
}

// notifyPvfChanged 在 PVF 内容/指纹发生变化后，让网关重算缓存。
//
// 为什么需要它：上传/注册/注销 PVF 是对**磁盘文件**的操作，两个进程都能做；
// 但 `/api/launcher/policy` 用的指纹来自**网关进程内存里的缓存**。
// 双进程模式下若不通知，会出现「后台显示 PVF 已更换，登录器仍拿到旧哈希、不下发更新」——
// 属于静默失效，排查成本高。网关进程内它退化为一次幂等的 RefreshCache。
func (s *Server) notifyPvfChanged() {
	if err := s.pvf.Refresh(); err != nil && s.logger != nil {
		s.logger.Warn(fmt.Sprintf("[PVF] 变更后刷新缓存失败: %v", err))
	}
}

func (s *Server) handleAdminUploadPvf(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	if err := r.ParseMultipartForm(2 << 30); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "no pvf file"})
		return
	}
	defer file.Close()

	info, err := s.pvfSvc.ReplacePvf(file)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	s.integritySvc.Bump()
	s.notifyPvfChanged()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "mode": "file", "hash": info.Hash, "algo": info.Algo,
		"size": info.Size, "modified_utc": info.ModifiedUtc,
	})
}

func (s *Server) handlePvfRegister(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req struct {
		File *string `json:"file"`
		Hash *string `json:"hash"`
		Algo *string `json:"algo"`
		Size *int64  `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}

	info, err := s.pvfSvc.RegisterStamp(req.File, req.Hash, req.Algo, req.Size)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	s.integritySvc.Bump()
	s.notifyPvfChanged()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "mode": "registered", "path": info.Path, "hash": info.Hash,
		"algo": info.Algo, "size": info.Size,
	})
}

func (s *Server) handlePvfUnregister(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	wasRegistered := s.pvfSvc.GetSourceMode() == "registered"
	s.pvfSvc.Unregister()
	if wasRegistered {
		s.integritySvc.Bump()
	}
	s.notifyPvfChanged()

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (s *Server) handleAdminIntegrity(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	snap := s.integritySvc.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"revision":   snap.Revision,
		"updated_at": snap.UpdatedAt,
		"white":      snap.WhiteList,
		"black":      snap.BlackList,
		"allowed":    snap.AllowedModules,
	})
}

func (s *Server) handleAdminIntegrityUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	kind := r.URL.Query().Get("kind")
	if kind != "white" && kind != "black" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "kind must be white or black"})
		return
	}

	if err := r.ParseMultipartForm(2 << 30); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	form := r.MultipartForm
	entries := make([]models.FingerprintEntry, 0)
	errs := make([]string, 0)

	for _, files := range form.File {
		for _, f := range files {
			file, err := f.Open()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", f.Filename, err))
				continue
			}
			defer file.Close()

			hash, algo := security.ComputeFileFingerprint(file)
			entries = append(entries, models.FingerprintEntry{
				FileName: f.Filename, Hash: hash, Algorithm: algo, Size: f.Size,
				Display: fmt.Sprintf("%s [%s]", f.Filename, utils.ShortHash(hash)),
			})
		}
	}

	added := 0
	if len(entries) > 0 {
		added = s.integritySvc.AddEntries(kind == "white", entries)
	}
	snap := s.integritySvc.Snapshot()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "kind": kind, "added": added, "total_files": len(entries),
		"errors": errs, "revision": snap.Revision,
	})
}

func (s *Server) handleAdminIntegrityAdd(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req struct {
		Kind    *string                   `json:"kind"`
		Entries []models.FingerprintEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}

	if req.Kind == nil || (*req.Kind != "white" && *req.Kind != "black") {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "kind must be white or black"})
		return
	}

	added := s.integritySvc.AddEntries(*req.Kind == "white", req.Entries)
	snap := s.integritySvc.Snapshot()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "kind": *req.Kind, "added": added, "total": len(req.Entries), "revision": snap.Revision,
	})
}

func (s *Server) handleAdminIntegrityRemove(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req struct {
		Kind *string `json:"kind"`
		File *string `json:"file"`
		Hash *string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}

	if req.Kind == nil || req.File == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "kind/file required"})
		return
	}

	removed := false
	switch *req.Kind {
	case "allow":
		removed = s.integritySvc.RemoveAllowedModule(*req.File)
	case "white", "black":
		if req.Hash == nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "hash required"})
			return
		}
		removed = s.integritySvc.RemoveEntry(*req.Kind == "white", *req.File, *req.Hash)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "invalid kind"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": removed, "kind": *req.Kind})
}

func (s *Server) handleAdminIntegrityAllow(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req struct {
		Names []string `json:"names"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}

	if len(req.Names) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "names required"})
		return
	}

	added, rejected := s.integritySvc.AddAllowedModules(req.Names)
	snap := s.integritySvc.Snapshot()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "added": added, "rejected": rejected,
		"revision": snap.Revision, "allowed_count": len(snap.AllowedModules),
	})
}

func (s *Server) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	keyword := r.URL.Query().Get("keyword")
	page := parseIntParam(r.URL.Query().Get("page"), 1)
	pageSize := parseIntParam(r.URL.Query().Get("page_size"), 50)

	total, accounts := s.accountSvc.ListAccounts(keyword, page, pageSize)

	// 在线标记：会话表在网关进程内存里，双进程模式下由 remote 后端经内部 API 取。
	// 取不到就整列按"离线"处理 —— 状态列少一个在线标签，总好过整个列表 500。
	online := make(map[string]struct{})
	if players, err := s.sessions.List(); err == nil {
		for _, p := range players {
			online[p.Account] = struct{}{}
		}
	}
	for _, a := range accounts {
		if name, ok := a["name"].(string); ok {
			_, a["online"] = online[name]
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total": total, "gateway_total": total, "game_total": total,
		"page": page, "page_size": pageSize, "accounts": accounts,
	})
}

func (s *Server) handleAdminSyncAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	result, err := s.db.SyncGameAccounts()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	if result == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "message": "游戏库未配置"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "message": result.Message,
		"game_accounts": result.GameAccounts, "imported": result.Imported,
		"skipped": result.Skipped, "failed": result.Failed,
	})
}

func (s *Server) handleAdminRoles(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	account := r.URL.Query().Get("account")
	roles, err := s.db.GetRolesByAccount(account)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "roles": roles,
	})
}

func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Account        *string `json:"account"`
		NewPasswordMd5 *string `json:"newPasswordMd5"`
		NewPassword    *string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	if body.Account == nil || strings.TrimSpace(*body.Account) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	// 明文与 MD5 二选一：管理页直接输入两次明文密码（前端确认一致性），
	// 服务端计算 MD5；保留 newPasswordMd5 兼容脚本/旧调用。
	if body.NewPasswordMd5 == nil && body.NewPassword != nil {
		pwd := *body.NewPassword
		if n := len(pwd); n < 6 || n > 32 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "密码长度需为 6-32 位"})
			return
		}
		md5 := security.HashMD5(pwd)
		body.NewPasswordMd5 = &md5
	}

	md5 := body.NewPasswordMd5
	if md5 == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "缺少 newPassword 或 newPasswordMd5"})
		return
	}

	code := s.adminSvc.ResetPassword(*body.Account, *md5)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": code == models.Err.Ok, "error_code": code,
		"message": mapErrorToMessage(code),
	})
}

// handleAdminResetDevice 解除账号设备绑定。
//
// 修复点：
//  1. 原实现忽略 s.db.ClearDeviceSecret 的返回值，失败也回 200，前端无法感知；
//  2. 原实现不校验账号是否存在，凭空返回“设备绑定已解除”；
//  3. 解绑后未踢下线，旧会话仍可继续使用，新设备反而要等冷却期。
//
// 现改为：校验账号 → 真实解绑 → 踢掉该账号在线会话 → 按结果返回。
func (s *Server) handleAdminResetDevice(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Account *string `json:"account"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Account == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	account := strings.TrimSpace(*body.Account)
	if account == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	code := s.adminSvc.ResetDeviceBinding(account)
	if code != models.Err.Ok {
		status := http.StatusInternalServerError
		if code == models.Err.AccountNotFound {
			status = http.StatusNotFound
		} else if code == models.Err.AccountEmpty {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]interface{}{
			"ok":      false,
			"code":    code,
			"message": mapErrorToMessage(code),
		})
		return
	}

	kicked, _ := s.sessions.Kick(account)
	session.LogKickAccount(account, s.logger)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"kicked":  kicked,
		"message": "设备绑定已解除，该账号在线会话已断开，新设备可直接登录",
	})
}

func (s *Server) handleAdminUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Account *string `json:"account"`
		All     bool    `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	if body.All {
		unlocked, _ := s.db.UnlockAllAccounts()
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "unlocked": unlocked, "was_locked": unlocked > 0})
		return
	}

	if body.Account == nil || strings.TrimSpace(*body.Account) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	unlocked, _ := s.db.UnlockAccount(*body.Account)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "unlocked": unlocked, "was_locked": unlocked})
}

func (s *Server) handleAdminResetAllPasswords(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		NewPassword    *string `json:"newPassword"`
		NewPasswordMd5 *string `json:"newPasswordMd5"`
		DryRun         bool    `json:"dryRun"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	// 明文优先：管理页让管理员输两次明文（前端先比一致性），MD5 在服务端算。
	// 保留 newPasswordMd5 只是为了不打断已有的脚本调用。
	if body.NewPassword != nil {
		pwd := *body.NewPassword
		if n := len(pwd); n < 6 || n > 32 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "密码长度需为 6-32 位"})
			return
		}
		computed := security.HashMD5(pwd)
		body.NewPasswordMd5 = &computed
	}
	if body.NewPasswordMd5 == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "缺少 newPassword 或 newPasswordMd5"})
		return
	}

	md5 := strings.TrimSpace(*body.NewPasswordMd5)
	if len(md5) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "newPasswordMd5 必须是 32 位 MD5"})
		return
	}

	names, _ := s.db.ListAllAccountNames()

	// dry-run：只统计将要影响的账号数量，不做任何写操作
	if body.DryRun {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true, "message": "预演完成（未执行任何修改）", "dry_run": true,
			"total": len(names), "updated": 0, "failed": 0,
		})
		return
	}

	updated := 0
	failed := 0
	for _, name := range names {
		if s.adminSvc.ResetPassword(name, md5) == models.Err.Ok {
			updated++
		} else {
			failed++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "message": "批量重置完成", "dry_run": false,
		"total": len(names), "updated": updated, "failed": failed,
	})
}

// maxBatchDeleteAccounts 单次批量删除的账号数上限。
//
// 删除会写两个库，一次删太多既不好审也无法一眼核对；超限直接拒绝，
// 让调用方分批，避免"一把删掉半个服"这种不可复核的操作。
const maxBatchDeleteAccounts = 200

// deleteAccountRequest 单删/批删的请求体（两者的单账号语义完全一致）。
type deleteAccountRequest struct {
	Account   *string  `json:"account"`
	Accounts  []string `json:"accounts"`
	PurgeLogs bool     `json:"purgeLogs"`
	DryRun    bool     `json:"dryRun"`
}

// handleAdminDeleteAccount 删除单个账号（支持 dryRun 预演）。
//
// 语义见 database.DeleteAccount：账号还有角色时**拒绝删除**（409），
// 因为游戏库 characters 对 accounts 是 ON DELETE CASCADE，删账号会连带删角色。
// 具体流程复用 deleteOneAccount，与批量删除走同一套逻辑。
func (s *Server) handleAdminDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body deleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Account == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	account := strings.TrimSpace(*body.Account)
	if account == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	item := s.deleteOneAccount(account, body.PurgeLogs, body.DryRun)

	// dryRun 是"查询"而不是"操作"：账号不存在 / 名为空照常报错（404 / 400），
	// 但"名下有角色、执行时会被跳过"不算错误 —— 返回 200 + 预演明细，
	// 由调用方读 preview.game_roles 自行决定（批量 dryRun 也是这个口径）。
	if body.DryRun {
		if item.Code != "" && item.Code != "has_characters" {
			writeJSON(w, deleteCodeToStatus(item.Code), map[string]interface{}{
				"ok": false, "code": item.Code, "message": item.Message,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true, "dry_run": true, "would_skip": item.Code == "has_characters",
			"preview": item.Preview, "message": item.Message,
		})
		return
	}

	if item.Code != "" {
		writeJSON(w, deleteCodeToStatus(item.Code), map[string]interface{}{
			"ok": false, "code": item.Code, "message": item.Message,
			"preview": item.Preview, "kicked": item.Kicked,
		})
		return
	}

	if result := item.Preview; result != nil && s.logger != nil {
		s.logger.Info(fmt.Sprintf("已删除账号: 账号=%s, m_id=%s, 游戏库账号=%v, 清理流水=%v",
			result.Account, result.MId, result.DeletedGame, result.PurgedLogs))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "kicked": item.Kicked, "preview": item.Preview, "message": item.Message,
	})
}

// handleAdminDeleteAccounts 批量删除账号。
//
// 逐条执行、逐条回报，不做"全成功才提交"——批量清理测试账号时，
// 个别账号有角色或已不存在是常态，整体失败反而更糟。
// batchDeleteItem 批量删除结果里的单条记录。
type batchDeleteItem struct {
	Account string                         `json:"account"`
	Ok      bool                           `json:"ok"`
	Kicked  int                            `json:"kicked"`
	Code    string                         `json:"code,omitempty"`
	Message string                         `json:"message"`
	Preview *database.AccountDeletePreview `json:"preview,omitempty"`
}

// deleteOneAccount 对单个账号执行「预演 → 有角色则拒绝 → 踢下线 → 删除」。
//
// dryRun=true 时只预演：不写库、不踢人。返回值里 Ok 表示"该账号可以被删掉
// （dryRun）或已经删掉（真删）"，Code 为空表示没有异常。
func (s *Server) deleteOneAccount(account string, purgeLogs, dryRun bool) batchDeleteItem {
	item := batchDeleteItem{Account: account}

	preview, err := s.db.PreviewAccountDelete(account)
	if err != nil {
		_, resp := deleteAccountErrorResponse(err)
		item.Code = errCodeOf(err)
		item.Message = fmt.Sprint(resp["message"])
		return item
	}
	item.Preview = preview

	if preview.GameRoles > 0 {
		item.Code = "has_characters"
		if dryRun {
			item.Message = fmt.Sprintf("名下仍有 %d 个角色，执行时会被跳过（请先在游戏内删除角色）", preview.GameRoles)
		} else {
			item.Message = fmt.Sprintf("名下仍有 %d 个角色，已跳过（请先在游戏内删除角色）", preview.GameRoles)
		}
		return item
	}

	if dryRun {
		item.Ok = true
		item.Message = deletePreviewMessage(preview)
		return item
	}

	// 确认能删了再踢下线：账号没角色也可能停在选人界面（会话已存在）。
	kicked, _ := s.sessions.Kick(account)
	session.LogKickAccount(account, s.logger)
	item.Kicked = kicked

	result, err := s.db.DeleteAccount(account, purgeLogs)
	if err != nil {
		_, resp := deleteAccountErrorResponse(err)
		item.Code = errCodeOf(err)
		item.Message = fmt.Sprint(resp["message"])
		return item
	}

	item.Ok = true
	item.Preview = result
	item.Message = fmt.Sprintf("已删除（设备历史 %d 条%s）", result.DeviceHistory, deleteLogsSuffix(result))
	return item
}

// handleAdminDeleteAccounts 批量删除账号。
//
// 逐条执行、逐条回报，不做"全成功才提交"——批量清理测试账号时，
// 个别账号有角色或已不存在是常态，整体失败反而更糟。
func (s *Server) handleAdminDeleteAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body deleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Accounts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}
	if len(body.Accounts) > maxBatchDeleteAccounts {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": fmt.Sprintf("单次最多删除 %d 个账号，当前 %d 个，请分批", maxBatchDeleteAccounts, len(body.Accounts)),
		})
		return
	}

	results := make([]batchDeleteItem, 0, len(body.Accounts))
	deleted, skipped, failed := 0, 0, 0

	for _, raw := range body.Accounts {
		account := strings.TrimSpace(raw)
		if account == "" {
			continue
		}

		item := s.deleteOneAccount(account, body.PurgeLogs, body.DryRun)
		switch {
		case item.Ok:
			deleted++
		case item.Code == "has_characters":
			skipped++
		default:
			failed++
		}
		results = append(results, item)
	}

	if s.logger != nil {
		s.logger.Info(fmt.Sprintf("批量删除账号: 共 %d 条，成功 %d，跳过 %d，失败 %d（dry_run=%v）",
			len(results), deleted, skipped, failed, body.DryRun))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": failed == 0, "dry_run": body.DryRun,
		"total": len(results), "deleted": deleted, "skipped": skipped, "failed": failed,
		"results": results,
	})
}

// deleteCodeToStatus 把 deleteOneAccount 的错误码映射到 HTTP 状态码。
func deleteCodeToStatus(code string) int {
	switch code {
	case "empty":
		return http.StatusBadRequest
	case "not_found":
		return http.StatusNotFound
	case "has_characters":
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// deleteAccountErrorResponse 把 database 层的哨兵错误映射到 HTTP 状态码与响应体。
func deleteAccountErrorResponse(err error) (int, map[string]interface{}) {
	switch {
	case errors.Is(err, database.ErrAccountDeleteEmpty):
		return http.StatusBadRequest, map[string]interface{}{
			"ok": false, "code": "empty", "message": "账号名不能为空"}
	case errors.Is(err, database.ErrAccountDeleteNotFound):
		return http.StatusNotFound, map[string]interface{}{
			"ok": false, "code": "not_found", "message": "账号不存在"}
	case errors.Is(err, database.ErrAccountHasCharacters):
		return http.StatusConflict, map[string]interface{}{
			"ok": false, "code": "has_characters", "message": err.Error()}
	default:
		return http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "code": "error", "message": err.Error()}
	}
}

// errCodeOf 提取错误码字符串（仅用于批量结果的逐条回报）。
func errCodeOf(err error) string {
	status, resp := deleteAccountErrorResponse(err)
	if code, ok := resp["code"].(string); ok && code != "" {
		return code
	}
	return fmt.Sprintf("http_%d", status)
}

// deleteLogsSuffix 拼出"是否清理流水"的提示后缀。
func deleteLogsSuffix(p *database.AccountDeletePreview) string {
	if p.PurgedLogs {
		return "，审计流水已一并清理"
	}
	if p.BonusLogs > 0 || p.AntiCheatRows > 0 {
		return fmt.Sprintf("；保留审计流水 %d 条奖励 / %d 条反作弊（如需清理请勾选清理流水）",
			p.BonusLogs, p.AntiCheatRows)
	}
	return ""
}

// deletePreviewMessage 生成预演文案。
func deletePreviewMessage(p *database.AccountDeletePreview) string {
	if p.GameRoles > 0 {
		return fmt.Sprintf("账号 %s 名下仍有 %d 个角色，删除会被拒绝；请先在游戏内删除角色。",
			p.Account, p.GameRoles)
	}
	game := "游戏库无此账号"
	if p.GameAccount {
		game = "会一并删除游戏库账号行"
	}
	if !p.GameConfigured {
		game = "游戏库未配置"
	}
	return fmt.Sprintf("将删除账号 %s（m_id=%s，点券 %d）：设备历史 %d 条、封禁记录 %v；%s%s",
		p.Account, p.MId, p.Cera, p.DeviceHistory, p.Banned, game,
		// 复用前缀拼装，保证与执行后的文案一致
		func() string {
			if p.BonusLogs > 0 || p.AntiCheatRows > 0 {
				return fmt.Sprintf("；审计流水 %d 条奖励 / %d 条反作弊将保留", p.BonusLogs, p.AntiCheatRows)
			}
			return ""
		}())
}

// maxSendItemsTargets 单次发放的角色数上限。
//
// 管理页「查看角色」是勾选发放，正常也就几个到几十个。设上限是为了拦住
// 手滑的全选请求 —— 邮件进了游戏库就是不可逆的（玩家会真的收到东西）。
const maxSendItemsTargets = 200

func (s *Server) handleAdminSendItems(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		CharacterId  int64                    `json:"characterId"`
		CharacterIds []int64                  `json:"characterIds"`
		Items        []models.MailItemRequest `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}
	if len(body.Items) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整：缺少 items"})
		return
	}

	// 单角色（characterId，老调用点）与多角色（characterIds，勾选发放）二选一。
	targets := make([]int64, 0, len(body.CharacterIds)+1)
	seen := make(map[int64]struct{}, len(body.CharacterIds))
	for _, id := range body.CharacterIds {
		if id <= 0 {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		targets = append(targets, id)
	}
	if len(targets) == 0 && body.CharacterId > 0 {
		targets = append(targets, body.CharacterId)
	}
	if len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "参数不完整：缺少 characterId 或 characterIds",
		})
		return
	}
	if len(targets) > maxSendItemsTargets {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": fmt.Sprintf("单次最多发放 %d 个角色（本次 %d 个），请分批", maxSendItemsTargets, len(targets)),
		})
		return
	}

	items := make([]database.MailItem, len(body.Items))
	for i, item := range body.Items {
		items[i] = database.MailItem{
			ItemTemplateId: item.ItemTemplateId,
			Count:          item.Count,
			Kind:           deref(item.Kind, 3),
			ItemType:       deref(item.ItemType, 0),
		}
	}

	// 逐个投递：一个角色失败不停下 —— 否则勾了 20 个、第 3 个失败就全停，
	// 管理员根本不知道到底发出去几个。失败明细原样带回前端。
	sent := 0
	failed := make([]map[string]interface{}, 0)
	for _, cid := range targets {
		if err := s.db.SendMail(cid, items); err != nil {
			failed = append(failed, map[string]interface{}{"character_id": cid, "error": err.Error()})
			continue
		}
		sent++
	}

	if sent == 0 {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "sent": 0, "total": len(targets), "failed": failed,
			"message": "全部角色投递失败",
		})
		return
	}

	msg := fmt.Sprintf("已向 %d 个角色投递邮件", sent)
	if len(failed) > 0 {
		msg += fmt.Sprintf("，%d 个失败", len(failed))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "sent": sent, "total": len(targets), "failed": failed, "message": msg,
	})
}

func (s *Server) handleAdminBans(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	keyword := r.URL.Query().Get("keyword")
	page := parseIntParam(r.URL.Query().Get("page"), 1)
	pageSize := parseIntParam(r.URL.Query().Get("page_size"), 20)

	total, entries, err := s.db.QueryBans(keyword, page, pageSize)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	rows := make([]map[string]interface{}, len(entries))
	for i, e := range entries {
		rows[i] = map[string]interface{}{"name": e.Name, "reason": e.Reason, "banned_at": e.BannedAt}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "total": total, "page": page, "page_size": pageSize, "rows": rows,
	})
}

func (s *Server) handleAdminBan(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Account *string `json:"account"`
		Reason  *string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Account == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	account := strings.TrimSpace(*body.Account)
	if account == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	if err := s.db.BanAccount(account, deref(body.Reason, "")); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	kicked, _ := s.sessions.Kick(account)
	session.LogKickAccount(account, s.logger)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "kicked": kicked})
}

func (s *Server) handleAdminUnban(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Account *string `json:"account"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Account == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	removed, _ := s.db.UnbanAccount(strings.TrimSpace(*body.Account))
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "removed": removed})
}

// handleAdminQQUnbind 解除账号与其 QQ 号的绑定（2026-09-24）。
//
// 与「解绑设备」是两件事：那个清 accounts.device_secret，这个删 qq_bindings 的一行。
//
// 后台必须保留这个入口：玩家 QQ 号被盗、换号、或那个 QQ 邮箱收不到信时，
// 只有玩家自己解不了 —— 没有这个按钮，他会永远卡在"登不进自己绑过 QQ 的账号"上。
func (s *Server) handleAdminQQUnbind(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Account *string `json:"account"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Account == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}
	account := strings.TrimSpace(*body.Account)
	if account == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}
	if s.qqBindSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]interface{}{"ok": false, "message": "QQ 绑定服务当前不可用"})
		return
	}

	code, msg := s.qqBindSvc.Unbind(account)
	switch code {
	case models.Err.Ok:
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "message": msg})
	case models.Err.QQNotBound:
		// 400 而不是 200：前端要能一眼区分"解绑成功"和"本来就没绑"。
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": msg})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "message": msg})
	}
}

func (s *Server) handleAdminRegisterBonusConfigGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	cfg := s.registerBonusSvc.GetConfig()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "configured": cfg != nil,
		"path":   s.registerBonusSvc.ConfigPath(),
		"config": cfg,
	})
}

func (s *Server) handleAdminRegisterBonusConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var cfg models.RegisterBonusConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "配置格式错误"})
		return
	}

	ok, message := s.registerBonusSvc.SaveConfig(&cfg)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": ok, "message": message})
}

// handleAdminBonusConfigGet 读泡点计费设置（Data/bonus.json）。
func (s *Server) handleAdminBonusConfigGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.bonusSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"ok": false, "message": "泡点服务未启用"})
		return
	}

	cfg, err := s.bonusSvc.GetConfig()
	if err != nil {
		// 文件缺失或 JSON 损坏都如实上报。这里**不能**回退成一份默认配置：
		// 后台会把"看起来正常"的默认值保存回去，反而把线上真正在跑的值覆盖掉。
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok": false, "error": err.Error(), "path": s.bonusSvc.ConfigPath(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "path": s.bonusSvc.ConfigPath(), "config": cfg,
	})
}

// handleAdminBonusConfigPost 保存泡点计费设置。
//
// 保存后**不需要重启网关**：泡点主循环每轮都重新读盘，最迟下一个计费周期生效。
func (s *Server) handleAdminBonusConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.bonusSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"ok": false, "message": "泡点服务未启用"})
		return
	}

	var cfg service.BonusConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "配置格式错误"})
		return
	}

	if err := s.bonusSvc.SaveConfig(&cfg); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "message": "已保存，最迟下一个计费周期生效（无需重启网关）",
	})
}

func (s *Server) handleAdminRegisterBonusLogs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	account := r.URL.Query().Get("account")
	rewardType := r.URL.Query().Get("reward_type")
	status := r.URL.Query().Get("status")
	page := parseIntParam(r.URL.Query().Get("page"), 1)
	pageSize := parseIntParam(r.URL.Query().Get("page_size"), 20)

	total, entries := s.registerBonusSvc.QueryLogs(account, rewardType, status, page, pageSize)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "total": total, "page": page, "page_size": pageSize, "rows": entries,
	})
}

func (s *Server) handleAdminServerStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	status := s.serverMgr.GetStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "control_enabled": s.config.Server.ControlEnabled, "status": status,
	})
}

func (s *Server) handleAdminServerControl(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Action *string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Action == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	result := s.serverMgr.Control(*body.Action)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": result.Ok, "error": result.Error, "result": result})
}

func (s *Server) handleAdminServerLogs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	key := r.URL.Query().Get("key")
	lines := parseIntParam(r.URL.Query().Get("lines"), 300)
	result := s.serverMgr.TailLog(key, lines)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": result.Error == "", "error": result.Error, "result": result})
}

func (s *Server) handleAdminServerPvf(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	if err := r.ParseMultipartForm(2 << 30); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "no pvf file"})
		return
	}
	defer file.Close()

	result := s.serverMgr.ReplacePvf(file)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": result.Ok, "error": result.Error, "result": result})
}

func (s *Server) handleAdminServerBackup(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	result := s.serverMgr.Backup()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": result.Ok, "error": result.Error, "result": result})
}

func (s *Server) handleAdminServerBackups(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	backups, err := database.ListBackups(s.config.Server.BackupDir)
	if backups == nil {
		backups = []database.BackupFile{}
	}
	// 目录不存在/无权限时不要把错误吞掉：返回空列表 + error 字段，
	// 前端至少能看到「为什么没有备份」，而不是一个空表格。
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": errMsg == "", "error": errMsg,
		"directory": s.config.Server.BackupDir,
		"count":     len(backups), "items": backups,
	})
}

func (s *Server) handleAdminGatewayStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	status := s.gatewayMgr.GetStatus()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "control_enabled": s.gatewayMgr.IsControlEnabled(),
		"gateway_log": s.gatewayMgr.GetGatewayLogPath(),
		"error_log":   s.gatewayMgr.GetErrorLogPath(),
		"status":      status,
	})
}

func (s *Server) handleAdminGatewayControl(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Action *string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Action == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数不完整"})
		return
	}

	result := s.gatewayMgr.Control(*body.Action)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": result.Ok, "error": result.Error, "result": result})
}

func (s *Server) handleAdminGatewayLogs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	key := r.URL.Query().Get("key")
	lines := parseIntParam(r.URL.Query().Get("lines"), 300)
	result := s.gatewayMgr.TailLog(key, lines)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": result.Error == "", "error": result.Error, "result": result})
}

func (s *Server) handleAdminLauncherConfigGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	// 版本门禁的权威值在网关进程：/api/launcher/policy 读的是**它的**内存
	lv, err := s.runtime.Launcher()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "min_version": lv.MinVersion,
		"download_url":  lv.DownloadURL,
		"update_notice": lv.UpdateNotice,
		"override_file": config.OverrideFileName,
	})
}

func (s *Server) handleAdminLauncherConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		MinVersion   *string `json:"min_version"`
		DownloadUrl  *string `json:"download_url"`
		UpdateNotice *string `json:"update_notice"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数错误"})
		return
	}

	// 交给运行时配置后端：它负责"改内存 + 落盘 override"，且必须作用在
	// **网关进程**的内存上（版本门禁由网关执行），否则后台改了不生效。
	changed, err := s.runtime.SetLauncher(body.MinVersion, body.DownloadUrl, body.UpdateNotice)
	if err != nil {
		s.logger.Error(fmt.Sprintf("[Admin] Launcher 配置更新失败: %v", err))
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "配置写入失败",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "changed": changed})
}

func (s *Server) handleAdminMaintenanceGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	// 维护模式的权威状态在网关进程（它才是拒绝登录的那一方）
	mv, err := s.runtime.Maintenance()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	admins := mv.AdminAccounts
	if admins == nil {
		admins = []string{}
	}
	online, _ := s.sessions.Count()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "enabled": mv.Enabled,
		"message":        mv.Message,
		"admin_accounts": admins,
		"online":         online,
	})
}

func (s *Server) handleAdminMaintenancePost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Enabled       *bool    `json:"enabled"`
		Message       *string  `json:"message"`
		AdminAccounts []string `json:"admin_accounts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数错误"})
		return
	}

	// 交给运行时配置后端：网关进程内直接改 cfg 并踢人；
	// admin 进程则转发给网关 —— 这是必须的，配置只在网关内存里，
	// 让 admin 改自己的副本会出现「后台显示已开维护模式，玩家照常登录」。
	// 开启维护模式时由后端负责踢掉非管理员会话。
	kicked, err := s.runtime.SetMaintenance(body.Enabled, body.Message, body.AdminAccounts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "维护模式设置失败", "error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "changed": true, "kicked": kicked,
	})
}

// ==================== 辅助函数 ====================

func (s *Server) checkAdmin(w http.ResponseWriter, r *http.Request) bool {
	key := r.Header.Get("X-Auth-Key")
	if key == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			key = auth[7:]
		}
	}

	if key == "" || !security.ConstantTimeEquals(key, s.config.Admin.AuthKey) {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"ok": false, "message": "unauthorized"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func getClientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	return host
}

// getLocalPort 返回本次请求实际到达的本地监听端口。
//
// 必须使用 http.LocalAddrContextKey（TCP 层真实本地地址），
// 不能用 r.Host —— Host 头由客户端完全控制，可被伪造成任意端口，
// 从而使 portSplitMiddleware 的 admin / launcher 端口隔离失效。
func getLocalPort(r *http.Request) int {
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && addr != nil {
		if _, portStr, err := net.SplitHostPort(addr.String()); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil {
				return p
			}
		}
	}
	// 无法确定真实本地端口时返回 0，调用方按"非 admin 端口"处理（走更严格的策略）
	return 0
}

func parseIntParam(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return defaultVal
		}
		n = n*10 + int(ch-'0')
	}
	if n <= 0 {
		return defaultVal
	}
	return n
}

func deref[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

func extractAccountNames(sessions []*models.Session) []string {
	names := make([]string, 0, len(sessions))
	for _, s := range sessions {
		names = append(names, s.Account)
	}
	return names
}

func mapErrorToMessage(code int) string {
	switch code {
	case models.Err.Ok:
		return "密码已重置"
	case models.Err.AccountNotFound:
		return "账号不存在"
	default:
		return "重置失败"
	}
}

func listDigest(entries []models.FingerprintEntry) string {
	if len(entries) == 0 {
		return "-"
	}
	return security.HashSHA256Str(fmt.Sprintf("%v", entries))
}

func namesDigest(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	return security.HashSHA256Str(fmt.Sprintf("%v", names))
}

func composeFingerprint(revision int, pvf *models.PvfInfo, white, black, allowed string) string {
	pvfHash := ""
	if pvf != nil {
		pvfHash = fmt.Sprintf("PSHA-256:%s:%d:%s", pvf.Hash, pvf.Size, pvf.ModifiedUtc)
	}
	return fmt.Sprintf("I%d;W%s;B%s;A%s;%s", revision, white, black, allowed, pvfHash)
}

// ==================== 外挂检测处理函数 ====================

// AntiCheatReportRequest 外挂检测上报请求。
// ReportToken 由登录器下发（放入请求体，与原网关契约一致），
// 是服务端归因依据，缺省或不合法一律 401。
type AntiCheatReportRequest struct {
	ReportToken string               `json:"reportToken"`
	Account     string               `json:"account"`
	Detections  []AntiCheatDetection `json:"detections"`
}

// AntiCheatDetection 单条检测记录。
type AntiCheatDetection struct {
	RuleName       string  `json:"ruleName"`
	Description    string  `json:"description"`
	ActualValue    float64 `json:"actualValue"`
	ThresholdValue float64 `json:"thresholdValue"`
	Timestamp      int64   `json:"timestamp"`
	Evidence       string  `json:"evidence"`
}

// handleAntiCheatReport 接收客户端外挂检测上报。
//
// 鉴权与原网关契约一致：reportToken 为空或会话校验不通过一律 401。
// 账号以会话解析结果为准；客户端自报的 account 只做交叉核对，不用于归因。
func (s *Server) handleAntiCheatReport(w http.ResponseWriter, r *http.Request) {
	var req AntiCheatReportRequest
	// 公开端点（校验会话 token 即可反复 POST）：1 MiB 收紧上限。
	// 正常上报是一批检测结果（插件 maxBatch=50），远小于 1 MiB。
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "error": "invalid request",
		})
		return
	}

	// 鉴权：必须携带登录器下发的有效会话 token
	if s.sessionMgr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": "unauthorized",
		})
		return
	}
	sess, ok := s.sessionMgr.ValidateToken(req.ReportToken)
	if !ok || sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": "unauthorized",
		})
		return
	}

	clientIP := getClientIP(r)
	account := sess.Account

	// 客户端自报账号与会话不一致：只记日志，不拒绝（与原网关一致）
	if req.Account != "" && req.Account != account {
		s.logger.Warn(fmt.Sprintf("[AntiCheat] account_mismatch: 会话=%s 自报=%s IP=%s",
			account, req.Account, clientIP))
	}

	// 存储检测记录到数据库
	now := time.Now().Unix()
	detections := make([]database.AntiCheatDetection, len(req.Detections))
	for i, d := range req.Detections {
		detections[i] = database.AntiCheatDetection{
			RuleName:       d.RuleName,
			Description:    d.Description,
			ActualValue:    d.ActualValue,
			ThresholdValue: d.ThresholdValue,
			EventTimestamp: d.Timestamp,
			Evidence:       d.Evidence,
			ClientIP:       clientIP,
			Account:        account,
			ReportedAt:     now,
		}
	}

	if err := s.db.InsertAntiCheatDetections(detections); err != nil {
		s.logger.Error(fmt.Sprintf("[AntiCheat] 存储失败: %v", err))
	}

	s.logger.Info(fmt.Sprintf("[AntiCheat] 收到上报: IP=%s, Account=%s, 检测数=%d", clientIP, account, len(req.Detections)))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "received": len(req.Detections),
	})
}

// AntiCheatDetectionResponse 检测记录响应。
type AntiCheatDetectionResponse struct {
	ID             string  `json:"id"`
	RuleName       string  `json:"ruleName"`
	Description    string  `json:"description"`
	ActualValue    float64 `json:"actualValue"`
	ThresholdValue float64 `json:"thresholdValue"`
	Timestamp      int64   `json:"timestamp"`
	Evidence       string  `json:"evidence"`
	ClientIP       string  `json:"clientIp"`
	ReportedAt     int64   `json:"reportedAt"`
}

// AntiCheatPlayerSummary 玩家检测汇总。
type AntiCheatPlayerSummary struct {
	Account         string   `json:"account"`
	DetectionCount  int      `json:"detectionCount"`
	LastDetectionAt int64    `json:"lastDetectionAt"`
	RuleNames       []string `json:"ruleNames"`
}

// handleAdminAntiCheatDetections 获取检测记录列表（后台管理）。
func (s *Server) handleAdminAntiCheatDetections(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": "unauthorized",
		})
		return
	}

	// 分页参数
	limit := parseLimit(r.URL.Query().Get("limit"), 50)
	offset := parseOffset(r.URL.Query().Get("offset"))

	detections, total, err := s.db.GetAntiCheatDetections(limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": err.Error(),
		})
		return
	}

	resp := make([]AntiCheatDetectionResponse, len(detections))
	for i, d := range detections {
		resp[i] = AntiCheatDetectionResponse{
			ID:             fmt.Sprintf("%d", d.ID),
			RuleName:       d.RuleName,
			Description:    d.Description,
			ActualValue:    d.ActualValue,
			ThresholdValue: d.ThresholdValue,
			Timestamp:      d.EventTimestamp,
			Evidence:       d.Evidence,
			ClientIP:       d.ClientIP,
			ReportedAt:     d.ReportedAt,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "detections": resp, "total": total, "limit": limit, "offset": offset,
	})
}

// handleAdminAntiCheatPlayers 获取玩家检测汇总列表。
func (s *Server) handleAdminAntiCheatPlayers(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": "unauthorized",
		})
		return
	}

	limit := parseLimit(r.URL.Query().Get("limit"), 50)
	offset := parseOffset(r.URL.Query().Get("offset"))

	summaries, total, err := s.db.GetAntiCheatPlayerSummary(limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "players": summaries, "total": total, "limit": limit, "offset": offset,
	})
}

// handleAdminAntiCheatPlayerDetails 获取单个玩家的详细检测记录。
func (s *Server) handleAdminAntiCheatPlayerDetails(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"ok": false, "error": "unauthorized",
		})
		return
	}

	vars := mux.Vars(r)
	account := vars["account"]

	limit := parseLimit(r.URL.Query().Get("limit"), 50)
	offset := parseOffset(r.URL.Query().Get("offset"))

	detections, total, err := s.db.GetAntiCheatDetectionsByAccount(account, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": err.Error(),
		})
		return
	}

	resp := make([]AntiCheatDetectionResponse, len(detections))
	for i, d := range detections {
		resp[i] = AntiCheatDetectionResponse{
			ID:             fmt.Sprintf("%d", d.ID),
			RuleName:       d.RuleName,
			Description:    d.Description,
			ActualValue:    d.ActualValue,
			ThresholdValue: d.ThresholdValue,
			Timestamp:      d.EventTimestamp,
			Evidence:       d.Evidence,
			ClientIP:       d.ClientIP,
			ReportedAt:     d.ReportedAt,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "account": account, "detections": resp, "total": total,
	})
}

// parseLimit 解析分页 limit 参数。
func parseLimit(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// parseOffset 解析分页 offset 参数。
func parseOffset(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// checkAdminKey 检查管理密钥。
func (s *Server) checkAdminKey(r *http.Request) bool {
	key := r.Header.Get("X-Auth-Key")
	if key == "" {
		return false
	}
	return security.ConstantTimeEquals(key, s.config.Admin.AuthKey)
}
