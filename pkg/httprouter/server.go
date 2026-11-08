package httprouter

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

	// bossIntrusionSvc 是 BOSS 乱入配置（2026-11-03）。
	//
	// 走**具体类型 + Setter 注入**而不是 Backends 接口：gateway 和 admin 两个
	// 进程都直接读写同一个 gateway.db 的 boss_intrusion_config 表，没有
	// 「内存快照只在网关进程里」的问题（对比 announce 的弹窗队列就必须转发）。
	// 见 boss_intrusion_handlers.go。
	bossIntrusionSvc *service.BossIntrusionConfigService

	// plugins 是插件下发目录的扫描器 + sha256 缓存（见 launcher_plugins.go）。
	//
	// 纯文件系统，**不依赖网关进程内存**，所以两个进程各持一份、共用同一个目录即可：
	// admin 进程(8443) 负责上传/删除文件，网关进程(8080) 负责按签名重扫后下发。
	// 不存在"改后台内存不影响玩家"那类错位，因此**不需要**走 backends 抽象。
	plugins *pluginStore

	// launcherUpdate 是登录器自更新分发（2026-10-01，见 launcher_update.go）。
	// 与 plugins 同模式：纯文件系统 + currentStamp（size+mtime）签名校验，
	// 两个进程各持一份共用 launcher_update/ 目录 —— admin 上传后网关进程
	// 下一次请求自动感知新版本，不需要跨进程通知。
	launcherUpdate *service.LauncherUpdateService

	// dnfExeUpdate 是 DNF.EXE 增量更新分发（2026-10-25，见 dnfexe_update.go）。
	// 与 launcherUpdate 同模式：纯文件系统 + currentStamp（size+mtime）签名校验，
	// 两个进程各持一份共用 dnfexe_update/ 目录 —— admin 上传后网关进程
	// 下一次请求自动感知新版本，不需要跨进程通知。
	dnfExeUpdate *service.DnfExeUpdateService

	// peerSync 是网关间同步服务，**只在主网关**非 nil（配了 Signing.Peers）。
	//
	// 用途：上传/回退登录器版本成功后，主动把新版本推送给从网关，
	// 让发版从"等从网关 300s 轮询"变成秒级生效。
	// 见 SetPeerSync 与 launcher_update.go 的触发点。
	peerSync *service.PeerSyncService

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
	//
	// 2026-10-17 双服：缓存按 game 维度分槽（key = game 参数原值，空串 =
	// 全部服的汇总视图）。共用一个槽会让「A 服视角的 body」返给不带 game
	// 的请求（或反过来）—— 两边 count/players 完全不同，是可见的错误数据。
	onlineCacheMu   sync.Mutex
	onlineCacheAt   map[string]time.Time
	onlineCacheBody map[string][]byte
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
		onlineCacheAt:    make(map[string]time.Time),
		onlineCacheBody:  make(map[string][]byte),
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
		cert:           cert,
		portStore:      portStore,
		plugins:        newPluginStore(cfg.Launcher.PluginDir),
		launcherUpdate: service.NewLauncherUpdateService(cfg, logger),
		dnfExeUpdate:   service.NewDnfExeUpdateService(cfg, logger),
		sessions:       b.Sessions,
		pvf:            b.Pvf,
		ports:          b.Ports,
		runtime:        b.Runtime,
		announce:       b.Announce,
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
	r.Use(s.adminPageNoCacheMiddleware)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("wwwroot")))
}

// adminPageNoCacheMiddleware 给后台静态页下发"禁止缓存"响应头。
//
// ★ 为什么需要它（2026-10-24 现场）：`wwwroot/index.html` 是从磁盘读的
//   （http.FileServer(http.Dir("wwwroot"))，不走 go:embed），更新页面后
//   服务器立刻就是新文件，但**浏览器仍拿旧缓存** —— http.FileServer 只发
//   Last-Modified，不发 Cache-Control，浏览器按启发式规则缓存，
//   用户按 F5 刷不出来，表现为"后台没有新功能"。
//   HTML 里那句 <meta http-equiv="Cache-Control"> 在很多浏览器/反代组合下
//   并不生效，必须在响应头层面禁用。
//
// 只对**非 /api** 路径生效：API 响应由各 handler 自己决定缓存策略
// （清单类接口本来就要短缓存），这里不插手。
func (s *Server) adminPageNoCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api") {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		next.ServeHTTP(w, r)
	})
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
	var err error
	if cert != nil {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	// http.ErrServerClosed 是优雅关闭（Shutdown/Close）的正常返回值，绝不能当故障。
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return
	}
	// G-8（2026-10-04 审查）：原先这里只调 logger.Fatal，而 ConsoleLogger.Fatal
	// **只写一行日志、不退出**；加上这段跑在 serveOn 的 goroutine 里 ——
	// 于是 8080/8443 被占用时网关照常打印"已启动"，实际少了一个端口，问题要等到
	// 玩家连不上才被发现。端口起不来就是致命错误：写日志后显式 os.Exit(1)，
	// 让 systemd 按失败处理（重启/告警），而不是假装健康地跑着。
	s.logger.Error(fmt.Sprintf("%s服务启动/运行失败（端口可能被占用）: %v", tlsLabel(cert), err))
	os.Exit(1)
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

	// 服清单下发（三服合一，2026-10-24）。
	// 免鉴权，返回 Ed25519 签名的服清单，登录器据此选服和解析端点。
	// 见 launcher_servers.go。
	r.HandleFunc("/api/launcher/servers", s.handleLauncherServers).Methods("GET")

	// Web 注册（三服合一，2026-10-24）。见 register_web.go。
	//
	// 同一路径两个方法：GET 返回表单页，POST 处理注册。
	// ★ 挂在 /api 下是因为 usePublicOnlyMiddleware 会把非 /api 路径 404
	//   （玩家端口刻意不暴露页面）。
	// ★ 从网关一律拒绝：GET 返回"请到主网关注册"说明页，POST 返回 403。
	r.HandleFunc("/api/register", s.handleWebRegisterPage).Methods("GET")
	r.HandleFunc("/api/register", s.handleWebRegister).Methods("POST")

	// PVF 增量包下载（2026-09-30 PVF 增量更新，公开只读）。
	//
	// 与插件下载同组限流（launcher-binary）：它同样是"版本更新时才发生一次"的
	// 大文件传输（实测 219 KB ~ 10.8 MB），不该占心跳/策略/榜单那份额度。
	//
	// ★ 端点是**无参**的：下发哪一份完全由网关当前状态决定（GetDelta）。
	//   客户端拿到的包是否匹配自己那版，由包头部（与 policy）里的 from_hash 判定，
	//   合成结果再由整文件 SHA-256 兜底 —— 不给客户端"点菜"的能力。
	//   存在竞态（取到 policy 后管理员又传了新 PVF），此时合成产物校验不过，
	//   客户端会保留旧文件并拒绝进游戏，下一次登录就拿到新的一份。
	r.HandleFunc("/api/launcher/pvf/delta", s.handleLauncherPvfDelta).Methods("GET")

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

	// 登录器自更新（2026-10-01，公开只读）。与插件同因走 /api 路由。
	// delta 必须带 ?from=<本地exe hash>；2.3.8 及更早客户端不认识这组端点。
	r.HandleFunc("/api/launcher/update", s.handleLauncherUpdateManifest).Methods("GET")
	r.HandleFunc("/api/launcher/update/exe", s.handleLauncherUpdateExe).Methods("GET")
	r.HandleFunc("/api/launcher/update/delta", s.handleLauncherUpdateDelta).Methods("GET")

	// DNF.EXE 增量更新（2026-10-25，公开只读）。与登录器自更新同构。
	// delta 必须带 ?from=<本地 DNF.EXE hash>。
	r.HandleFunc("/api/dnfexe/update", s.handleDnfExeUpdateManifest).Methods("GET")
	r.HandleFunc("/api/dnfexe/update/exe", s.handleDnfExeUpdateExe).Methods("GET")
	r.HandleFunc("/api/dnfexe/update/delta", s.handleDnfExeUpdateDelta).Methods("GET")

	// 心跳
	r.HandleFunc("/api/heartbeat", s.handleHeartbeat).Methods("POST")

	// 外挂检测上报（玩家客户端调用）
	r.HandleFunc("/api/anticheat/report", s.handleAntiCheatReport).Methods("POST")

	// 玩家内辅（上游 PR #71 的服务端接口）转发到账号 API。
	// 复用 8080 这个 HTTPS 监听：不新开端口、不用新证书。
	// 见 player_helper_proxy.go。
	r.HandleFunc(playerHelperProxyPath, s.handlePlayerHelperProxy).Methods("POST")
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
	// 运行时能力探测（2026-10-29）：前端据此决定哪些按钮该显示。
	// 例如 S5A3 下「删除账号」必须隐藏（网关不能安全删）、
	// 「改密」要提示密码是服务端 bcrypt。
	r.HandleFunc("/api/admin/runtime", s.handleAdminRuntime).Methods("GET")
	r.HandleFunc("/api/admin/online/kick", s.handleAdminKick).Methods("POST")

	// 全服发放
	r.HandleFunc("/api/admin/broadcast", s.handleAdminBroadcast).Methods("POST")

	// PVF 管理
	r.HandleFunc("/api/admin/refresh-pvf", s.handleAdminRefreshPvf).Methods("POST")
	r.HandleFunc("/api/pvf/info", s.handlePvfInfo).Methods("GET")
	r.HandleFunc("/api/admin/upload-pvf", s.handleAdminUploadPvf).Methods("POST")
	r.HandleFunc("/api/admin/pvf/register", s.handlePvfRegister).Methods("POST")
	r.HandleFunc("/api/admin/pvf/unregister", s.handlePvfUnregister).Methods("POST")
	// 版本历史与回退（2026-09-30 方案①：任意历史版 → 按需增量 / 一键回退）
	r.HandleFunc("/api/admin/pvf/history", s.handleAdminPvfHistory).Methods("GET")
	r.HandleFunc("/api/admin/pvf/rollback", s.handleAdminPvfRollback).Methods("POST")

	// 完整性策略
	r.HandleFunc("/api/admin/integrity", s.handleAdminIntegrity).Methods("GET")
	r.HandleFunc("/api/admin/integrity/upload", s.handleAdminIntegrityUpload).Methods("POST")
	r.HandleFunc("/api/admin/integrity/add", s.handleAdminIntegrityAdd).Methods("POST")
	r.HandleFunc("/api/admin/integrity/remove", s.handleAdminIntegrityRemove).Methods("POST")
	r.HandleFunc("/api/admin/integrity/allow", s.handleAdminIntegrityAllow).Methods("POST")

	// 驱动白名单（2026-10-16）。
	// 存放位置与完整性策略**同一个快照**（integrity_policy.json 的 driver_allow），
	// 因而共用 revision / 热加载 / policy 下发链路；但上传走独立的验签链路
	//（shell 里多一道"未签名或签名后被改过一律拒"，见 handleAdminDriversUpload）。
	// ★ upload 路径必须与 bodylimit.go 的 uploadPaths 完全一致，否则会被 8 MiB 全局上限打死。
	r.HandleFunc("/api/admin/drivers", s.handleAdminDrivers).Methods("GET")
	r.HandleFunc("/api/admin/drivers/upload", s.handleAdminDriversUpload).Methods("POST")
	r.HandleFunc("/api/admin/drivers/remove", s.handleAdminDriversRemove).Methods("POST")

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

	// 邀请码（2026-10-24）。见 admin_invite.go。
	// 开启 Register.RequireInvite（默认开）后，注册必须带这里生成的码。
	r.HandleFunc("/api/admin/invite/generate", s.handleAdminInviteGenerate).Methods("POST")
	r.HandleFunc("/api/admin/invite/list", s.handleAdminInviteList).Methods("GET")
	r.HandleFunc("/api/admin/invite/revoke", s.handleAdminInviteRevoke).Methods("POST")
	r.HandleFunc("/api/admin/invite/export", s.handleAdminInviteExport).Methods("GET")

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

	// BOSS 乱入配置（2026-11-03）：后台读写，游戏服务端从内部端口轮询。
	r.HandleFunc("/api/admin/boss-intrusion/config", s.handleAdminBossIntrusionConfigGet).Methods("GET")
	r.HandleFunc("/api/admin/boss-intrusion/config", s.handleAdminBossIntrusionConfigPost).Methods("POST")

	// 金币寄售回收配置（2026-11-08）：后台读写文件，服务端从内部端口轮询。
	// 与乱入同一套 revision 机制，只是存储换成 data/gold_consign_buyback.json。
	r.HandleFunc("/api/admin/gold-consign-buyback/config", s.handleAdminGoldConsignBuybackConfigGet).Methods("GET")
	r.HandleFunc("/api/admin/gold-consign-buyback/config", s.handleAdminGoldConsignBuybackConfigPost).Methods("POST")

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
	// ★ 2026-09-30 移除了 "/api/admin/plugins/meta/draft"（按目录生成清单草稿）。
	//   它会**整体覆盖** plugins.json 且把每条都写成"非核心 + 默认关闭"，
	//   误触一次就要手工把 12 条的顺序与核心标记全部重排回来（真实踩过）。
	//   首次部署的清单以仓库里的 plugins/plugins.json 为准，不再由后台推导。

	// 登录器版本管理（2026-10-01 自更新）。与插件同模式：纯文件系统、
	// 两个进程共用 launcher_update/ 目录，不走内部 API。
	// ★ /api/admin/launcher/upload 收 134 MiB exe，已加 bodylimit 白名单。
	r.HandleFunc("/api/admin/launcher/versions", s.handleAdminLauncherVersions).Methods("GET")
	r.HandleFunc("/api/admin/launcher/upload", s.handleAdminLauncherUpload).Methods("POST")
	r.HandleFunc("/api/admin/launcher/rollback", s.handleAdminLauncherRollback).Methods("POST")

	// DNF.EXE 版本管理（2026-10-25 增量更新）。与登录器同模式：纯文件系统、
	// 两个进程共用 dnfexe_update/ 目录，不走内部 API。
	// ★ /api/admin/dnfexe/upload 收 ~20 MiB exe，已加 bodylimit 白名单。
	r.HandleFunc("/api/admin/dnfexe/versions", s.handleAdminDnfExeVersions).Methods("GET")
	r.HandleFunc("/api/admin/dnfexe/upload", s.handleAdminDnfExeUpload).Methods("POST")
	r.HandleFunc("/api/admin/dnfexe/rollback", s.handleAdminDnfExeRollback).Methods("POST")

	// 服务端管理
	r.HandleFunc("/api/admin/server/status", s.handleAdminServerStatus).Methods("GET")
	r.HandleFunc("/api/admin/server/control", s.handleAdminServerControl).Methods("POST")
	r.HandleFunc("/api/admin/server/logs", s.handleAdminServerLogs).Methods("GET")
	r.HandleFunc("/api/admin/server/pvf", s.handleAdminServerPvf).Methods("POST")
	r.HandleFunc("/api/admin/server/pvf/info", s.handleAdminServerPvfInfo).Methods("GET")
	r.HandleFunc("/api/admin/server/backup", s.handleAdminServerBackup).Methods("POST")
	r.HandleFunc("/api/admin/server/backups", s.handleAdminServerBackups).Methods("GET")
	r.HandleFunc("/api/admin/backup/targets", s.handleAdminBackupTargets).Methods("GET")

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

	// 注册限额（反批量注册，2026-10-13）
	r.HandleFunc("/api/admin/register-limit", s.handleAdminRegisterLimitGet).Methods("GET")
	r.HandleFunc("/api/admin/register-limit", s.handleAdminRegisterLimitPost).Methods("POST")
	r.HandleFunc("/api/admin/register-logs", s.handleAdminRegisterLogs).Methods("GET")

	// 心跳超时（2026-10-14）：会话超时清理由网关进程执行，权威值在网关内存里，
	// admin 进程必须经运行时配置后端转发（同 register-limit 的理由）。
	r.HandleFunc("/api/admin/heartbeat", s.handleAdminHeartbeatGet).Methods("GET")
	r.HandleFunc("/api/admin/heartbeat", s.handleAdminHeartbeatPost).Methods("POST")

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

	// BOSS 乱入配置（2026-11-03）：游戏服务端每 10 秒轮询一次，
	// revision 变了才重建装备池。见 boss_intrusion_handlers.go。
	r.HandleFunc("/internal/boss-intrusion/config", s.checkInternal(s.handleInternalBossIntrusionConfig)).Methods("GET")

	// 金币寄售回收配置（2026-11-08）：服务端每 10 秒轮询，revision 变了才应用。
	// 见 gold_consign_buyback_handlers.go。
	r.HandleFunc("/internal/gold-consign-buyback/config", s.checkInternal(s.handleInternalGoldConsignBuybackConfig)).Methods("GET")

	// 登录器包同步（三服合一，2026-10-24）：主网关做权威，从网关拉取。
	// 见 launcher_sync.go。
	r.HandleFunc("/internal/launcher/sync", s.checkInternal(s.handleInternalLauncherSync)).Methods("GET")
	r.HandleFunc("/internal/launcher/push", s.checkInternal(s.handleInternalLauncherPush)).Methods("POST")

	// DNF.EXE 包同步（三服合一，2026-10-25）：主网关做权威，从网关拉取。
	// 见 dnfexe_sync.go。
	r.HandleFunc("/internal/dnfexe/sync", s.checkInternal(s.handleInternalDnfExeSync)).Methods("GET")
	r.HandleFunc("/internal/dnfexe/push", s.checkInternal(s.handleInternalDnfExePush)).Methods("POST")

	// 账号事件同步（三服合一，2026-10-24）：从网关增量拉取主网关的事件流。
	// 见 account_sync.go。
	r.HandleFunc("/internal/account/events", s.checkInternal(s.handleInternalAccountEvents)).Methods("GET")
	// 账号凭据反查（登录兜底）：从网关本地查不到账号时向主网关取 pwd_hash/salt/m_id。
	r.HandleFunc("/internal/account/credential", s.checkInternal(s.handleInternalAccountCredential)).Methods("GET")
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
	Launcher      LauncherView      `json:"launcher"`
	Maintenance   MaintenanceView   `json:"maintenance"`
	RegisterLimit RegisterLimitView `json:"register_limit"`
	Heartbeat     HeartbeatView     `json:"heartbeat"`
	Online        int               `json:"online"`
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

	rv, err := s.runtime.RegisterLimit()
	if err != nil {
		return out, err
	}
	out.RegisterLimit = rv

	hv, err := s.runtime.Heartbeat()
	if err != nil {
		return out, err
	}
	out.Heartbeat = hv

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
		"ok":             true,
		"launcher":       out.Launcher,
		"maintenance":    out.Maintenance,
		"register_limit": out.RegisterLimit,
		"heartbeat":      out.Heartbeat,
		"online":         out.Online,
	})
}

func (s *Server) handleInternalRuntimeConfigSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Launcher *struct {
			MinVersion   *string `json:"min_version"`
			DownloadURL  *string `json:"download_url"`
			UpdateNotice *string `json:"update_notice"`
			MaxInstances *int    `json:"max_instances"`
		} `json:"launcher"`
		Maintenance *struct {
			Enabled       *bool    `json:"enabled"`
			Message       *string  `json:"message"`
			AdminAccounts []string `json:"admin_accounts"`
		} `json:"maintenance"`
		RegisterLimit *struct {
			Enabled     *bool `json:"enabled"`
			PerIPPerDay *int  `json:"per_ip_per_day"`
			PerMachine  *int  `json:"per_machine"`
		} `json:"register_limit"`
		Heartbeat *struct {
			TimeoutSeconds *int `json:"timeout_seconds"`
		} `json:"heartbeat"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}

	changed := false
	if body.Launcher != nil {
		c, err := s.runtime.SetLauncher(body.Launcher.MinVersion, body.Launcher.DownloadURL, body.Launcher.UpdateNotice, body.Launcher.MaxInstances)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		changed = changed || c
	}

	if body.RegisterLimit != nil {
		c, err := s.runtime.SetRegisterLimit(body.RegisterLimit.Enabled,
			body.RegisterLimit.PerIPPerDay, body.RegisterLimit.PerMachine)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		changed = changed || c
	}

	if body.Heartbeat != nil {
		c, err := s.runtime.SetHeartbeat(body.Heartbeat.TimeoutSeconds)
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
	lz := s.config.LauncherSnapshot() // G-5：运行时可变段走快照
	minVer := strings.TrimSpace(lz.MinVersion)
	if minVer == "" {
		minVer = "1.0.0"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":      minVer,
		"download_url": lz.DownloadUrl,
	})
}

// launcherChannelInfo 组装下发给登录器的频道目录快照。
//
// 形状：
//
//	{
//	  "landing": 10,                        // 建议落点频道（常驻城镇）
//	  "open":    [10, 11, 23, 28, 75, ...], // 当前真正在听的频道号（升序）
//	  "count":   21,
//	  "source":  "proxy"                    // proxy=代理实况；config=配置兜底
//	}
//
// ★ 为什么用「代理实况」而不是配置里的 GamePorts：
//   配置可以列 120 个端口，但运维会在 `proxy_ports.json` 里只开其中一部分
//   （90CN 就是只开 21 个）。玩家只能连到真正在听的那些，登录器如果按配置
//   全量去判定"频道有效"，就会把连不上的频道当成可用，等于没修。
//
// ★ 端口 → 频道号是 `端口 - 10000`（`channel_info.etc` 的默认映射，
//   见 Docs/CHANNEL_TABLE_DEPLOYMENT.md："默认端口为 10000 + 频道号"）。
//
// 失败一律返回空 open + 配置兜底的 landing，**不让 policy 整个失败** ——
// 频道目录是"锦上添花"，登录器拿不到就退回它自己的编译期常量。
func (s *Server) launcherChannelInfo() map[string]interface{} {
	landing := config.DefaultLandingChannel
	if s.config != nil {
		landing = s.config.ResolveLandingChannel()
	}

	out := map[string]interface{}{
		"landing": landing,
		"open":    []int{},
		"count":   0,
		"source":  "proxy",
	}

	if s.ports == nil {
		out["source"] = "config"
		return out
	}
	active, err := s.ports.Active()
	if err != nil {
		out["source"] = "config"
		return out
	}

	open := make([]int, 0, len(active))
	for port := range active {
		// 只认游戏口。频道引导口是 7001、内部口在 18080，都不在这个区间。
		if port > 10000 && port < 20000 {
			open = append(open, port-10000)
		}
	}
	sort.Ints(open)

	out["open"] = open
	out["count"] = len(open)

	// 落点不在开放列表里时，退到"开放列表里最小的那个"并标注出来 ——
	// 运维把落点关掉了属于配置错误，但让登录器拿到一个能连的号，
	// 总比让它把玩家写到一个连不上的频道上强。
	if len(open) > 0 {
		found := false
		for _, c := range open {
			if c == landing {
				found = true
				break
			}
		}
		if !found {
			out["landing"] = open[0]
			out["landing_fallback"] = true
		}
	}
	return out
}

func (s *Server) handleLauncherPolicy(w http.ResponseWriter, r *http.Request) {
	rev := r.URL.Query().Get("rev")
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"

	// 选服维度（2026-10-17）：登录器按选中的服拉策略，网关回该服的门禁开关。
	// 空 = 默认服（改造前的老登录器不带这个参数，行为完全不变）。
	gameID := strings.TrimSpace(r.URL.Query().Get("game"))
	var profile config.GameServerEntry
	var gameFound bool
	if s.config != nil {
		profile, gameFound = s.config.FindGameServer(gameID)
	}
	gates := gateSwitchesFor(profile, gameFound)

	pvfInfo := s.pvfSvc.GetPvfInfo()
	snap := s.integritySvc.Snapshot()

	whiteDigest := listDigest(snap.WhiteList)
	blackDigest := listDigest(snap.BlackList)
	allowedDigest := namesDigest(snap.AllowedModules)
	drvDigest := driverDigest(snap.DriverAllow)
	// G-2（2026-10-04 审查）：本端点是**免鉴权公开端点、每个登录器启动必打**。
	// GetPvfInfo 在「PVF 文件在、但哈希失败」时会返回 nil（它把 RefreshCache 的
	// error 吞掉后返回 s.info），直接解引用就是进程级 panic，重启后重复命中
	// ⇒ 崩溃循环。composeFingerprint 已容忍 nil，下面的 pvfObj 也必须判空
	// （同文件 handleAdminPvfHistory 就是先判空再取字段）。
	fingerprint := composeFingerprint(snap.Revision, pvfInfo, whiteDigest, blackDigest, allowedDigest, drvDigest)

	changed := force || rev != fingerprint

	// nil 时下发空指纹：登录器拿不到匹配的 hash 就不会替换本地 PVF
	// （有整文件 SHA-256 兜底），比让网关崩掉好得多。
	pvfObj := map[string]interface{}{
		"hash": "", "algo": "", "size": int64(0), "modified_utc": nil,
	}
	if pvfInfo != nil {
		var pvfUtc interface{}
		if pvfInfo.ModifiedUtc != "" {
			pvfUtc = pvfInfo.ModifiedUtc
		}
		pvfObj = map[string]interface{}{
			"hash": pvfInfo.Hash, "algo": pvfInfo.Algo,
			"size": pvfInfo.Size, "modified_utc": pvfUtc,
		}
	}
	// PVF 增量更新（2026-09-30）：只有当网关手里有一份「上一版 → 当前版」的增量包，
	// 且它的 to_hash 就是当前 PVF 时才下发（GetDelta 内部已校）。
	//
	// 登录器的用法：本地 PVF 的 SHA-256
	//   == pvf.hash          → 直接锁定（现状，无需下载）
	//   == pvf.delta.from_hash → 下 url 并合成，校验 to_hash 后原子替换
	//   其它                  → 没有可用增量，维持现状（提示手动更新客户端）
	//
	// url 给相对路径：登录器自己有"连的是哪个网关"，与插件下载口径一致，
	// 换成 CDN/对象存储时只改这里（或另加绝对 URL 字段），客户端不用动。
	if d := s.pvfSvc.GetDelta(); d != nil {
		pvfObj["delta"] = map[string]interface{}{
			"from_hash":   d.FromHash,
			"to_hash":     d.ToHash,
			"to_size":     d.ToSize,
			"size":        d.Size,
			"url":         "/api/launcher/pvf/delta",
			"algo":        "block2048",
			"created_utc": d.CreatedUtc,
		}
	}

	resp := map[string]interface{}{
		"ok":             true,
		"changed":        changed,
		"fingerprint":    fingerprint,
		"revision":       snap.Revision,
		"pvf":            pvfObj,
		"white_digest":   whiteDigest,
		"black_digest":   blackDigest,
		"allowed_digest": allowedDigest,
		"driver_digest":  drvDigest,
		"white_count":    len(snap.WhiteList),
		"black_count":    len(snap.BlackList),
		"allowed_count":  len(snap.AllowedModules),
		"driver_count":   len(snap.DriverAllow),

		// ── 选服维度（2026-10-17）──────────────────────────────────
		// ★ gates 与 game **恒返回**，不受 changed 短路影响。
		//   原因：fingerprint 里不含 game，玩家从 S4A21 切到 S5A95 时 rev 仍是命中态
		//   （changed=false），若把 gates 塞进 changed 分支，切服后登录器会继续按上一服的
		//   门禁跑 —— 表现为"选了 DNF95 却被要求校验 S4A21 的 PVF"。
		"game":       profile.Id,
		"game_found": gameFound,
		"gates":      gates,
	}

	// ── 频道目录（2026-10-29）────────────────────────────────────
	//
	// 登录器启动前要按"服务端当前有哪些频道"来修正客户端的频道记忆
	// （DNF.cfg 里存着上次连的频道号；频道改号后旧号已不存在，客户端会按旧号
	// 去连 → 连不上 → 卡在选人界面 → 弹回频道列表）。
	//
	// 数据源是**代理实际在听的端口**（不是配置里的 GamePorts）：
	// 配置可以列 120 个，但运维可能只开了其中一部分（`proxy_ports.json` 的
	// enabled 开关），客户端只能连到真正在听的那些。频道号 = 端口 - 10000。
	//
	// 同样**恒返回**（与 gates 同理）：它不受 changed 短路影响，
	// 否则指纹没变时登录器拿不到频道表，改完频道还得等 PVF/策略变化才生效。
	//
	// 兼容性：老登录器不认识 `channels` 键，多收一个对象不会有任何影响。
	resp["channels"] = s.launcherChannelInfo()
	if changed {
		resp["white"] = snap.WhiteList
		resp["black"] = snap.BlackList
		resp["allowed"] = snap.AllowedModules
		// 驱动白名单：只有 changed 时才全量下发（与 white/black 同口径）。
		// 老登录器不认识这个键，多收一个数组不会有任何影响。
		resp["driver"] = snap.DriverAllow
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

	// 角色名 / 等级（2026-11-01）。
	//
	// 后台在线表原来只有「账号 / IP / 在线时长」，运营看不出这个号现在在玩哪个角色、
	// 多少级 —— 玩家来报"我卡住了"时对不上人。
	//
	// 两步批量查（账号 → m_id → 当前角色），不按人循环打库：
	// S5A3 下 m_id 是 `dnf:10001` 这种，由 GetMIdsByNames 的 S5A3 分支解析。
	names := make([]string, 0, len(online))
	for _, p := range online {
		names = append(names, p.Account)
	}
	mIds := map[string]string{}
	roleByMId := map[string]database.OnlineRoleCandidate{}
	if s.db != nil && len(names) > 0 {
		if got, err := s.db.GetMIdsByNames(names); err == nil {
			mIds = got
			mIdList := make([]string, 0, len(got))
			for _, m := range got {
				mIdList = append(mIdList, m)
			}
			if roles, err := s.db.GetCurrentRolesByMIds(mIdList); err == nil {
				roleByMId = roles
			}
		}
	}

	// 刻意保留原来的 camelCase 键名，前端按这些键取值
	players := make([]map[string]interface{}, 0, len(online))
	for _, p := range online {
		item := map[string]interface{}{
			"account":       p.Account,
			"ip":            p.IP,
			"onlineMinutes": p.OnlineMinutes,
			"lastHeartbeat": p.LastHeartbeat,
			"bonusGranted":  p.BonusGranted,
			"cera":          p.Cera,
		}
		// 停在选人界面时没有当前角色 —— 这几个字段就不下发，前端显示 "-"。
		if mId, ok := mIds[p.Account]; ok {
			if c, ok := roleByMId[mId]; ok {
				item["roleName"] = c.Name
				item["roleLevel"] = c.Level
				item["roleJob"] = c.Job
				item["roleCount"] = c.RoleCount
			}
		}
		players = append(players, item)
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

	// 版本备注（2026-09-30 方案①）：随上传写进 pvf_history 记录，
	// 后台「版本历史」表展示、回退时人工辨认用。可空。
	name := strings.TrimSpace(r.FormValue("name"))

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "no pvf file"})
		return
	}
	defer file.Close()

	// 浏览器（尤其老 IE）可能给整个本地路径，只留文件名进记录。
	filename := ""
	if header != nil {
		filename = filepath.Base(filepath.Clean(header.Filename))
	}

	info, err := s.pvfSvc.ReplacePvf(file, name, filename)
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

// handleAdminPvfHistory 版本历史列表（后台「PVF 版本历史」表）。
// GetHistory 内部带惰性 seed（当前版/.bak 版不在史会先入史），因此
// 首次打开该页就能看到可回退的版本 —— 不依赖运维先走过上传流程。
func (s *Server) handleAdminPvfHistory(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	entries := s.pvfSvc.GetHistory()
	currentHash := ""
	if info := s.pvfSvc.GetPvfInfo(); info != nil {
		currentHash = info.Hash
	}
	out := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]interface{}{
			"hash":       e.Hash,
			"size":       e.Size,
			"name":       e.Name,
			"filename":   e.Filename,
			"stored_utc": e.StoredUtc,
			"is_current": strings.EqualFold(e.Hash, currentHash),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "current_hash": currentHash, "entries": out,
	})
}

// handleAdminPvfRollback 回退到历史版本。
// 走 PvfService.RollbackPvf（完整 ReplacePvf 链路：备份 → 替换 → 刷新 →
// 重建固定增量 → 历史入档），随后与 upload-pvf 同样的收尾（Bump + 通知网关）。
// 回退后：在**回退前版本**上的玩家，下次登录会走增量更新降到回退版。
func (s *Server) handleAdminPvfRollback(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	var body struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "请求体不是合法 JSON"})
		return
	}
	info, err := s.pvfSvc.RollbackPvf(body.Hash)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	s.integritySvc.Bump()
	s.notifyPvfChanged()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "hash": info.Hash, "algo": info.Algo, "size": info.Size,
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

			// G-14（2026-10-08，审查报告）：**不要**在这里 defer file.Close()。
			// 这是循环体 —— defer 要等整个 handler 返回才执行，批量上传（成百个分片）
			// 会把句柄全压在手里，撞 ulimit -n 时报的是"打开文件过多"，
			// 看着像系统资源问题，其实是这里攒出来的。
			hash, algo := security.ComputeFileFingerprint(file)
			file.Close()
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

// ==================== 驱动白名单（2026-10-16） ====================
//
// 需求来源：玩家被登录器内核驱动扫描拦下，而放行名单**硬编码在登录器里**
// （Security/KernelThreatScanner.cs 的 DriverShaAllowList，3 条：完美世界 / KK / HWiNFO），
// 加一个驱动就得重编 + 重分发 127 MB 的登录器。这里把名单搬到网关：
// 后台上传 .sys → 服务端验签 + 算 SHA-256 → 随 /api/launcher/policy 下发 →
// 登录器合并进运行期名单（网关条目为增量，硬编码那几条继续兜底）。
//
// ★★ 风险必须记账（与 2026-10-03 放行 HWiNFO 同一类决定，2026-10-16 再次拍板）：
//   加白一个驱动 = 对**全网**放行该文件，而登录器**无法区分**「正常玩家在用」
//   与「外挂借道这份原版签名驱动做内核读写」—— BYOVD 外挂用的正是原版签名驱动本身。
//   因此：每条都必须填 reason（放行理由），后台列表常驻风险提示，新增/移除都写审计日志。
//
// ★ 能力边界：网关侧验签是**运营侧守门**（拒未签名、拒签名后被改过的文件），
//   不做 PKCS#7 密码学验证与证书链信任判定；运行时安全边界在**客户端**——
//   登录器只按「文件名 + SHA-256」精确匹配放行，加白的那份字节改一个即失效。
//   详见 pkg/security/authenticode.go 头部说明。

// maxDriverUploadBytes 单个驱动上传上限，与 security 侧的上限保持一致。
const maxDriverUploadBytes = 64 << 20

// handleAdminDrivers 列出驱动白名单。
func (s *Server) handleAdminDrivers(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	snap := s.integritySvc.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"revision":   snap.Revision,
		"updated_at": snap.UpdatedAt,
		"count":      len(snap.DriverAllow),
		"drivers":    snap.DriverAllow,
	})
}

// handleAdminDriversUpload 上传驱动文件并登记白名单。
//
// 必须先过验签（未签名 / 签名后改过 → 拒），再算 SHA-256 入库。
func (s *Server) handleAdminDriversUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	if r.MultipartForm == nil || len(r.MultipartForm.File) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "请选择要上传的驱动文件（.sys）",
		})
		return
	}

	// 放行理由必填 —— 加白即对全网放行，没有理由的加白事后无从追溯。
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false,
			"message": "必须填写放行理由：它会随条目入库并在后台展示，" +
				"用于事后追溯「为什么放行这个驱动」",
		})
		return
	}

	entries := make([]models.DriverEntry, 0)
	errs := make([]string, 0)
	for _, files := range r.MultipartForm.File {
		for _, f := range files {
			// 不 defer Close：这是循环体，批量上传会把句柄全压在手里
			//（同 handleAdminIntegrityUpload 的 G-14 教训）。
			file, err := f.Open()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", f.Filename, err))
				continue
			}
			// 多读 1 字节用于判超限：读满上限却看不出"超了"会把问题留到后面。
			data, rerr := io.ReadAll(io.LimitReader(file, maxDriverUploadBytes+1))
			file.Close()
			if rerr != nil {
				errs = append(errs, fmt.Sprintf("%s: 读取失败: %v", f.Filename, rerr))
				continue
			}
			if len(data) > maxDriverUploadBytes {
				errs = append(errs, fmt.Sprintf("%s: 超过 %d MiB 上限", f.Filename, maxDriverUploadBytes>>20))
				continue
			}

			// ★ 验签闸门。
			sig, verr := security.VerifyPEBytes(data)
			if verr != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", f.Filename, verr))
				s.logger.Warn(fmt.Sprintf("[驱动白名单] 拒绝上传 %s: %v", f.Filename, verr))
				continue
			}

			hash, algo := security.ComputeFileFingerprint(bytes.NewReader(data))
			if hash == "" {
				errs = append(errs, fmt.Sprintf("%s: 指纹计算失败", f.Filename))
				continue
			}
			entries = append(entries, models.DriverEntry{
				FileName:  f.Filename,
				Hash:      hash,
				Algorithm: algo,
				Size:      int64(len(data)),
				Signer:    sig.Signer,
				Reason:    reason,
			})
		}
	}

	added, rejected := 0, make([]string, 0)
	if len(entries) > 0 {
		added, rejected = s.integritySvc.AddDriverEntries(entries)
	}
	// 审计日志：加白驱动是安全决策，留痕（谁、什么文件、什么哈希、谁签的、什么理由）。
	for _, e := range entries {
		s.logger.Warn(fmt.Sprintf("[驱动白名单] 新增 %s sha256=%s size=%d signer=%q reason=%q —— 加白=对全网放行该文件",
			e.FileName, e.Hash, e.Size, e.Signer, e.Reason))
	}
	for _, rj := range rejected {
		s.logger.Warn("[驱动白名单] 未采纳: " + rj)
	}

	snap := s.integritySvc.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":          added > 0,
		"added":       added,
		"total_files": len(entries) + len(errs),
		"errors":      errs,
		"rejected":    rejected,
		"revision":    snap.Revision,
		"count":       len(snap.DriverAllow),
	})
}

// handleAdminDriversRemove 从驱动白名单移除一条（文件名 + 指纹精确匹配）。
func (s *Server) handleAdminDriversRemove(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req struct {
		File *string `json:"file"`
		Hash *string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.File == nil || req.Hash == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "file/hash required"})
		return
	}

	removed := s.integritySvc.RemoveDriverEntry(*req.File, *req.Hash)
	if removed {
		s.logger.Warn(fmt.Sprintf("[驱动白名单] 移除 %s sha256=%s —— 该文件的放行随之取消", *req.File, *req.Hash))
	}
	snap := s.integritySvc.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": removed, "revision": snap.Revision, "count": len(snap.DriverAllow),
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

// handleAdminRuntime 返回运行时的能力快照，供前端决定哪些按钮该显示。
//
// 目前只有 `game_backend`（"sqlite" / "s5a3" / ""）：
//   - s5a3：隐藏「删除账号」（网关不能安全删，会留孤儿数据）、
//           「改密」提示密码是服务端 bcrypt、
//           「账号同步」只同步身份不同步密码。
//   - sqlite：S4A21 的原有行为，全部按钮照旧。
func (s *Server) handleAdminRuntime(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	backend := s.db.GameBackend()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"game_backend": backend,
		// 前端只需要一个布尔就能决定隐藏哪些危险按钮，
		// 但把原始值也给出，便于排查"为什么按钮不见了"。
		"s5a3": backend == "s5a3",
		"capabilities": map[string]interface{}{
			"delete_account": backend != "s5a3",
			"reset_password": true,
			"password_plain": backend == "s5a3", // S5A3 要明文，S4A21 服务端转 MD5
			"account_sync":   true,
			"device_binding": backend != "s5a3", // S5A3 登录器不传 device_secret
			"game_events":    backend != "s5a3", // S5A3 的活动开关在 GM 工具里
			"register_limit": true,
		},
	})
}

func (s *Server) handleAdminSyncAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	// ★ S5A3 分支（2026-10-29）：语义不同。
	//
	// S4A21 的"同步"是把游戏库 accounts 表的密码哈希/盐**导入**网关库。
	// S5A3 的账号主权在服务端 MySQL，密码是 bcrypt 不可互转（三服合一
	// 评估文档限制 #6），所以这里只同步**身份**（m_id + name），
	// 密码列留空 —— 目的是让后台列表/账号事件/封禁能对上号。
	if s.db.GameBackend() == "s5a3" {
		result, err := s.db.SyncS5A3AccountMirrors()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":      true,
			"message": fmt.Sprintf("S5A3 账号身份同步完成：共 %d 个，新建 %d，已存在 %d", result.Total, result.Created, result.Existing),
			// 复用前端的字段名，避免为 S5A3 再改一套渲染逻辑。
			"game_accounts": result.Total,
			"imported":      result.Created,
			"skipped":       result.Existing,
			"failed":        len(result.Failed),
			"conflicts":     result.Conflicts,
			"failed_items":  result.Failed,
			"note":          "只同步账号身份（m_id + 账号名），不同步密码 —— S5A3 密码是服务端 bcrypt，网关这份镜像不能用来验密",
		})
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

	// ★ S5A3 分支（2026-10-29）：密码由服务端 bcrypt 掌管，网关必须拿**明文**
	// 才能生成能被服务端校验的哈希（MD5 不可逆）。所以这条路径优先要 newPassword，
	// 且不能走下面的"明文转 MD5"逻辑。
	//
	// 只传了 newPasswordMd5 的调用方（旧脚本）在 S5A3 下会拿到明确提示，
	// 而不是写进一条永远验不过的哈希。
	if s.db.GameBackend() == "s5a3" {
		if body.NewPassword == nil || strings.TrimSpace(*body.NewPassword) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"ok": false, "success": false,
				"message": "S5A3 服的密码是服务端 bcrypt，重置必须提供明文新密码（newPassword），不能用 newPasswordMd5",
			})
			return
		}
		code, msg := s.adminSvc.ResetPasswordS5A3(*body.Account, *body.NewPassword)
		ok := code == models.Err.Ok
		if msg == "" {
			if ok {
				msg = "重置成功"
			} else {
				msg = "重置失败"
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok": ok, "success": ok, "message": msg,
		})
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

	// ★ S5A3 分支（2026-10-29）：批量重置必须走 bcrypt，且只能收明文。
	//
	// 这条路径逐个账号算 bcrypt（每个约 50~80ms），100 个账号要 5~8 秒 ——
	// 所以前端要给出"正在执行"的感知，别让管理员以为卡死。
	if s.db.GameBackend() == "s5a3" {
		if body.NewPassword == nil || strings.TrimSpace(*body.NewPassword) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"ok": false, "message": "S5A3 服的密码是服务端 bcrypt，批量重置必须提供明文新密码（newPassword）",
			})
			return
		}
		newPwd := *body.NewPassword
		if err := database.ValidateS5A3Password(newPwd); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
			return
		}
		names, err := s.db.ListS5A3AccountNames()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "message": err.Error()})
			return
		}
		if body.DryRun {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"ok": true, "message": "预演完成（未执行任何修改）", "dry_run": true,
				"total": len(names), "updated": 0, "failed": 0,
			})
			return
		}
		updated, failed := 0, 0
		for _, name := range names {
			if code, _ := s.adminSvc.ResetPasswordS5A3(name, newPwd); code == models.Err.Ok {
				updated++
			} else {
				failed++
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true, "message": "S5A3 批量重置完成（服务端 bcrypt 已全部更新）", "dry_run": false,
			"total": len(names), "updated": updated, "failed": failed,
		})
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
	// S5A3 下删号是被明确禁止的能力，用 409（能力不可用）而不是 500 ——
	// 这不是服务端错误，是"这个部署不支持这个动作"。
	case errors.Is(err, database.ErrS5A3AccountDeleteUnsupported):
		return http.StatusConflict, map[string]interface{}{
			"ok": false, "code": "unsupported", "message": err.Error()}
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
//
// 三类流水一起说：注册奖励 / 反作弊 / 注册流水（register_logs）。
// 注册流水还有个副作用必须让管理员知道 —— 清掉它等于**返还该 IP / 机器码的注册配额**。
func deleteLogsSuffix(p *database.AccountDeletePreview) string {
	if p.PurgedLogs {
		return "，审计流水（奖励/反作弊/注册）已一并清理，该 IP/机器码的注册配额随之释放"
	}
	if p.BonusLogs > 0 || p.AntiCheatRows > 0 || p.RegisterRows > 0 {
		return fmt.Sprintf("；保留审计流水 %d 条奖励 / %d 条反作弊 / %d 条注册（如需清理请勾选清理流水）",
			p.BonusLogs, p.AntiCheatRows, p.RegisterRows)
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
		rows[i] = map[string]interface{}{
			"name": e.Name, "reason": e.Reason, "banned_at": e.BannedAt,
			// scope（三服合一，2026-10-24）：global = 三服同封，其余 = 只封该服
			"scope": e.Scope,
		}
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
		// Scope 是封禁范围（三服合一，2026-10-24）：
		// "global"（缺省）= 三服同时封；"s4a21"/"s5a3"/"s5a95" = 只封该服。
		Scope *string `json:"scope"`
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

	reason := deref(body.Reason, "")
	scope := strings.TrimSpace(deref(body.Scope, ""))
	if scope == "" {
		scope = database.BanScopeGlobal
	}

	if err := s.db.BanAccountScoped(account, reason, scope); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	// 记录账号事件（供从网关同步）。
	// 只有 global 封禁才需要广播到其它服；分服封禁留在本服。
	// 写流水失败不影响封禁本身（封禁已落库）。
	if err := s.db.RecordAccountEvent(database.AccountEventBan, account, reason, scope); err != nil {
		s.logger.Warn("记录账号事件(ban)失败: " + err.Error())
	}

	kicked, _ := s.sessions.Kick(account)
	session.LogKickAccount(account, s.logger)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "kicked": kicked, "scope": scope})
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

	account := strings.TrimSpace(*body.Account)
	removed, _ := s.db.UnbanAccount(account)

	// 记录账号事件（供从网关同步解封）
	if removed {
		if err := s.db.RecordAccountEvent(database.AccountEventUnban, account, "", database.BanScopeGlobal); err != nil {
			s.logger.Warn("记录账号事件(unban)失败: " + err.Error())
		}
	}
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

// handleAdminServerPvf 替换**服务端使用的** PVF（明文，DfoServer 读的那份）。
//
// ★★ 2026-09-30 方案调整后的边界（别再把两者合并回去）：
//
//	「替换服务端 PVF」（本端点）→ 服务端文件夹。**不**登记客户端校验指纹、
//	    **不**生成增量包、**不**写版本历史、**不**通知网关。
//	「上传 PVF」（/api/admin/upload-pvf）→ 网关侧保存的「客户端基准」
//	    （将来可换成加密版）。客户端的校验指纹 / 增量更新 / 版本历史围绕它。
//
// 两条路径必须指向**不同文件**。指向同一个文件时，本端点会把客户端的 `.bak`
// 覆盖成新版自己 ⇒ rebuildDelta 产出 from==to 的自差分 ⇒ 全体旧版客户端进不去
// —— 这正是 09-30 那次线上事故。所以这里加一道硬守卫，宁可拒绝也不留隐患。
func (s *Server) handleAdminServerPvf(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	// 路径守卫放在解析 multipart **之前**：先把不允许的操作挡掉，连文件都不收。
	target, err := s.serverMgr.ResolvePvfPath()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	if managed := s.pvfSvc.PvfPath(); sameFilePath(target, managed) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false,
			"message": fmt.Sprintf(
				"拒绝替换：服务端 PVF 与网关管理的客户端 PVF 指向同一个文件（%s）。"+
					"在此配置下替换服务端 PVF 会覆盖客户端的增量基线 .bak，"+
					"生成「新版→新版」的自差分，导致旧版客户端全部进不去。"+
					"请把「客户端基准」（Pvf.FilePath）与服务端 PVF 配到不同文件"+
					"（服务端用明文、网关侧存客户端基准），或改用「上传 PVF」。", target),
		})
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
	if !result.Ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "error": result.Error})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "path": result.Path, "hash": result.Hash, "algo": result.Algo,
		"size": result.Size, "modified_utc": result.ModifiedUtc,
		"note": "仅更新服务端使用的 PVF；客户端校验指纹与增量更新不受影响",
	})
}

// handleAdminServerPvfInfo 读服务端 PVF 的当前落盘信息。
//
// 与 /api/pvf/info（客户端基准）**刻意分开**：这两份是不同文件、各自独立版本，
// 页面必须分别显示，否则运维会以为改一个另一个跟着变。
func (s *Server) handleAdminServerPvfInfo(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	info, err := s.serverMgr.ServerPvfInfo()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "path": info.Path, "hash": info.Hash, "algo": info.Algo,
		"size": info.Size, "modified_utc": info.ModifiedUtc,
		"client_path": s.pvfSvc.PvfPath(),
	})
}

// sameFilePath 判断两个路径是否指向同一个文件。
//
// 优先用 os.SameFile（能识破软链/不同写法的同一路径）；文件还没落盘时
// 退化为 Clean 后比较 —— 保守方向正确：认不出「相同」只是少拦一次，
// 认错「相同」会挡住正常上传。
func sameFilePath(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(fa, fb)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func (s *Server) handleAdminServerBackup(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	// body 可以是空的（更新流程向导第 8 步与旧前端发的就是 {}），
	// 这时走默认目标集 = 两个库 + PVF，行为与改造前一致。
	//
	// ★ 空 body 不能判成 400：io.EOF 是「没有内容」而不是「内容坏了」。
	var body struct {
		Targets []string `json:"targets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "请求体不是合法 JSON"})
		return
	}

	result := s.serverMgr.BackupWith(service.BackupOptions{Targets: body.Targets})
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": result.Ok, "error": result.Error, "result": result})
}

// handleAdminBackupTargets 列出可备份目标（只读）。
//
// 备份是"选了什么就备什么"的操作，前提是先让人看见有哪些东西可备、
// 每个现在多大多新、路径解析到了哪 —— 勾一个不存在的文件必须当场看得出来。
func (s *Server) handleAdminBackupTargets(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	targets := s.serverMgr.ListBackupTargets()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "count": len(targets), "items": targets,
	})
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
		"max_instances": lv.MaxInstances,
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
		MaxInstances *int    `json:"max_instances"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数错误"})
		return
	}

	// 交给运行时配置后端：它负责"改内存 + 落盘 override"，且必须作用在
	// **网关进程**的内存上（版本门禁由网关执行），否则后台改了不生效。
	changed, err := s.runtime.SetLauncher(body.MinVersion, body.DownloadUrl, body.UpdateNotice, body.MaxInstances)
	if err != nil {
		s.logger.Error(fmt.Sprintf("[Admin] Launcher 配置更新失败: %v", err))
		// 值域错误是**用户输入问题**，回 400 并原样透出原因（同 heartbeat / register-limit）。
		// 后台按 400 才能在输入框旁提示"取值必须在 0~32 之间"，而不是弹一个含糊的失败。
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "取值必须在") {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]interface{}{
			"ok": false, "message": err.Error(),
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

// ==================== 注册限额（2026-10-13）====================
//
// 判定发生在**网关进程**的 TCP 注册路径上（service.CheckRegisterLimit），
// 所以权威值只在网关内存里。admin 进程必须经运行时配置后端转发，
// 让它改自己的副本会出现「后台显示已改、注册照旧不拦」的静默失效。

func (s *Server) handleAdminRegisterLimitGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	rv, err := s.runtime.RegisterLimit()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":             true,
		"enabled":        rv.Enabled,
		"per_ip_per_day": rv.PerIPPerDay,
		"per_machine":    rv.PerMachine,
		"override_file":  config.OverrideFileName,
	})
}

func (s *Server) handleAdminRegisterLimitPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Enabled     *bool `json:"enabled"`
		PerIPPerDay *int  `json:"per_ip_per_day"`
		PerMachine  *int  `json:"per_machine"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数错误"})
		return
	}

	changed, err := s.runtime.SetRegisterLimit(body.Enabled, body.PerIPPerDay, body.PerMachine)
	if err != nil {
		s.logger.Error(fmt.Sprintf("[Admin] 注册限额配置更新失败: %v", err))
		// 值域错误是**用户输入问题**，回 400 并原样透出原因，让后台能提示到具体字段；
		// 其它错误（落盘失败等）才是 500。
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "取值必须在") {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "changed": changed})
}

// ==================== 心跳超时（2026-10-14）====================
//
// 会话超时清理由**网关进程**的巡检协程执行（每 CheckIntervalSeconds 读一次
// TimeoutSeconds），所以权威值只在网关内存里。admin 进程必须经运行时配置后端转发，
// 改自己的副本会出现「后台显示已改、掉线照旧」的静默失效。
//
// 为什么会有这个开关：超时与登录器心跳周期（30s）必须配套。TimeoutSeconds=60 时
// 只容忍丢 1 拍，一旦玩家侧链路整段不通、或客户端把心跳停掉，玩家就会在"游戏里"
// 被清会话。做成热改之后调这个值**不需要重启网关**（重启 = 全体掉线）。

func (s *Server) handleAdminHeartbeatGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	hv, err := s.runtime.Heartbeat()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":              true,
		"timeout_seconds": hv.TimeoutSeconds,
		"override_file":   config.OverrideFileName,
	})
}

func (s *Server) handleAdminHeartbeatPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		TimeoutSeconds *int `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "参数错误"})
		return
	}

	changed, err := s.runtime.SetHeartbeat(body.TimeoutSeconds)
	if err != nil {
		s.logger.Error(fmt.Sprintf("[Admin] 心跳超时配置更新失败: %v", err))
		// 值域错误是**用户输入问题**，回 400 并原样透出原因（同 register-limit）。
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "取值必须在") {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "changed": changed})
}

// handleAdminRegisterLogs 查注册流水（按 IP 或机器码）。
//
// 用途：玩家来问"为什么我注册不了"时，后台要能立刻看到"这个 IP / 这台机器
// 最近注册了哪些号"。纯读、不依赖网关内存，admin 进程直读自己的 db 句柄即可。
func (s *Server) handleAdminRegisterLogs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.db == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "logs": []interface{}{}})
		return
	}

	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	machine := strings.TrimSpace(r.URL.Query().Get("machine"))
	limit := parseIntParam(r.URL.Query().Get("limit"), 20)

	var (
		logs []database.RegistrationLog
		err  error
	)
	switch {
	case ip != "":
		logs, err = s.db.ListRecentRegistrationLogsByIP(ip, limit)
	case machine != "":
		logs, err = s.db.ListRecentRegistrationLogsByMachine(machine, limit)
	default:
		// 2026-11-01：不再强制要求 ip/machine。
		//
		// 运营来查的时候手里往往只有一个账号名，或者玩家只说了一句"我注册不了"，
		// 逼他们填 IP/机器码等于把功能废掉（这正是"注册流水功能无效"的成因）。
		// 不填就给最近 N 条。
		logs, err = s.db.ListRecentRegistrationLogs(limit)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	// 被拒记录（2026-11-01）：回答"为什么注册不了"。
	// 只有给了 ip 才按 ip 过滤；否则给最近的。查失败不影响主列表。
	rejects, rerr := s.db.ListRecentRegisterRejects(ip, limit)
	if rerr != nil {
		rejects = nil
		s.logger.Warn("查注册被拒流水失败: " + rerr.Error())
	}

	out := make([]map[string]interface{}, 0, len(logs))
	for _, l := range logs {
		out = append(out, map[string]interface{}{
			"account":    l.Account,
			"m_id":       l.MID,
			"ip":         l.IP,
			"machine_id": l.MachineID,
			"created_at": l.CreatedAt,
		})
	}

	rejectsOut := make([]map[string]interface{}, 0, len(rejects))
	for _, j := range rejects {
		rejectsOut = append(rejectsOut, map[string]interface{}{
			"account":     j.Account,
			"ip":          j.IP,
			"machine_id":  j.MachineID,
			"reason_code": j.ReasonCode,
			"reason":      j.Reason,
			"created_at":  j.CreatedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"logs":    out,
		"rejects": rejectsOut,
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

// extractAccountNames 从会话快照里取出账号名。
// G-9（2026-10-04 审查）：GetAllSessions 改为返回值快照后，这里同步改成值切片。
func extractAccountNames(sessions []models.Session) []string {
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

// driverDigest 计算驱动白名单的规范摘要。
//
// ★★ 口径必须与登录器侧 SecurityPolicy.DriverDigest **逐字节一致**。
// 只覆盖 file 与 hash 两列 —— 参与安全判定的就这两列：
// 每项拼 "file\thash"，项间用 "\n" 连接，取 SHA-256 小写十六进制；空名单为 "-"。
//
// 为什么不复用上面 listDigest 的 Go `%v` 口径：那会把结构体**每个字段**
// （含展示名、放行理由、加入时间）都算进摘要 —— 以后往 DriverEntry 加一个纯展示
// 字段就会改变摘要，客户端必须同步改、否则每次都判"缓存被改"而全量重拉。
// 显式格式下，展示与审计字段完全不参与摘要。
func driverDigest(entries []models.DriverEntry) string {
	if len(entries) == 0 {
		return "-"
	}
	var sb strings.Builder
	for i, e := range entries {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(e.FileName)
		sb.WriteByte('\t')
		sb.WriteString(e.Hash)
	}
	return security.HashSHA256Str(sb.String())
}

// composeFingerprint 合成组合指纹。
//
// 任何一段变了，登录器下次拉 policy 就会看到 changed=true 并全量重取 ——
// 所以新增段（如 2026-10-16 的驱动名单 D%s）会让**全体客户端一次性全量重拉**，
// 这是预期行为（它们必须拿到驱动名单才能正确判定），不是故障。
func composeFingerprint(revision int, pvf *models.PvfInfo, white, black, allowed, driver string) string {
	pvfHash := ""
	if pvf != nil {
		pvfHash = fmt.Sprintf("PSHA-256:%s:%d:%s", pvf.Hash, pvf.Size, pvf.ModifiedUtc)
	}
	return fmt.Sprintf("I%d;W%s;B%s;A%s;D%s;%s", revision, white, black, allowed, driver, pvfHash)
}

// ==================== 外挂检测处理函数 ====================

// AntiCheatReportRequest 外挂检测上报请求。
// ReportToken 由登录器下发（放入请求体，与原网关契约一致），
// 是服务端归因依据，缺省或不合法一律 401。
type AntiCheatReportRequest struct {
	ReportToken string `json:"reportToken"`
	Account     string `json:"account"`
	// PlayerName 角色名。客户端从 [Identity] playerName 取（由登录器渲染下发）。
	// 空串是合法值：登录器没渲染该字段、或玩家还在选人界面时都会是空。
	PlayerName string               `json:"playerName"`
	Detections []AntiCheatDetection `json:"detections"`
}

// AntiCheatDetection 单条检测记录。
//
// 末尾两个字段来自新版客户端插件（老客户端不发，缺省为 0，兼容）：
//   - Exempt  ：命中时自研组件（NF.dll / EquipmentSwap.dll）是否在场。只作区分，
//     命中一律照常入库 —— 丢弃会让外挂靠加载同名 DLL 把自己从数据里抹掉。
//   - DedupID ：客户端生成的去重 ID，本期仅存档（见 database 建表处注释）。
//
// 注意 DedupID 在 JSON 里是可能超过 2^53 的整数，浏览器侧（JS）拿到会丢精度；
// 后台只展示不参与计算，且 Go 侧按 uint64 原样收，不受影响。
type AntiCheatDetection struct {
	RuleName       string  `json:"ruleName"`
	Description    string  `json:"description"`
	ActualValue    float64 `json:"actualValue"`
	ThresholdValue float64 `json:"thresholdValue"`
	Timestamp      int64   `json:"timestamp"`
	Evidence       string  `json:"evidence"`
	Exempt         int     `json:"exempt"`
	DedupID        uint64  `json:"dedupId"`
	// RoomNumber / MapID：插件一直在发这两个字段（ACReporter 的 roomNumber / mapId），
	// 而早期网关的结构里没有它们 —— json 解码不报错、直接丢弃。补上之后，
	// 「击杀间隔过短」这类命中才能还原出「在哪张图的哪个房间」。
	// 老客户端不发时为 0，与「城镇/未知」同义，不区分。
	RoomNumber int `json:"roomNumber"`
	MapID      int `json:"mapId"`
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
	// 角色名是「报文级」字段（一批检测同属一次会话快照），逐条冗余写进每一行，
	// 明细查询才能按角色直接过滤，不必再回表拼报文。
	//
	// ★ 角色名**由网关解析**，不用客户端自报的值：插件读不到角色名（客户端里账号/角色名
	// 加密存放，且明文副本没有任何静态指针指向，详见 database.CurrentRoleName 的注释）。
	// 这里取「账号 → 当前角色」，与 /api/launcher/online 的在线角色同一口径；
	// 本 handler 已校验 reportToken，此刻该账号必然在线，推定成立。
	now := time.Now().Unix()
	fromDB := ""
	if s.db != nil {
		fromDB = s.db.CurrentRoleName(account)
	}
	playerName, roleMismatch := pickPlayerName(req.PlayerName, fromDB)
	if roleMismatch {
		s.logger.Warn(fmt.Sprintf("[AntiCheat] role_name_mismatch: 会话=%s 客户端自报=%s 网关解析=%s IP=%s",
			account, strings.TrimSpace(req.PlayerName), fromDB, clientIP))
	}
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
			Exempt:         d.Exempt,
			DedupID:        int64(d.DedupID),
			RoomNumber:     d.RoomNumber,
			MapID:          d.MapID,
			PlayerName:     playerName,
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

// pickPlayerName 决定最终入库的角色名，并回报两个来源是否不一致。
//
// 优先级：客户端自报 > 网关解析。
//   - 客户端自报非空 → 用它。它是那个进程的真实角色，比任何推定都准；
//   - 否则用网关解析值（当前唯一可用的来源，插件恒为空串）；
//   - 两个都有值但不相等 → 仍然用客户端的，但把 mismatch 回报给调用方打 Warn
//     —— 那条日志是「插件终于读到角色名了」的唯一信号，别把它静默掉。
//
// 做成纯函数是为了能直接断言优先级，不必起一整套 Server + 库 + 会话。
func pickPlayerName(clientName, fromDB string) (name string, mismatch bool) {
	client := strings.TrimSpace(clientName)
	server := strings.TrimSpace(fromDB)
	if client == "" {
		return server, false
	}
	return client, server != "" && server != client
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
	// Exempt=1 表示这条命中发生时自研组件在场，后台据此打「豁免」标记。
	Exempt int `json:"exempt"`
	// Account 是会话解析出来的账号（可信）；PlayerName 是客户端自报的角色名（可能为空）。
	// 后台「检测明细」要按这两项区分与筛选，所以必须回传，不能只靠玩家汇总页。
	Account    string `json:"account"`
	PlayerName string `json:"playerName"`
	// RoomNumber / MapID 触发时所在房间号与地图ID。0 = 客户端未提供（老客户端）。
	RoomNumber int `json:"roomNumber"`
	MapID      int `json:"mapId"`
}

// toAntiCheatResponses 把库记录转成后台响应体。
//
// 两个 handler（全表明细 / 单账号明细）共用这一份转换，避免以后加字段时
// 只改一处、另一个接口悄悄少一个字段。
func toAntiCheatResponses(detections []database.AntiCheatDetection) []AntiCheatDetectionResponse {
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
			Exempt:         d.Exempt,
			Account:        d.Account,
			PlayerName:     d.PlayerName,
			RoomNumber:     d.RoomNumber,
			MapID:          d.MapID,
		}
	}
	return resp
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
	q := r.URL.Query()
	limit := parseLimit(q.Get("limit"), 50)
	offset := parseOffset(q.Get("offset"))

	// 筛选参数（全部可选）。空值 = 该条件不生效。
	// 对外用短参数名（role / rule），避免把库列名直接暴露给前端。
	f := database.AntiCheatFilter{
		Account:    strings.TrimSpace(q.Get("account")),
		PlayerName: strings.TrimSpace(q.Get("role")),
		RuleName:   strings.TrimSpace(q.Get("rule")),
		Keyword:    strings.TrimSpace(q.Get("keyword")),
		Since:      parseInt64Seconds(q.Get("since")),
		Until:      parseInt64Seconds(q.Get("until")),
	}
	// exempt 缺省 = 不限；只有显式给 0/1 才过滤。
	// 用指针传是为了避开「零值 0 静默变成『只看非豁免』」这个陷阱。
	if v, ok := parseOptionalInt(q.Get("exempt")); ok && (v == 0 || v == 1) {
		f.ExemptFilter = &v
	}

	detections, total, err := s.db.QueryAntiCheatDetections(f, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "detections": toAntiCheatResponses(detections),
		"total": total, "limit": limit, "offset": offset,
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

	q := r.URL.Query()
	limit := parseLimit(q.Get("limit"), 50)
	offset := parseOffset(q.Get("offset"))

	// 账号来自 URL 路径（必定非空）；角色名与其它条件作为附加过滤。
	f := database.AntiCheatFilter{
		Account:    account,
		PlayerName: strings.TrimSpace(q.Get("role")),
		RuleName:   strings.TrimSpace(q.Get("rule")),
		Keyword:    strings.TrimSpace(q.Get("keyword")),
		Since:      parseInt64Seconds(q.Get("since")),
		Until:      parseInt64Seconds(q.Get("until")),
	}
	if v, ok := parseOptionalInt(q.Get("exempt")); ok && (v == 0 || v == 1) {
		f.ExemptFilter = &v
	}

	detections, total, err := s.db.QueryAntiCheatDetections(f, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "account": account,
		"detections": toAntiCheatResponses(detections), "total": total,
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

// parseOptionalInt 解析可选的整数筛选参数。
//
// 返回 ok=false 表示「参数没给 / 非法」= 该条件不生效。刻意与「给了 0」区分开：
// 筛选 exempt=0（只看非豁免）是合法需求，不能和「没给」混为一谈。
func parseOptionalInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseInt64Seconds 解析可选的秒级时间戳筛选参数。
// 空串 / 非法 / <=0 一律返回 0（= 该条件不生效）。
func parseInt64Seconds(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
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
