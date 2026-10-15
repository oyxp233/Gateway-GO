package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"s4a21-gateway/pkg/auth"
	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/httprouter"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/notify"
	"s4a21-gateway/pkg/proxy"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/service"
	"s4a21-gateway/pkg/session"
)

func main() {
	configPath := "./appsettings.json"
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
		}
	}

	// 加载配置
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 配置加载失败: %v\n", err)
		os.Exit(1)
	}

	// 校验配置
	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 配置校验失败: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	logDir := "./logs"
	lvl, _ := logger.ParseLevel("Information")
	log, err := logger.NewConsoleLogger(logDir, lvl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 日志初始化失败: %v\n", err)
	}
	logger.SetGlobal(log)

	// 初始化数据库
	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               cfg.Database.Path,
		GamePath:           cfg.Database.GamePath,
		WalMode:            cfg.Database.WalMode,
		BusyTimeoutSeconds: cfg.Database.BusyTimeoutSeconds,
	})
	if err != nil {
		log.Fatal(fmt.Sprintf("数据库初始化失败: %v", err))
		os.Exit(1)
	}
	defer db.Close()

	if err := db.EnsureInitialized(); err != nil {
		log.Fatal(fmt.Sprintf("数据库建表失败: %v", err))
		os.Exit(1)
	}

	// 账号迁移
	accountSvc := service.NewAccountService(db, cfg, log)
	migrateResult, err := accountSvc.MigrateAccountsFromGameDb()
	if err != nil {
		log.Error(fmt.Sprintf("账号迁移失败: %v", err))
	} else {
		log.Info(fmt.Sprintf("账号迁移: %s", migrateResult.Message))
	}

	// 创建服务
	adminSvc := service.NewAdminService(db, cfg, log)
	banSvc := service.NewBanService(db, nil)
	pvfSvc := service.NewPvfService(cfg, log)
	integritySvc := service.NewIntegrityStore(filepath.Dir(configPath), log)
	registerBonusSvc := service.NewRegisterBonusService(db, cfg, log)
	bonusSvc := service.NewBonusService(db, cfg, log)

	// QQ 号绑定：发信通道 + 绑定业务（2026-09-24）。
	//
	// Mailer 是"没配就不启用"的：Smtp.Enabled=false 或缺授权码时，
	// 绑定类命令会明确返回"邮件服务未开启"，而不是让网关启动失败。
	// 启动日志把状态打全 —— "看着开了其实发不出去"（Enabled=true 但忘了注入
	// 环境变量）是最难排查的一种，这里主动告警。
	mailer := notify.NewMailer(cfg.Smtp)
	if mailer.Enabled() && !mailer.PasswordConfigured() {
		log.Warn("[SMTP] Smtp.Enabled=true 但授权码为空：请用环境变量 S4A21_SMTP_PASS 注入，" +
			"否则绑定 QQ 的验证码一封都发不出去")
	}
	log.Info(fmt.Sprintf("[SMTP] 发信通道 enabled=%v host=%s port=%d user=%s 授权码已注入=%v",
		mailer.Enabled(), cfg.Smtp.Host, cfg.Smtp.Port, cfg.Smtp.Username, mailer.PasswordConfigured()))
	qqBindSvc := service.NewQQBindService(db, mailer, cfg, log)
	deviceSvc := service.NewDeviceCredentialService(db, cfg, log)
	serverMgr := service.NewServerManager(cfg, log)
	gatewayMgr := service.NewGatewayManager(cfg, log, ".")
	settingsEditor := service.NewAppSettingsEditor(filepath.Dir(configPath), cfg)

	// 全服公告服务：配置快照 + 事件落库 + 弹窗队列，**只有本进程持有**。
	// 它必须早于 httpServer 启动，因为内部 API 的 pull 路径直接读它的内存快照。
	announceSvc := service.NewAnnounceService(db, log)
	announceSvc.Start()
	defer announceSvc.Stop()

	// 注册奖励和泡点默认配置。
	// 注意：bonusSvc.Start() 不在这里调 —— 泡点按「玩家真实在游戏频道内的
	// 时长」计费，必须先拿到会话管理器（见下面 SetSessionManager），
	// 否则主循环第一轮就会因为看不到会话表而空转告警。
	registerBonusSvc.EnsureDefaultFile()
	bonusSvc.EnsureDefaultFile()

	// PVF 预热
	go func() {
		if err := pvfSvc.RefreshCache(); err != nil {
			log.Error(fmt.Sprintf("[PVF] 启动预热失败: %v", err))
		}
	}()

	// 会话管理器
	var channelListenerStarted = false
	sessionMgr := session.NewSessionManager(
		func() {
			if !channelListenerStarted {
				channelListenerStarted = true
			}
		},
		func() {},
	)

	// 泡点计费依赖会话表（要判断玩家是否真的在游戏频道里），
	// 所以必须等会话管理器建好再注入并启动。
	bonusSvc.SetSessionManager(sessionMgr)
	bonusSvc.Start()

	// TLS 证书
	var cert *tls.Certificate
	if cfg.Tls.Enabled {
		c, err := security.LoadCertificate(cfg.Tls.CertFormat, cfg.Tls.CertPath, cfg.Tls.CertKeyPath, cfg.Tls.CertPassword)
		if err != nil {
			log.Fatal(fmt.Sprintf("[TLS] 证书加载失败: %v", err))
			os.Exit(1)
		}
		cert = c
		log.Info(fmt.Sprintf("[TLS] HTTP 服务已启用 HTTPS"))
	} else {
		log.Warn("[SECURITY] Tls.Enabled=false，HTTP 服务保持明文")
	}

	// TCP 认证服务器
	authHandler := auth.NewHandler(accountSvc, adminSvc, sessionMgr, registerBonusSvc, qqBindSvc, cfg, log)
	authServer := auth.NewServer(cfg, authHandler, log, cert)
	if err := authServer.Start(); err != nil {
		log.Fatal(fmt.Sprintf("TCP 认证服务器启动失败: %v", err))
		os.Exit(1)
	}

	// 代理服务器
	var proxyServer *proxy.ProxyServer
	portConfig := proxy.NewPortConfigStoreBootstrap(filepath.Dir(configPath), func(newConfig *proxy.ProxyPortConfig) proxy.ReloadResult {
		if proxyServer != nil {
			return proxyServer.ReloadPorts(newConfig)
		}
		return proxy.ReloadResult{}
	}, proxy.BuildBootstrapPortConfig(cfg))
	portConfig.StartWatching()

	// 游戏口准入（方案 D）的凭证校验器：复用 AccountService 的密码判定入口
	// （含迁移账号的空 salt 直比 MD5 分支）。nil 时口令路径不可用，
	// 仅 token 路径生效，且任何"无法验证"都回退旧行为、不会据此拒人。
	proxyServer = proxy.NewProxyServer(cfg, sessionMgr, log, portConfig, accountSvc)
	proxyServer.Start()

	// HTTP 服务器
	//
	// 后端注入：网关进程用 local 实现 —— 直接操作本进程的内存
	//（会话表 / PVF 缓存 / 代理监听状态 / 运行时配置）。
	// 分离后的 admin 进程会换成走内部 API 的 remote 实现，handler 代码不变。
	sessionsBackend := httprouter.NewLocalSessionBackend(sessionMgr, db)
	pvfBackend := httprouter.NewLocalPvfBackend(pvfSvc)
	portsBackend := httprouter.NewLocalPortsBackend(func() map[int]int {
		if proxyServer != nil {
			return proxyServer.GetActivePorts()
		}
		return nil
	}, func() map[int]int {
		if proxyServer != nil {
			return proxyServer.PortConnections()
		}
		return nil
	}, portConfig)
	runtimeBackend := httprouter.NewLocalRuntimeConfigBackend(cfg, settingsEditor, sessionsBackend)
	announceBackend := httprouter.NewLocalAnnounceBackend(announceSvc)

	httpServer := httprouter.NewServer(cfg, log, db, sessionMgr,
		accountSvc, adminSvc, banSvc, pvfSvc, integritySvc,
		registerBonusSvc, bonusSvc, deviceSvc, serverMgr, gatewayMgr, settingsEditor,
		qqBindSvc, announceSvc,
		cert, portConfig, httprouter.Backends{
			Sessions: sessionsBackend,
			Pvf:      pvfBackend,
			Ports:    portsBackend,
			Runtime:  runtimeBackend,
			Announce: announceBackend,
		})

	// 玩家侧（TCP 8000 / HTTP 8080 / 代理 8001+）—— 进程分离后仍然只有这里提供
	httpServer.StartPublic()

	// 内部 API：只绑 loopback，供 s4a21-admin 进程取网关内存状态
	httpServer.StartInternal()

	// 管理后台：默认由独立的 s4a21-admin 进程提供（8443）。
	// 仅当显式打开回滚开关时，网关才自持管理端口。
	if cfg.ShouldServeAdminInProcess() {
		httpServer.StartAdmin()
		log.Warn("[Admin] Gateway.ServeAdminInProcess=true：网关自持管理后台（单进程/回滚模式）。" +
			"正常部署请置 false 并使用 s4a21-admin 进程。")
		// 只有这个回滚形态下，网关进程才会代管「启停服务」按钮 —— 自检一次权限
		service.PreflightSystemdControl(cfg, log)
	} else if strings.TrimSpace(cfg.Admin.InternalKey) == "" {
		// 双进程模式却没配内部密钥 → 内部端口不开、admin 进程也起不来，
		// 结果是谁都不提供管理后台。这属于严重误配，必须喊出来。
		log.Error("[Admin] Gateway.ServeAdminInProcess=false 且 Admin.InternalKey 为空：" +
			"管理后台将无任何进程提供。请配置 Admin.InternalKey 并启动 s4a21-admin 服务。")
	}

	// 启动清理服务
	go func() {
		ticker := newHeartbeatTicker(cfg.Heartbeat.CheckIntervalSeconds)
		// G-16：拿到的是 *Ticker（不是裸 channel），退出时 Stop 掉。
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// 明细打点（2026-10-10）：以前只有「清理超时会话: N」，出事后
				// 回答不了"清的是谁、心跳停了多久、当时在不在游戏里"。
				// 这里逐条打账号 / 停滞秒数 / 游戏连接数，便于回看是不是误清。
				//
				// ★ 超时值走运行时快照（2026-10-14）：原先直接读 cfg.Heartbeat.TimeoutSeconds，
				// 而管理员现在能在后台**热改**它（runtimeConfigBackend.SetHeartbeat 在锁内写）。
				// 继续裸读就是数据竞争（-race 会报），且可能读到半改的值。
				// 走快照还有个好处：改完**下一个 tick 就生效**，不必重启网关（= 不踢人）。
				cleaned, details := sessionMgr.CleanExpiredSessionsWithDetails(cfg.HeartbeatSnapshot().TimeoutSeconds)
				if cleaned > 0 {
					log.Info(fmt.Sprintf("清理超时会话: %d", cleaned))
				}
				for _, d := range details {
					log.Info(fmt.Sprintf("会话超时清理: 账号=%s m_id=%s IP=%s 心跳停滞=%ds 游戏连接=%d 频道连接=%d",
						d.Account, d.MId, d.ClientIP, d.StaleSecs, d.GameConns, d.ProxyConns))
				}
			case <-done:
				return
			}
		}
	}()

	// 日志输出
	log.Info(fmt.Sprintf("网关已启动: TCP %d, HTTP %d, Proxy %d",
		cfg.Gateway.TcpPort, cfg.Gateway.HttpPort, cfg.Gateway.ProxyPort))

	// 等待信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Info(fmt.Sprintf("收到信号 %v，正在关闭...", sig))

	close(done)
	proxyServer.Stop()
	authServer.Stop()
	log.Close()
}

func validateConfig(cfg *config.GatewayConfig) error {
	const defaultAuthKey = "CHANGE-ME-NOW"
	if cfg.Admin.AuthKey == "" || cfg.Admin.AuthKey == defaultAuthKey {
		return fmt.Errorf("管理密钥 Admin.AuthKey 为默认值，拒绝启动。请在 appsettings.json 中设置强密钥。")
	}
	// 已知的示例/弱密钥：不拒绝启动（避免打断既有部署），但必须显著告警。
	// 管理密钥等于后台最高权限（重置密码 / 踢人 / 封号 / 发道具），泄露后果严重。
	if isWeakAuthKey(cfg.Admin.AuthKey) {
		fmt.Fprintf(os.Stderr,
			"[WARN] Admin.AuthKey 是已知示例或弱密钥，强烈建议更换！\n"+
				"[WARN] 推荐不要写进 appsettings.json，改用环境变量 %s 注入（优先级最高）。\n",
			config.EnvAdminAuthKey)
	}
	if cfg.GameServer.PublicIP == "" {
		return fmt.Errorf("GameServer.PublicIP 不能为空")
	}
	if cfg.Gateway.AdminHttpPort < 0 || cfg.Gateway.AdminHttpPort > 65535 {
		return fmt.Errorf("Gateway.AdminHttpPort 必须是 0-65535")
	}
	if cfg.Gateway.AdminHttpPort > 0 && cfg.Gateway.AdminHttpPort == cfg.Gateway.HttpPort {
		return fmt.Errorf("Gateway.AdminHttpPort 不能与 Gateway.HttpPort 相同")
	}

	// 启动参数模板只允许白名单占位符（防密码/密钥回流命令行）
	bad := service.FindUnsupportedLaunchArgsPlaceholders(cfg.GameServer.LaunchArgsFormat)
	if len(bad) > 0 {
		return fmt.Errorf("GameServer.LaunchArgsFormat 含未支持的占位符: %s。仅支持 %v",
			strings.Join(bad, ", "), service.SupportedLaunchArgsPlaceholders)
	}

	// 模板与代码默认值不一致时告警。
	// 历史上 appsettings.json 里残留过一版把 {token} 与常量 1 位置写反的旧模板，
	// 游戏端会拿到写死的 "1" 当 token，表现为“能登录但连不上游戏”，排查成本很高。
	// 这里不拒绝启动（允许运营自定义模板），但把差异显著打出来。
	if strings.TrimSpace(cfg.GameServer.LaunchArgsFormat) != service.DefaultLaunchArgsFormat {
		fmt.Fprintf(os.Stderr,
			"[WARN] GameServer.LaunchArgsFormat 与代码默认模板不一致（当前来自配置文件）。\n"+
				"[WARN] 请确认 {token} 的位置正确，未被常量或其它占位符顶替，否则玩家会登录成功但无法进入游戏。\n")
	}
	return nil
}

// isWeakAuthKey 判定管理密钥是否为已知示例值或明显弱值。
func isWeakAuthKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))

	// 已知的示例/出厂密钥
	known := []string{
		"s4a21-admin-key-2026-secure-random-xyz",
		"change-me-now",
		"changeme",
		"admin",
		"123456",
	}
	for _, bad := range known {
		if k == bad {
			return true
		}
	}

	// 过短
	if len(key) < 16 {
		return true
	}

	// 明显是占位符
	if strings.Contains(k, "change") || strings.Contains(k, "your-") ||
		strings.Contains(k, "placeholder") || strings.Contains(k, "xxxx") {
		return true
	}
	return false
}

// done 全局停止信号。
var done = make(chan struct{})

// newHeartbeatTicker 创建心跳清理定时器。
//
// G-16（2026-10-08，审查报告）：原先返回 `time.NewTicker(...).C` —— 把 Ticker 对象
// 直接丢掉，此后**谁也没法 Stop 它**（循环退出后运行时定时器仍挂到进程结束）。
// 改为返回 *time.Ticker，由调用方 defer Stop。
//
// 顺带挡掉 <=0：`time.NewTicker(0)` 会 panic，而间隔来自外部可改的配置。
func newHeartbeatTicker(intervalSeconds int) *time.Ticker {
	if intervalSeconds <= 0 {
		intervalSeconds = 60
	}
	return time.NewTicker(time.Duration(intervalSeconds) * time.Second)
}
