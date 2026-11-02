package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"s4a21-gateway/pkg/backends"
	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/httprouter"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/proxy"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/service"
)

// main 是管理后台独立进程（systemd 单元 s4a21-admin）。
//
// 它存在的唯一理由：**让"更新管理后台"不再需要重启网关**。
// 原先管理后台与网关同进程，任何后端改动都要重启 gateway，
// 而重启会断开 TCP 8000 / 8001 / 20001+ 上的全部连接 → 在线玩家掉线。
//
// 本进程只做三件事：
//  1. 提供 8443 的管理 API + 静态页（wwwroot，路径与分离前完全一致，前端零改动）；
//  2. 直连 gateway.db 做账号/封禁/流水等纯数据库操作，本地执行 systemctl；
//  3. 把少数依赖**网关进程内存**的能力（在线名单、踢人、PVF 缓存、端口表实际监听、
//     登录器版本门禁、维护模式）经内部 API（默认 127.0.0.1:18080）转发给网关。
//
// ⚠️ 运行硬约束（写错会出各种诡异问题）：
//  1. **WorkingDirectory 必须是网关目录**（/opt/gateway）：
//     `wwwroot`、`./Data`、`./logs` 都是相对路径，且本进程要读网关写的
//     `./logs/gateway.log` 来展示"网关日志"。
//  2. **不要调用 db.EnsureInitialized()**：建表由网关负责。两个进程同时跑迁移
//     会互相抢 SQLite 写锁。本进程只借用已有表结构。
//  3. **不要调用 bonusSvc.Start()**：那是网关的泡点/发放后台循环，
//     在两个进程里各跑一遍会导致重复发放。
//  4. **不要调 portConfig.StartWatching()**：网关已经在 watch 同一个文件并 reload，
//     这里再 watch 会因为同一份变更触发两次 reload（第二次的"新开/关闭"明细为空）。
func main() {
	configPath := "./appsettings.json"
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
		}
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 配置加载失败: %v\n", err)
		os.Exit(1)
	}
	if err := validateAdminConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 配置校验失败: %v\n", err)
		os.Exit(1)
	}

	// 日志写到**独立目录**：网关的 ./logs/gateway.log 是网关写的文件，
	// 管理后台的"网关日志"页读的就是它，绝不能被本进程的日志污染。
	logDir := "./logs-admin"
	lvl, _ := logger.ParseLevel("Information")
	log, err := logger.NewConsoleLogger(logDir, lvl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 日志初始化失败: %v\n", err)
	}
	logger.SetGlobal(log)

	// 数据库：借用网关建好的表，不建表
	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               cfg.Database.Path,
		GamePath:           cfg.Database.GamePath,
		WalMode:            cfg.Database.WalMode,
		BusyTimeoutSeconds: cfg.Database.BusyTimeoutSeconds,
		// S5A3 的 MariaDB 游戏库（全服邮件/泡点/注册奖励/角色查询用）。
		// 留空 = 该部署没有 S5A3 后端，相关功能会明确报"未配置"。
		GameDSN:         cfg.S5A3GameDSN(),
		GameTablePrefix: cfg.S5A3TablePrefix(),
	})
	if err != nil {
		log.Fatal(fmt.Sprintf("数据库初始化失败: %v", err))
		os.Exit(1)
	}
	defer db.Close()

	// 内部 API 客户端（网关侧）
	internalHost := cfg.ResolveInternalListenAddress()
	client := backends.NewClient(internalHost, cfg.Gateway.InternalPort, cfg.Admin.InternalKey)
	log.Info(fmt.Sprintf("内部 API 目标: %s", client.BaseURL()))

	// 启动自检：连不上只告警不退出 —— 网关可能正在重启，admin 应当自愈。
	// 受影响的只是"依赖网关内存"的那几个接口，其余管理功能照常可用。
	if err := client.Ping(); err != nil {
		log.Error(fmt.Sprintf("[Internal] 启动自检失败：网关内部 API 暂不可达（%v）。"+
			"在线列表/踢人/PVF/端口表等功能将返回错误，其余管理功能不受影响。", err))
	} else {
		log.Info("[Internal] 网关内部 API 连通正常")
	}

	// ---- 纯 db / systemctl / 文件类服务：本进程各持一份，与网关互不干扰 ----
	accountSvc := service.NewAccountService(db, cfg, log)
	adminSvc := service.NewAdminService(db, cfg, log)
	banSvc := service.NewBanService(db, nil)

	// QQ 号绑定：admin 侧**只做解绑，不发信**（sender 传 nil）。
	//
	// 复用同一个服务而不是在后台另写一份"直连数据库删一行"，
	// 是为了让解绑走同一套日志、错误映射和幂等判断 ——
	// 两条路径各写一遍，早晚会在"解绑不存在的绑定该报什么错"上分叉。
	qqBindSvc := service.NewQQBindService(db, nil, cfg, log)
	// pvfSvc 只用来做 PVF **文件操作**（上传/注册/注销）；
	// 指纹缓存的读取与重算走网关（见下方的 pvf 后端注入）。
	pvfSvc := service.NewPvfService(cfg, log)
	integritySvc := service.NewIntegrityStore(filepath.Dir(configPath), log)
	registerBonusSvc := service.NewRegisterBonusService(db, cfg, log)
	bonusSvc := service.NewBonusService(db, cfg, log)
	deviceSvc := service.NewDeviceCredentialService(db, cfg, log)
	serverMgr := service.NewServerManager(cfg, log)
	gatewayMgr := service.NewGatewayManager(cfg, log, ".")
	settingsEditor := service.NewAppSettingsEditor(filepath.Dir(configPath), cfg)

	// 「启停服务 / 重启网关」按钮依赖**宿主机**的 polkit 规则（不在二进制里）。
	// 规则缺失时按钮会以一句 "Interactive authentication required" 静默失败，
	// 所以启动时自检一次并给出修复命令（不阻断启动，启停只是功能之一）。
	service.PreflightSystemdControl(cfg, log)

	// 端口配置存储（**只读**）。
	//
	// onChange 传 nil、且不调 StartWatching，是有意为之：
	// 这个 store 在本进程里只负责把 proxy_ports.json 读给管理页看。
	// "保存并生效"整体交给网关（见 RemotePortsBackend.Apply）——网关才是
	// 持有监听器的一方，也是唯一该写这个文件的一方。
	// 若让 admin 也写，网关的文件轮询会抢先把变更 apply 掉，导致管理页
	// 拿到的"新开/关闭"明细为空（详见 pkg/backends/remote.go 的说明）。
	portConfig := proxy.NewPortConfigStoreBootstrap(
		filepath.Dir(configPath),
		nil,
		proxy.BuildBootstrapPortConfig(cfg))

	// TLS（与网关保持一致：Tls.Enabled 时管理端口也走 HTTPS）
	var cert *tls.Certificate
	if cfg.Tls.Enabled {
		c, err := security.LoadCertificate(cfg.Tls.CertFormat, cfg.Tls.CertPath, cfg.Tls.CertKeyPath, cfg.Tls.CertPassword)
		if err != nil {
			log.Fatal(fmt.Sprintf("[TLS] 证书加载失败: %v", err))
			os.Exit(1)
		}
		cert = c
		log.Info("[TLS] 管理后台已启用 HTTPS")
	} else {
		log.Warn("[SECURITY] Tls.Enabled=false，管理后台保持明文")
	}

	// sessionMgr 传 nil：本进程不注册 /api/heartbeat 等公开路由，
	// 那些只在网关进程存在（属于玩家链路）。
	//
	// announceSvc 也传 nil：公告配置的快照与弹窗队列都在网关进程，
	// 本进程通过 Backends.Announce（remote）读写；
	// 事件列表 / 弹窗历史是纯历史数据，handler 直接读本进程的 db 句柄。
	server := httprouter.NewServer(cfg, log, db, nil,
		accountSvc, adminSvc, banSvc, pvfSvc, integritySvc,
		registerBonusSvc, bonusSvc, deviceSvc, serverMgr, gatewayMgr, settingsEditor,
		qqBindSvc,
		nil,
		cert, portConfig, httprouter.Backends{
			Sessions: backends.NewRemoteSessionBackend(client),
			Pvf:      backends.NewRemotePvfBackend(client),
			Ports:    backends.NewRemotePortsBackend(client, portConfig),
			Runtime:  backends.NewRemoteRuntimeConfigBackend(client),
			Announce: backends.NewRemoteAnnounceBackend(client),
		})

	// 只起管理端口。玩家链路（8000/8001/20001+/8080）完全不经本进程，
	// 所以本进程重启/升级对在线玩家是透明的 —— 这就是本次改造的目的。
	server.StartAdmin()

	log.Info(fmt.Sprintf("管理后台进程已启动: HTTP %s:%d（内部 API 依赖 %s）",
		cfg.Gateway.AdminHttpListenAddress, cfg.Gateway.AdminHttpPort, client.BaseURL()))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Info(fmt.Sprintf("收到信号 %v，正在关闭管理后台进程...", sig))
	log.Close()
}

// validateAdminConfig 校验管理后台进程的运行前提。
func validateAdminConfig(cfg *config.GatewayConfig) error {
	const defaultAuthKey = "CHANGE-ME-NOW"
	if cfg.Admin.AuthKey == "" || cfg.Admin.AuthKey == defaultAuthKey {
		return fmt.Errorf("管理密钥 Admin.AuthKey 为默认值，拒绝启动")
	}
	if cfg.Gateway.AdminHttpPort <= 0 {
		return fmt.Errorf("Gateway.AdminHttpPort 未配置（管理后台端口，例如 8443）")
	}
	if cfg.Gateway.AdminHttpPort == cfg.Gateway.HttpPort {
		return fmt.Errorf("Gateway.AdminHttpPort 不能与 Gateway.HttpPort 相同")
	}
	if cfg.Gateway.InternalPort <= 0 {
		return fmt.Errorf("Gateway.InternalPort 未配置（内部 API 端口，例如 18080）")
	}
	if !isLoopbackHost(cfg.ResolveInternalListenAddress()) {
		return fmt.Errorf("Gateway.InternalListenAddress 必须是回环地址（当前 %q）",
			cfg.ResolveInternalListenAddress())
	}
	// InternalKey 为空时网关根本不会起内部 API（安全默认），本进程就成了一个
	// "一半功能报错"的后台 —— 与其让它带病运行，不如直接拒绝启动并说清怎么配。
	if strings.TrimSpace(cfg.Admin.InternalKey) == "" {
		return fmt.Errorf("Admin.InternalKey 未配置：内部 API 鉴权密钥为空时网关不会启动内部端口，" +
			"本进程的在线列表/踢人/PVF/端口表/维护模式都会不可用。" +
			"请在 appsettings.json 配置 Admin.InternalKey（或用环境变量 " + config.EnvAdminInternalKey + " 注入）")
	}
	return nil
}

// isLoopbackHost 判断地址是否为本机回环。
func isLoopbackHost(addr string) bool {
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
