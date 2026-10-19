package proxy

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/safego"
	"s4a21-gateway/pkg/session"
)

const (
	copyBufferSize = 8192
	maxFrameSize   = 1024 * 1024
)

// 频道列明文布局与 0x12 opcode、ChannelListRewriter 已搬迁至
// adapter_s4a21.go（S4A21ChannelAdapter）；帧头常量见 adapter.go。

// portView 端口映射的只读快照。
//
// 下行热路径（频道列表重写）要读它，配置热加载要换它，所以它必须是
// 不可变对象 + 原子替换。曾经这里是裸 map 一边无锁读一边加锁写，
// 保存端口配置时只要有玩家在拉频道列表，就会命中 Go 运行时的
// "concurrent map read and map write" 致命错误，整个网关进程被打挂。
type portView struct {
	// backendToPublic 后端监听端口 -> 当前启用中的公网端口。
	// 只有 Enabled=true 的条目才在这里，因此它同时也是
	// "哪些端口现在是开放的" 的唯一判据（与监听器一一对应）。
	backendToPublic map[int]int
}

func newPortView() *portView {
	return &portView{backendToPublic: make(map[int]int)}
}

// buildPortView 由端口表构建视图（只收启用且端口合法的条目）。
func buildPortView(gamePorts []GamePortMapping) *portView {
	view := &portView{backendToPublic: make(map[int]int, len(gamePorts))}
	for _, m := range gamePorts {
		if !m.Enabled || m.Public <= 0 || m.Backend <= 0 {
			continue
		}
		view.backendToPublic[m.Backend] = m.Public
	}
	return view
}

// buildPortViewFromResolved 由 appsettings 解析出的 公网->后端 映射构建视图。
func buildPortViewFromResolved(resolved map[int]int) *portView {
	view := &portView{backendToPublic: make(map[int]int, len(resolved))}
	for pub, back := range resolved {
		if pub <= 0 || back <= 0 {
			continue
		}
		view.backendToPublic[back] = pub
	}
	return view
}

// publicFor 返回后端端口当前对应的公网端口，第二个返回值为 false 表示该端口未开放。
func (v *portView) publicFor(backend int) (int, bool) {
	if v == nil {
		return 0, false
	}
	pub, ok := v.backendToPublic[backend]
	return pub, ok
}

// ClosedPortInfo 描述一个在热加载中被关闭的公网端口。
type ClosedPortInfo struct {
	Port              int    `json:"port"`
	OnlineConnections int    `json:"online_connections"`
	Reason            string `json:"reason"`
}

// ReloadResult 描述一次端口表热加载的实际结果。
type ReloadResult struct {
	Opened []int            `json:"opened,omitempty"`
	Closed []ClosedPortInfo `json:"closed,omitempty"`
	Failed map[int]string   `json:"failed,omitempty"`
	Active map[int]int      `json:"active,omitempty"`
}

// GameCredentialVerifier 是游戏口首包凭证校验器（方案 D）。
//
// 由 service 层实现（AccountService.VerifyAccountCredential），proxy 包
// 不直接依赖 database —— 密码判定全网关只有一个入口
// （service.verifyAccountPassword，含迁移账号的「空 salt 直比 MD5」分支），
// 游戏口必须复用它。
//
// 返回值三态：
//   - (true, nil)  凭证匹配；
//   - (false, nil) 确定不匹配（含网关库无此 m_id 的账号）；
//   - (false, err) 无法验证（库故障等）—— 调用方必须回退旧行为，不得据此拒人。
type GameCredentialVerifier interface {
	VerifyAccountCredential(mId, pwdField string) (bool, error)
}

// ProxyServer 管理单个游戏服（Profile）的 Channel/Game 代理端口。
//
// 双服模型（2026-10-16）：一个网关进程持多个 ProxyServer（每个启用的
// GameServers 条目一个，由 ProxyManager 统一装配）。本结构体内的全部
// 配置读取都走 p.profile（该服自己的段），不再有"全网关一个 GameServer"。
type ProxyServer struct {
	config          *config.GatewayConfig
	profile         config.GameServerEntry
	sessionManager  *session.SessionManager
	logger          *logger.ConsoleLogger
	listenAddr      string
	gamePortMap     map[int]int
	ports           atomic.Pointer[portView]
	shutdown        chan struct{}
	wg              sync.WaitGroup
	mu              sync.RWMutex
	channelLock     sync.Mutex
	channelListener net.Listener
	channelCts      chan struct{}
	gameListeners   map[int]net.Listener
	gameCts         map[int]chan struct{}
	gamePorts       map[int]struct{}
	connCounts      map[int]int
	portConfig      *PortConfigStore

	firstReadTimeout   time.Duration
	idleTimeout        time.Duration
	backendConnTimeout time.Duration

	// channelAdapter / gameAdapter 是本服的下行适配器（按 profile.Protocol
	// 在构造时绑定）。nil = 纯透传（协议不是 S5A95 时）。
	channelAdapter DownlinkAdapter
	gameAdapter    DownlinkAdapter

	// gameAuth 是游戏口凭证校验器（方案 D）。nil = 口令路径不可用
	// （仅 token 路径生效；生产环境由 cmd/gateway 注入 AccountService）。
	gameAuth GameCredentialVerifier
	// keepAlivePeriod 是代理两端 TCP 的 SO_KEEPALIVE 探测周期；<=0 表示不开。
	// 它是**发现死连接**的唯一手段 —— 见 TcpKeepAliveSeconds 的注释：
	// 客户端被强杀时不会有 FIN，半开连接只能靠它暴露，否则会一直占着
	// MaxConnectionsPerIP 的槽位直到 IdleTimeoutSeconds 用尽。
	keepAlivePeriod time.Duration
}

// channelPort 返回本服频道口（频道列表转发）的公网监听端口。
// profile.ChannelListenerPort=0（仅单服允许）= 沿用 Gateway.ProxyPort，
// 与改造前逐字节等价。
func (p *ProxyServer) channelPort() int {
	if p.profile.ChannelListenerPort > 0 {
		return p.profile.ChannelListenerPort
	}
	return p.config.Gateway.ProxyPort
}

// NewProxyServer 创建某个游戏服的代理服务器。
//
// profile 是该服的配置（config.GameServers 中的一个条目）；gameAuth 是
// 游戏口首包凭证校验器（方案 D），传 nil 时口令路径不可用（仅 token 路径
// 生效，且任何"无法验证"都回退旧行为，不会据此拒人）。
func NewProxyServer(
	cfg *config.GatewayConfig,
	profile config.GameServerEntry,
	sm *session.SessionManager,
	logger *logger.ConsoleLogger,
	portConfig *PortConfigStore,
	gameAuth GameCredentialVerifier,
) *ProxyServer {
	gamePortMap := profile.GamePortMapResolved()

	// S5A9（DNF95）两个服务端侧差异，在适配器绑定前一次性落地：
	//  1. PROXY protocol 强制关 —— S5A9 的 DfoServer 不认这行头，
	//     发了会把游戏包头当垃圾，全体连不上；
	//  2. 方案 D 首包凭证强制关 —— 首包布局是 S5A9 自己的 GameFrame，
	//     parseGameLoginPacket 解不出来；且 S5A9 后端**自校验 digest**，
	//     准入由后端把关，网关侧只做每 IP 并发限制（回退白名单口径）。
	if profile.Protocol == config.ProtocolS5A95 {
		profile.ProxyProtocol = "off"
		profile.GamePortAuth.Enabled = false
	}

	// 初始视图先按 appsettings 建好；Start() 会用端口表覆盖它。
	// 这样即使退回 appsettings 分支，频道列表过滤也有正确判据。
	initialView := buildPortViewFromResolved(gamePortMap)

	firstReadTimeout := time.Duration(profile.FirstReadTimeoutSeconds) * time.Second
	if profile.FirstReadTimeoutSeconds <= 0 {
		firstReadTimeout = 0
	}

	idleTimeout := time.Duration(profile.IdleTimeoutSeconds) * time.Second
	if profile.IdleTimeoutSeconds <= 0 {
		idleTimeout = 0
	}

	backendConnTimeout := time.Duration(profile.BackendConnectTimeoutSeconds) * time.Second
	if profile.BackendConnectTimeoutSeconds <= 0 {
		backendConnTimeout = 0
	}

	// <=0 视为「不开保活」，保持历史行为（缺省关）。
	keepAlivePeriod := time.Duration(profile.TcpKeepAliveSeconds) * time.Second
	if profile.TcpKeepAliveSeconds <= 0 {
		keepAlivePeriod = 0
	}

	// 初始化端口集合
	gamePorts := make(map[int]struct{})
	for port := range gamePortMap {
		gamePorts[port] = struct{}{}
	}

	srv := &ProxyServer{
		config:              cfg,
		profile:             profile,
		sessionManager:      sm,
		logger:              logger,
		listenAddr:          cfg.Gateway.ListenAddress,
		gamePortMap:         gamePortMap,
		shutdown:            make(chan struct{}),
		gameListeners:       make(map[int]net.Listener),
		gameCts:             make(map[int]chan struct{}),
		gamePorts:           gamePorts,
		connCounts:          make(map[int]int),
		portConfig:          portConfig,
		firstReadTimeout:    firstReadTimeout,
		idleTimeout:         idleTimeout,
		backendConnTimeout:  backendConnTimeout,
		keepAlivePeriod:     keepAlivePeriod,
		gameAuth:            gameAuth,
	}
	srv.ports.Store(initialView)

	// 下行适配器按协议绑定（差异全部收在适配层，热路径无分支）。
	//
	// 两种协议都必须绑频道适配器：网关靠它把频道列表里的 IP/端口改写成
	// 自己的公网值。没绑 = 明文透传后端真实地址 —— 客户端会显示「全部
	// 频道」（后端整张表都在），但点进去连的是内网/非公开端口，一律失败。
	//
	//   S4A21（193 生产口径）：0x12 频道列，日密钥 + zlib + AES-128-ECB，
	//     游戏口无需改写，只绑 channelAdapter。
	//   S5A95：op18 Directory（固定密钥）+ 游戏口 LOGIN 内嵌 Endpoint，
	//     两个适配器都要绑。
	//
	// 其余未知协议一律不绑 —— 转发仍是纯透传，并显式告警：
	// 静默透传是以前"配错协议也能启动、进游戏才发现连不上"的根源。
	switch profile.Protocol {
	case config.ProtocolS4A21:
		srv.channelAdapter = NewS4A21ChannelAdapter(profile, &srv.ports, logger)
	case config.ProtocolS5A95:
		srv.channelAdapter = NewS5A95ChannelAdapter(profile.PublicIP, &srv.ports, logger)
		srv.gameAdapter = NewS5A95GameAdapter(profile.PublicIP, &srv.ports, logger)
	default:
		// logger 可为 nil（单测直构 ProxyServer 时不传），告警前先判空。
		if logger != nil {
			logger.Warn(fmt.Sprintf(
				"游戏服 %q 协议 %q 无下行适配器（只支持 %s / %s）：频道列表地址将按原样透传，客户端会连到后端真实地址",
				profile.Id, profile.Protocol, config.ProtocolS4A21, config.ProtocolS5A95))
		}
	}
	return srv
}

// Start 启动所有代理端口，返回本次游戏口热加载结果（供多服管理器汇总
// 启动报告：哪个服的哪些端口没起来，必须显式可见）。
//
// Game 端口以 proxy_ports.json（PortConfigStore）为准：该文件首次运行时
// 由 appsettings 的 GameServer 段派生生成，此后它就是端口表的唯一真源。
// 若这里直接读 appsettings，管理员在后台保存的端口改动会在下次重启后回滚。
func (p *ProxyServer) Start() ReloadResult {
	// Channel 代理端口（频道列表转发）
	p.StartChannelListener()

	if cfg := p.storedPortConfig(); cfg != nil {
		res := p.ReloadPorts(cfg)
		p.logger.Info("代理服务器已启动")
		return res
	}
	// 端口表不可用（理论上不会走到）：退回 appsettings 的静态端口列表。
	p.logger.Warn("端口表不可用，Game 代理退回 appsettings 的 GameServer.GamePorts")
	p.startGameProxies()
	p.logger.Info("代理服务器已启动")
	return ReloadResult{Failed: map[int]string{}}
}

// storedPortConfig 返回端口表中当前生效的配置，未就绪时返回 nil。
func (p *ProxyServer) storedPortConfig() *ProxyPortConfig {
	if p.portConfig == nil {
		return nil
	}
	return p.portConfig.GetConfig()
}

// Stop 关闭所有代理。
func (p *ProxyServer) Stop() {
	close(p.shutdown)
	p.StopChannelListener()

	p.mu.Lock()
	for port, cts := range p.gameCts {
		close(cts)
		delete(p.gameCts, port)
	}
	for port, listener := range p.gameListeners {
		listener.Close()
		delete(p.gameListeners, port)
	}
	p.mu.Unlock()
	p.wg.Wait()
}

// ReloadPorts 热加载端口表：按新配置开/关监听，并及时刷新频道列表视图。
//
// "开/关端口不影响在线玩家" 靠三条保证：
//  1. 关闭端口只关 net.Listener（停止 accept），已 accept 的连接是独立 socket，
//     其与后端的双向转发照常跑完，不会被踢下线；
//  2. 公网端口不变但后端端口被改（重绑定）时，同样先关旧监听再开新监听，
//     存量连接留在旧后端上跑完，新连接走新后端；
//  3. 原子替换频道列表视图，让被关闭端口的频道从客户端频道列表中消失
//     （下次拉取列表时生效），玩家不能再选到已关闭端口的频道。
//
// 全程只依赖"新配置"作为输入，不读 appsettings，因此后台保存与启动走同一套逻辑。
func (p *ProxyServer) ReloadPorts(newConfig *ProxyPortConfig) ReloadResult {
	res := ReloadResult{Failed: map[int]string{}}
	if newConfig == nil {
		return res
	}

	newGamePortMap := make(map[int]int)
	newGamePorts := make(map[int]struct{})
	declared := make(map[int]bool, len(newConfig.GamePorts))
	for _, mapping := range newConfig.GamePorts {
		if mapping.Public <= 0 || mapping.Backend <= 0 {
			continue
		}
		declared[mapping.Public] = true
		if !mapping.Enabled {
			continue
		}
		newGamePortMap[mapping.Public] = mapping.Backend
		newGamePorts[mapping.Public] = struct{}{}
	}

	// 先算出要关的监听：新表里没有该公网端口，或它的后端端口被改了。
	type closing struct {
		port   int
		reason string
	}
	p.mu.Lock()
	toClose := make([]closing, 0, len(p.gameListeners))
	for port := range p.gameListeners {
		backend, ok := newGamePortMap[port]
		switch {
		case !ok:
			if declared[port] {
				toClose = append(toClose, closing{port, "disabled"})
			} else {
				toClose = append(toClose, closing{port, "removed"})
			}
		case backend != p.gamePortMap[port]:
			toClose = append(toClose, closing{port, "remapped"})
		}
	}
	p.mu.Unlock()

	// 再执行关闭。Close 可能让 accept 循环醒来，故不持锁调用。
	for _, c := range toClose {
		p.mu.Lock()
		if cts, ok := p.gameCts[c.port]; ok {
			close(cts)
			delete(p.gameCts, c.port)
		}
		listener := p.gameListeners[c.port]
		delete(p.gameListeners, c.port)
		online := p.connCounts[c.port]
		// 顺手把计数清掉：端口一关就没人再维护这个值了，下次同一 publicPort 被重新启用时，
		// 新连接会从陈旧旧值起算（p.connCounts[publicPort]++），后台「在线连接数」虚高。
		// 仍活着的旧连接稍后退出时走的是 `n > 1 ? n-1 : delete` 分支，不会把新计数减成负数。
		delete(p.connCounts, c.port)
		p.mu.Unlock()

		if listener != nil {
			listener.Close()
		}
		res.Closed = append(res.Closed, ClosedPortInfo{
			Port:              c.port,
			OnlineConnections: online,
			Reason:            c.reason,
		})
		p.logger.Info(fmt.Sprintf(
			"关闭 Game 代理端口: %d（%s；该端口仍有 %d 个在线连接，保持不断开）",
			c.port, closeReasonLabel(c.reason), online))
	}

	// 启动新端口（含刚被重绑定的）
	for publicPort, backendPort := range newGamePortMap {
		p.mu.RLock()
		_, exists := p.gameListeners[publicPort]
		p.mu.RUnlock()
		if exists {
			continue
		}

		addr := net.JoinHostPort(p.listenAddr, strconv.Itoa(publicPort))
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			res.Failed[publicPort] = err.Error()
			p.logger.Error(fmt.Sprintf("启动 Game 代理失败 %d: %v", publicPort, err))
			continue
		}

		cts := make(chan struct{})
		p.mu.Lock()
		p.gameListeners[publicPort] = listener
		p.gameCts[publicPort] = cts
		p.mu.Unlock()

		p.wg.Add(1)
		go p.acceptGameLoop(listener, publicPort, backendPort, cts)
		res.Opened = append(res.Opened, publicPort)
		p.logger.Info(fmt.Sprintf("Game 代理已启动: %s -> %s:%d",
			addr, p.profile.BackendHost, backendPort))
	}
	sort.Ints(res.Opened)
	sort.Slice(res.Closed, func(i, j int) bool { return res.Closed[i].Port < res.Closed[j].Port })

	// 原子替换只读视图 + 更新内部状态（顺序固定：先换视图，再换映射）
	p.ports.Store(buildPortView(newConfig.GamePorts))

	p.mu.Lock()
	p.gamePortMap = newGamePortMap
	p.gamePorts = newGamePorts
	res.Active = make(map[int]int, len(p.connCounts))
	for port, n := range p.connCounts {
		if n > 0 {
			res.Active[port] = n
		}
	}
	p.mu.Unlock()

	summary := fmt.Sprintf("端口表已应用: 开放 %d 个 Game 端口", len(newGamePorts))
	if len(res.Closed) > 0 {
		summary += fmt.Sprintf("，关闭 %d 个", len(res.Closed))
	}
	if len(res.Failed) > 0 {
		summary += fmt.Sprintf("，失败 %d 个", len(res.Failed))
	}
	p.logger.Info(summary)

	return res
}

// closeReasonLabel 把关闭原因翻译成人话。
func closeReasonLabel(reason string) string {
	switch reason {
	case "disabled":
		return "已停用"
	case "remapped":
		return "后端端口已改绑"
	default:
		return "已从端口表移除"
	}
}

// PortConnections 返回各公网端口当前的在线连接数快照。
func (p *ProxyServer) PortConnections() map[int]int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[int]int, len(p.connCounts))
	for port, n := range p.connCounts {
		result[port] = n
	}
	return result
}

// GetActivePorts 获取当前活跃的代理端口。
func (p *ProxyServer) GetActivePorts() map[int]int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make(map[int]int)
	for port := range p.gameListeners {
		result[port] = p.gamePortMap[port]
	}
	return result
}

// StartChannelListener 打开 Channel 代理端口。
func (p *ProxyServer) StartChannelListener() {
	p.channelLock.Lock()
	defer p.channelLock.Unlock()

	if p.channelListener != nil {
		return
	}

	addr := net.JoinHostPort(p.listenAddr, strconv.Itoa(p.channelPort()))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		p.logger.Error(fmt.Sprintf("启动 Channel 代理失败: %v", err))
		return
	}

	p.channelListener = listener
	p.channelCts = make(chan struct{})
	p.wg.Add(1)
	go p.acceptChannelLoop(listener, p.channelCts)
	p.logger.Info(fmt.Sprintf("Channel 代理已开放: %s", addr))
}

// ChannelListenerUp 返回频道口监听是否真正起来了。
//
// StartChannelListener 失败只记日志不退出进程（单服故障不该拖死整个网关），
// 因此调用方需要这个探针来汇总启动报告 —— 多服模型下某个服起不来
// 必须在启动日志里显式可见，不能静默。
func (p *ProxyServer) ChannelListenerUp() bool {
	p.channelLock.Lock()
	defer p.channelLock.Unlock()
	return p.channelListener != nil
}

// StopChannelListener 关闭 Channel 代理端口。
func (p *ProxyServer) StopChannelListener() {
	p.channelLock.Lock()
	defer p.channelLock.Unlock()

	if p.channelListener == nil {
		return
	}

	close(p.channelCts)
	p.channelListener.Close()
	p.channelCts = nil
	p.channelListener = nil
	p.logger.Info("Channel 代理已关闭(无玩家在线)")
}

func (p *ProxyServer) startGameProxies() {
	seen := make(map[int]bool)
	for _, port := range p.profile.GamePorts {
		if seen[port] {
			continue
		}
		seen[port] = true

		addr := net.JoinHostPort(p.listenAddr, strconv.Itoa(port))
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			p.logger.Error(fmt.Sprintf("启动 Game 代理失败 %d: %v", port, err))
			continue
		}

		cts := make(chan struct{})
		p.mu.Lock()
		p.gameListeners[port] = listener
		p.gameCts[port] = cts
		p.gamePorts[port] = struct{}{}
		p.mu.Unlock()

		backendPort := p.resolveBackendPort(port)
		p.wg.Add(1)
		go p.acceptGameLoop(listener, port, backendPort, cts)
		p.logger.Info(fmt.Sprintf("Game 代理已启动: %s -> %s:%d", addr, p.profile.BackendHost, backendPort))
	}
}

func (p *ProxyServer) acceptChannelLoop(listener net.Listener, cts chan struct{}) {
	defer p.wg.Done()

	for {
		select {
		case <-cts:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-cts:
				return
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return
		}

		p.wg.Add(1)
		// G-1（2026-10-04 审查）：裸 goroutine，panic 会打挂整个网关进程（= 全体掉线）。
		// 见 pkg/safego 的说明。
		safego.Go(p.logger, "proxy.handleChannelClient", func() { p.handleChannelClient(conn) })
	}
}

func (p *ProxyServer) acceptGameLoop(listener net.Listener, publicPort, backendPort int, cts chan struct{}) {
	defer p.wg.Done()

	for {
		select {
		case <-cts:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-cts:
				return
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return
		}

		p.wg.Add(1)
		// G-1（2026-10-04 审查）：同 acceptChannelLoop —— 游戏端口代理 goroutine 也裸跑。
		safego.Go(p.logger, "proxy.handleGameClient", func() {
			p.handleGameClient(conn, publicPort, backendPort)
		})
	}
}

func (p *ProxyServer) handleChannelClient(client net.Conn) {
	defer p.wg.Done()
	defer client.Close()

	remoteIP := GetRemoteIP(client)

	// 接入控制：仅允许已登录玩家 IP
	sessionObj, ok := p.sessionManager.TryGetSessionForChannelProxy(remoteIP)
	if !ok {
		reason := "IP 不在已登录玩家白名单"
		if p.sessionManager.IsIPAllowed(remoteIP) {
			reason = "该 IP 对应会话已全部占用代理连接"
		}
		p.logger.Warn(fmt.Sprintf("拒绝 Channel 连接: %s（%s）", remoteIP, reason))
		return
	}

	// 等待客户端首包
	firstBuf := make([]byte, copyBufferSize)
	firstRead, err := p.readWithTimeout(client, firstBuf, p.firstReadTimeout, "Channel 首包")
	if err != nil || firstRead <= 0 {
		if err != nil {
			p.logger.Warn(fmt.Sprintf("Channel 首包读取超时: %s", remoteIP))
		}
		return
	}

	// 验证会话仍然有效
	if _, valid := p.sessionManager.ValidateToken(sessionObj.Token); !valid {
		p.logger.Warn(fmt.Sprintf("Channel 连接首包等待期间会话已失效: %s (%s)", sessionObj.Account, remoteIP))
		return
	}

	// 登记代理连接
	p.sessionManager.AddProxyConnection(sessionObj, client)
	defer p.sessionManager.RemoveProxyConnection(sessionObj, client)
	p.logger.Info(fmt.Sprintf("Channel 连接验证通过: %s (%s)", sessionObj.Account, remoteIP))

	// 建立后端连接
	backend, err := p.connectBackendTo(p.profile.BackendChannelPort)
	if err != nil {
		p.logger.Warn(fmt.Sprintf("连接游戏后端失败: %v", err))
		return
	}
	defer backend.Close()

	// 先发送首包到后端
	setNoDelay(backend, true)
	setNoDelay(client, true)
	// 客户端侧保活：强杀/崩溃/断网不会有 FIN，靠它让半开连接尽快被判死，
	// 从而释放 MaxConnectionsPerIP 的槽位（而非死等 IdleTimeoutSeconds）。
	setKeepAlive(client, p.keepAlivePeriod)
	if p.proxyProtocolEnabled() {
		if err := p.writeProxyHeader(
			backend, client, p.channelPort()); err != nil {
			p.logger.Warn(fmt.Sprintf(
				"Channel PROXY 头写入失败，放弃连接: %v", err))
			return
		}
	}
	backend.Write(firstBuf[:firstRead])

	// 双向透传
	clientStream := client
	backendStream := backend

	task := make(chan struct{}, 2)

	// 上行
	go func() {
		p.copyWithTimeout(clientStream, backendStream, "Channel 上行")
		task <- struct{}{}
	}()

	// 下行（带帧重写：适配器为 nil 时纯透传）
	go func() {
		p.copyDownlink(backendStream, clientStream, p.channelAdapter, "Channel 下行")
		task <- struct{}{}
	}()

	<-task
}

func (p *ProxyServer) handleGameClient(client net.Conn, publicPort, backendPort int) {
	defer p.wg.Done()
	defer client.Close()

	remoteIP := GetRemoteIP(client)

	// ★★★ 游戏口协议是**服务端先说话**（2026-10-16 线上抓包实证）：
	// 后端一收到 PROXY 头就主动下发 83 字节频道 greeting（内容含频道名
	// ch.10 与 endpoint），客户端收到它才发登录包。因此**后端连接必须
	// 在等首包之前建立**——方案 D 初版把「连后端」挪到首包准入之后，
	// 结果客户端等 greeting、网关等首包，互相干等到客户端超时（线上
	// 实测 1.8~8 秒），就是用户反馈的「进频道/切频道延迟比较高」。
	//
	// 准入依然只认首包凭证：客户端的登录包在准入通过前一个字节都不会
	// 进后端，不通过就地关闭后端连接。代价与旧代码一致——静默连接最多
	// 占一个后端连接直到首包超时（30s）。
	//
	// GamePortAuth 关闭时先按 IP 白名单快拒（与旧代码逐字一致）：那时
	// 白名单是唯一闸门，没必要让扫描器摸到后端。开启时不能预拒——凭证
	// 命中有权放行任意来源 IP（正式服2 事件二误伤的修法）。
	if !p.profile.GamePortAuth.Enabled && !p.sessionManager.IsIPAllowed(remoteIP) {
		p.logger.Warn(fmt.Sprintf("拒绝非白名单 IP 的 Game 连接: %s -> %d", remoteIP, publicPort))
		return
	}

	// 后端连接先于首包建立（连到该公网端口映射的后端游戏端口，而非 Channel 端口）
	backend, err := p.connectBackendTo(backendPort)
	if err != nil {
		p.logger.Warn(fmt.Sprintf("连接游戏后端 %d 失败: %v", backendPort, err))
		return
	}
	defer backend.Close()

	setNoDelay(client, true)
	setNoDelay(backend, true)
	setKeepAlive(client, p.keepAlivePeriod)

	// PROXY protocol：必须在转发客户端首包**之前**写入。服务端会把它读掉，
	// 当作会话的真实远端地址 —— PK 场的 UDP 绑定校验、组队/副本下发给
	// 队友的 P2P 端点、账号的最后登录 IP 三处都依赖它。后端也正是收到它
	// 才下发 greeting，所以这一笔同样不能晚。
	if p.proxyProtocolEnabled() {
		if err := p.writeProxyHeader(backend, client, publicPort); err != nil {
			p.logger.Warn(fmt.Sprintf(
				"Game %d PROXY 头写入失败，放弃连接: %v", publicPort, err))
			return
		}
	}

	// 下行：后端 -> 客户端。**必须在等首包之前启动**——greeting 到达就要
	// 立刻转发给客户端，晚一步客户端就多干等一整轮（S5A9 的 LOGIN 回包
	// 带 Endpoint(地址,端口)，由 gameAdapter 改写；S4A21 无游戏口下行
	// 适配器 = 纯透传）。
	downlinkDone := make(chan struct{})
	go func() {
		p.copyDownlink(backend, client, p.gameAdapter, fmt.Sprintf("Game %d 下行", publicPort))
		close(downlinkDone)
	}()

	// 首包：尽量读齐一个完整帧。
	//
	// 为什么不再是"读一次就转发"（旧行为）：登录包被 TCP 分包切碎时只读到
	// 前半段，m_id 解析必然失败（归属退化成按 IP）；方案 D 要拿首包做准入
	// 判定，更必须按 header 里的 length 字段循环读齐。读不齐（超时/对端
	// 沉默/帧长非法）时把已读字节交还后续逻辑，回退旧行为——不新增任何
	// "杀连接"路径。
	firstBuf, frameComplete := p.readFirstGamePacket(client, publicPort)
	if len(firstBuf) == 0 {
		// 与旧行为一致：首包窗口内一个字节都没收到 ⇒ 关闭代理连接
		// （readFirstGamePacket 内部已打过日志）。
		return
	}

	// 准入判定（方案 D：首包 m_id + 凭证；不满足则回退 IP 白名单或拒绝）
	adm := p.admitGameClient(remoteIP, firstBuf, frameComplete)
	if !adm.allowed {
		if adm.reason == reasonIPNotAllowed {
			// 保持旧日志措辞不变（监控/排障脚本按这行 grep）
			p.logger.Warn(fmt.Sprintf("拒绝非白名单 IP 的 Game 连接: %s -> %d", remoteIP, publicPort))
		} else {
			p.logger.Warn(fmt.Sprintf("拒绝 Game 连接: %s -> %d（%s）", remoteIP, publicPort, adm.reason))
		}
		return
	}

	// 并发槽位，两个维度分开计：
	//   · 凭证准入按 **m_id** 计——加速器/网吧/NAT 共享出口的多个玩家不再
	//     互相挤占（正式服2 事件二：同一出口 IP 半天 49 次连接全被拒），
	//     一个账号最多 MaxConnectionsPerIP 条游戏连接；
	//   · 回退白名单的按 IP 计——与旧行为完全一致。
	//
	// ★ 槽位 defer 必须紧跟 Acquire 注册：后面还有若干 return 路径
	// （后端连接失败等），任何一条漏掉都会让该维度额度被永久占住。
	if adm.authed {
		if !p.sessionManager.TryAcquireGameSlotByMId(adm.mId, p.profile.MaxConnectionsPerIP) {
			p.logger.Warn(fmt.Sprintf("拒绝 Game 连接: %s -> %d（账号 %s 并发已达上限 %d）",
				remoteIP, publicPort, adm.mId, p.profile.MaxConnectionsPerIP))
			return
		}
		defer p.sessionManager.ReleaseGameSlotByMId(adm.mId)
	} else {
		if !p.sessionManager.TryAcquireGameSlot(remoteIP, p.profile.MaxConnectionsPerIP) {
			p.logger.Warn(fmt.Sprintf("拒绝 Game 连接: %s -> %d（单 IP 并发已达上限 %d）",
				remoteIP, publicPort, p.profile.MaxConnectionsPerIP))
			return
		}
		defer p.sessionManager.ReleaseGameSlot(remoteIP)
	}

	// 该公网端口的在线连接计数：关闭端口时用来告知管理员"还有几人在线、不会断开"
	p.mu.Lock()
	p.connCounts[publicPort]++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if n := p.connCounts[publicPort]; n > 1 {
			p.connCounts[publicPort] = n - 1
		} else {
			delete(p.connCounts, publicPort)
		}
		p.mu.Unlock()
	}()

	// ★★ 会话归属。
	//
	// 凭证准入时用准入阶段锁定的会话——含"确定无归属"这一种：口令/token
	// 正确但会话已过期（心跳超时/被踢）的玩家照常放行，只是不记泡点，
	// 也避免错记到同 IP 的别人头上。
	//
	// 回退路径完全走旧逻辑：**优先按首包里的 m_id 精确匹配**，匹配不到才按 IP。
	//
	// 为什么必须这样：客户端 launch_args 第 4 段就是它自己的 m_id，登录包原样带上来。
	// 只按 IP 挑「心跳最新」的会话，在**同一公网 IP 多开**时（一台机器开两个客户端，
	// 或同一路由器后面多个玩家）会把所有游戏连接都算到最活跃的那个账号头上 ——
	// 实测：服务端收到 `Login request parsed: m_id=msp`，网关却记成
	// `Game 连接已建立: msp2`，泡点也因此全发给了 msp2。
	//
	// 解析失败（首包被分包切碎 / 不是登录包 / m_id 含非 ASCII）时**完全回退旧行为**，
	// 所以对既有玩家零退化。
	var sessionObj *models.Session
	route := "ip"
	if adm.sessionDecided {
		sessionObj = adm.session
		if sessionObj != nil {
			route = "m_id"
		} else {
			route = "none"
		}
	} else {
		mId, hasMId := parseGameLoginMId(firstBuf)
		var found bool
		sessionObj, found = p.sessionManager.FindSessionByMId(mId)
		if !hasMId || !found {
			sessionObj, _ = p.sessionManager.TryGetSessionForGameProxy(remoteIP)
		} else {
			route = "m_id"
		}
	}

	// ★ 这条 Game 代理连接同时是**泡点计时的唯一依据**：只要会话上挂着
	// GameProxyConnections（= 玩家真的连上了游戏频道），泡点主循环才累计
	// 时长；这里 defer 断开后计时立即停止。改动本函数的连接登记时机
	// 会直接影响泡点发放，见 session.CollectBonusAwards。
	p.sessionManager.AddGameProxyConnection(sessionObj, client)
	defer p.sessionManager.RemoveGameProxyConnection(sessionObj, client)

	// 首包转发到后端（始终原样转发，解析只是旁路观察）
	backend.Write(firstBuf)

	// sessionObj 可能为 nil（凭证准入但会话已过期 / 归属前被清理）。
	// 旧代码直接解引用 sessionObj.Account 打日志，一旦命中就是空指针 panic，
	// 会把整个网关进程打挂 —— 这里做空值兜底，只影响日志展示。
	joined := "<无归属会话>"
	if sessionObj != nil {
		joined = sessionObj.Account
	}
	// 归属来源 + 准入方式都要打出来：双开同 IP 时「按 m_id 命中」与「回退按 IP」
	// 的后果完全不同，排查「在线/泡点记到别人头上」时这一列就是第一手证据；
	// 准入方式则是方案 D 观察期的核心判据——真实客户端首包到底发 token 还是口令，
	// 全看这一列（不含任何凭证内容，只记形态）。
	p.logger.Info(fmt.Sprintf("Game 连接已建立: %s (%s) -> %d [归属=%s][准入=%s]",
		joined, remoteIP, backendPort, route, adm.cred))

	// 上行：客户端 -> 后端
	p.copyWithTimeout(client, backend, fmt.Sprintf("Game %d 上行", publicPort))

	// 等待下行结束
	<-downlinkDone
}

// gamePacketHeaderSize 是服务端 GamePacketHeader（Pack = 1）的线上长度：
// cmd:u8 + type:u16 + length:u32 + checksum:u32 + seq:u16 + extra:u8 = 14 字节。
const gamePacketHeaderSize = 14

// parseGameLoginMId 从游戏连接首包里取出登录包中的 m_id。
//
// 线上布局（与服务端 Network/Parsers/LoginRequestParser.cs 对齐）：
//
//	[GamePacketHeader 14B][i32 mIdLen][mId bytes][i32 pwdLen][pwd bytes]
//
// 刻意只读不改：首包**始终原样**转发给后端，这里纯旁路观察。
// m_id 目前是纯数字/ASCII（database.AllocateNumericMId），字节序列与 Go 字符串一致；
// 存量带非 ASCII 的账号匹配不上，会安全回退到按 IP 归属。
func parseGameLoginMId(buf []byte) (string, bool) {
	if len(buf) < gamePacketHeaderSize+4 {
		return "", false
	}
	body := buf[gamePacketHeaderSize:]
	n := int(binary.LittleEndian.Uint32(body[:4]))
	// 长度上限与服务端 LoginRequestParser 一致；同时要求数据真的到齐，
	// 否则说明首包不完整 —— 放弃解析，交给调用方回退。
	if n <= 0 || n > 256 || len(body) < 4+n {
		return "", false
	}
	return string(body[4 : 4+n]), true
}

// 游戏口准入（方案 D）的拒绝原因。reasonIPNotAllowed 刻意保持旧日志措辞，
// 监控/排障脚本按原句 grep，不能改。
const (
	reasonIPNotAllowed = "IP 不在已登录玩家白名单"
	reasonCredMismatch = "首包凭证与账号不匹配（疑似冒充）"
)

// gameAdmission 描述一次游戏口准入判定结果。
type gameAdmission struct {
	allowed bool
	// authed = 凭首包凭证（token/口令）准入。决定并发槽位按 m_id 计。
	authed bool
	// mId 是准入依据的账号 m_id（authed 时非空）。
	mId string
	// session / sessionDecided：凭证准入时锁定归属会话。
	// sessionDecided=true 时 session 为 nil = "确定无归属"——凭证正确但
	// 会话已过期的玩家照常放行，只是不记泡点，也避免错记到同 IP 的别人头上。
	session        *models.Session
	sessionDecided bool
	// cred 是准入方式（日志用）：token / pwd / ""（回退白名单）。
	// 只记形态不记内容——观察期靠它确认真实客户端首包凭证形态。
	cred string
	// reason 是拒绝原因（allowed=false 时非空）。
	reason string
}

// admitGameClient 判定一次游戏口连接是否放行（方案 D 核心）。
//
// 背景：后端游戏登录**不校验密码**（LoginHandler 只 GetByMid、陌生 m_id
// 自动建号后直接绑定进选角），频道口后端零鉴权 ⇒ 游戏口准入是账号安全
// 唯一闸门。旧形态只有「IP 白名单」一道，带来两个问题：
//  1. 加速器/跨网段玩家登录 IP ≠ 游戏出口 IP 时被误伤（正式服2 事件二实盘：
//     单账号单日 49 次连接全打频道口/游戏口、全被拒）；
//  2. 已登录用户可伪造首包 m_id 冒充任意账号（网关旧代码不校验首包与
//     来源 IP 的一致性，后端又不验密码）。
//
// 判定矩阵（cfg = GameServer.GamePortAuth）：
//
//	| 首包          | 会话(m_id) | 凭证              | require_credential | 结果            |
//	|---------------|-----------|-------------------|--------------------|-----------------|
//	| 解析失败      | -         | -                 | 任意               | 回退 IP 白名单  |
//	| 登录包        | 有        | token 命中        | 任意               | 放行（任意 IP） |
//	| 登录包        | 有        | 口令匹配          | 任意               | 放行（任意 IP） |
//	| 登录包        | 有        | 不符 / 库故障     | false              | 回退 IP 白名单  |
//	| 登录包        | 有        | 不符              | true               | 拒绝（堵冒充）  |
//	| 登录包        | 无        | 口令匹配          | 任意               | 放行（无归属）  |
//	| 登录包        | 无        | 不符 / 库故障     | false              | 回退 IP 白名单  |
//	| 登录包        | 无        | 不符              | true               | 拒绝           |
//	| 开关关闭      | -         | -                 | 任意               | 回退 IP 白名单  |
//
// "回退 IP 白名单" = 与旧行为完全一致（IsIPAllowed + 按 m_id/IP 归属），
// 所以 RequireCredential=false（缺省）时本方案**不新增任何拒绝路径**，
// 可以在生产上先观察，再收紧。
func (p *ProxyServer) admitGameClient(remoteIP string, firstBuf []byte, frameComplete bool) gameAdmission {
	cfg := p.profile.GamePortAuth
	if !cfg.Enabled || !frameComplete {
		return p.fallbackWhitelist(remoteIP)
	}

	mId, pwd, ok := parseGameLoginPacket(firstBuf)
	if !ok {
		// 首包不是标准登录包（分包未齐/非登录帧/非数字 m_id）——
		// 完全回退旧行为，既有玩家零退化。
		return p.fallbackWhitelist(remoteIP)
	}
	return p.admitByCredential(remoteIP, mId, pwd, cfg)
}

// admitByCredential 首包凭证准入（方案 D）。
//
// 凭证有两种实证形态（161 游戏库 password_hash 实证 + launch_args 模板）：
//  1. **会话 token**（当前客户端）：launch_args 第 5 段就是 {token}，
//     游戏库 81 个"只在游戏库建档"的账号，其 password_hash 全是 64 位 hex
//     —— 与服务端 Create(mId, passwordHash) 原样入库合起来看，客户端首包
//     密码字段的当前形态就是 token。token 每次登录重新生成、不可枚举，
//     且与来源 IP 无关——加速器玩家的登录 IP 与游戏出口 IP 本就不是一个。
//  2. **账号口令 MD5**（老客户端）：与 8000 登录同一判定入口
//     （verifyAccountPassword，含迁移账号的空 salt 直比分支）。
//
// 任一命中即放行（任意来源 IP）；都不命中且 RequireCredential=true 时拒绝
// —— 这正是"已登录用户伪造首包冒充任意账号"的堵法。
func (p *ProxyServer) admitByCredential(remoteIP, mId, pwd string, cfg config.GamePortAuthSection) gameAdmission {
	// 凭证一：会话 token（恒定时间比较；token 长度 64，pwd 形态不符时
	// ConstantTimeCompare 直接按长度不等返回 false）。
	if s, ok := p.sessionManager.FindSessionByMIdAndToken(mId, pwd); ok {
		return gameAdmission{
			allowed: true, authed: true, mId: mId,
			session: s, sessionDecided: true, cred: "token",
		}
	}

	// 凭证二：账号口令。库故障时**不许**因网关自身故障拒人——
	// 告警 + 回退旧行为（与今天完全一致）。
	matched, err := p.verifyAccountCredential(mId, pwd)
	if err != nil {
		p.logger.Warn(fmt.Sprintf("Game 凭证校验失败（网关库故障），回退白名单: m_id=%s err=%v", mId, err))
		return p.fallbackWhitelist(remoteIP)
	}

	if s, ok := p.sessionManager.FindSessionByMId(mId); ok {
		if matched {
			return gameAdmission{
				allowed: true, authed: true, mId: mId,
				session: s, sessionDecided: true, cred: "pwd",
			}
		}
	} else if matched {
		// 会话已过期（心跳超时/被踢）但口令正确：放行，不归属任何会话。
		return gameAdmission{
			allowed: true, authed: true, mId: mId,
			session: nil, sessionDecided: true, cred: "pwd",
		}
	}

	// 凭证不符。注意 p.gameAuth == nil（校验器没接上）时永远走回退——
	// "无法验证"与"验证不通过"必须区别对待，前者不能拒人。
	if cfg.RequireCredential && p.gameAuth != nil {
		return gameAdmission{allowed: false, reason: reasonCredMismatch}
	}
	return p.fallbackWhitelist(remoteIP)
}

// fallbackWhitelist 回退旧行为：IP 白名单是唯一闸门。
// 归属不锁定（sessionDecided=false），由调用方按旧逻辑确定。
func (p *ProxyServer) fallbackWhitelist(remoteIP string) gameAdmission {
	if p.sessionManager.IsIPAllowed(remoteIP) {
		return gameAdmission{allowed: true}
	}
	return gameAdmission{allowed: false, reason: reasonIPNotAllowed}
}

// verifyAccountCredential 走注入的校验器；未注入（nil）时返回 (false, nil)
// —— 无法验证，调用方据此回退，不会误拒。
func (p *ProxyServer) verifyAccountCredential(mId, pwd string) (bool, error) {
	if p.gameAuth == nil {
		return false, nil
	}
	return p.gameAuth.VerifyAccountCredential(mId, pwd)
}

// maxFirstGamePacket 是首包读齐循环的缓冲上限（与服务端 MaxPacketLength 一致）。
// 登录包本身只有几十字节；length 超过它说明不是合法帧长，继续等也不会有
// 完整帧——按"解析失败"处理，避免无限缓冲。
const maxFirstGamePacket = maxFrameSize

// firstFrameComplete 判断已读字节里是否已包含完整首帧。
// sane=false 表示 length 字段非法（等不出完整帧，应按解析失败处理）。
//
// length 字段口径（服务端 FlexiblePacketProcessor）：**含 14 字节头**的
// 整帧长度（packetLength < headerSize 会被服务端直接判非法断开）。
func firstFrameComplete(buf []byte) (complete bool, sane bool) {
	if len(buf) < gamePacketHeaderSize {
		return false, true
	}
	total := int(binary.LittleEndian.Uint32(buf[3:7]))
	if total < gamePacketHeaderSize || total > maxFirstGamePacket {
		return false, false
	}
	return len(buf) >= total, true
}

// readFirstGamePacket 读客户端首包，尽量读齐一个完整帧。
//
// 与旧行为（readWithTimeout 读一次）的差异只在"没读齐"时：旧代码把读到
// 的残缺字节直接转发、按 IP 归属；本函数按 header 的 length 循环读齐，
// 读不齐（超时/对端沉默/帧长非法）时同样返回已读字节 + complete=false，
// 由调用方回退旧行为——不新增任何"杀连接"路径。
//
// 超时是**绝对期限**（进入前一次性 SetReadDeadline）：防止对端慢滴
// （每次只吐一片）把连接无限期持有。未配首包超时（<=0）时保持旧语义——
// 只读一次，读到什么算什么。
func (p *ProxyServer) readFirstGamePacket(client net.Conn, publicPort int) ([]byte, bool) {
	buf := make([]byte, 0, copyBufferSize)
	tmp := make([]byte, copyBufferSize)

	if p.firstReadTimeout > 0 {
		client.SetReadDeadline(time.Now().Add(p.firstReadTimeout))
		defer client.SetReadDeadline(time.Time{})
	}

	for {
		n, err := client.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			done, sane := firstFrameComplete(buf)
			if done {
				return buf, true
			}
			if !sane {
				return buf, false
			}
		}
		if err != nil {
			if len(buf) == 0 {
				p.logger.Warn(fmt.Sprintf("Game %d 首包: %ds 内无任何数据，关闭代理连接",
					publicPort, int(p.firstReadTimeout.Seconds())))
			}
			return buf, false
		}
		if p.firstReadTimeout <= 0 {
			// 未配首包超时：旧语义——只读一次
			return buf, false
		}
	}
}

// parseGameLoginPacket 从游戏连接首包里解析登录包的 (m_id, 口令字段)。
//
// 线上布局（与服务端 Network/Parsers/LoginRequestParser.cs 对齐）：
//
//	[GamePacketHeader 14B: cmd u8, type u16, length u32(含头), checksum u32, seq u16, extra u8]
//	[i32 mIdLen][mId 字节][i32 pwdLen][pwd 字节]
//
// 与 parseGameLoginMId（归属用，宽松）的区别——本函数是**准入**依据，
// 必须严格，四条全满足才认：
//  1. 首帧完整（length 含头、缓冲区够长）；
//  2. 正文恰好两个 DStr、无拖尾（非登录包直接判失败）；
//  3. m_id 非空（服务端口径）；
//  4. m_id 是网关分配的纯数字号（3~10 位，与 database.IsNumericMId 同口径）。
//
// 存量非数字 m_id（老网关"m_id 填账号名"口径）走不到凭证路径，自动落回退
// 分支 = 旧行为，不受影响。口令字段两种实证形态见 admitByCredential 注释，
// 本函数只负责原样取出（GBK 解码对纯 ASCII 的 MD5/token 与 ASCII 一致）。
func parseGameLoginPacket(buf []byte) (string, string, bool) {
	if len(buf) < gamePacketHeaderSize+8 {
		return "", "", false
	}
	total := int(binary.LittleEndian.Uint32(buf[3:7]))
	if total < gamePacketHeaderSize || total > maxFirstGamePacket || len(buf) < total {
		return "", "", false
	}

	body := buf[gamePacketHeaderSize:total]
	off := 0
	mId, ok := readGameDStr(body, &off)
	if !ok || mId == "" {
		return "", "", false
	}
	pwd, ok := readGameDStr(body, &off)
	if !ok {
		return "", "", false
	}
	if off != len(body) {
		// 正文不是恰好两个 DStr ⇒ 不是登录包
		return "", "", false
	}
	if !isNumericMIdStrict(mId) {
		return "", "", false
	}
	return mId, pwd, true
}

// readGameDStr 读一个 [i32 len][bytes] 字段，口径与服务端 TryReadDStr 一致：
// len 允许 0（服务端只要求 mId 非空），上限 256。
func readGameDStr(body []byte, off *int) (string, bool) {
	if *off+4 > len(body) {
		return "", false
	}
	n := int(binary.LittleEndian.Uint32(body[*off : *off+4]))
	*off += 4
	if n < 0 || n > 256 || *off+n > len(body) {
		return "", false
	}
	s := string(body[*off : *off+n])
	*off += n
	return s, true
}

// isNumericMIdStrict 判断是否为网关分配的纯数字 m_id。
// 口径与 database.IsNumericMId（3~10 位数字）一致——那里是权威定义，
// 这里为避免 proxy → database 依赖复制一份；改动时两边同步。
func isNumericMIdStrict(mId string) bool {
	if len(mId) < 3 || len(mId) > 10 {
		return false
	}
	for i := 0; i < len(mId); i++ {
		if mId[i] < '0' || mId[i] > '9' {
			return false
		}
	}
	return true
}

// copyWithTimeout 双向透传，带空闲超时。
func (p *ProxyServer) copyWithTimeout(src, dst net.Conn, context string) {
	buf := make([]byte, copyBufferSize)
	for {
		select {
		case <-p.shutdown:
			return
		default:
		}

		n, err := p.readTimeout(src, buf, p.idleTimeout)
		if err != nil || n <= 0 {
			return
		}

		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

// copyDownlink 下行透传；adapter 非 nil 时按帧交给适配器改写
// （频道口 / 游戏口共用，协议差异在适配器里）。
func (p *ProxyServer) copyDownlink(src, dst net.Conn, adapter DownlinkAdapter, context string) {
	buf := make([]byte, copyBufferSize)
	pending := make([]byte, 0, copyBufferSize)

	if adapter == nil {
		// 纯透传
		p.copyWithTimeout(src, dst, context)
		return
	}

	for {
		select {
		case <-p.shutdown:
			return
		default:
		}

		n, err := p.readTimeout(src, buf, p.idleTimeout)
		if err != nil || n <= 0 {
			return
		}

		// 追加到缓冲区
		pending = append(pending, buf[:n]...)

		// 处理缓冲区（完整帧逐个过适配器，残包返回拼到下一次读）
		pending = adapter.ProcessDownlink(pending, dst)
	}
}

// connectBackendTo 连接到游戏后端的指定端口。
func (p *ProxyServer) connectBackendTo(port int) (net.Conn, error) {
	addr := net.JoinHostPort(p.profile.BackendHost, strconv.Itoa(port))
	var conn net.Conn
	var err error
	if p.backendConnTimeout > 0 {
		dialer := net.Dialer{Timeout: p.backendConnTimeout}
		conn, err = dialer.Dial("tcp", addr)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	// 后端侧同样开保活：服务端进程卡死/重启时，这条连接不会被无限期挂着。
	setKeepAlive(conn, p.keepAlivePeriod)
	return conn, nil
}

// connectBackend 连接到游戏后端 Channel 端口。
func (p *ProxyServer) connectBackend() (net.Conn, error) {
	return p.connectBackendTo(p.profile.BackendChannelPort)
}

func (p *ProxyServer) resolveBackendPort(publicPort int) int {
	if bp, ok := p.gamePortMap[publicPort]; ok {
		return bp
	}
	return publicPort
}

// readWithTimeout 带超时读取数据。
func (p *ProxyServer) readWithTimeout(conn net.Conn, buf []byte, timeout time.Duration, context string) (int, error) {
	if timeout <= 0 {
		return conn.Read(buf)
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			p.logger.Warn(fmt.Sprintf("%s: %ds 内无任何数据，关闭代理连接", context, int(timeout.Seconds())))
		}
		return 0, err
	}
	return n, nil
}

// readTimeout 带空闲超时读取。
// errShutdown 表示转发循环是被进程关闭主动打断的（不是网络错误）。
var errShutdown = errors.New("proxy: server shutting down")

// shutdownPollInterval 是阻塞读的轮询粒度。
//
// ★ 为什么要"切片等待"：GameServer.IdleTimeoutSeconds 默认 1800 秒，而 Stop()
// 只是 close(shutdown) + 关监听；已经建立的连接要靠各自的转发 goroutine 自己退出。
// 若直接 SetReadDeadline(now+1800s) 然后阻塞在 Read 上，shutdown 根本唤不醒它，
// wg.Wait() 就会一直等到 systemd 的 TimeoutStopUSec（90 秒）被 SIGKILL ——
// 表现为每次重启/部署都卡 90 秒、玩家连接处在半死不活的状态。
// 切成 1 秒的小片之后，最多 1 秒即可醒来退出，重启不再拖 90 秒。
const shutdownPollInterval = time.Second

// readTimeout 读一次数据，最长等 timeout。
//
// 语义与「SetReadDeadline(now+timeout) + Read」等价：超时返回错误、读到数据返回 n。
// 区别是等待被切成 shutdownPollInterval 的小片，每片醒来检查一次 shutdown，
// 好让 Stop() 及时唤醒阻塞中的转发 goroutine。
func (p *ProxyServer) readTimeout(conn net.Conn, buf []byte, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		return conn.Read(buf)
	}
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-p.shutdown:
			return 0, errShutdown
		default:
		}

		slice := shutdownPollInterval
		if remain := time.Until(deadline); remain < slice {
			slice = remain
		}
		if slice <= 0 {
			// 整体等待时间用尽且始终没读到数据 → 按空闲超时处理
			return 0, os.ErrDeadlineExceeded
		}

		conn.SetReadDeadline(time.Now().Add(slice))
		n, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue // 只是这一片到点，整体还没到期，继续等
			}
			return 0, err
		}
		return n, nil
	}
}

// GetRemoteIP 从连接获取远端 IP。
func GetRemoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	if host == "" {
		return conn.RemoteAddr().String()
	}
	return host
}

// proxyProtocolEnabled 返回是否向后端写 PROXY protocol v1 头。
//
// 取值：""/"off" = 关（缺省）；"v1"（也接受 1/true/on）= 开。
// 大小写与首尾空白都容忍，免得配置文件里写成 "V1" 变成静默失效。
func (p *ProxyServer) proxyProtocolEnabled() bool {
	switch strings.ToLower(
		strings.TrimSpace(p.profile.ProxyProtocol)) {
	case "v1", "1", "true", "on":
		return true
	default:
		return false
	}
}

// writeProxyHeader 在转发任何客户端字节**之前**，向后端写一行 PROXY protocol v1 头。
//
// 格式（HAProxy 规范，单行、CRLF 结尾）：
//
//	PROXY TCP4 <真实客户端IP> <本机IP> <真实源端口> <目的端口>\r\n
//
// 服务端 MultiStructureTcpServer 会把它读掉并记成会话的真实远端地址；
// 而且**只在连接来自回环地址时**才采信，所以这里不需要额外鉴权 ——
// 网关与服务端同机，非回环连接根本到不了这些后端端口。
//
// 失败一律返回 error，调用方应当**放弃这条连接**而不是继续转发：
// 少写这行头会让服务端拿 127.0.0.1 当客户端地址（PK 场立刻坏掉），
// 写了一半更糟 —— 半行文本会被当成游戏包头，解析失败。
func (p *ProxyServer) writeProxyHeader(backend, client net.Conn, publicPort int) error {
	srcIP, srcPort := splitHostPort(client.RemoteAddr())
	if srcIP == "" {
		return fmt.Errorf("客户端源地址不可用")
	}

	// 目的地址按「客户端看到的公网 IP」上报；未配置时回退到本机出接口地址。
	dstIP := strings.TrimSpace(p.profile.PublicIP)
	if dstIP == "" || dstIP == "0.0.0.0" {
		dstIP, _ = splitHostPort(client.LocalAddr())
	}

	family := "TCP4"
	if ip := net.ParseIP(srcIP); ip != nil && ip.To4() == nil {
		family = "TCP6"
	}

	header := fmt.Sprintf(
		"PROXY %s %s %s %d %d\r\n",
		family, srcIP, dstIP, srcPort, publicPort)
	if _, err := backend.Write([]byte(header)); err != nil {
		return fmt.Errorf("写 PROXY 头失败: %w", err)
	}
	return nil
}

// splitHostPort 把 net.Addr 拆成 IP 文本与端口号；不可用时返回 ("", 0)。
func splitHostPort(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(portText)
	return host, port
}

// setNoDelay 设置 TCP 连接的 NODELAY 选项。
func setNoDelay(conn net.Conn, enabled bool) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(enabled)
	}
}

// setKeepAlive 开启 TCP 保活探测，period > 0 时生效。
//
// ★ 它解决的是「半开连接永久占槽」：客户端被强杀 / 崩溃 / 拔网线时 TCP
// 不会发 FIN，网关侧的连接会一直挂在那里，直到 IdleTimeoutSeconds（默认 1800s）
// 用尽才释放 MaxConnectionsPerIP 的槽位 —— 玩家关掉游戏后重开仍被拒。
// 开了保活后，死连接会在「探测周期 × 探测次数」内被内核判死，
// 后续读立即返回错误 ⇒ 连接关闭 ⇒ 槽位马上释放。
//
// ★ 为什么不用「调小 IdleTimeoutSeconds」代替：那个超时看的是**有没有应用
// 层数据**，纯挂机（站着不动、不发包）的玩家会被误踢；而 keepalive 是传输层
// 探活，对端主机还在就会回 ACK，挂机玩家不受影响。
//
// 非 TCP 连接（测试里的 net.Pipe 等）静默跳过，不影响调用方。
func setKeepAlive(conn net.Conn, period time.Duration) {
	if period <= 0 {
		return
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return
	}
	// 同时设置 TCP_KEEPIDLE 与 TCP_KEEPINTVL；探测次数取系统
	// net.ipv4.tcp_keepalive_probes（部署脚本把它调到 3）。
	_ = tcpConn.SetKeepAlivePeriod(period)
}

// getFd 已删除（2026-09-23）：会话登记改为直接持有 net.Conn，
// 踢下线时逐个 Close 真连接（历史版本只记 fd 句柄数，踢人不断链路）。

func padTo16(data []byte) []byte {
	padding := (16 - len(data)%16) % 16
	if padding == 0 {
		return data
	}
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	return padded
}

func aes128EncryptECB(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Encrypt(encrypted[i:i+16], data[i:i+16])
	}
	return encrypted, nil
}

func aes128DecryptECB(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		block.Decrypt(decrypted[i:i+16], data[i:i+16])
	}
	return decrypted, nil
}

// zlibCompress 压缩数据。
//
// 产出必须与服务端 EncryptTool.ZlibCompress、以及原 .NET 网关完全同口径：
//
//	[0x78][0x9C] + raw deflate + 4B adler32(大端，对原始数据求)
//
// 注意这里的 deflate 是**裸 deflate**（flate.Writer），不能图省事用 zlib.Writer：
// zlib.Writer 会再写一遍 zlib 头，产出 [78 9C][78 9C]... 的"双重头"，
// 客户端按"跳过 2 字节后 raw inflate"解析会直接失败。
func zlibCompress(data []byte) []byte {
	var result bytes.Buffer
	result.WriteByte(0x78)
	result.WriteByte(0x9C)

	if w, err := flate.NewWriter(&result, flate.DefaultCompression); err == nil {
		w.Write(data)
		w.Close()
	}

	checksum := adler32(data)
	result.WriteByte(byte(checksum >> 24))
	result.WriteByte(byte(checksum >> 16))
	result.WriteByte(byte(checksum >> 8))
	result.WriteByte(byte(checksum))

	return result.Bytes()
}

// zlibDecompress 解压游戏端/服务端的压缩体，口径：
//
//	[0x78][0x9C] + raw deflate + 4B adler32(大端)
//
// 必须用 flate.NewReader 解 data[2:len-4]：那一段是裸 deflate，没有 zlib 头。
// 曾经这里用的是 zlib.NewReader，它会把 deflate 的第一个字节当 zlib 头校验，
// 直接返回 "zlib: invalid header" —— 结果是频道列表永远解不开、改写被静默跳过，
// 客户端拿到的还是服务端自报的 IP/端口（网关实际被绕过）。
func zlibDecompress(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("compressed data too short")
	}
	if data[0] != 0x78 {
		return nil, fmt.Errorf("invalid zlib header: 0x%02x", data[0])
	}

	reader := flate.NewReader(bytes.NewReader(data[2 : len(data)-4]))
	decompressed, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return nil, fmt.Errorf("inflate: %w", err)
	}

	stored := uint32(data[len(data)-4])<<24 |
		uint32(data[len(data)-3])<<16 |
		uint32(data[len(data)-2])<<8 |
		uint32(data[len(data)-1])

	if adler32(decompressed) != stored {
		return nil, fmt.Errorf("ADLER32 checksum mismatch")
	}

	return decompressed, nil
}

func adler32(data []byte) uint32 {
	const mod uint32 = 65521
	var a, b uint32 = 1, 0
	for _, v := range data {
		a = (a + uint32(v)) % mod
		b = (b + a) % mod
	}
	return (b << 16) | a
}
