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
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/session"
)

const (
	channelHeaderSize   = 11
	scAskChannelInfoNew = 0x12
	copyBufferSize      = 8192
	maxFrameSize        = 1024 * 1024

	// 频道列表明文布局（与服务端 ChannelProtocolHandler 对齐）：
	// 2B 组号 + 4B 条目数，每条 20B 名称 + 4B 容量 + 4B 在线数 + 16B IP + 4B 端口。
	channelListPrefixSize = 6
	channelListEntrySize  = 48
	channelListIPOffset   = 28
	channelListPortOffset = 44
)

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

// ProxyServer 管理 Channel/Game 代理端口。
type ProxyServer struct {
	config             *config.GatewayConfig
	sessionManager     *session.SessionManager
	rewriter           *ChannelListRewriter
	logger             *logger.ConsoleLogger
	listenAddr         string
	gamePortMap        map[int]int
	ports              atomic.Pointer[portView]
	shutdown           chan struct{}
	wg                 sync.WaitGroup
	mu                 sync.RWMutex
	channelLock        sync.Mutex
	channelListener    net.Listener
	channelCts         chan struct{}
	gameListeners      map[int]net.Listener
	gameCts            map[int]chan struct{}
	gamePorts          map[int]struct{}
	connCounts         map[int]int
	portConfig         *PortConfigStore
	firstReadTimeout   time.Duration
	idleTimeout        time.Duration
	backendConnTimeout time.Duration
}

// NewProxyServer 创建代理服务器。
func NewProxyServer(
	cfg *config.GatewayConfig,
	sm *session.SessionManager,
	logger *logger.ConsoleLogger,
	portConfig *PortConfigStore,
) *ProxyServer {
	gamePortMap := cfg.GamePortMapResolved()

	// 初始视图先按 appsettings 建好；Start() 会用端口表覆盖它。
	// 这样即使退回 appsettings 分支，频道列表过滤也有正确判据。
	initialView := buildPortViewFromResolved(gamePortMap)

	firstReadTimeout := time.Duration(cfg.GameServer.FirstReadTimeoutSeconds) * time.Second
	if cfg.GameServer.FirstReadTimeoutSeconds <= 0 {
		firstReadTimeout = 0
	}

	idleTimeout := time.Duration(cfg.GameServer.IdleTimeoutSeconds) * time.Second
	if cfg.GameServer.IdleTimeoutSeconds <= 0 {
		idleTimeout = 0
	}

	backendConnTimeout := time.Duration(cfg.GameServer.BackendConnectTimeoutSeconds) * time.Second
	if cfg.GameServer.BackendConnectTimeoutSeconds <= 0 {
		backendConnTimeout = 0
	}

	// 初始化端口集合
	gamePorts := make(map[int]struct{})
	for port := range gamePortMap {
		gamePorts[port] = struct{}{}
	}

	srv := &ProxyServer{
		config:             cfg,
		sessionManager:     sm,
		rewriter:           NewChannelListRewriter(cfg.GameServer.KeyTimeZoneOffsetHours),
		logger:             logger,
		listenAddr:         cfg.Gateway.ListenAddress,
		gamePortMap:        gamePortMap,
		shutdown:           make(chan struct{}),
		gameListeners:      make(map[int]net.Listener),
		gameCts:            make(map[int]chan struct{}),
		gamePorts:          gamePorts,
		connCounts:         make(map[int]int),
		portConfig:         portConfig,
		firstReadTimeout:   firstReadTimeout,
		idleTimeout:        idleTimeout,
		backendConnTimeout: backendConnTimeout,
	}
	srv.ports.Store(initialView)
	return srv
}

// Start 启动所有代理端口。
//
// Game 端口以 proxy_ports.json（PortConfigStore）为准：该文件首次运行时
// 由 appsettings 的 GameServer 段派生生成，此后它就是端口表的唯一真源。
// 若这里直接读 appsettings，管理员在后台保存的端口改动会在下次重启后回滚。
func (p *ProxyServer) Start() {
	// Channel 代理端口（频道列表转发）
	p.StartChannelListener()

	if cfg := p.storedPortConfig(); cfg != nil {
		p.ReloadPorts(cfg)
	} else {
		// 端口表不可用（理论上不会走到）：退回 appsettings 的静态端口列表。
		p.logger.Warn("端口表不可用，Game 代理退回 appsettings 的 GameServer.GamePorts")
		p.startGameProxies()
	}
	p.logger.Info("代理服务器已启动")
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
			addr, p.config.GameServer.BackendHost, backendPort))
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

	addr := net.JoinHostPort(p.listenAddr, strconv.Itoa(p.config.Gateway.ProxyPort))
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
	for _, port := range p.config.GameServer.GamePorts {
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
		p.logger.Info(fmt.Sprintf("Game 代理已启动: %s -> %s:%d", addr, p.config.GameServer.BackendHost, backendPort))
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
		go p.handleChannelClient(conn)
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
		go p.handleGameClient(conn, publicPort, backendPort)
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
	backend, err := p.connectBackendTo(p.config.GameServer.BackendChannelPort)
	if err != nil {
		p.logger.Warn(fmt.Sprintf("连接游戏后端失败: %v", err))
		return
	}
	defer backend.Close()

	// 先发送首包到后端
	setNoDelay(backend, true)
	setNoDelay(client, true)
	if p.proxyProtocolEnabled() {
		if err := p.writeProxyHeader(
			backend, client, p.config.Gateway.ProxyPort); err != nil {
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

	// 下行（带帧重写）
	go func() {
		p.copyChannelDownlink(backendStream, clientStream, "Channel 下行")
		task <- struct{}{}
	}()

	<-task
}

func (p *ProxyServer) handleGameClient(client net.Conn, publicPort, backendPort int) {
	defer p.wg.Done()
	defer client.Close()

	remoteIP := GetRemoteIP(client)

	// IP 白名单检查
	if !p.sessionManager.IsIPAllowed(remoteIP) {
		p.logger.Warn(fmt.Sprintf("拒绝非白名单 IP 的 Game 连接: %s -> %d", remoteIP, publicPort))
		return
	}

	// 单 IP 并发上限
	if !p.sessionManager.TryAcquireGameSlot(remoteIP, p.config.GameServer.MaxConnectionsPerIP) {
		p.logger.Warn(fmt.Sprintf("拒绝 Game 连接: %s -> %d（单 IP 并发已达上限 %d）",
			remoteIP, publicPort, p.config.GameServer.MaxConnectionsPerIP))
		return
	}
	// ★ 槽位 defer 必须紧跟 Acquire 注册：会话归属要等首包才定，后面还有若干
	// return 路径（首包读取失败等），任何一条漏掉都会让该 IP 的并发额度被永久占住。
	defer p.sessionManager.ReleaseGameSlot(remoteIP)

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

	// 后端连接先于首包建立（连到该公网端口映射的后端游戏端口，而非 Channel 端口）
	backend, err := p.connectBackendTo(backendPort)
	if err != nil {
		p.logger.Warn(fmt.Sprintf("连接游戏后端 %d 失败: %v", backendPort, err))
		return
	}
	defer backend.Close()

	setNoDelay(client, true)
	setNoDelay(backend, true)

	// PROXY protocol：必须在转发客户端首包**之前**写入。服务端会把它读掉，
	// 当作会话的真实远端地址 —— PK 场的 UDP 绑定校验、组队/副本下发给
	// 队友的 P2P 端点、账号的最后登录 IP 三处都依赖它。
	if p.proxyProtocolEnabled() {
		if err := p.writeProxyHeader(backend, client, publicPort); err != nil {
			p.logger.Warn(fmt.Sprintf(
				"Game %d PROXY 头写入失败，放弃连接: %v", publicPort, err))
			return
		}
	}

	// 下行：后端 -> 客户端
	downlinkDone := make(chan struct{})
	go func() {
		p.copyWithTimeout(backend, client, fmt.Sprintf("Game %d 下行", publicPort))
		close(downlinkDone)
	}()

	// 等待客户端首包（= 游戏登录包，里面带 m_id）
	firstBuf := make([]byte, copyBufferSize)
	firstRead, readErr := p.readWithTimeout(client, firstBuf, p.firstReadTimeout, fmt.Sprintf("Game %d 首包", publicPort))
	if readErr != nil || firstRead <= 0 {
		return
	}

	// ★★ 会话归属：**优先按首包里的 m_id 精确匹配**，匹配不到才回退按 IP。
	//
	// 为什么必须这样：客户端 launch_args 第 4 段就是它自己的 m_id，登录包原样带上来。
	// 只按 IP 挑「心跳最新」的会话，在**同一公网 IP 多开**时（一台机器开两个客户端，
	// 或同一路由器后面多个玩家）会把所有游戏连接都算到最活跃的那个账号头上 ——
	// 实测：服务端收到 `Login request parsed: m_id=msp`，网关却记成
	// `Game 连接已建立: msp2`，泡点也因此全发给了 msp2。
	//
	// 解析失败（首包被分包切碎 / 不是登录包 / m_id 含非 ASCII）时**完全回退旧行为**，
	// 所以对既有玩家零退化。
	mId, hasMId := parseGameLoginMId(firstBuf[:firstRead])
	sessionObj, found := p.sessionManager.FindSessionByMId(mId)
	if !hasMId || !found {
		sessionObj, _ = p.sessionManager.TryGetSessionForGameProxy(remoteIP)
	}

	// ★ 这条 Game 代理连接同时是**泡点计时的唯一依据**：只要会话上挂着
	// GameProxyConnections（= 玩家真的连上了游戏频道），泡点主循环才累计
	// 时长；这里 defer 断开后计时立即停止。改动本函数的连接登记时机
	// 会直接影响泡点发放，见 session.CollectBonusAwards。
	p.sessionManager.AddGameProxyConnection(sessionObj, client)
	defer p.sessionManager.RemoveGameProxyConnection(sessionObj, client)

	// 首包转发到后端（始终原样转发，解析只是旁路观察）
	backend.Write(firstBuf[:firstRead])

	// sessionObj 可能为 nil（会话在 IP 白名单检查之后、这里之前被清理/踢掉）。
	// 旧代码直接解引用 sessionObj.Account 打日志，一旦命中就是空指针 panic，
	// 会把整个网关进程打挂 —— 这里做空值兜底，只影响日志展示。
	joined := "<无归属会话>"
	if sessionObj != nil {
		joined = sessionObj.Account
	}
	// 归属来源要打出来：双开同 IP 时「按 m_id 命中」与「回退按 IP」的后果完全不同，
	// 排查「在线/泡点记到别人头上」时这一列就是第一手证据。
	route := "ip"
	if hasMId && found {
		route = "m_id"
	}
	p.logger.Info(fmt.Sprintf("Game 连接已建立: %s (%s) -> %d [归属=%s]",
		joined, remoteIP, backendPort, route))

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

// copyChannelDownlink Channel 下行透传，带帧重写。
func (p *ProxyServer) copyChannelDownlink(src, dst net.Conn, context string) {
	buf := make([]byte, copyBufferSize)
	pending := make([]byte, 0, copyBufferSize)

	if !p.config.GameServer.RewriteChannelList {
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

		// 处理缓冲区
		pending = p.processChannelData(pending, dst)
	}
}

func (p *ProxyServer) processChannelData(pending []byte, dst net.Conn) []byte {
	// 每次读到的数据块取一次端口视图快照：配置热加载对下一块数据即生效，
	// 且整个处理过程共享同一个不可变快照（无锁、无并发 map 读写风险）。
	view := p.ports.Load()

	offset := 0
	for offset+channelHeaderSize <= len(pending) {
		// 帧格式：[2 bytes seq][4 bytes length][...body]
		frameLength := int(binary.LittleEndian.Uint32(pending[offset+2 : offset+6]))
		if frameLength < channelHeaderSize || frameLength > maxFrameSize {
			// 帧长度非法：原样转发剩余字节
			dst.Write(pending[offset:])
			return nil
		}

		if len(pending)-offset < frameLength {
			break
		}

		msgNo := pending[offset+1]
		if msgNo == scAskChannelInfoNew {
			body := pending[offset+channelHeaderSize : offset+frameLength]
			rewritten, kept, dropped := p.rewriter.RewriteChannelInfoWithFallback(
				body, p.config.GameServer.PublicIP, view)
			if dropped > 0 && kept == 0 {
				p.logger.Warn(fmt.Sprintf(
					"[频道列表] %d 条频道全部不在端口表的开放范围内，已放弃过滤（请检查端口表映射口径）",
					dropped))
			} else if dropped > 0 {
				p.logger.Info(fmt.Sprintf(
					"[频道列表] 已隐藏 %d 个已关闭端口的频道，保留 %d 个", dropped, kept))
			}
			if rewritten != nil && len(rewritten) > 0 {
				// 输出重写后的帧头 + body
				header := make([]byte, channelHeaderSize)
				copy(header, pending[offset:offset+channelHeaderSize])
				binary.LittleEndian.PutUint32(header[2:6], uint32(channelHeaderSize+len(rewritten)))
				dst.Write(header)
				dst.Write(rewritten)
			} else {
				// 重写失败：原样转发
				dst.Write(pending[offset : offset+frameLength])
			}
		} else {
			dst.Write(pending[offset : offset+frameLength])
		}

		offset += frameLength
	}

	if offset == 0 {
		return pending
	}

	if offset < len(pending) {
		return pending[offset:]
	}
	return nil
}

// connectBackendTo 连接到游戏后端的指定端口。
func (p *ProxyServer) connectBackendTo(port int) (net.Conn, error) {
	addr := net.JoinHostPort(p.config.GameServer.BackendHost, strconv.Itoa(port))
	if p.backendConnTimeout > 0 {
		dialer := net.Dialer{Timeout: p.backendConnTimeout}
		return dialer.Dial("tcp", addr)
	}
	return net.Dial("tcp", addr)
}

// connectBackend 连接到游戏后端 Channel 端口。
func (p *ProxyServer) connectBackend() (net.Conn, error) {
	return p.connectBackendTo(p.config.GameServer.BackendChannelPort)
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
		strings.TrimSpace(p.config.GameServer.ProxyProtocol)) {
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
	dstIP := strings.TrimSpace(p.config.GameServer.PublicIP)
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

// getFd 已删除（2026-09-23）：会话登记改为直接持有 net.Conn，
// 踢下线时逐个 Close 真连接（历史版本只记 fd 句柄数，踢人不断链路）。

// ChannelListRewriter 频道列表端口重写器。
type ChannelListRewriter struct {
	timezoneOffset int
}

func NewChannelListRewriter(timezoneOffset int) *ChannelListRewriter {
	return &ChannelListRewriter{timezoneOffset: timezoneOffset}
}

// currentKey 返回当天有效的频道列表密钥。
//
// 密钥日期口径统一由 pkg/security 提供（含时区偏移处理），
// 本包不再自行格式化日期，避免两处实现在跨零点/跨时区时行为漂移。
func (r *ChannelListRewriter) currentKey() string {
	return security.ChannelKey(r.timezoneOffset)
}

// previousDayKey 返回昨天的频道列表密钥，用于跨零点回退。
func (r *ChannelListRewriter) previousDayKey() string {
	return security.ChannelKeyPreviousDay(r.timezoneOffset)
}

// RewriteChannelInfoWithFallback 重写频道列表：改写 IP/端口，并剔除已关闭端口的频道。
//
// 返回可直接下发的密文；kept/dropped 供调用方做审计日志。
// body 无法解密时原样返回（kept=dropped=0）。
func (r *ChannelListRewriter) RewriteChannelInfoWithFallback(
	body []byte,
	publicIP string,
	view *portView,
) ([]byte, int, int) {
	plaintext, key, ok := r.decryptAny(body)
	if !ok {
		// 解密失败，原样返回
		return body, 0, 0
	}

	rewritten, kept, dropped := rewritePlaintextAndFilter(plaintext, publicIP, view)
	if kept == 0 && dropped > 0 {
		// 安全阀：一条都没命中，说明端口表与频道列表口径对不上
		// （例如全部被写成同端口转发）。宁可不改，也不能让所有频道凭空消失。
		return body, 0, dropped
	}
	if dropped == 0 && bytes.Equal(plaintext, rewritten) {
		// 与原文一致，省掉一次压缩 + 加密
		return body, kept, 0
	}
	return r.encrypt(rewritten, key), kept, dropped
}

// decryptAny 依次尝试当天、昨天的频道列表密钥，返回明文与命中的密钥。
func (r *ChannelListRewriter) decryptAny(data []byte) ([]byte, string, bool) {
	current := r.currentKey()
	if plaintext, err := r.decrypt(data, current); err == nil && isValidChannelList(plaintext) {
		return plaintext, current, true
	}
	previous := r.previousDayKey()
	if plaintext, err := r.decrypt(data, previous); err == nil && isValidChannelList(plaintext) {
		return plaintext, previous, true
	}
	return nil, "", false
}

func (r *ChannelListRewriter) decrypt(data []byte, key string) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	// 检查 zlib 头 (0x78 0x9C)
	if len(data) > 1 && data[0] == 0x78 {
		var err error
		data, err = zlibDecompress(data)
		if err != nil {
			return nil, err
		}
	}
	return aes128DecryptECB(data, getKeyBytes(key))
}

func (r *ChannelListRewriter) encrypt(data []byte, key string) []byte {
	padded := padTo16(data)
	encrypted, err := aes128EncryptECB(padded, getKeyBytes(key))
	if err != nil {
		return data
	}
	return zlibCompress(encrypted)
}

func getKeyBytes(key string) []byte {
	keyBytes := make([]byte, 16)
	src := []byte(key)
	copy(keyBytes, src[:len(src)])
	if len(src) < 16 {
		copy(keyBytes, src)
	}
	return keyBytes
}

func isValidChannelList(plaintext []byte) bool {
	if len(plaintext) < 6 {
		return false
	}
	count := int(binary.LittleEndian.Uint32(plaintext[2:6]))
	if count < 0 {
		return false
	}
	expected := padTo16Len(6 + count*48)
	return len(plaintext) == expected
}

// rewritePlaintextAndFilter 单遍完成两件事：
//  1. 剔除"所在端口已关闭"的频道条目（回传 kept/dropped 供审计）；
//  2. 把保留条目的 IP 改写为公网 IP、端口改写为公网端口。
//
// 过滤口径与 ReloadPorts 的开监听口径严格一致：条目端口（服务端填的是后端监听
// 端口，如 10011）在端口表里存在一条 Enabled=true 的映射（如 20011:10011），
// 才算"这个频道可进"。端口被停用 / 被删除 / 从未纳管时，网关都不会为它开监听，
// 客户端连上去必然失败（connection refused），因此直接从列表里移除，
// 玩家在选频道界面既看不到、也选不到它。
//
// 安全性依据：服务端并不靠条目下标决定频道号，而是由连接落在哪个监听端口推导
// （见 DfoServer CharacterSelectHandler / GameNetworkConfig.ResolveGameChannel），
// 所以移除条目导致的列表下标平移不会造成"选 A 频道进 B 频道"。
func rewritePlaintextAndFilter(plaintext []byte, publicIP string, view *portView) ([]byte, int, int) {
	if len(plaintext) < channelListPrefixSize {
		return plaintext, 0, 0
	}
	count := int(binary.LittleEndian.Uint32(plaintext[2:channelListPrefixSize]))
	if count <= 0 {
		return plaintext, 0, 0
	}

	keep := make([]bool, count)
	kept := 0
	for i := 0; i < count; i++ {
		off := channelListPrefixSize + i*channelListEntrySize
		if off+channelListEntrySize > len(plaintext) {
			break
		}
		backendPort := int(binary.LittleEndian.Uint32(
			plaintext[off+channelListPortOffset : off+channelListPortOffset+4]))
		if _, ok := view.publicFor(backendPort); !ok {
			continue
		}
		keep[i] = true
		kept++
	}

	dropped := count - kept
	if kept == 0 {
		// 全部被过滤：交由调用方走安全阀
		return plaintext, 0, dropped
	}

	out := make([]byte, channelListPrefixSize+kept*channelListEntrySize)
	copy(out[0:2], plaintext[0:2]) // 组号原样保留
	binary.LittleEndian.PutUint32(out[2:channelListPrefixSize], uint32(kept))

	ipBytes := []byte(publicIP)
	if len(ipBytes) > 16 {
		ipBytes = ipBytes[:16]
	}

	dst := channelListPrefixSize
	for i := 0; i < count; i++ {
		if !keep[i] {
			continue
		}
		src := channelListPrefixSize + i*channelListEntrySize
		copy(out[dst:dst+channelListEntrySize], plaintext[src:src+channelListEntrySize])

		// 重写 IP
		ipOff := dst + channelListIPOffset
		clear(out[ipOff : ipOff+16])
		if len(ipBytes) > 0 {
			copy(out[ipOff:ipOff+len(ipBytes)], ipBytes)
		}

		// 重写端口（后端 -> 公网）
		backendPort := int(binary.LittleEndian.Uint32(
			plaintext[src+channelListPortOffset : src+channelListPortOffset+4]))
		if pub, ok := view.publicFor(backendPort); ok {
			binary.LittleEndian.PutUint32(out[dst+channelListPortOffset:], uint32(pub))
		}

		dst += channelListEntrySize
	}

	return out, kept, dropped
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func padTo16Len(length int) int {
	return length + (16-length%16)%16
}

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
