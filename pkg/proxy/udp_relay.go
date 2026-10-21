package proxy

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// S5A3 组队 UDP 中继（1:1 端口透传 + 每客户端独立后端源端口）
//
// ── 为什么需要 ───────────────────────────────────────────────────────────
//
// S5A3 的组队/副本 P2P 走 UDP 30000~30063（服务端 party_udp_relay_port_start
// / _count）。S4A21 时代靠 PROXY protocol 把真实 IP 告诉服务端就能对上
// "UDP 源 IP == TCP 源 IP"，但 S5A3 关掉了 PROXY 头，且它的中继是
// **observed endpoint** 模型：服务端按收到的数据报的真实来源地址
// 记住每个玩家的端点，再把队友的包转发过去。
//
// 如果网关只转 TCP，服务端看到的 UDP 来源就是玩家自己（直连），
// 只有在服务端 UDP 端口对玩家可达时才成立；一旦网关做了前置，
// 玩家连不到服务端 UDP，组队就断。
//
// ── 为什么是"每客户端一个后端 socket" ───────────────────────────────────
//
// 最直觉的做法是：一个监听 socket 收到谁的就转给后端，后端回什么就
// 转给最后一个人 —— 这是错的。S5A3 服务端要给**每个玩家**记一个端点，
// 如果所有玩家共用一个后端 socket，服务端看到的是同一个
// (网关IP, 同一端口)，所有队友会被折叠成同一个端点，转发全乱。
//
// 所以每个客户端分配一个独立的、连到后端的中继 socket（源端口随机）。
// 服务端看到的是 (网关IP, 各自不同的端口)，正好一对一；它回给某个端点的
// 数据报落在那个 socket 上，我们再转回对应的客户端。语义与"玩家直连"
// 完全等价，服务端不需要知道中间有网关。
//
// ── 边界 ─────────────────────────────────────────────────────────────────
//
//   * 只在 GameServerEntry.PartyUDPPorts 非空时启用，默认关闭；
//   * 端口 1:1 透传（公网 30000 → 后端 30000），不做重映射 ——
//     重映射会破坏服务端下发给客户端的 UDP 端点字段；
//   * 空闲会话按 idleTimeout 回收，避免玩家掉线后一直占着 socket。
// ─────────────────────────────────────────────────────────────────────────────

const (
	udpRelayIdleTimeout  = 120 * time.Second
	udpRelaySweepPeriod  = 30 * time.Second
	udpRelayReadBufBytes = 64 << 10
)

// udpRelaySession 是一个客户端在中继里的上下文。
type udpRelaySession struct {
	client *net.UDPAddr
	// upstream 是连到后端的独立 socket，源端口由系统分配。
	// 服务端据此区分不同玩家。
	upstream *net.UDPConn
	// lastSeen 用纳秒时间戳存，收发两条 goroutine 都会写，
	// 走 atomic 避免为每个会话再加一把锁。
	lastSeen atomic.Int64
}

func (s *udpRelaySession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *udpRelaySession) idleFor() time.Duration {
	return time.Since(time.Unix(0, s.lastSeen.Load()))
}

// UDPRelay 是一个服的 UDP 中继集合（每端口一个监听）。
type UDPRelay struct {
	serverId string
	backend  string
	ports    []int

	// listeners 按端口索引，不能用 r.ports 的下标 ——
	// 某个端口监听失败时两个切片就不再等长，按位对齐会串包。
	listeners map[int]*net.UDPConn

	// backendPorts 是"公网端口 → 后端端口"的例外映射，nil = 全部 1:1。
	//
	// 生产部署永远是 1:1（服务端下发给客户端的 UDP 端点就是那个端口号，
	// 重映射会破坏它）。这里只为了让单测能在同一台机器上同时起
	// "后端 socket" 和 "监听 socket"（否则同端口无法共存）。
	backendPorts map[int]int

	mu       sync.Mutex
	sessions map[int]map[string]*udpRelaySession // 端口 -> 客户端地址 -> 会话
	closed   bool

	stop chan struct{}
	wg   sync.WaitGroup
}

// NewUDPRelay 按服配置创建中继。PartyUDPPorts 为空返回 nil（不启用）。
func NewUDPRelay(serverId, backendHost string, ports []int) *UDPRelay {
	if len(ports) == 0 || backendHost == "" {
		return nil
	}
	return &UDPRelay{
		serverId:  serverId,
		backend:   backendHost,
		ports:     append([]int(nil), ports...),
		listeners: make(map[int]*net.UDPConn, len(ports)),
		sessions:  make(map[int]map[string]*udpRelaySession),
		stop:      make(chan struct{}),
	}
}

// Start 为每个端口起监听。单个端口失败只记录并继续，
// 与 TCP 端口热加载的口径一致（部分可用好过全不可用）。
func (r *UDPRelay) Start() []error {
	var failures []error
	for _, port := range r.ports {
		addr := &net.UDPAddr{IP: net.IPv4zero, Port: port}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			failures = append(failures, fmt.Errorf("服 %s UDP %d 监听失败: %w", r.serverId, port, err))
			continue
		}

		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			_ = conn.Close()
			return failures
		}
		r.listeners[port] = conn
		if r.sessions[port] == nil {
			r.sessions[port] = make(map[string]*udpRelaySession)
		}
		// Add 必须在 closed 判定同一把锁内完成，否则会与 Stop 里的
		// Wait 撞上（WaitGroup 不允许 Add 与 Wait 并发）。
		r.wg.Add(1)
		r.mu.Unlock()

		go r.serve(port, conn)
	}

	r.mu.Lock()
	if len(r.listeners) > 0 && !r.closed {
		r.wg.Add(1)
		r.mu.Unlock()
		go r.sweep()
	} else {
		r.mu.Unlock()
	}
	return failures
}

// Stop 关闭所有监听与会话。
func (r *UDPRelay) Stop() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.stop)
	sessions := r.sessions
	r.sessions = make(map[int]map[string]*udpRelaySession)
	listeners := r.listeners
	r.listeners = make(map[int]*net.UDPConn)
	r.mu.Unlock()

	for _, conn := range listeners {
		_ = conn.Close()
	}
	for _, byClient := range sessions {
		for _, session := range byClient {
			_ = session.upstream.Close()
		}
	}
	r.wg.Wait()
}

// serve 是单个公网端口的收包循环。
func (r *UDPRelay) serve(port int, conn *net.UDPConn) {
	defer r.wg.Done()
	buf := make([]byte, udpRelayReadBufBytes)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // 监听被关闭
		}
		if n <= 0 {
			continue
		}
		session := r.sessionFor(port, client)
		if session == nil {
			continue
		}
		// 复制一份：buf 会被下一轮覆盖，而 Write 是同步的，
		// 这里其实可以直接用，但复制能避免未来改成异步时踩坑。
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if _, err := session.upstream.Write(payload); err != nil {
			r.dropSession(port, client)
		}
	}
}

// backendPort 返回某个公网端口对应的后端端口（默认 1:1）。
func (r *UDPRelay) backendPort(port int) int {
	if mapped, ok := r.backendPorts[port]; ok && mapped > 0 {
		return mapped
	}
	return port
}

// sessionFor 取或建客户端会话。
func (r *UDPRelay) sessionFor(port int, client *net.UDPAddr) *udpRelaySession {
	key := client.String()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	byClient := r.sessions[port]
	if byClient == nil {
		byClient = make(map[string]*udpRelaySession)
		r.sessions[port] = byClient
	}
	if session, ok := byClient[key]; ok {
		r.mu.Unlock()
		session.touch()
		return session
	}
	r.mu.Unlock()

	backendAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", r.backend, r.backendPort(port)))
	if err != nil {
		return nil
	}
	upstream, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		return nil
	}
	session := &udpRelaySession{client: client, upstream: upstream}
	session.touch()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = upstream.Close()
		return nil
	}
	if existing, ok := r.sessions[port][key]; ok {
		// 并发首次发包时可能被别人先建好，复用它的 socket。
		r.mu.Unlock()
		_ = upstream.Close()
		return existing
	}
	r.sessions[port][key] = session
	// 与 Stop 的 Wait 同步：Add 必须在锁内、且在 closed 判定之后。
	r.wg.Add(1)
	r.mu.Unlock()

	// 回程：后端 → 该 socket → 对应客户端。
	go r.pumpBack(port, session)
	return session
}

// pumpBack 把后端回包转回客户端。
func (r *UDPRelay) pumpBack(port int, session *udpRelaySession) {
	defer r.wg.Done()
	buf := make([]byte, udpRelayReadBufBytes)
	for {
		n, err := session.upstream.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		session.touch()
		// 从该端口对应的公网监听回包（按端口查，多端口时不会串包）。
		r.mu.Lock()
		conn := r.listeners[port]
		r.mu.Unlock()
		if conn != nil {
			_, _ = conn.WriteToUDP(buf[:n], session.client)
		}
	}
}

func (r *UDPRelay) dropSession(port int, client *net.UDPAddr) {
	key := client.String()
	r.mu.Lock()
	byClient := r.sessions[port]
	var session *udpRelaySession
	if byClient != nil {
		session = byClient[key]
		delete(byClient, key)
	}
	r.mu.Unlock()
	if session != nil {
		_ = session.upstream.Close()
	}
}

// sweep 回收空闲会话。玩家退出游戏后不会再发包，不回收的话
// 每个客户端都会长期占着一个后端源端口（服务端的端点表也会残留）。
func (r *UDPRelay) sweep() {
	defer r.wg.Done()
	ticker := time.NewTicker(udpRelaySweepPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.mu.Lock()
			for _, byClient := range r.sessions {
				for key, session := range byClient {
					if session.idleFor() > udpRelayIdleTimeout {
						delete(byClient, key)
						_ = session.upstream.Close()
					}
				}
			}
			r.mu.Unlock()
		}
	}
}

// SessionCount 返回当前活跃会话数（运维打点 / 测试用）。
func (r *UDPRelay) SessionCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, byClient := range r.sessions {
		total += len(byClient)
	}
	return total
}

// UDPRelayPorts 生成 S5A3 默认的组队 UDP 端口段。
//
// 与 S5A3 服务端的 party_udp_relay_port_start / _count 对齐
// （cmd/server/control/instance.go: defaultPartyUDPRelayPortStart = 30000，
// count 默认 64）。运维在配置里显式写 PartyUDPPorts 时以配置为准。
func UDPRelayPorts(start, count int) []int {
	if start <= 0 || count <= 0 {
		return nil
	}
	ports := make([]int, 0, count)
	for offset := 0; offset < count; offset++ {
		ports = append(ports, start+offset)
	}
	return ports
}
