package auth

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/ratelimiter"
	"s4a21-gateway/pkg/safego"
)

const (
	maxFrameSize = 1024 * 1024 // 1MB
)

// Server TCP 认证服务器。
type Server struct {
	config      *config.GatewayConfig
	handler     CommandHandler
	logger      *logger.ConsoleLogger
	rateLimiter *ratelimiter.RateLimiter
	listener    net.Listener
	cert        *tls.Certificate
	maxConns    int
	idleTimeout int
	// handshakeTimeout 是 TLS 握手专属超时（秒），独立于 idleTimeout。
	// 取值见 resolveHandshakeTimeout；背景见 config.GatewaySection 的注释与 G-8 测试。
	handshakeTimeout int
	shutdown         chan struct{}
	wg               sync.WaitGroup
	activeConns      int
	activeMu         sync.Mutex
	// conns 是当前活跃连接集合（已做 TLS 包装的那份）。
	//
	// G-7（2026-10-04 审查）：ReadFrame 走 io.ReadFull 是**裸阻塞读**，
	// close(shutdown) 唤不醒它 —— 原先 Stop() 只关监听 + wg.Wait()，
	// 于是要等满 TcpIdleTimeoutSeconds（默认 600s），远超 systemd 的
	// TimeoutStopUSec ⇒ 每次发版都被 SIGKILL。Stop() 里主动关连接即可。
	//
	// 之所以不用 proxy 那套「1 秒切片轮询」：那边轮询的是单次 Read，
	// 而这里是长度前缀帧 —— 切片会让 ReadFrame 读半个帧后超时，
	// 重试就从 body 中间开始读，**帧错位**。所以只能靠"关连接"来唤醒。
	conns map[net.Conn]struct{}
}

// CommandHandler 处理 TCP 命令的接口。
type CommandHandler interface {
	Handle(req *models.GatewayRequest, clientIP string) (*models.GatewayResponse, error)
}

// NewServer 创建 TCP 认证服务器。
func NewServer(cfg *config.GatewayConfig, handler CommandHandler, logger *logger.ConsoleLogger, cert *tls.Certificate) *Server {
	return &Server{
		config:           cfg,
		handler:          handler,
		logger:           logger,
		rateLimiter:      ratelimiter.NewRateLimiter(cfg.RateLimit.Enabled, cfg.RateLimit.RequestsPerMinute),
		cert:             cert,
		maxConns:         cfg.Gateway.TcpMaxConnections,
		idleTimeout:      cfg.Gateway.TcpIdleTimeoutSeconds,
		handshakeTimeout: resolveHandshakeTimeout(cfg.Gateway.TcpHandshakeTimeoutSeconds),
		shutdown:         make(chan struct{}),
		conns:            make(map[net.Conn]struct{}),
	}
}

// Start 启动 TCP 认证服务器。
func (s *Server) Start() error {
	addr := net.JoinHostPort(s.config.Gateway.ListenAddress, strconv.Itoa(s.config.Gateway.TcpPort))
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	if s.cert != nil {
		s.logger.Info(fmt.Sprintf("认证 TCP 服务已启动: %s (TLS 已启用)", addr))
	} else {
		s.logger.Warn(fmt.Sprintf("[SECURITY] 认证 TCP 服务保持明文模式: %s", addr))
	}

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
			}

			// 临时性错误（如 fd 耗尽）不应终止整个 accept 循环。
			// 注意：net.Error.Temporary 已被标记为 Deprecated，且 Go 1.18 起
			// 多数场景返回 false；这里保留它作为兼容判断，真正的退出信号
			// 由上面的 shutdown 分支负责。
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				s.logger.Warn(fmt.Sprintf("接受连接失败（临时错误，继续监听）: %v", err))
				time.Sleep(5 * time.Millisecond)
				continue
			}
			s.logger.Error(fmt.Sprintf("接受连接失败，accept 循环退出: %v", err))
			return
		}

		// G-8（2026-10-15，正式服2 故障定型）：握手与后续处理全部移到
		// per-connection goroutine。同步握手时，一个"连上但不发 ClientHello"的
		// 连接能把 acceptLoop 卡住整个 TcpIdleTimeoutSeconds（线上 600s）——
		// 期间新玩家 TCP 连得上（内核 backlog 照常接纳）却永远等不到 ServerHello，
		// 登录器 20s 超时后批量报 L4002。回归见 server_handshake_test.go。
		s.wg.Add(1)
		safego.Go(s.logger, "auth.handleNewConn", func() { s.handleNewConn(conn) })
	}
}

// DefaultTcpHandshakeTimeoutSeconds 是 TLS 握手超时的默认值（秒）。
// 10s 足够覆盖跨网段的 TCP + TLS 握手；到期即失败，绝不像 idle 超时那样
// 让一个沉默连接堵住整条 acceptLoop。
const DefaultTcpHandshakeTimeoutSeconds = 10

// resolveHandshakeTimeout 归一化握手超时：配置值 >0 时采用，否则用默认值。
func resolveHandshakeTimeout(cfgValue int) int {
	if cfgValue > 0 {
		return cfgValue
	}
	return DefaultTcpHandshakeTimeoutSeconds
}

// handleNewConn 在独立 goroutine 里完成 TLS 握手、连接数上限检查，
// 然后把连接交给 handleClient。单个慢/沉默连接只会占用自己的 goroutine，
// 不再拖累 acceptLoop 与后续所有连接。
func (s *Server) handleNewConn(conn net.Conn) {
	defer s.wg.Done()

	// TLS 握手（启用时）
	if s.cert != nil {
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{*s.cert},
			MinVersion:   tls.VersionTLS12,
		})
		hs := time.Duration(s.handshakeTimeout) * time.Second
		if hs > 0 {
			tlsConn.SetDeadline(time.Now().Add(hs))
		}
		if err := tlsConn.Handshake(); err != nil {
			s.logger.Warn(fmt.Sprintf("TLS 握手失败: %s: %v", GetRemoteIP(conn), err))
			conn.Close()
			return
		}
		if hs > 0 {
			tlsConn.SetDeadline(time.Time{})
		}
		conn = tlsConn
	}

	// 连接数上限检查
	if s.maxConns > 0 && s.getActiveConns() >= s.maxConns {
		remoteIP := GetRemoteIP(conn)
		s.logger.Warn(fmt.Sprintf("认证连接数已达上限 %d，拒绝来自 %s 的新连接", s.maxConns, remoteIP))
		conn.Close()
		return
	}

	s.wg.Add(1)
	s.activeMu.Lock()
	s.activeConns++
	s.conns[conn] = struct{}{}
	s.activeMu.Unlock()
	// G-1（2026-10-04 审查）：panic 兜底由 acceptLoop 里的 safego.Go 提供。
	s.handleClient(conn)
}

func (s *Server) handleClient(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// activeConns 的递减必须 defer 到函数返回 —— 原来写成函数入口立即执行。
	// acceptLoop 里的 ++ 就在 `go s.handleClient(conn)` 上一行，两者几乎紧挨，
	// 于是 getActiveConns() 读到的是"刚 accept、handler goroutine 还没跑起来"的瞬时数（通常≈0），
	// acceptLoop 里那条 `getActiveConns() >= maxConns` 的上限判断因此**永远不成立**：
	// Gateway.TcpMaxConnections 形同虚设，一个简单的 TCP flood 就能把 fd 打穿。
	// G-7：同时把连接从活跃集合里摘掉。摘除必须和 -- 一样 defer 到函数返回，
	// 否则 Stop() 会拿到一个已经不在读的连接去 Close（无害），但更要紧的是
	// **漏摘**会让 conns 无限增长（连接对象被 map 强引用，GC 收不掉）。
	defer func() {
		s.activeMu.Lock()
		s.activeConns--
		delete(s.conns, conn)
		s.activeMu.Unlock()
	}()

	remoteIP := GetRemoteIP(conn)

	// 设置读超时
	if s.idleTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(s.idleTimeout) * time.Second))
	}

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		// 读帧
		payload, err := ReadFrame(conn)
		if err != nil {
			if err != io.EOF {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					s.logger.Warn(fmt.Sprintf("认证连接空闲超时 %ds，已关闭: %s", s.idleTimeout, remoteIP))
				}
			}
			return
		}

		// 重置空闲超时
		if s.idleTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(time.Duration(s.idleTimeout) * time.Second))
		}

		// 限流（在反序列化之前）
		if !s.rateLimiter.TryAcquire(remoteIP) {
			WriteResponse(conn, models.GatewayResponse{
				Cmd:       "",
				Ok:        false,
				ErrorCode: models.Err.RateLimited,
				Message:   strPtr("请求过于频繁"),
			})
			continue
		}

		// 反序列化
		var req models.GatewayRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			WriteResponse(conn, models.GatewayResponse{
				Cmd:       "",
				Ok:        false,
				ErrorCode: models.Err.DecodeFailed,
				Message:   strPtr("请求解码失败"),
			})
			continue
		}

		if req.Cmd == "" {
			WriteResponse(conn, models.GatewayResponse{
				Cmd:       "",
				Ok:        false,
				ErrorCode: models.Err.DecodeFailed,
				Message:   strPtr("请求解码失败"),
			})
			continue
		}

		// 处理命令
		resp, err := s.handler.Handle(&req, remoteIP)
		if err != nil {
			WriteResponse(conn, models.GatewayResponse{
				Cmd:       req.Cmd,
				Ok:        false,
				ErrorCode: models.Err.DatabaseError,
				Message:   strPtr("数据库操作失败"),
			})
			continue
		}

		WriteResponse(conn, *resp)
	}
}

// Stop 优雅关闭服务器。
//
// G-7（2026-10-04 审查）：handleClient 里的 ReadFrame 是 io.ReadFull 裸阻塞读，
// close(s.shutdown) 唤不醒它 ⇒ 原先这里要等满 TcpIdleTimeoutSeconds
// （默认 600s）才等到 wg.Wait() 返回，远超 systemd 的 TimeoutStopUSec
// ⇒ **每次发版都被 SIGKILL**（网关整体重启 = 全体掉线）。
//
// 处置：关完监听就主动 Close 全部活跃连接 —— 阻塞中的 ReadFrame 立刻返回
// net.ErrClosed，handleClient 走到 return、wg 归零。多给 3 秒兜底，超时就放弃等待
// （剩下的连接已经在关的路上，进程退出会由内核回收，绝不再拖满 600s）。
func (s *Server) Stop() {
	close(s.shutdown)
	if s.listener != nil {
		s.listener.Close()
	}

	// 快照后逐个关闭：不要在持锁状态下 Close（Close 可能触发对端 RST 与
	// 后续 defer 里的 delete，虽然不冲突，但缩短持锁区总是更好）。
	s.activeMu.Lock()
	pending := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		pending = append(pending, c)
	}
	s.activeMu.Unlock()

	for _, c := range pending {
		c.Close()
	}
	if n := len(pending); n > 0 {
		s.logger.Info(fmt.Sprintf("认证服务关闭：已主动断开 %d 个活跃连接", n))
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		s.logger.Warn("认证服务关闭：等待连接收尾超过 3 秒，不再阻塞进程退出")
	}
}

// ReadFrame 读取一个大端序长度前缀的 JSON 帧。
func ReadFrame(conn io.Reader) ([]byte, error) {
	// 读取 4 字节长度
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(lenBuf))

	if length <= 0 || length > maxFrameSize {
		return nil, fmt.Errorf("invalid frame length: %d", length)
	}

	// 读取 payload
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// WriteFrame 写入一个大端序长度前缀的 JSON 帧。
func WriteFrame(conn io.Writer, payload []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// WriteResponse 序列化并写入响应。
func WriteResponse(conn io.Writer, resp models.GatewayResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return WriteFrame(conn, data)
}

// SerializeResponse 序列化响应。
func SerializeResponse(resp models.GatewayResponse) ([]byte, error) {
	return json.Marshal(resp)
}

// GetRemoteIP 从连接获取远端 IP。
func GetRemoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil || host == "" {
		return conn.RemoteAddr().String()
	}
	return host
}

// getActiveConns 获取当前活跃连接数。
func (s *Server) getActiveConns() int {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	return s.activeConns
}

// strPtr 返回字符串指针。
func strPtr(s string) *string {
	return &s
}
