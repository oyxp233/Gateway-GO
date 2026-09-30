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
	shutdown    chan struct{}
	wg          sync.WaitGroup
	activeConns int
	activeMu    sync.Mutex
}

// CommandHandler 处理 TCP 命令的接口。
type CommandHandler interface {
	Handle(req *models.GatewayRequest, clientIP string) (*models.GatewayResponse, error)
}

// NewServer 创建 TCP 认证服务器。
func NewServer(cfg *config.GatewayConfig, handler CommandHandler, logger *logger.ConsoleLogger, cert *tls.Certificate) *Server {
	return &Server{
		config:      cfg,
		handler:     handler,
		logger:      logger,
		rateLimiter: ratelimiter.NewRateLimiter(cfg.RateLimit.Enabled, cfg.RateLimit.RequestsPerMinute),
		cert:        cert,
		maxConns:    cfg.Gateway.TcpMaxConnections,
		idleTimeout: cfg.Gateway.TcpIdleTimeoutSeconds,
		shutdown:    make(chan struct{}),
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

		// TLS 握手（启用时）
		if s.cert != nil {
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{*s.cert},
				MinVersion:   tls.VersionTLS12,
			})
			idle := time.Duration(s.idleTimeout) * time.Second
			if idle > 0 {
				tlsConn.SetDeadline(time.Now().Add(idle))
			}
			if err := tlsConn.Handshake(); err != nil {
				s.logger.Warn(fmt.Sprintf("TLS 握手失败: %s: %v", GetRemoteIP(conn), err))
				conn.Close()
				continue
			}
			if idle > 0 {
				tlsConn.SetDeadline(time.Time{})
			}
			conn = tlsConn
		}

		// 连接数上限检查
		if s.maxConns > 0 && s.getActiveConns() >= s.maxConns {
			remoteIP := GetRemoteIP(conn)
			s.logger.Warn(fmt.Sprintf("认证连接数已达上限 %d，拒绝来自 %s 的新连接", s.maxConns, remoteIP))
			conn.Close()
			continue
		}

		s.wg.Add(1)
		s.activeMu.Lock()
		s.activeConns++
		s.activeMu.Unlock()
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// activeConns 的递减必须 defer 到函数返回 —— 原来写成函数入口立即执行。
	// acceptLoop 里的 ++ 就在 `go s.handleClient(conn)` 上一行，两者几乎紧挨，
	// 于是 getActiveConns() 读到的是"刚 accept、handler goroutine 还没跑起来"的瞬时数（通常≈0），
	// acceptLoop 里那条 `getActiveConns() >= maxConns` 的上限判断因此**永远不成立**：
	// Gateway.TcpMaxConnections 形同虚设，一个简单的 TCP flood 就能把 fd 打穿。
	defer func() {
		s.activeMu.Lock()
		s.activeConns--
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
func (s *Server) Stop() {
	close(s.shutdown)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
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
