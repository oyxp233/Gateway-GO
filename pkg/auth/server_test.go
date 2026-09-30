package auth

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// TcpMaxConnections 必须真正生效（审查报告 网关 P1-2）
//
// 修复前：handleClient 一进函数就把 activeConns 减掉（不是 defer），
// 而 acceptLoop 的 ++ 就在 `go handleClient` 上一行 —— 计数器读到的是
// "刚 accept、handler goroutine 还没跑"的瞬时数（通常≈0），上限判断永不成立。
//
// 断言口径：上限设 2，占住 2 条连接后，第 3 条必须被服务端**立刻关闭**（读到 EOF）；
// 修复前第 3 条会正常挂住（不会 EOF），只能等 30s 空闲超时。
// ─────────────────────────────────────────────────────────────────────────────

type mockHandler struct{}

func (mockHandler) Handle(*models.GatewayRequest, string) (*models.GatewayResponse, error) {
	return &models.GatewayResponse{Ok: true}, nil
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func newTestAuthServer(t *testing.T, maxConns int) *Server {
	t.Helper()
	// 日志目录不用 t.TempDir：Windows 上句柄未释放会让 TempDir 清理报错
	dir, err := os.MkdirTemp("", "s4a21-auth-test-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	log, err := logger.NewConsoleLogger(dir, logger.Error) // Error 级别：屏蔽限流噪声
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	cfg := &config.GatewayConfig{
		Gateway: config.GatewaySection{
			TcpPort:               freeTCPPort(t),
			ListenAddress:         "127.0.0.1",
			TcpMaxConnections:     maxConns,
			TcpIdleTimeoutSeconds: 30,
		},
		// 限流关掉：本用例考的是连接数上限，别让限流先拒绝
		RateLimit: config.RateLimitSection{Enabled: false},
	}
	return NewServer(cfg, mockHandler{}, log, nil)
}

// dialAndHold 建立一条连接并返回。连接不发任何数据 → handleClient 阻塞在读帧上。
func dialAndHold(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatalf("建立连接失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// isClosedByServer 判断服务端是否已把这条连接关掉：EOF/其它错误 = 已关；读超时 = 还挂着。
func isClosedByServer(t *testing.T, conn net.Conn, wait time.Duration) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return true
}

func TestTcpMaxConnectionsIsEnforced(t *testing.T) {
	const maxConns = 2
	s := newTestAuthServer(t, maxConns)
	if err := s.Start(); err != nil {
		t.Fatalf("启动认证服务失败: %v", err)
	}
	t.Cleanup(s.Stop)

	port := s.config.Gateway.TcpPort

	// 占满两个名额
	hold1 := dialAndHold(t, port)
	hold2 := dialAndHold(t, port)

	// 等 acceptLoop 把它们计入（连接建立即计数，给一点调度余量）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.getActiveConns() >= maxConns {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.getActiveConns(); got < maxConns {
		t.Fatalf("活跃连接计数应达到 %d，实际 %d —— 递减位置又跑到函数入口去了？", maxConns, got)
	}

	// 第三条必须被拒绝
	over := dialAndHold(t, port)
	if !isClosedByServer(t, over, 1500*time.Millisecond) {
		t.Fatalf("超过 TcpMaxConnections=%d 的连接没有被关闭（上限保护失效）", maxConns)
	}

	// 关掉一条后，计数要能降下来（证明递减确实发生在连接结束时）
	_ = hold1.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.getActiveConns() < maxConns {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := s.getActiveConns(); got >= maxConns {
		t.Fatalf("连接关闭后计数没有回落：仍为 %d", got)
	}

	// 释放出名额后，新连接应当重新被接受
	_ = hold2.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.getActiveConns() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	again := dialAndHold(t, port)
	if isClosedByServer(t, again, 800*time.Millisecond) {
		t.Fatalf("名额释放后新连接仍被拒 —— 计数只增不减")
	}
}
