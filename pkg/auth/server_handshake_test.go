package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
// 握手不得阻塞 acceptLoop（G-8，2026-10-15 正式服2 故障定型）
//
// 修复前：acceptLoop 在主循环里**同步**执行 tlsConn.Handshake()，超时复用
// TcpIdleTimeoutSeconds（线上 600s）。一个"连上但不发 ClientHello"的连接
// 即可把 acceptLoop 卡住整个 idle 时长；期间新玩家 TCP 连得上（内核 backlog
// 照常接纳）却永远等不到 ServerHello，登录器 20s 超时批量报 L4002。
//
// 193 实测特征（journal）：一批玩家 IP 在同一秒全部 "TLS 握手失败: EOF"，
//  preceded by 一条 "i/o timeout"（沉默连接 600s deadline 到期的痕迹）。
//
// 断言口径（修复前必须红）：
//   ① 沉默连接在场时，正常客户端仍能在 3s 内完成 TLS 握手并收到响应；
//   ② 沉默连接按**握手超时**（独立配置，非 idle 超时）被关闭。
// ─────────────────────────────────────────────────────────────────────────────

// selfSignedCert 造一张仅测试用的自签证书（127.0.0.1）。
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("自签证书失败: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTestTLSAuthServer 造一个开 TLS 的认证服务（maxConns=0 表示不限制）。
func newTestTLSAuthServer(t *testing.T, maxConns, idleSecs, hsSecs int) *Server {
	t.Helper()
	// 日志目录不用 t.TempDir：Windows 上句柄未释放会让 TempDir 清理报错
	dir, err := os.MkdirTemp("", "s4a21-auth-tls-test-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	log, err := logger.NewConsoleLogger(dir, logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	cert := selfSignedCert(t)
	cfg := &config.GatewayConfig{
		Gateway: config.GatewaySection{
			TcpPort:                    freeTCPPort(t),
			ListenAddress:              "127.0.0.1",
			TcpMaxConnections:          maxConns,
			TcpIdleTimeoutSeconds:      idleSecs,
			TcpHandshakeTimeoutSeconds: hsSecs,
		},
		RateLimit: config.RateLimitSection{Enabled: false},
	}
	return NewServer(cfg, mockHandler{}, log, &cert)
}

// tlsLoginRoundTrip 走完整链路：TLS 握手 → 写一个登录帧 → 读响应。
func tlsLoginRoundTrip(t *testing.T, port int) error {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp",
		"127.0.0.1:"+strconv.Itoa(port),
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	payload := []byte(`{"cmd":"login","launcher_version":"9.9.9"}`)
	if err := WriteFrame(conn, payload); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n == 0 {
		t.Fatal("读到空响应")
	}
	return nil
}

// TestSlowHandshakeDoesNotBlockOthers：
// 沉默连接（连上不发 ClientHello）不得阻塞其他客户端的握手。
func TestSlowHandshakeDoesNotBlockOthers(t *testing.T) {
	s := newTestTLSAuthServer(t, 0, 30, 10)
	if err := s.Start(); err != nil {
		t.Fatalf("启动认证服务失败: %v", err)
	}
	t.Cleanup(s.Stop)

	port := s.config.Gateway.TcpPort

	// 复现故障连接：TCP 连上后一个字节都不发
	silent := dialAndHold(t, port)
	_ = silent

	// 正常客户端必须在 3s 内完成握手并收到响应
	done := make(chan error, 1)
	go func() { done <- tlsLoginRoundTrip(t, port) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("沉默连接在场时正常客户端握手失败: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("沉默连接存在时，正常客户端 3s 内未能完成 TLS 握手 —— acceptLoop 同步握手缺陷复发（玩家会批量 L4002）")
	}
}

// TestHandshakeTimeoutIsIndependentOfIdleTimeout：
// 沉默连接必须按握手超时（2s）被关闭，而不是等满 idle 超时（30s）。
func TestHandshakeTimeoutIsIndependentOfIdleTimeout(t *testing.T) {
	s := newTestTLSAuthServer(t, 0, 30, 2)
	if err := s.Start(); err != nil {
		t.Fatalf("启动认证服务失败: %v", err)
	}
	t.Cleanup(s.Stop)

	silent := dialAndHold(t, s.config.Gateway.TcpPort)
	if !isClosedByServer(t, silent, 4*time.Second) {
		t.Fatal("沉默连接未在握手超时（2s）内被关闭 —— 握手超时未独立于 idle timeout（线上会被卡 600s）")
	}
}

// TestTlsLoginStillWorks 回归：TLS 全链路（握手 + 登录帧往返）修复后仍正常。
func TestTlsLoginStillWorks(t *testing.T) {
	s := newTestTLSAuthServer(t, 0, 30, 10)
	if err := s.Start(); err != nil {
		t.Fatalf("启动认证服务失败: %v", err)
	}
	t.Cleanup(s.Stop)

	if err := tlsLoginRoundTrip(t, s.config.Gateway.TcpPort); err != nil {
		t.Fatalf("TLS 登录往返失败: %v", err)
	}
}

var _ = models.GatewayRequest{} // 保持 models 导入（夹具演进备用）
