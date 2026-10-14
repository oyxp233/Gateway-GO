//go:build linux

package proxy

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// 硬证据：SO_KEEPALIVE 真的被置上了（不是「函数调用了」就算过）
//
// 只在 linux 编译 —— Windows 的 syscall.GetsockoptInt 签名不同（Handle vs int），
// 混在一起过不了编译。部署目标就是 linux，本地开发跳过即可。
// ─────────────────────────────────────────────────────────────────────────────

// soKeepAlive 读取 socket 的 SO_KEEPALIVE 当前值。
func soKeepAlive(t *testing.T, conn net.Conn) int {
	t.Helper()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("不是 *net.TCPConn: %T", conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var val int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		val, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if serr != nil {
		t.Fatalf("GetsockoptInt: %v", serr)
	}
	return val
}

// keepAliveIdleSecs 读取 TCP_KEEPIDLE（保活探测启动前的空闲秒数）。
func keepAliveIdleSecs(t *testing.T, conn net.Conn) int {
	t.Helper()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("不是 *net.TCPConn: %T", conn)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var val int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		val, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if serr != nil {
		t.Fatalf("GetsockoptInt(TCP_KEEPIDLE): %v", serr)
	}
	return val
}

// TestSetKeepAliveSetsSocketOptionLinux 开启后 socket 上必须能看到
// SO_KEEPALIVE=1，且 TCP_KEEPIDLE 等于配置的周期（不能是系统默认 7200s，
// 那样仍然要两小时才探一次，等于没修）。
func TestSetKeepAliveSetsSocketOptionLinux(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// 前置：默认应未开启（证明断言有区分力，不是恒真）
	if got := soKeepAlive(t, client); got != 0 {
		t.Fatalf("未调用 setKeepAlive 前 SO_KEEPALIVE 就已是 %d，断言无意义", got)
	}

	setKeepAlive(client, 60*time.Second)

	if got := soKeepAlive(t, client); got != 1 {
		t.Fatalf("setKeepAlive 后 SO_KEEPALIVE = %d, want 1（保活没开 ⇒ 半开连接仍会占槽 30 分钟）", got)
	}
	if got := keepAliveIdleSecs(t, client); got != 60 {
		t.Fatalf("TCP_KEEPIDLE = %d, want 60（周期没生效 ⇒ 仍在用系统默认的 7200s）", got)
	}
}

// TestSetKeepAliveZeroLeavesOptionOff 配置为 0（关闭）时**不得**改动 socket：
// 这条是关掉功能的退路，必须保持可用。
func TestSetKeepAliveZeroLeavesOptionOff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	setKeepAlive(client, 0)

	if got := soKeepAlive(t, client); got != 0 {
		t.Fatalf("period=0 时不应开启保活，实际 SO_KEEPALIVE = %d", got)
	}
}
