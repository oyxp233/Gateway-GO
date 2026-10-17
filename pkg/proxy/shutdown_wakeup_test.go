package proxy

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"s4a21-gateway/pkg/session"
)

// TestReadTimeoutWakesOnShutdown 验证 Stop() 能唤醒正阻塞在转发读上的 goroutine。
//
// 背景：GameServer.IdleTimeoutSeconds 默认 1800 秒，而 ProxyServer.Stop() 只是
// close(shutdown) + 关闭监听；已建立的连接要等各自的转发 goroutine 自己退出。
// 若 readTimeout 直接 SetReadDeadline(now+1800s) 后阻塞在 Read 上，shutdown
// 根本唤不醒它，wg.Wait() 就会一直等到 systemd 的 TimeoutStopUSec(90 秒）被 SIGKILL。
// 本用例锁住「shutdown 后必须迅速返回」这个行为。
func TestReadTimeoutWakesOnShutdown(t *testing.T) {
	p := &ProxyServer{
		shutdown:    make(chan struct{}),
		idleTimeout: 30 * time.Minute,
	}

	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	done := make(chan error, 1)
	go func() {
		_, err := p.readTimeout(conn, make([]byte, 16), p.idleTimeout)
		done <- err
	}()

	// 给它一点时间真正进入阻塞读
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	close(p.shutdown)

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if !errors.Is(err, errShutdown) {
			t.Fatalf("期望 errShutdown，实际 err=%v", err)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("shutdown 后 %v 才返回：没能及时唤醒（上线会拖到 systemd 90s SIGKILL）", elapsed)
		}
		t.Logf("shutdown 后 %v 返回（err=%v）", elapsed, err)
	case <-time.After(6 * time.Second):
		t.Fatal("readTimeout 在 shutdown 后 6 秒仍未返回 —— 唤醒失效")
	}
}

// TestReadTimeoutStillReturnsData 确认切片等待没有破坏正常读取。
func TestReadTimeoutStillReturnsData(t *testing.T) {
	p := &ProxyServer{
		shutdown:    make(chan struct{}),
		idleTimeout: 5 * time.Second,
	}

	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = peer.Write([]byte("hello"))
	}()

	buf := make([]byte, 16)
	n, err := p.readTimeout(conn, buf, p.idleTimeout)
	if err != nil {
		t.Fatalf("期望正常读到数据，实际 err=%v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("期望读到 hello，实际 n=%d buf=%q", n, buf[:n])
	}
}

// TestReadTimeoutStillExpires 确认空闲超时仍然生效（没被切片逻辑无限延长）。
func TestReadTimeoutStillExpires(t *testing.T) {
	p := &ProxyServer{
		shutdown:    make(chan struct{}),
		idleTimeout: 300 * time.Millisecond,
	}

	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	start := time.Now()
	_, err := p.readTimeout(conn, make([]byte, 16), p.idleTimeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("期望空闲超时错误，实际 nil")
	}
	if errors.Is(err, errShutdown) {
		t.Fatalf("不该返回 errShutdown（没关过服务），实际 %v", err)
	}
	if elapsed < 250*time.Millisecond {
		t.Fatalf("过早超时：%v（应约等于 idleTimeout=300ms）", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("超时被拉长到 %v（应约等于 idleTimeout=300ms）", elapsed)
	}
	t.Logf("空闲 %v 后超时（err=%v）", elapsed, err)
}

// TestStopClosesConnectionPromptly 集成级验证：一条已进入转发的在线连接存在时，
// Stop() 也必须秒级返回。
//
// 这是 216 上「每次重启都卡 90 秒、最后被 SIGKILL」的直接复现场景：
// 转发 goroutine 阻塞在 readTimeout（idleTimeout=30s，线上默认 1800s）上，
// 只 close(shutdown) 唤不醒它，wg.Wait() 就一路等到 systemd 的 TimeoutStopUSec。
func TestStopClosesConnectionPromptly(t *testing.T) {
	backendPort := freePort(t)
	pub := freePort(t)
	channelPort := freePort(t)

	backend, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(backendPort)))
	if err != nil {
		t.Fatalf("起假后端失败: %v", err)
	}
	defer backend.Close()

	store := NewPortConfigStoreBootstrap(t.TempDir(), nil, nil)
	pHolder := wireStore(store)
	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub, Backend: backendPort, Enabled: true},
	}}); err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}

	sm := session.NewSessionManager(func() {}, func() {})
	if _, err := sm.CreateSession("tester", "test-mid", "127.0.0.1", "dev-secret", ""); err != nil {
		t.Fatalf("建会话失败: %v", err)
	}

	p := newTestProxy(t, store, sm, channelPort)
	*pHolder = p
	p.Start()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(pub)), 2*time.Second)
	if err != nil {
		t.Fatalf("连接测试端口失败: %v", err)
	}
	defer conn.Close()

	// 首帧用"完整但非登录"的 14 字节帧——立即读齐、不进首包超时等待；
	// 非登录包 ⇒ 回退 IP 白名单（127.0.0.1 上建有会话）⇒ 放行，与旧行为等价。
	// 注意后端连接在首包之前就已建立（游戏口是服务端先说话协议，
	// 见 handleGameClient 的时序说明），这里的 Accept 本就能立刻拿到。
	if _, err := conn.Write(nonLoginFirstPacket()); err != nil {
		t.Fatalf("发送首包失败: %v", err)
	}

	_ = backend.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	backendConn, err := backend.Accept()
	if err != nil {
		t.Fatalf("代理未连上后端: %v", err)
	}
	defer backendConn.Close()

	first := make([]byte, 64)
	_ = backendConn.(*net.TCPConn).SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := backendConn.Read(first); err != nil || first[0] != 0xAA {
		t.Fatalf("首包未透传到后端: n=%d err=%v", n, err)
	}

	// 此刻转发 goroutine 正阻塞在 readTimeout（newTestProxy 里 idleTimeout=30s）。
	done := make(chan time.Duration, 1)
	go func() {
		t0 := time.Now()
		p.Stop()
		done <- time.Since(t0)
	}()

	select {
	case elapsed := <-done:
		if elapsed > 3*time.Second {
			t.Fatalf("Stop() 用了 %v 才返回（应秒级返回）", elapsed)
		}
		t.Logf("Stop() 用时 %v", elapsed)
	case <-time.After(8 * time.Second):
		t.Fatal("Stop() 8 秒仍未返回 —— 转发 goroutine 卡在长空闲读上（上线会拖到 90s SIGKILL）")
	}
}
