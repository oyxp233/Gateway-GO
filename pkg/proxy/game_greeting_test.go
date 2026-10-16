package proxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"s4a21-gateway/pkg/session"
)

// ─────────────────────────────────────────────────────────────
// 游戏口「服务端先说话」时序回归（2026-10-16 线上事故）
//
// 事故：方案 D 初版把「连后端」前移到首包准入之后。但游戏口协议是
// **服务端先说话**——后端一收到 PROXY 头就主动下发 83 字节频道
// greeting（内容含频道名 ch.10 与 endpoint），客户端收到它才发登录包。
// 于是客户端等 greeting、网关等首包，互相干等到客户端超时（线上抓包
// 实测 1.8~8 秒），用户反馈「进频道/切频道延迟比较高」。
//
// 修法：连后端 + 写 PROXY 头 + 启下行 goroutine 回到首包之前（accept
// 即连），准入仍只认首包凭证——客户端数据在准入通过前一个字节都不进
// 后端。下面两个用例分别锁住这两半。
// ─────────────────────────────────────────────────────────────

// acceptGreetingBackend 接受一条后端连接：立即下发 greeting（复刻线上
// dfo-server「只收 PROXY 头、零客户端数据也发」的行为），并把随后收到
// 的全部字节（直到对端关闭或超时）送到返回 channel（cap=1，无需读取）。
func acceptGreetingBackend(ln net.Listener, greeting []byte, wait time.Duration) <-chan []byte {
	out := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer c.Close()
		_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(greeting)
		_ = c.SetReadDeadline(time.Now().Add(wait))
		data, _ := io.ReadAll(c)
		out <- data
	}()
	return out
}

// TestGameGreetingReachesClientBeforeFirstPacket 回归：客户端只连、不发，
// 也必须在秒级收到后端 greeting——这是服务端先说话协议的生命线。
// 把「连后端」挪回首包之后，本用例必红（greeting 永远不来，
// 客户端干等到自己的超时，线上即 1.8~8 秒的进频道延迟）。
func TestGameGreetingReachesClientBeforeFirstPacket(t *testing.T) {
	greeting := []byte("GREETING ch.10 endpoint=127.0.0.2")
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假后端失败: %v", err)
	}
	defer backend.Close()
	acceptGreetingBackend(backend, greeting, 10*time.Second)

	_, bpStr, _ := net.SplitHostPort(backend.Addr().String())
	backendPort, _ := strconv.Atoi(bpStr)

	pub := freePort(t)
	channelPort := freePort(t)

	store := NewPortConfigStoreBootstrap(t.TempDir(), nil, nil)
	pHolder := wireStore(store)
	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub, Backend: backendPort, Enabled: true},
	}}); err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}

	sm := session.NewSessionManager(func() {}, func() {})
	p := newTestProxy(t, store, sm, channelPort)
	// 开 GamePortAuth（= 161 现配）：不预拒 IP，让连接走到连后端这一步
	p.profile.GamePortAuth.Enabled = true
	*pHolder = p
	defer p.Stop()
	p.Start()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(pub)), 2*time.Second)
	if err != nil {
		t.Fatalf("连接测试端口失败: %v", err)
	}
	defer conn.Close()

	// 只连、不发：等网关把后端 greeting 转过来
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(greeting))
	start := time.Now()
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("连接后 %v 仍未收到后端 greeting（err=%v）——网关把连后端推迟到了首包之后，"+
			"客户端等 greeting、网关等首包，线上表现为进频道/切频道延迟数秒", time.Since(start), err)
	}
	if !bytes.Equal(buf, greeting) {
		t.Fatalf("greeting 内容不符: got=%q want=%q", buf, greeting)
	}
	t.Logf("连接后 %v 收到 greeting", time.Since(start))
}

// TestRejectedGameConnNeverReachesBackend 回归：准入不通过的连接，
// 客户端的字节一个都不能进后端——后端只允许看到 PROXY 头（greeting 需要它），
// 且后端连接必须被网关立即关掉。
func TestRejectedGameConnNeverReachesBackend(t *testing.T) {
	greeting := []byte("GREETING")
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起假后端失败: %v", err)
	}
	defer backend.Close()
	received := acceptGreetingBackend(backend, greeting, 10*time.Second)

	_, bpStr, _ := net.SplitHostPort(backend.Addr().String())
	backendPort, _ := strconv.Atoi(bpStr)

	pub := freePort(t)
	channelPort := freePort(t)

	store := NewPortConfigStoreBootstrap(t.TempDir(), nil, nil)
	pHolder := wireStore(store)
	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub, Backend: backendPort, Enabled: true},
	}}); err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}

	// 无会话 ⇒ 127.0.0.1 不在白名单。开 GamePortAuth（观察模式）⇒
	// 首包解析失败 ⇒ 回退白名单 ⇒ 拒绝（与线上一致：零新增拒绝路径）。
	sm := session.NewSessionManager(func() {}, func() {})
	p := newTestProxy(t, store, sm, channelPort)
	p.profile.GamePortAuth.Enabled = true
	p.profile.ProxyProtocol = "v1" // 对齐 161 现配：后端靠这行头触发 greeting
	*pHolder = p
	defer p.Stop()
	p.Start()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(pub)), 2*time.Second)
	if err != nil {
		t.Fatalf("连接测试端口失败: %v", err)
	}
	defer conn.Close()

	// 完整但非登录的首帧 ⇒ 回退白名单 ⇒ 拒
	if _, err := conn.Write(nonLoginFirstPacket()); err != nil {
		t.Fatalf("发送首包失败: %v", err)
	}

	select {
	case data := <-received:
		if !bytes.HasPrefix(data, []byte("PROXY ")) {
			t.Fatalf("后端应先收到 PROXY 头，实际: %q", data)
		}
		// PROXY 头之后不该有任何客户端字节
		if idx := bytes.Index(data, []byte("\r\n")); idx < 0 || len(data) != idx+2 {
			t.Fatalf("拒绝连接仍把客户端字节送进了后端: %q", data)
		}
		t.Logf("后端只收到 PROXY 头（%d 字节），连接已被网关关闭", len(data))
	case <-time.After(5 * time.Second):
		t.Fatal("后端连接 5 秒未被关闭——拒决后网关没释放后端连接")
	}
}
