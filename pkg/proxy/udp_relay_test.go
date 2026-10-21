package proxy

import (
	"net"
	"testing"
	"time"
)

// freeUDPPort 借一个空闲 UDP 端口（先绑 :0 拿号，再关掉）。
//
// 只给单测用：中继要求"监听端口 == 后端端口"，本机做不到，
// 所以测试走 backendPorts 例外映射，公网侧仍需要一个具体端口号。
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("借端口失败: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

// readWithTimeout 从 UDP 连接读一个数据报，超时即失败。
func readWithTimeout(t *testing.T, conn *net.UDPConn, who string) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("%s 设置读超时失败: %v", who, err)
	}
	buf := make([]byte, 2048)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("%s 读失败: %v", who, err)
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, addr
}

// TestUDPRelayPerClientUpstreamSocket 验证 S5A3 最关键的一条语义：
// 不同客户端在中继后端必须表现为**不同的源端口**。
//
// 如果所有客户端共用一个后端 socket，服务端会把所有队友折叠成同一个
// 端点，组队转发全乱 —— 这正是这个中继存在的理由。
func TestUDPRelayPerClientUpstreamSocket(t *testing.T) {
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("后端监听失败: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port

	publicPort := freeUDPPort(t)
	relay := NewUDPRelay("s5a3", "127.0.0.1", []int{publicPort})
	if relay == nil {
		t.Fatal("中继未创建")
	}
	relay.backendPorts = map[int]int{publicPort: backendPort}
	if failures := relay.Start(); len(failures) > 0 {
		t.Fatalf("中继启动失败: %v", failures)
	}
	defer relay.Stop()

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: publicPort}
	client1, err := net.DialUDP("udp", nil, clientAddr)
	if err != nil {
		t.Fatalf("客户端1 连接失败: %v", err)
	}
	defer client1.Close()
	client2, err := net.DialUDP("udp", nil, clientAddr)
	if err != nil {
		t.Fatalf("客户端2 连接失败: %v", err)
	}
	defer client2.Close()

	if _, err := client1.Write([]byte("hello-from-1")); err != nil {
		t.Fatalf("客户端1 发送失败: %v", err)
	}
	if _, err := client2.Write([]byte("hello-from-2")); err != nil {
		t.Fatalf("客户端2 发送失败: %v", err)
	}

	seen := map[string]string{} // 后端观察到的源地址 → 收到的内容
	var upstreamAddrs []*net.UDPAddr
	for i := 0; i < 2; i++ {
		payload, addr := readWithTimeout(t, backend, "后端")
		seen[addr.String()] = string(payload)
		upstreamAddrs = append(upstreamAddrs, addr)
	}

	if len(seen) != 2 {
		t.Fatalf("后端只看到 %d 个源端点（期望 2 个）：%v —— 客户端被折叠成同一端点，组队会串包",
			len(seen), seen)
	}
	if upstreamAddrs[0].Port == upstreamAddrs[1].Port {
		t.Fatalf("两个客户端的后端源端口相同（%d），服务端无法区分玩家", upstreamAddrs[0].Port)
	}
	if len(seen) != 2 {
		t.Fatalf("后端内容数不符: %v", seen)
	}

	// 回程：分别回不同的包，客户端必须各自收到自己的那一份。
	if _, err := backend.WriteToUDP([]byte("reply-for-1"), upstreamAddrs[0]); err != nil {
		t.Fatalf("后端回包1失败: %v", err)
	}
	if _, err := backend.WriteToUDP([]byte("reply-for-2"), upstreamAddrs[1]); err != nil {
		t.Fatalf("后端回包2失败: %v", err)
	}

	got1, _ := readWithTimeout(t, client1, "客户端1")
	got2, _ := readWithTimeout(t, client2, "客户端2")

	// 哪个后端端点属于哪个客户端，取决于谁先到；用内容对齐验证不错位。
	firstPayload := seen[upstreamAddrs[0].String()]
	wantForClient1, wantForClient2 := "reply-for-1", "reply-for-2"
	if firstPayload == "hello-from-2" {
		wantForClient1, wantForClient2 = "reply-for-2", "reply-for-1"
	}
	if string(got1) != wantForClient1 {
		t.Fatalf("客户端1 收到 %q，期望 %q —— 回程串包", got1, wantForClient1)
	}
	if string(got2) != wantForClient2 {
		t.Fatalf("客户端2 收到 %q，期望 %q —— 回程串包", got2, wantForClient2)
	}
}

// TestUDPRelayReusesSessionForSameClient 同一客户端连发多包只应建一个后端 socket。
func TestUDPRelayReusesSessionForSameClient(t *testing.T) {
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("后端监听失败: %v", err)
	}
	defer backend.Close()
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port

	publicPort := freeUDPPort(t)
	relay := NewUDPRelay("s5a3", "127.0.0.1", []int{publicPort})
	relay.backendPorts = map[int]int{publicPort: backendPort}
	if failures := relay.Start(); len(failures) > 0 {
		t.Fatalf("中继启动失败: %v", failures)
	}
	defer relay.Stop()

	client, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: publicPort})
	if err != nil {
		t.Fatalf("客户端连接失败: %v", err)
	}
	defer client.Close()

	for i := 0; i < 3; i++ {
		if _, err := client.Write([]byte("tick")); err != nil {
			t.Fatalf("第 %d 次发送失败: %v", i+1, err)
		}
		if _, err := backend.Read(make([]byte, 128)); err != nil {
			t.Fatalf("第 %d 次后端读失败: %v", i+1, err)
		}
	}
	// 给会话建立一点时间（第一包是同步建的，这里只是稳妥）。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if relay.SessionCount() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := relay.SessionCount(); got != 1 {
		t.Fatalf("会话数 = %d，期望 1（同一客户端应复用后端 socket）", got)
	}
}

// TestUDPRelayPorts 端口段生成与服务端默认值对齐。
func TestUDPRelayPorts(t *testing.T) {
	ports := UDPRelayPorts(30000, 64)
	if len(ports) != 64 {
		t.Fatalf("端口数 = %d，期望 64", len(ports))
	}
	if ports[0] != 30000 || ports[63] != 30063 {
		t.Fatalf("端口段边界错误: %d..%d", ports[0], ports[63])
	}
	if got := UDPRelayPorts(0, 64); got != nil {
		t.Fatalf("start=0 应返回 nil，得到 %v", got)
	}
	if got := UDPRelayPorts(30000, 0); got != nil {
		t.Fatalf("count=0 应返回 nil，得到 %v", got)
	}
}

// TestNewUDPRelayDisabled 没配端口/后端地址时不应创建中继。
func TestNewUDPRelayDisabled(t *testing.T) {
	if relay := NewUDPRelay("s5a3", "127.0.0.1", nil); relay != nil {
		t.Fatal("端口为空时应返回 nil")
	}
	if relay := NewUDPRelay("s5a3", "", []int{30000}); relay != nil {
		t.Fatal("后端地址为空时应返回 nil")
	}
}
