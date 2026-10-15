package proxy

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/session"
)

// freePort 取一个当前空闲的 TCP 端口（先监听 :0 再释放）。
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// dialOK 判断某端口当前是否有人监听（能完成 TCP 握手即算监听中）。
func dialOK(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func newTestProxy(t *testing.T, store *PortConfigStore, sm *session.SessionManager, channelPort int) *ProxyServer {
	t.Helper()
	// 日志目录不用 t.TempDir：Windows 上日志文件句柄未释放会让 TempDir 清理报错
	logDir, err := os.MkdirTemp("", "s4a21-gw-test-")
	if err != nil {
		t.Fatalf("建测试日志目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(logDir) })

	// 级别 Error：屏蔽热加载的 Info 噪声，只留真正的问题
	log, err := logger.NewConsoleLogger(logDir, logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}

	cfg := &config.GatewayConfig{
		Gateway: config.GatewaySection{
			ProxyPort:     channelPort,
			ListenAddress: "127.0.0.1",
		},
		GameServer: config.GameServerSection{
			PublicIP:                "127.0.0.1",
			BackendHost:             "127.0.0.1",
			BackendChannelPort:      7001,
			MaxConnectionsPerIP:     4,
			FirstReadTimeoutSeconds: 10,
			IdleTimeoutSeconds:      30,
		},
	}
	return NewProxyServer(cfg, sm, log, store, nil)
}

// wireStore 把端口表的 onChange 接到代理服务器上（模拟 main.go 的接线）。
func wireStore(store *PortConfigStore) **ProxyServer {
	holder := new(*ProxyServer)
	store.onChange = func(cfg *ProxyPortConfig) ReloadResult {
		if *holder == nil {
			return ReloadResult{}
		}
		return (*holder).ReloadPorts(cfg)
	}
	return holder
}

// TestReloadPorts_HotOpenAndClose 验证端口表热加载：
// 保存即开/关监听，无需重启；关闭后可重新启用；改后端端口会重建监听；
// 删除一行等价于关闭该端口。
func TestReloadPorts_HotOpenAndClose(t *testing.T) {
	pub1, pub2, pub3 := freePort(t), freePort(t), freePort(t)
	channelPort := freePort(t)

	store := NewPortConfigStoreBootstrap(t.TempDir(), nil, nil)
	pHolder := wireStore(store)

	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10001, Enabled: true},
		{Public: pub2, Backend: 10002, Enabled: true},
		{Public: pub3, Backend: 10003, Enabled: false},
	}}); err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}

	p := newTestProxy(t, store, session.NewSessionManager(func() {}, func() {}), channelPort)
	*pHolder = p
	p.Start()
	defer p.Stop()

	if !dialOK(pub1) || !dialOK(pub2) {
		t.Fatal("启用中的端口应处于监听状态")
	}
	if dialOK(pub3) {
		t.Fatal("停用的端口不应被监听")
	}

	// 关掉 pub2、打开 pub3 —— 只保存，不重启
	res, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10001, Enabled: true},
		{Public: pub2, Backend: 10002, Enabled: false},
		{Public: pub3, Backend: 10003, Enabled: true},
	}})
	if err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}
	if len(res.Opened) != 1 || res.Opened[0] != pub3 {
		t.Fatalf("期望新开 pub3，实际 %v", res.Opened)
	}
	if len(res.Closed) != 1 || res.Closed[0].Port != pub2 || res.Closed[0].Reason != "disabled" {
		t.Fatalf("期望关闭 pub2(disabled)，实际 %+v", res.Closed)
	}
	if !dialOK(pub1) || !dialOK(pub3) {
		t.Fatal("pub1 应保持监听，pub3 应立即开始监听")
	}
	if dialOK(pub2) {
		t.Fatal("pub2 应立即停止监听")
	}

	// 重新启用被关掉的 pub2：必须能重新绑定（验证关/开可反复）
	res, err = store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10001, Enabled: true},
		{Public: pub2, Backend: 10002, Enabled: true},
		{Public: pub3, Backend: 10003, Enabled: true},
	}})
	if err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}
	if len(res.Opened) != 1 || res.Opened[0] != pub2 {
		t.Fatalf("期望重新打开 pub2，实际 %v", res.Opened)
	}
	if !dialOK(pub2) {
		t.Fatal("重新启用的端口应重新处于监听状态")
	}

	// 改 pub1 的后端端口：公网端口没变，但监听必须按新后端重建
	res, err = store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10099, Enabled: true},
		{Public: pub2, Backend: 10002, Enabled: true},
		{Public: pub3, Backend: 10003, Enabled: true},
	}})
	if err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}
	if len(res.Closed) != 1 || res.Closed[0].Port != pub1 || res.Closed[0].Reason != "remapped" {
		t.Fatalf("期望 pub1 因改绑而重建监听，实际 %+v", res.Closed)
	}
	if len(res.Opened) != 1 || res.Opened[0] != pub1 {
		t.Fatalf("期望 pub1 重新打开，实际 %v", res.Opened)
	}
	if !dialOK(pub1) {
		t.Fatal("改绑后的端口应处于监听状态")
	}

	// 端口表视图同步刷新（决定频道列表里还有哪些频道可选）
	view := p.ports.Load()
	if pub, ok := view.publicFor(10099); !ok || pub != pub1 {
		t.Fatalf("视图应把 10099 映射到 %d，实际 %d/%v", pub1, pub, ok)
	}
	if _, ok := view.publicFor(10002); !ok {
		t.Fatal("pub2 的后端 10002 仍应可进")
	}

	// 删除 pub3 那一行：等价于关闭该端口
	res, err = store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10099, Enabled: true},
		{Public: pub2, Backend: 10002, Enabled: true},
	}})
	if err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}
	if len(res.Closed) != 1 || res.Closed[0].Reason != "removed" {
		t.Fatalf("期望 pub3 以 removed 关闭，实际 %+v", res.Closed)
	}
	if dialOK(pub3) {
		t.Fatal("被删除的端口应立即停止监听")
	}
	if _, ok := p.ports.Load().publicFor(10003); ok {
		t.Fatal("被删除端口对应的频道不应再可选")
	}
}

// TestReloadPorts_ExistingConnectionSurvivesClose 验证关闭端口不踢在线玩家：
// 已建立并进入转发的连接，在端口被关闭后仍能双向收发。
func TestReloadPorts_ExistingConnectionSurvivesClose(t *testing.T) {
	backendPort := freePort(t)
	pub := freePort(t)
	channelPort := freePort(t)

	// 假后端：接收代理转发过来的数据
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
	// 建一个本机会话，让 127.0.0.1 进入 Game 代理白名单
	if _, err := sm.CreateSession("tester", "test-mid", "127.0.0.1", "dev-secret"); err != nil {
		t.Fatalf("建会话失败: %v", err)
	}

	p := newTestProxy(t, store, sm, channelPort)
	*pHolder = p
	p.Start()
	defer p.Stop()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(pub)), 2*time.Second)
	if err != nil {
		t.Fatalf("连接测试端口失败: %v", err)
	}
	defer conn.Close()

	// 方案 D 起「连后端」前移到首包准入之后：先写首包再等后端 Accept
	// （完整非登录帧 ⇒ 回退白名单放行，同 shutdown_wakeup_test.go 的说明）
	if _, err := conn.Write(nonLoginFirstPacket()); err != nil {
		t.Fatalf("发送首包失败: %v", err)
	}

	// 代理应已连上假后端，说明这条连接确实进入了转发链路
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

	// 关闭该端口：只停监听，必须在线的连接不受影响
	res, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub, Backend: backendPort, Enabled: false},
	}})
	if err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}
	if len(res.Closed) != 1 || res.Closed[0].OnlineConnections != 1 {
		t.Fatalf("关闭时应报告 1 个在线连接，实际 %+v", res.Closed)
	}
	if dialOK(pub) {
		t.Fatal("端口应已停止接受新连接")
	}

	// 关键断言：已建立的连接仍是活的，数据照常双向透传
	if _, err := conn.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("关闭端口后，已在线连接被断开: %v", err)
	}
	buf := make([]byte, 3)
	_ = backendConn.(*net.TCPConn).SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := backendConn.Read(buf); err != nil {
		t.Fatalf("关闭端口后，已在线连接的数据未能透传到后端: %v", err)
	}
	if buf[0] != 0x01 || buf[1] != 0x02 || buf[2] != 0x03 {
		t.Fatalf("透传数据不一致: %v", buf)
	}

	// 反方向（后端 -> 客户端）同样不能断
	if _, err := backendConn.Write([]byte{0x09}); err != nil {
		t.Fatalf("后端下行写入失败: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	back := make([]byte, 1)
	if _, err := conn.Read(back); err != nil || back[0] != 0x09 {
		t.Fatalf("关闭端口后，下行数据未透传到客户端: %v/%v", back, err)
	}
}

// TestPortViewConcurrentReloadAndRead 复现"管理员保存端口配置的同时，
// 有玩家在拉频道列表"这一并发场景。
//
// 旧实现里 backendToPublic 是裸 map：下行热路径无锁读、ReloadPorts 加锁写，
// 一旦撞上就是 Go 运行时的致命错误
// "fatal error: concurrent map read and map write"，整个网关进程当场挂掉。
// 改成不可变快照 + 原子替换后，这里应该稳定跑完。
func TestPortViewConcurrentReloadAndRead(t *testing.T) {
	pub1, pub2 := freePort(t), freePort(t)

	store := NewPortConfigStoreBootstrap(t.TempDir(), nil, nil)
	pHolder := wireStore(store)
	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: pub1, Backend: 10011, Enabled: true},
		{Public: pub2, Backend: 10012, Enabled: true},
	}}); err != nil {
		t.Fatalf("保存端口表失败: %v", err)
	}

	p := newTestProxy(t, store, session.NewSessionManager(func() {}, func() {}), freePort(t))
	*pHolder = p
	p.Start()
	defer p.Stop()

	// 频道列表明文在进入并发之前先造好（构造器里用了 t.Fatalf）
	plain := buildTestChannelList(t,
		[]string{"#ch.11", "#ch.12"},
		[]int{10011, 10012},
		"100.64.0.9")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// 模拟多个玩家同时拉频道列表
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rewritePlaintextAndFilter(plain, "10.0.0.1", p.ports.Load())
			}
		}()
	}

	// 主线程反复保存（开/关/改绑交替），模拟管理员连点保存
	for i := 0; i < 60; i++ {
		_, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
			{Public: pub1, Backend: 10011, Enabled: i%2 == 0},
			{Public: pub2, Backend: 10011 + i%2, Enabled: true},
		}})
		if err != nil {
			t.Fatalf("第 %d 次保存失败: %v", i, err)
		}
	}

	close(stop)
	wg.Wait()
}

func TestPortConfigStore_SavePersistsNoteAndReloadsFromFile(t *testing.T) {
	dir := t.TempDir()
	store := NewPortConfigStoreBootstrap(dir, nil, nil)

	if _, err := store.Save(&ProxyPortConfig{GamePorts: []GamePortMapping{
		{Public: 20011, Backend: 10011, Enabled: true, Note: "一线"},
	}}); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 重启（新进程重新读取同一个文件）后，备注与端口表都必须还在
	reloaded := NewPortConfigStoreBootstrap(dir, nil, nil)
	conf := reloaded.GetConfig()
	if conf == nil || len(conf.GamePorts) != 1 {
		t.Fatalf("重新加载端口表失败: %+v", conf)
	}
	if conf.GamePorts[0].Note != "一线" {
		t.Fatalf("备注未持久化: %+v", conf.GamePorts[0])
	}
	if _, err := os.Stat(filepath.Join(dir, "proxy_ports.json")); err != nil {
		t.Fatalf("端口表文件不存在: %v", err)
	}
}
