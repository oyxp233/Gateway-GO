package proxy

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// S5A3 服的代理侧强制设置
//
// 与 S5A95 的 TestNewProxyServerS5A95ForcedSettings 同一思路：配置里怎么写
// 都不算数，NewProxyServer 里对 S5A3 有两处硬性覆盖，这里把它们钉死。
// ─────────────────────────────────────────────────────────────────────────────

func s5a3TestConfig() *config.GatewayConfig {
	profile := config.GameServerEntry{
		Id:       "s5a3",
		Name:     "S5A3",
		Protocol: config.ProtocolS5A3,
	}
	profile.BackendHost = "127.0.0.1"
	profile.BackendChannelPort = 7001
	profile.ChannelListenerPort = 7001
	profile.GamePorts = []int{10006}
	profile.PartyUDPPorts = []int{30000, 30001}

	cfg := &config.GatewayConfig{}
	cfg.Gateway.ListenAddress = "127.0.0.1"
	cfg.GameServers = []config.GameServerEntry{profile}
	return cfg
}

func TestNewProxyServerS5A3ForcedSettings(t *testing.T) {
	cfg := s5a3TestConfig()
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(lg.Close)

	// 故意把两个开关全打开，验证被强制关掉
	profile := cfg.GameServers[0]
	profile.ProxyProtocol = "v1"
	profile.GamePortAuth.Enabled = true

	srv := NewProxyServer(cfg, profile, nil, lg, nil, nil)

	// 1) PROXY protocol 必须关：S5A3 服务端不认这行头，
	//    发了它会把 PROXY 行当成游戏包头，解析失败 → 玩家立刻掉线。
	if srv.profile.ProxyProtocol != "off" {
		t.Fatalf("S5A3 的 ProxyProtocol 应被强制为 off，实际 %q", srv.profile.ProxyProtocol)
	}

	// 2) 方案 D（游戏口首包凭证）必须关：S5A3 的游戏口是**服务端先说话**
	//    （先下发频道 greeting），网关等首包准入会与客户端互相干等到超时。
	if srv.profile.GamePortAuth.Enabled {
		t.Fatal("S5A3 的 GamePortAuth.Enabled 应被强制为 false")
	}

	// 3) 频道口必须绑透传适配器（不能是 nil，nil 与"显式透传"在
	//    copyDownlink 里行为相同，但 nil 会让人误以为"忘了配适配器"）。
	if srv.channelAdapter == nil {
		t.Fatal("S5A3 应绑定频道口透传适配器")
	}
	if _, ok := srv.channelAdapter.(s5a3PassthroughAdapter); !ok {
		t.Fatalf("S5A3 频道口适配器类型应为 s5a3PassthroughAdapter，实际 %T", srv.channelAdapter)
	}
}

// TestS5A3PassthroughAdapterWritesBytes 透传适配器必须**把字节真的写给 dst**。
//
// ★ 2026-10-22 重写。原测试断言的是 `ProcessDownlink(input, nil) == input`，
// 把接口语义搞反了：DownlinkAdapter 的返回值是**尚未处理完的残包**，不是
// "处理结果"。于是初版实现 `return pending` 既没写 dst、又把数据留在缓冲区，
// 原测试却全程绿灯——测试固化了一个会让频道口彻底瘫痪的 bug（线上表现为
// 「接受频道信息失败」，后端 13.6KB 频道表被网关吞进内存）。
//
// 现在断言两件事，缺一不可：
//  1. 字节逐字节到达 dst（不改写，守"网关不理解 S5A3 帧"的承诺）；
//  2. 返回值必须是空（无残包），否则 copyDownlink 会无限堆积。
func TestS5A3PassthroughAdapterWritesBytes(t *testing.T) {
	adapter := NewS5A3PassthroughAdapter()

	// 空输入：不写、不 panic、无残包。dst 给 nil 也不该被触碰。
	for _, input := range [][]byte{nil, {}} {
		if left := adapter.ProcessDownlink(input, nil); len(left) != 0 {
			t.Fatalf("空输入不应产生残包，实际 %d 字节", len(left))
		}
	}

	cases := [][]byte{
		{0x00},
		bytes.Repeat([]byte{0xFF}, 1500),
		[]byte("class0/op1 CHANNELINFO \x00\xb5\xb5"),
		bytes.Repeat([]byte{0xA5}, 13*1024), // 对齐线上实测的频道表体量
	}
	for index, input := range cases {
		server, client := net.Pipe()
		// net.Pipe 是同步管道：Write 会阻塞到对端 Read，接收必须放独立协程。
		received := make(chan []byte, 1)
		go func() {
			buf := make([]byte, len(input))
			n, _ := io.ReadFull(client, buf)
			received <- buf[:n]
		}()

		left := adapter.ProcessDownlink(input, server)
		if len(left) != 0 {
			server.Close()
			client.Close()
			t.Fatalf("用例 %d：透传适配器不应留下残包，实际 %d 字节", index, len(left))
		}
		server.Close()

		got := <-received
		client.Close()
		if !bytes.Equal(got, input) {
			t.Fatalf("用例 %d：透传后字节不一致\n输入 %x\n输出 %x", index, input, got)
		}
	}
}

// TestS5A3PassthroughAdapterNoPendingGrowth 回归测试：连续多轮喂数据，
// 每轮都必须立刻写出且不留残包。
//
// 初版 `return pending` 在这里第一轮就会失败（返回值非空、对端收不到字节），
// 而且 pending 会随轮次无界增长——这正是「接受频道信息失败」的直接成因。
func TestS5A3PassthroughAdapterNoPendingGrowth(t *testing.T) {
	adapter := NewS5A3PassthroughAdapter()

	server, client := net.Pipe()
	defer client.Close()

	const rounds = 5
	chunkSize := 3000
	var total atomic.Int64
	drained := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			total.Add(int64(n))
			if err != nil {
				close(drained)
				return
			}
		}
	}()

	pending := make([]byte, 0, 4096)
	for round := 0; round < rounds; round++ {
		pending = append(pending, bytes.Repeat([]byte{byte(round)}, chunkSize)...)
		pending = adapter.ProcessDownlink(pending, server)
		if len(pending) != 0 {
			t.Fatalf("第 %d 轮后残留 %d 字节：透传适配器必须每轮清空缓冲区",
				round, len(pending))
		}
	}

	server.Close()
	<-drained
	if got, want := total.Load(), int64(rounds*chunkSize); got != want {
		t.Fatalf("客户端收到 %d 字节，应为 %d 字节", got, want)
	}
}

// TestStartUDPRelaysSkipsNonS5A3 非 S5A3 服不应开任何 UDP 监听。
func TestStartUDPRelaysSkipsNonS5A3(t *testing.T) {
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(lg.Close)

	cfg := &config.GatewayConfig{}
	profile := config.GameServerEntry{Id: "s4a21", Protocol: config.ProtocolS4A21}
	profile.BackendHost = "127.0.0.1"
	profile.PartyUDPPorts = []int{30000} // 即便配了端口，非 s5a3 也不该启用
	cfg.GameServers = []config.GameServerEntry{profile}

	mgr := StartUDPRelays(cfg, lg)
	t.Cleanup(mgr.Stop)
	if mgr.Count() != 0 {
		t.Fatalf("非 S5A3 服不应启用 UDP 中继，实际启用 %d 个", mgr.Count())
	}
}
