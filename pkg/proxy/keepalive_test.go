package proxy

import (
	"net"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// Game/Channel 代理两端的 TCP 保活（2026-10-13 新机双开测试复盘）
//
// 故障：玩家关掉游戏后重开，仍然被「单 IP 并发已达上限」拒之门外。
// 根因：客户端被强杀/崩溃/断网时 TCP 不会发 FIN，半开连接一直占着
// MaxConnectionsPerIP 的槽位，只能等 IdleTimeoutSeconds（1800s）用尽才释放。
//
// 修复：连接建立后开 SO_KEEPALIVE + 探测周期 —— 传输层探活，
// 对端主机还在就回 ACK，所以**纯挂机玩家不会被误踢**（这是它优于
// 「直接调小 IdleTimeoutSeconds」的关键）。
//
// ★ 刻意不写成「读源码字符串」这类装饰性断言：每条都真实建连接/算配置，
//   把修复换掉后必须变红（回退验证见 verify_keepalive_fix.py）。
// ─────────────────────────────────────────────────────────────────────────────

// TestKeepAlivePeriodFromConfig 锁住「配置秒数 → 探测周期」的映射，
// 以及 0/负值 = 关（保持历史行为，缺省关）。
func TestKeepAlivePeriodFromConfig(t *testing.T) {
	cases := []struct {
		name   string
		secs   int
		want   time.Duration
		closed bool
	}{
		{"缺省 60s", 60, 60 * time.Second, false},
		{"自定义 30s", 30, 30 * time.Second, false},
		{"0 = 关", 0, 0, true},
		{"负数 = 关", -1, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.GameServer.TcpKeepAliveSeconds = tc.secs

			srv := NewProxyServer(cfg, cfg.DefaultGameServerEntry(), nil, nil, nil, nil)
			if got := srv.keepAlivePeriod; got != tc.want {
				t.Fatalf("keepAlivePeriod = %v,  want %v (配置 %d 秒)", got, tc.want, tc.secs)
			}
			if tc.closed && srv.keepAlivePeriod > 0 {
				t.Fatalf("配置 %d 秒应按「不开保活」处理，却得到 %v", tc.secs, srv.keepAlivePeriod)
			}
		})
	}
}

// TestDefaultConfigHasKeepAlive 默认值必须真的开着 —— 部署时若忘了在
// appsettings 里填这一项（老配置文件没有该字段），缺省仍要生效。
func TestDefaultConfigHasKeepAlive(t *testing.T) {
	if got := config.DefaultConfig().GameServer.TcpKeepAliveSeconds; got <= 0 {
		t.Fatalf("DefaultConfig().GameServer.TcpKeepAliveSeconds = %d，必须 > 0（缺省关闭会让半开连接继续占槽 30 分钟）", got)
	}
}

// TestSetKeepAliveNonTCPNoPanic 非 TCP 连接（测试替身、未来可能的其他传输）
// 必须被静默跳过，不能 panic 打挂网关。
func TestSetKeepAliveNonTCPNoPanic(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	setKeepAlive(c1, 60*time.Second)
	setKeepAlive(c1, 0)
}

// TestSetKeepAliveKeepsConnectionUsable 开了保活后连接必须仍然能正常读写 ——
// 防止「为了修槽位泄漏把链路搞坏」这类回归。
func TestSetKeepAliveKeepsConnectionUsable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			setKeepAlive(c, 60*time.Second) // 服务端侧也开，模拟 backend
			done <- c
		} else {
			done <- nil
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	setKeepAlive(client, 60*time.Second)

	server := <-done
	if server == nil {
		t.Fatal("accept 失败")
	}
	defer server.Close()

	// 双向各跑一轮，确认链路没被 keepalive 设置破坏
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client 写失败: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("server 读失败: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("数据不一致: %q", buf)
	}
	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server 写失败: %v", err)
	}
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("client 读失败: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("数据不一致: %q", buf)
	}
}
