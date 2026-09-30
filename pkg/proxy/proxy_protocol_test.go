package proxy

import (
	"net"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// PROXY protocol v1 注头（PKC 联机「A2 方案」）
//
// 背景：网关是用户态 TCP 代理，服务端看到的 TCP 对端恒为 127.0.0.1；
// 而服务端 PvP 的 UDP 中继强制「UDP 源 IP == TCP 源 IP」（PartyUdpRelay 的
// SecureBinding 判定），于是 PK 场的数据报全部被判 rejected source tuple。
// 修法是网关在向后端转发任何字节**之前**，先写一行 PROXY 头声明真实地址。
//
// 这行头写错比不写更糟：服务端会把它当成游戏包头，解析失败 → 玩家立刻掉线。
// 所以格式、取值、失败语义都在这一个文件里钉死。
//
// 服务端侧的对应实现与断言：Network/Core/ProxyProtocolHeader.cs 与
// SelfTests/A21ProxyProtocolSelfTest.cs —— 两边改一边必须同步改另一边。
// ─────────────────────────────────────────────────────────────────────────────

// fakeAddr / fakeConn：writeProxyHeader 只依赖 Write + RemoteAddr + LocalAddr，
// 用最小替身把这三件事钉住，避免引入真实连接的握手时序不确定性。
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeConn struct {
	// 嵌入 nil 接口只为满足 net.Conn 的形状；本测试只会调用
	// 下面三个被覆盖的方法（Write / RemoteAddr / LocalAddr）。
	net.Conn

	remote  fakeAddr
	local   fakeAddr
	written []byte
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) LocalAddr() net.Addr  { return c.local }

func (c *fakeConn) Write(b []byte) (int, error) {
	c.written = append(c.written, b...)
	return len(b), nil
}

func newHeaderTestProxy(publicIP, mode string) *ProxyServer {
	return &ProxyServer{
		config: &config.GatewayConfig{
			GameServer: config.GameServerSection{
				PublicIP:      publicIP,
				ProxyProtocol: mode,
			},
		},
	}
}

// TestProxyProtocolToggleParsing 钉住开关的取值口径。
//
// 这里刻意把 "off"/"no"/"false"/"0"/"v2" 都归到「关」——配置里写错值时
// **必须**落到不发送，绝不能因为大小写或空格差异意外打开（那会让整服掉线）。
func TestProxyProtocolToggleParsing(t *testing.T) {
	cases := map[string]bool{
		"":    false,
		" ":   false,
		"off": false, "OFF": false, " off ": false,
		"no": false, "0": false, "false": false,
		"v2": false, "truex": false,
		"v1": true, "V1": true, "  v1  ": true,
		"1": true, "true": true, "on": true,
	}

	for value, want := range cases {
		p := newHeaderTestProxy("1.2.3.4", value)
		if got := p.proxyProtocolEnabled(); got != want {
			t.Errorf("ProxyProtocol=%q: 期望 %v，实际 %v", value, want, got)
		}
	}
}

// TestWriteProxyHeaderFormat 是**跨语言契约锚**。
//
// 精确到字节：源 IP、目的 IP（取配置的 PublicIP）、源端口、目的端口，
// 以 CRLF 结尾。服务端 ProxyProtocolHeader 只接受这个形状。
func TestWriteProxyHeaderFormat(t *testing.T) {
	p := newHeaderTestProxy("123.207.249.161", "v1")
	backend := &fakeConn{}
	client := &fakeConn{
		remote: "163.142.116.138:56640",
		// 本机出接口地址**故意**不同于 PublicIP：这样"目的地址取配置值"
		// 这条断言才有区分力（若实现改成本机地址，期望值就对不上了）。
		local: "10.9.9.9:20050",
	}

	if err := p.writeProxyHeader(backend, client, 20050); err != nil {
		t.Fatalf("写头失败: %v", err)
	}

	want := "PROXY TCP4 163.142.116.138 123.207.249.161 56640 20050\r\n"
	if string(backend.written) != want {
		t.Fatalf("头格式不符\n期望 %q\n实际 %q", want, string(backend.written))
	}
}

// TestWriteProxyHeaderHonoursPublicPort 目的端口必须用**客户端看到的公网端口**，
// 而不是后端端口 —— 服务端用它只能做日志/审计，用错了会误导排查。
func TestWriteProxyHeaderHonoursPublicPort(t *testing.T) {
	p := newHeaderTestProxy("123.207.249.161", "v1")
	backend := &fakeConn{}
	client := &fakeConn{
		remote: "10.1.2.3:40000",
		local:  "123.207.249.161:20001",
	}

	if err := p.writeProxyHeader(backend, client, 20001); err != nil {
		t.Fatalf("写头失败: %v", err)
	}
	if !strings.HasSuffix(string(backend.written), " 40000 20001\r\n") {
		t.Fatalf("目的端口应为公网端口 20001，实际 %q", string(backend.written))
	}
}

// TestWriteProxyHeaderFallsBackToLocalAddr：没配 PublicIP 时用本机出接口地址兜底，
// 不写 0.0.0.0（服务端可能因此拒绝整行）。
func TestWriteProxyHeaderFallsBackToLocalAddr(t *testing.T) {
	for _, publicIP := range []string{"", "0.0.0.0"} {
		p := newHeaderTestProxy(publicIP, "v1")
		backend := &fakeConn{}
		client := &fakeConn{
			remote: "10.0.0.9:1234",
			local:  "10.0.0.1:8001",
		}

		if err := p.writeProxyHeader(backend, client, 8001); err != nil {
			t.Fatalf("PublicIP=%q 写头失败: %v", publicIP, err)
		}

		want := "PROXY TCP4 10.0.0.9 10.0.0.1 1234 8001\r\n"
		if string(backend.written) != want {
			t.Fatalf("PublicIP=%q\n期望 %q\n实际 %q",
				publicIP, want, string(backend.written))
		}
	}
}

// TestWriteProxyHeaderIPv6Family：源是 IPv6 时必须报 TCP6。
// 报成 TCP4 而地址是 v6 的话，服务端会因地址族不匹配而拒绝整行。
func TestWriteProxyHeaderIPv6Family(t *testing.T) {
	p := newHeaderTestProxy("123.207.249.161", "v1")
	backend := &fakeConn{}
	client := &fakeConn{
		remote: "[2001:db8::1]:5555",
		local:  "[2001:db8::2]:20050",
	}

	if err := p.writeProxyHeader(backend, client, 20050); err != nil {
		t.Fatalf("写头失败: %v", err)
	}

	got := string(backend.written)
	if !strings.HasPrefix(got, "PROXY TCP6 2001:db8::1 123.207.249.161 5555 20050\r\n") {
		t.Fatalf("IPv6 源应报 TCP6，实际 %q", got)
	}
}

// TestWriteProxyHeaderRefusesUnknownSource：源地址取不到时**必须报错且一个字节都不写**。
//
// 这是本功能唯一的失败模式。写半行头的后果比不写严重得多：
// 服务端会把半行当成游戏包头，解析失败断开，症状看起来像「随机的连不上」。
func TestWriteProxyHeaderRefusesUnknownSource(t *testing.T) {
	p := newHeaderTestProxy("123.207.249.161", "v1")
	backend := &fakeConn{}
	client := &fakeConn{} // remote 为零值：SplitHostPort 失败

	if err := p.writeProxyHeader(backend, client, 20050); err == nil {
		t.Fatal("源地址不可用时必须返回 error")
	}
	if len(backend.written) != 0 {
		t.Fatalf("报错时不应写出任何字节，实际 %q", string(backend.written))
	}
}
