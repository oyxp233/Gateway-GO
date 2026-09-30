package proxy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildTestChannelList 按服务端 ChannelProtocolHandler 的布局造一份频道列表明文。
func buildTestChannelList(t *testing.T, names []string, ports []int, ip string) []byte {
	t.Helper()
	if len(names) != len(ports) {
		t.Fatalf("names/ports 长度不一致: %d/%d", len(names), len(ports))
	}

	plain := make([]byte, channelListPrefixSize+channelListEntrySize*len(names))
	binary.LittleEndian.PutUint16(plain[0:2], 1)
	binary.LittleEndian.PutUint32(plain[2:channelListPrefixSize], uint32(len(names)))

	for i, name := range names {
		off := channelListPrefixSize + i*channelListEntrySize
		copy(plain[off:off+20], []byte(name))
		binary.LittleEndian.PutUint32(plain[off+20:off+24], 100) // 容量
		binary.LittleEndian.PutUint32(plain[off+24:off+28], 0)   // 在线人数
		copy(plain[off+channelListIPOffset:off+channelListIPOffset+16], []byte(ip))
		binary.LittleEndian.PutUint32(
			plain[off+channelListPortOffset:off+channelListPortOffset+4],
			uint32(ports[i]))
	}

	// 与服务端一致：补齐到 16 字节对齐
	return append(plain, make([]byte, padTo16Len(len(plain))-len(plain))...)
}

// parseTestChannelList 解析过滤后的明文，返回 (条目数, 端口列表, IP 列表)。
//
// 只校验"长度够放 count 条"，因为过滤函数返回的是未补齐的中间态
// （补齐发生在 encrypt 里）；严格对齐校验见 isValidChannelList。
func parseTestChannelList(t *testing.T, plain []byte) (int, []int, []string) {
	t.Helper()
	if len(plain) < channelListPrefixSize {
		t.Fatalf("结果过短: len=%d", len(plain))
	}
	count := int(binary.LittleEndian.Uint32(plain[2:channelListPrefixSize]))
	if len(plain) < channelListPrefixSize+count*channelListEntrySize {
		t.Fatalf("结果长度不足以容纳 %d 条: len=%d", count, len(plain))
	}
	ports := make([]int, 0, count)
	ips := make([]string, 0, count)
	for i := 0; i < count; i++ {
		off := channelListPrefixSize + i*channelListEntrySize
		ports = append(ports, int(binary.LittleEndian.Uint32(
			plain[off+channelListPortOffset:off+channelListPortOffset+4])))
		ip := bytes.TrimRight(plain[off+channelListIPOffset:off+channelListIPOffset+16], "\x00")
		ips = append(ips, string(ip))
	}
	return count, ports, ips
}

// 端口表：20011->10011（开）、20012->10012（开）、20013->10013（关）
func testPortView() *portView {
	return buildPortView([]GamePortMapping{
		{Public: 20011, Backend: 10011, Enabled: true},
		{Public: 20012, Backend: 10012, Enabled: true},
		{Public: 20013, Backend: 10013, Enabled: false},
	})
}

func TestRewriteAndFilter_KeepEnabledRewritePortAndIP(t *testing.T) {
	plain := buildTestChannelList(t,
		[]string{"#ch.11", "#ch.12", "#ch.13"},
		[]int{10011, 10012, 10013},
		"100.64.0.9")

	out, kept, dropped := rewritePlaintextAndFilter(plain, "10.0.0.1", testPortView())
	if kept != 2 || dropped != 1 {
		t.Fatalf("kept/dropped 期望 2/1，实际 %d/%d", kept, dropped)
	}

	count, ports, ips := parseTestChannelList(t, out)
	if count != 2 {
		t.Fatalf("条目数期望 2，实际 %d", count)
	}
	// 关闭端口 10013 的频道（#ch.13）必须消失；其余端口改写成公网端口
	if ports[0] != 20011 || ports[1] != 20012 {
		t.Fatalf("端口应改写为 20011/20012，实际 %v", ports)
	}
	for i, ip := range ips {
		if ip != "10.0.0.1" {
			t.Fatalf("第 %d 条 IP 未改写，实际 %q", i, ip)
		}
	}
}

func TestRewriteAndFilter_DropPortsNotInTable(t *testing.T) {
	// 10099 从未纳管（例如服务端新增了频道但端口表没加）-> 一并隐藏
	plain := buildTestChannelList(t,
		[]string{"#ch.11", "#ch.99"},
		[]int{10011, 10099},
		"100.64.0.9")

	out, kept, dropped := rewritePlaintextAndFilter(plain, "10.0.0.1", testPortView())
	if kept != 1 || dropped != 1 {
		t.Fatalf("kept/dropped 期望 1/1，实际 %d/%d", kept, dropped)
	}
	count, ports, _ := parseTestChannelList(t, out)
	if count != 1 || ports[0] != 20011 {
		t.Fatalf("应只剩 20011 一条，实际 count=%d ports=%v", count, ports)
	}
}

func TestRewriteAndFilter_SafetyValveWhenNothingMatches(t *testing.T) {
	// 端口表口径完全对不上（同端口转发）-> 一条都不该被隐藏
	plain := buildTestChannelList(t,
		[]string{"#ch.11", "#ch.12"},
		[]int{10011, 10012},
		"100.64.0.9")
	identity := buildPortView([]GamePortMapping{
		{Public: 20011, Backend: 20011, Enabled: true},
	})

	out, kept, dropped := rewritePlaintextAndFilter(plain, "10.0.0.1", identity)
	if kept != 0 || dropped != 2 {
		t.Fatalf("应为 kept=0/dropped=2（触发安全阀），实际 %d/%d", kept, dropped)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("安全阀触发时应原样返回明文")
	}

	// 走完整链路时，客户端拿到的应仍是原始密文（不做任何改动）
	r := NewChannelListRewriter(0)
	body := r.encrypt(plain, r.currentKey())
	got, k, d := r.RewriteChannelInfoWithFallback(body, "10.0.0.1", identity)
	if !bytes.Equal(got, body) {
		t.Fatal("安全阀触发时应原样返回密文，避免所有频道消失")
	}
	if k != 0 || d != 2 {
		t.Fatalf("期望 kept=0/dropped=2，实际 %d/%d", k, d)
	}
}

func TestRewriteChannelInfoWithFallback_RoundTrip(t *testing.T) {
	r := NewChannelListRewriter(0)
	plain := buildTestChannelList(t,
		[]string{"#ch.11", "#ch.12", "#ch.13"},
		[]int{10011, 10012, 10013},
		"100.64.0.9")
	body := r.encrypt(plain, r.currentKey())

	got, kept, dropped := r.RewriteChannelInfoWithFallback(body, "10.0.0.1", testPortView())
	if kept != 2 || dropped != 1 {
		t.Fatalf("kept/dropped 期望 2/1，实际 %d/%d", kept, dropped)
	}
	if bytes.Equal(got, body) {
		t.Fatal("应按端口表改动密文（隐藏 1 条 + 改写 IP/端口）")
	}

	// 客户端视角：解回来必须是合法列表、且只有 2 条
	back, err := r.decrypt(got, r.currentKey())
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	count, ports, ips := parseTestChannelList(t, back)
	if count != 2 || ports[0] != 20011 || ports[1] != 20012 {
		t.Fatalf("解密后应剩 2 条且端口为 20011/20012，实际 count=%d ports=%v", count, ports)
	}
	if ips[0] != "10.0.0.1" {
		t.Fatalf("IP 未改写，实际 %q", ips[0])
	}
}

func TestRewriteChannelInfoWithFallback_UndecryptablePassThrough(t *testing.T) {
	r := NewChannelListRewriter(0)
	garbage := []byte{0x78, 0x9C, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	got, kept, dropped := r.RewriteChannelInfoWithFallback(garbage, "10.0.0.1", testPortView())
	if !bytes.Equal(got, garbage) {
		t.Fatal("无法解密时必须原样透传")
	}
	if kept != 0 || dropped != 0 {
		t.Fatalf("无法解密时不应报告过滤结果，实际 %d/%d", kept, dropped)
	}
}

func TestRewriteChannelInfoWithFallback_NoChangeKeepsCiphertext(t *testing.T) {
	// 所有端口都开放 -> 密文仍会因 IP/端口改写而变化，但 kept 必须等于原条目数
	r := NewChannelListRewriter(0)
	plain := buildTestChannelList(t, []string{"#ch.11", "#ch.12"}, []int{10011, 10012}, "100.64.0.9")
	body := r.encrypt(plain, r.currentKey())

	got, kept, dropped := r.RewriteChannelInfoWithFallback(body, "10.0.0.1", testPortView())
	if kept != 2 || dropped != 0 {
		t.Fatalf("kept/dropped 期望 2/0，实际 %d/%d", kept, dropped)
	}
	back, err := r.decrypt(got, r.currentKey())
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	count, ports, _ := parseTestChannelList(t, back)
	if count != 2 || ports[0] != 20011 || ports[1] != 20012 {
		t.Fatalf("应保留 2 条且改写端口，实际 count=%d ports=%v", count, ports)
	}
}
