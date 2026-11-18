package proxy

// ============================================================================
// S5A3 频道列表代理模式测试（2026-10-25）
//
// 验证链路：构造与 Server-S5A3 完全一致的明文 → 用同一套密钥/算法加密 →
// 喂给适配器 → 断言"端口已关闭的频道被剔除，其余原样保留、IP 未被改动"。
//
// 关键不变量：
//   ① 端口未纳管/已关闭的条目被剔除，count 同步递减
//   ② 保留条目的**每个字节**不变（尤其 IP —— S5A3 不改 IP）
//   ③ 前缀前 8 字节（server_count + server_id）原样保留
//   ④ 非 CHANNELINFO 帧一个字节都不改
//   ⑤ 一条都不剩时放弃过滤（安全阀），而不是给客户端空列表
//   ⑥ 密文损坏/密钥不对时原样透传（降级）
// ============================================================================

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
)

// s5a3TestEntry 描述一条待构造的频道条目。
type s5a3TestEntry struct {
	name string
	port int
	ip   string
}

// buildS5A3ChannelPlain 按 Server-S5A3 的 writeChannelInfoPrefix/Entries 布局造明文。
func buildS5A3ChannelPlain(entries []s5a3TestEntry, serverID uint32) []byte {
	out := make([]byte, s5a3ChannelPrefixSize+len(entries)*s5a3ChannelEntrySize)
	binary.LittleEndian.PutUint32(out[0:4], 1)        // server_count
	binary.LittleEndian.PutUint32(out[4:8], serverID) // server_id
	binary.LittleEndian.PutUint32(out[s5a3ChannelCountOffset:s5a3ChannelPrefixSize], uint32(len(entries)))

	for i, e := range entries {
		off := s5a3ChannelPrefixSize + i*s5a3ChannelEntrySize
		name := append([]byte("#"), []byte(e.name)...)
		copy(out[off:off+20], name)
		binary.LittleEndian.PutUint32(out[off+20:off+24], 100) // 容量
		binary.LittleEndian.PutUint32(out[off+24:off+28], 0)   // 在线
		copy(out[off+s5a3ChannelIPOffset:off+s5a3ChannelIPOffset+16], []byte(e.ip))
		binary.LittleEndian.PutUint32(out[off+s5a3ChannelPortOffset:off+s5a3ChannelPortOffset+4], uint32(e.port))
	}
	return out
}

// wrapS5A3ChannelFrame 把明文加密并包成 **11 字节 legacy 头** 的完整帧。
//
// 与服务端 buildLegacyPacket / 真实夹具一致：[0]=class、[1]=msgID 低字节、
// [2:6]=总长(LE32)、[10]=1，body 从 11 开始，无 checksum。
func wrapS5A3ChannelFrame(t *testing.T, plain []byte, r *ChannelListRewriter) []byte {
	t.Helper()
	encrypted := r.encrypt(plain, r.currentKey())
	if len(encrypted) == 0 {
		t.Fatal("加密失败")
	}
	frame := make([]byte, channelFrameHeaderSize+len(encrypted))
	frame[0] = 0
	frame[1] = s5a3ChannelInfoMsgID
	binary.LittleEndian.PutUint32(frame[channelFrameLenOffset:], uint32(len(frame)))
	frame[10] = 1
	copy(frame[channelFrameHeaderSize:], encrypted)
	return frame
}

// newS5A3FilterTestAdapter 构造只关心过滤的适配器（端口表由调用方给）。
func newS5A3FilterTestAdapter(openPorts ...int) (*S5A3ChannelAdapter, *s5CollectConn) {
	view := newPortView()
	for _, p := range openPorts {
		view.backendToPublic[p] = p
	}
	holder := &atomic.Pointer[portView]{}
	holder.Store(view)
	r := NewChannelListRewriter(0)
	return &S5A3ChannelAdapter{rewriter: r, ports: holder}, &s5CollectConn{}
}

// TestS5A3FilterDropsClosedPortChannels 核心用例：关掉的端口对应频道消失。
func TestS5A3FilterDropsClosedPortChannels(t *testing.T) {
	adapter, dst := newS5A3FilterTestAdapter(10010, 10012)

	plain := buildS5A3ChannelPlain([]s5a3TestEntry{
		{name: "cain-10", port: 10010, ip: "203.0.113.100"},
		{name: "cain-11", port: 10011, ip: "203.0.113.100"}, // 端口没开 → 应剔除
		{name: "cain-12", port: 10012, ip: "203.0.113.100"},
	}, 0)
	frame := wrapS5A3ChannelFrame(t, plain, adapter.rewriter)

	if rest := adapter.ProcessDownlink(frame, dst); rest != nil {
		t.Fatalf("完整帧不该留下残包，实际 %d 字节", len(rest))
	}

	written := dst.written
	if len(written) < channelFrameHeaderSize {
		t.Fatalf("输出过短: %d 字节", len(written))
	}
	total := int(binary.LittleEndian.Uint32(written[channelFrameLenOffset:]))
	if total != len(written) {
		t.Fatalf("帧头长度 %d 与实际 %d 不符", total, len(written))
	}

	// 解回来验证
	decrypted, _, ok := adapter.rewriter.decryptAnyS5A3(written[channelFrameHeaderSize:])
	if !ok {
		t.Fatal("输出帧无法解密回合法频道列表")
	}
	count := int(binary.LittleEndian.Uint32(decrypted[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	if count != 2 {
		t.Fatalf("过滤后条目数 = %d，期望 2", count)
	}

	// 前缀前 8 字节必须原样
	if !bytes.Equal(decrypted[0:8], plain[0:8]) {
		t.Fatalf("前缀 server_count/server_id 被改动: %x vs %x", decrypted[0:8], plain[0:8])
	}

	// 保留条目必须逐字节等于原文（含 IP —— S5A3 不改 IP）
	//
	// ★ 注意按**精确长度**切片：decrypt 返回的是 16 字节对齐后的明文，
	// 尾部有 pad 0，直接 decrypted[x:] 会把 padding 也算进去。
	entryLen := s5a3ChannelEntrySize
	srcOff1 := s5a3ChannelPrefixSize + 0*s5a3ChannelEntrySize
	srcOff2 := s5a3ChannelPrefixSize + 2*s5a3ChannelEntrySize

	got1 := decrypted[s5a3ChannelPrefixSize : s5a3ChannelPrefixSize+entryLen]
	want1 := plain[srcOff1 : srcOff1+entryLen]
	if !bytes.Equal(got1, want1) {
		t.Fatalf("第 1 条（端口 10010）被改动:\n got=%x\nwant=%x", got1, want1)
	}

	got2 := decrypted[s5a3ChannelPrefixSize+entryLen : s5a3ChannelPrefixSize+2*entryLen]
	want2 := plain[srcOff2 : srcOff2+entryLen]
	if !bytes.Equal(got2, want2) {
		t.Fatalf("第 2 条（端口 10012）被改动:\n got=%x\nwant=%x", got2, want2)
	}
}

// newS5A3FilterTestAdapterMapped 构造带端口映射的适配器（backend -> public 不一致）。
func newS5A3FilterTestAdapterMapped(mapping map[int]int) (*S5A3ChannelAdapter, *s5CollectConn) {
	view := newPortView()
	for backend, public := range mapping {
		view.backendToPublic[backend] = public
	}
	holder := &atomic.Pointer[portView]{}
	holder.Store(view)
	r := NewChannelListRewriter(0)
	return &S5A3ChannelAdapter{rewriter: r, ports: holder}, &s5CollectConn{}
}

// TestS5A3FilterRewritesPortWhenMapped 回归用例（2026-11-18）。
//
// 现场 bug：端口表把 10010 映射成 20010 对外（安全组只放行 200xx），
// 但频道表里仍有 10010。此时**所有端口都开着** ⇒ dropped==0，
// 旧代码在 `if dropped == 0 { 原样转发 }` 处把改写结果丢掉，
// 客户端拿到的仍是 10010 → 安全组过滤 → 每 3 秒重连频道口，表现为"连不上频道"。
//
// 本用例钉住：dropped==0 但端口需要改写时，必须重新加密下发，且：
//   · 条目端口 = public（20010）
//   · 条目数不变、前缀前 8 字节不变、IP 不变
func TestS5A3FilterRewritesPortWhenMapped(t *testing.T) {
	adapter, dst := newS5A3FilterTestAdapterMapped(map[int]int{10010: 20010, 10012: 20012})

	plain := buildS5A3ChannelPlain([]s5a3TestEntry{
		{name: "cain-10", port: 10010, ip: "43.136.78.193"},
		{name: "cain-12", port: 10012, ip: "43.136.78.193"},
	}, 0)
	frame := wrapS5A3ChannelFrame(t, plain, adapter.rewriter)

	if rest := adapter.ProcessDownlink(frame, dst); rest != nil {
		t.Fatalf("完整帧不该留下残包，实际 %d 字节", len(rest))
	}

	written := dst.written
	if len(written) < channelFrameHeaderSize {
		t.Fatalf("输出过短: %d 字节", len(written))
	}
	if total := int(binary.LittleEndian.Uint32(written[channelFrameLenOffset:])); total != len(written) {
		t.Fatalf("帧头长度 %d 与实际 %d 不符", total, len(written))
	}

	decrypted, _, ok := adapter.rewriter.decryptAnyS5A3(written[channelFrameHeaderSize:])
	if !ok {
		t.Fatal("输出帧无法解密回合法频道列表")
	}

	count := int(binary.LittleEndian.Uint32(decrypted[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	if count != 2 {
		t.Fatalf("条目数 = %d，期望 2（只改端口不该过滤）", count)
	}
	if !bytes.Equal(decrypted[0:8], plain[0:8]) {
		t.Fatalf("前缀 server_count/server_id 被改动: %x vs %x", decrypted[0:8], plain[0:8])
	}

	wantPorts := []int{20010, 20012}
	for i, want := range wantPorts {
		off := s5a3ChannelPrefixSize + i*s5a3ChannelEntrySize
		got := int(binary.LittleEndian.Uint32(decrypted[off+s5a3ChannelPortOffset : off+s5a3ChannelPortOffset+4]))
		if got != want {
			t.Fatalf("第 %d 条端口 = %d，期望 %d（未改写回 public）", i+1, got, want)
		}
		gotIP := decrypted[off+s5a3ChannelIPOffset : off+s5a3ChannelIPOffset+16]
		if !bytes.HasPrefix(gotIP, []byte("43.136.78.193")) {
			t.Fatalf("第 %d 条 IP 被改写: %q", i+1, gotIP)
		}
	}

	// 再直接验一次返回值语义：dropped==0 但 rewritten==true
	if _, kept, dropped, rewritten := filterS5A3ChannelList(plain, adapter.ports.Load()); kept != 2 || dropped != 0 || !rewritten {
		t.Fatalf("filter 返回值 kept=%d dropped=%d rewritten=%v，期望 2/0/true", kept, dropped, rewritten)
	}
}

// TestS5A3FilterKeepsIPUntouched 钉住"S5A3 不改 IP"这条与 S4A21 的关键差异。
func TestS5A3FilterKeepsIPUntouched(t *testing.T) {
	adapter, _ := newS5A3FilterTestAdapter(10010)
	plain := buildS5A3ChannelPlain([]s5a3TestEntry{
		{name: "cain-10", port: 10010, ip: "1.2.3.4"},
		{name: "cain-99", port: 10099, ip: "1.2.3.4"}, // 剔除
	}, 0)

	filtered, kept, dropped, _ := filterS5A3ChannelList(plain, adapter.ports.Load())
	if kept != 1 || dropped != 1 {
		t.Fatalf("kept=%d dropped=%d，期望 1/1", kept, dropped)
	}
	gotIP := filtered[s5a3ChannelPrefixSize+s5a3ChannelIPOffset : s5a3ChannelPrefixSize+s5a3ChannelIPOffset+16]
	if !bytes.HasPrefix(gotIP, []byte("1.2.3.4")) {
		t.Fatalf("IP 被改写了: %q", gotIP)
	}
}

// TestS5A3FilterGivesUpWhenNothingLeft 安全阀：全被过滤时放弃过滤。
func TestS5A3FilterGivesUpWhenNothingLeft(t *testing.T) {
	adapter, dst := newS5A3FilterTestAdapter() // 一个端口都没开

	plain := buildS5A3ChannelPlain([]s5a3TestEntry{
		{name: "cain-10", port: 10010, ip: "203.0.113.100"},
		{name: "cain-11", port: 10011, ip: "203.0.113.100"},
	}, 0)
	frame := wrapS5A3ChannelFrame(t, plain, adapter.rewriter)

	adapter.ProcessDownlink(frame, dst)

	// 原样透传（含原帧头与密文）
	if !bytes.Equal(dst.written, frame) {
		t.Fatal("全部被过滤时应原样透传，而不是下发空列表")
	}
}

// TestS5A3FilterPassesNonChannelFrames 非 CHANNELINFO 帧一个字节都不改。
func TestS5A3FilterPassesNonChannelFrames(t *testing.T) {
	adapter, dst := newS5A3FilterTestAdapter(10010)

	other := make([]byte, channelFrameHeaderSize+32)
	other[1] = 0x99 // 不是 CHANNELINFO
	binary.LittleEndian.PutUint32(other[channelFrameLenOffset:], uint32(len(other)))
	other[10] = 1

	adapter.ProcessDownlink(other, dst)
	if !bytes.Equal(dst.written, other) {
		t.Fatal("非 CHANNELINFO 帧被改动了")
	}
}

// TestS5A3FilterPassesThroughCorruptBody 密文损坏时原样透传（降级）。
func TestS5A3FilterPassesThroughCorruptBody(t *testing.T) {
	adapter, dst := newS5A3FilterTestAdapter(10010)

	garbage := make([]byte, channelFrameHeaderSize+64)
	garbage[1] = s5a3ChannelInfoMsgID
	binary.LittleEndian.PutUint32(garbage[channelFrameLenOffset:], uint32(len(garbage)))
	garbage[10] = 1
	for i := channelFrameHeaderSize; i < len(garbage); i++ {
		garbage[i] = 0x5A
	}

	adapter.ProcessDownlink(garbage, dst)
	if !bytes.Equal(dst.written, garbage) {
		t.Fatal("无法解密的帧应原样透传")
	}
}

// TestS5A3FilterKeepsResidualFrame 半帧要作为残包返回，等下次补齐。
func TestS5A3FilterKeepsResidualFrame(t *testing.T) {
	adapter, dst := newS5A3FilterTestAdapter(10010)
	plain := buildS5A3ChannelPlain([]s5a3TestEntry{
		{name: "cain-10", port: 10010, ip: "203.0.113.100"},
	}, 0)
	frame := wrapS5A3ChannelFrame(t, plain, adapter.rewriter)

	// 只喂前 10 字节（不足一个头）
	rest := adapter.ProcessDownlink(frame[:10], dst)
	if len(rest) != 10 {
		t.Fatalf("残包长度 = %d，期望 10", len(rest))
	}
	if len(dst.written) != 0 {
		t.Fatal("不足一帧时不该写出任何字节")
	}

	// 补齐后应能正常处理
	rest2 := adapter.ProcessDownlink(append(rest, frame[10:]...), dst)
	if rest2 != nil {
		t.Fatalf("补齐后不该再有残包，实际 %d 字节", len(rest2))
	}
	if len(dst.written) == 0 {
		t.Fatal("补齐后应写出完整帧")
	}
}

// TestS5A3FilterNoDropIsByteIdentical 没有可剔除条目时输出与输入完全一致。
func TestS5A3FilterNoDropIsByteIdentical(t *testing.T) {
	adapter, dst := newS5A3FilterTestAdapter(10010, 10011)
	plain := buildS5A3ChannelPlain([]s5a3TestEntry{
		{name: "cain-10", port: 10010, ip: "203.0.113.100"},
		{name: "cain-11", port: 10011, ip: "203.0.113.100"},
	}, 0)
	frame := wrapS5A3ChannelFrame(t, plain, adapter.rewriter)

	adapter.ProcessDownlink(frame, dst)
	if !bytes.Equal(dst.written, frame) {
		t.Fatal("无需剔除时应原样转发（省掉一次重加密）")
	}
}

// 确保 bufferConn 满足 net.Conn（测试内用它当 dst）。
var _ net.Conn = (*s5CollectConn)(nil)
