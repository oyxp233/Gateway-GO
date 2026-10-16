package proxy

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"s4a21-gateway/pkg/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// S5A95（S5A9 / DNF95）适配器测试（2026-10-16 双服改造）
//
// 夹具不是本文件生成的，而是由**独立实现**（Node.js stdlib crypto/zlib，
// 逐行对照 S5A9 服务端 C# 源码）产出的十六进制向量：
//
//	ChannelPackets.cs：Directory / Endpoint / Frame / Encrypt（AES-128-ECB
//	                  固定密钥 "EMU-LAB-KEY-0001" + zlib）
//	GameFrame.cs     ：Build（16B 头）+ CRC32（反射多项式 0x4DB89129）
//
// 这样"AES 口径 / zlib 口径 / 帧布局 / CRC 表"四项各有独立锚点，
// 不会出现"用被测试代码自己生成夹具、错了也看不出来"的循环论证。
//
// 场景设定（与向量一致）：S5A9 后端在内网 192.168.1.50，两个频道
// 游戏口 23101 / 23102；网关公网 IP 203.0.113.7，端口表
// 24001→23101、24002→23102。
// ─────────────────────────────────────────────────────────────────────────────

// s5FixtureDirectory 是服务端原样的 op18 Directory 帧（2 个频道）。
const s5FixtureDirectoryHex = "7c128b000000000000000178da9b18903c25fde03c662d1515d7b92ad6a28b5fb72edda83aadb3bd93c1daa6e26aa7e49e8bbb43fe17fa4ef8fad97e4eee1cbd0d2baaa6f625bf0a71b891bb5f34c33bab746945f80136f10d87de2af9e69cd8c09d3d77dd8bdb5902b1bd076b1c6d72f29208e9cf4a68dc6f2e98f4f8f251debe69cb77e6030093814709"

// s5FixtureLogin 是服务端原样的游戏口 LOGIN 回包（kind=1 opcode=1 seq=7，
// Endpoint 指向 192.168.1.50:23102）。
const s5FixtureLoginHex = "0101004800000000f40be607000000000101010001000000000c0000003139322e3136382e312e35303e5a0000000000000000010100000000000000000000000000000000000000"

// s5FixtureNoti 是 NOTI CHANNELINFO 帧（kind=0、opcode 同为 1、无地址）——
// 适配器必须原样放过，绝不能因为 opcode 撞号而改坏它。
const s5FixtureNotiHex = "0001002800000047d0739709000000004e4f54492d4348414e4e454c494e464f2d4e4f2d41444452"

// s5FixtureLoginCRC 是独立实现对 s5FixtureLogin[11:]（seq+body）算出的
// CRC32 已知答案 —— 钉死网关 CRC 表与服务端同源。
const s5FixtureLoginCRC = 0xe60bf400

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("夹具十六进制非法: %v", err)
	}
	return b
}

// s5TestPorts 构造一个指向 24001→23101 / 24002→23102 的端口视图。
func s5TestPorts(t *testing.T, resolved map[int]int) *atomic.Pointer[portView] {
	t.Helper()
	var p atomic.Pointer[portView]
	p.Store(buildPortViewFromResolved(resolved))
	return &p
}

// s5CollectConn 收集适配器写入的字节与次数（复用同包 fakeConn 的 Write
// 收集；writes 记帧数 —— 一次 Write 对应一帧）。
type s5CollectConn struct {
	fakeConn
	writes int
}

func newS5CollectConn() *s5CollectConn {
	return &s5CollectConn{}
}

func (c *s5CollectConn) Write(b []byte) (int, error) {
	c.writes++
	return c.fakeConn.Write(b)
}

// decryptDirectory 按服务端同算法解开 Directory 帧，返回明文。
// 独立锚点在"夹具由 Node 生成"这件事上；这里用包内 helper 解密是为了
// 断言改写后的字段值（若 encrypt/decrypt 任一口径错，得到的就不是
// 可读的频道条目，断言自然会红）。
func decryptDirectory(t *testing.T, frame []byte) []byte {
	t.Helper()
	if len(frame) < channelFrameHeaderSize {
		t.Fatalf("帧长度 %d 不足 11B 头", len(frame))
	}
	plain, err := zlibDecompress(frame[channelFrameHeaderSize:])
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	plain, err = aes128DecryptECB(plain, []byte(s5DirectoryKey))
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	return plain
}

func directoryEntryIP(plain []byte, i int) string {
	off := s5DirectoryHeaderSize + i*s5DirectoryEntrySize + s5DirectoryIPOffset
	return strings.TrimRight(string(plain[off:off+s5DirectoryIPSize]), "\x00")
}

func directoryEntryPort(plain []byte, i int) int {
	off := s5DirectoryHeaderSize + i*s5DirectoryEntrySize + s5DirectoryPortOffset
	return int(binary.LittleEndian.Uint32(plain[off : off+4]))
}

// ── CRC 已知答案 ────────────────────────────────────────────────────────────

// TestCrc32S5A9KnownAnswer 钉死 CRC 表：独立实现（Node）对同一份
// seq+body 算出 0xe60bf400。若有人把多项式"顺手"改成标准 IEEE
// 0xEDB88320，这个测试必须红。
func TestCrc32S5A9KnownAnswer(t *testing.T) {
	frame := mustHex(t, s5FixtureLoginHex)
	got := crc32S5A9(frame[11:])
	if got != s5FixtureLoginCRC {
		t.Fatalf("CRC32(seq+body) = 0x%08x， want 0x%08x（独立实现锚点）", got, s5FixtureLoginCRC)
	}
}

// ── 频道口 Directory 改写 ──────────────────────────────────────────────────

func TestS5A95ChannelAdapterRewritesDirectory(t *testing.T) {
	adapter := NewS5A95ChannelAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)
	conn := newS5CollectConn()

	rest := adapter.ProcessDownlink(mustHex(t, s5FixtureDirectoryHex), conn)
	if rest != nil {
		t.Fatalf("整帧处理完应返回 nil，实际 % x", rest)
	}
	if conn.writes != 1 {
		t.Fatalf("应写出 1 帧，实际 %d 帧 / %d 字节", conn.writes, len(conn.written))
	}

	frame := conn.written
	// 帧头：方向标记 / op / 长度自洽 / 保留位原样
	if frame[0] != 0x7c || frame[1] != s5DirectoryOpcode || frame[10] != 1 {
		t.Fatalf("帧头被改坏: % x", frame[:channelFrameHeaderSize])
	}
	if total := int(binary.LittleEndian.Uint32(frame[2:6])); total != len(frame) {
		t.Fatalf("帧长字段 %d 与实际 %d 不符", total, len(frame))
	}

	plain := decryptDirectory(t, frame)
	if n := int(binary.LittleEndian.Uint32(plain[8:12])); n != 2 {
		t.Fatalf("改写后频道数 = %d, want 2", n)
	}
	// 头两个 u32（1 / serverIndex）必须原样保留
	if v := binary.LittleEndian.Uint32(plain[0:4]); v != 1 {
		t.Fatalf("明文头 u32@0 = %d, want 1", v)
	}
	if v := binary.LittleEndian.Uint32(plain[4:8]); v != 3 {
		t.Fatalf("serverIndex = %d, want 3（原样保留）", v)
	}
	for i, want := range []struct {
		name string
		port int
	}{{"#ch.1", 24001}, {"#ch.2", 24002}} {
		off := s5DirectoryHeaderSize + i*s5DirectoryEntrySize
		if got := strings.TrimRight(string(plain[off:off+8]), "\x00"); got != want.name {
			t.Fatalf("条目 %d 频道名 = %q, want %q", i, got, want.name)
		}
		if got := directoryEntryIP(plain, i); got != "203.0.113.7" {
			t.Fatalf("条目 %d IP = %q, want 203.0.113.7", i, got)
		}
		if got := directoryEntryPort(plain, i); got != want.port {
			t.Fatalf("条目 %d 端口 = %d, want %d（后端→公网映射）", i, got, want.port)
		}
	}
}

func TestS5A95ChannelAdapterFiltersClosedPorts(t *testing.T) {
	// 端口表只开 23101：23102 的频道必须从列表里消失，
	// 否则客户端选到它必然连不上。
	adapter := NewS5A95ChannelAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101}), nil)
	conn := newS5CollectConn()

	adapter.ProcessDownlink(mustHex(t, s5FixtureDirectoryHex), conn)
	plain := decryptDirectory(t, conn.written)

	if n := int(binary.LittleEndian.Uint32(plain[8:12])); n != 1 {
		t.Fatalf("过滤后频道数 = %d, want 1", n)
	}
	off := s5DirectoryHeaderSize
	if got := strings.TrimRight(string(plain[off:off+8]), "\x00"); got != "#ch.1" {
		t.Fatalf("留下的应是 #ch.1，实际 %q", got)
	}
	if got := directoryEntryPort(plain, 0); got != 24001 {
		t.Fatalf("端口 = %d, want 24001", got)
	}
}

func TestS5A95ChannelAdapterAllFilteredPassesThrough(t *testing.T) {
	// 安全阀：全部频道都不在端口表内（典型根因是端口表口径不匹配）时
	// 原样转发，绝不改坏帧、绝不吞帧。
	adapter := NewS5A95ChannelAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{}), nil)
	conn := newS5CollectConn()

	original := mustHex(t, s5FixtureDirectoryHex)
	rest := adapter.ProcessDownlink(original, conn)
	if rest != nil {
		t.Fatalf("应返回 nil，实际 % x", rest)
	}
	if string(conn.written) != string(original) {
		t.Fatalf("全过滤时应原样转发\n实际 % x\n期望 % x", conn.written, original)
	}
}

func TestS5A95ChannelAdapterCorruptBodyPassesThrough(t *testing.T) {
	// op18 但 body 不是合法 zlib：解不开就原样转发。
	frame := mustHex(t, s5FixtureDirectoryHex)
	frame = append(frame[:channelFrameHeaderSize:channelFrameHeaderSize],
		[]byte("this-is-not-zlib")...)
	binary.LittleEndian.PutUint32(frame[2:6], uint32(len(frame)))

	adapter := NewS5A95ChannelAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)
	conn := newS5CollectConn()
	adapter.ProcessDownlink(frame, conn)
	if string(conn.written) != string(frame) {
		t.Fatalf("解不开时应原样转发\n实际 % x\n期望 % x", conn.written, frame)
	}
}

func TestS5A95ChannelAdapterPartialFrameAccumulates(t *testing.T) {
	adapter := NewS5A95ChannelAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)

	full := mustHex(t, s5FixtureDirectoryHex)
	half := len(full) / 2

	conn := newS5CollectConn()
	rest := adapter.ProcessDownlink(full[:half], conn)
	if len(conn.written) != 0 {
		t.Fatalf("半帧不应写出任何字节，实际 % x", conn.written)
	}
	if string(rest) != string(full[:half]) {
		t.Fatalf("半帧应原样退回继续攒")
	}

	// 拼完整后必须能处理
	rest = adapter.ProcessDownlink(append(rest, full[half:]...), conn)
	if rest != nil {
		t.Fatalf("拼完整后应返回 nil，实际 % x", rest)
	}
	if len(conn.written) == 0 {
		t.Fatalf("拼完整后应写出改写帧")
	}
}

func TestS5A95ChannelAdapterMultipleFramesOnePending(t *testing.T) {
	// 一次读里塞两帧：Directory + 一个 op9 无关帧，都要按序写出，
	// 且 op9 帧一个字节都不能动。
	adapter := NewS5A95ChannelAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)

	other := make([]byte, channelFrameHeaderSize+5)
	other[0] = 0x7c
	other[1] = 9
	binary.LittleEndian.PutUint32(other[2:6], uint32(len(other)))
	other[10] = 1
	copy(other[channelFrameHeaderSize:], []byte("hello"))

	pending := append(mustHex(t, s5FixtureDirectoryHex), other...)
	conn := newS5CollectConn()
	rest := adapter.ProcessDownlink(pending, conn)
	if rest != nil {
		t.Fatalf("应返回 nil，实际 % x", rest)
	}
	if len(conn.written) <= len(pending) {
		t.Fatalf("两帧都应写出（Directory 改写后长度会变），实际 %d 字节", len(conn.written))
	}
	// 末帧必须是原样的 op9 帧
	if !strings.HasSuffix(string(conn.written), string(other)) {
		t.Fatalf("op9 帧应原样写在末尾\n实际尾部 % x", conn.written[len(conn.written)-len(other):])
	}
}

// ── 游戏口 LOGIN 回包改写 ──────────────────────────────────────────────────

func TestS5A95GameAdapterRewritesLogin(t *testing.T) {
	adapter := NewS5A95GameAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)
	conn := newS5CollectConn()

	rest := adapter.ProcessDownlink(mustHex(t, s5FixtureLoginHex), conn)
	if rest != nil {
		t.Fatalf("应返回 nil，实际 % x", rest)
	}

	frame := conn.written
	// 16B 帧头：kind/opcode/seq 原样，长度与 CRC 按新 body 重算
	if frame[0] != s5CmdKind {
		t.Fatalf("kind = %d, want %d", frame[0], s5CmdKind)
	}
	if op := int(binary.LittleEndian.Uint16(frame[1:3])); op != s5CmdLogin {
		t.Fatalf("opcode = %d, want %d", op, s5CmdLogin)
	}
	if seq := int(binary.LittleEndian.Uint16(frame[11:13])); seq != 7 {
		t.Fatalf("seq = %d, want 7（原样保留）", seq)
	}
	if total := int(binary.LittleEndian.Uint32(frame[3:7])); total != len(frame) {
		t.Fatalf("帧长字段 %d 与实际 %d 不符", total, len(frame))
	}
	if got := crc32S5A9(frame[11:]); got != binary.LittleEndian.Uint32(frame[7:11]) {
		t.Fatalf("CRC 未按新 body 重算: 帧内 0x%08x, 实算 0x%08x",
			binary.LittleEndian.Uint32(frame[7:11]), got)
	}

	body := frame[s5GameFrameHeaderSize:]
	// Endpoint：5B magic + u32 0 原样，ipLen/ip/port 换成公网值，尾部一个字节不动
	if !bytes.Equal(body[:5], []byte{1, 1, 1, 0, 1}) {
		t.Fatalf("magic 被改坏: % x", body[:5])
	}
	if v := binary.LittleEndian.Uint32(body[5:9]); v != 0 {
		t.Fatalf("magic 后的 u32 = %d, want 0", v)
	}
	ipLen := int(binary.LittleEndian.Uint32(body[s5EndpointIPLenOffset : s5EndpointIPLenOffset+4]))
	ipStart := s5EndpointIPLenOffset + 4
	if ipLen != len("203.0.113.7") {
		t.Fatalf("ipLen = %d, want %d", ipLen, len("203.0.113.7"))
	}
	if got := string(body[ipStart : ipStart+ipLen]); got != "203.0.113.7" {
		t.Fatalf("Endpoint IP = %q, want 203.0.113.7", got)
	}
	if got := int(binary.LittleEndian.Uint32(body[ipStart+ipLen : ipStart+ipLen+4])); got != 24002 {
		t.Fatalf("Endpoint 端口 = %d, want 24002", got)
	}
	// 尾部（u32 0 + {0,0,1,1,0,0,0} + 其余零块）必须逐字节保留
	origBody := mustHex(t, s5FixtureLoginHex)[s5GameFrameHeaderSize:]
	origTail := origBody[13+12+4:]
	newTail := body[ipStart+ipLen+4:]
	if string(newTail) != string(origTail) {
		t.Fatalf("尾部被改坏\n实际 % x\n期望 % x", newTail, origTail)
	}
}

func TestS5A95GameAdapterIgnoresNotiChannelInfo(t *testing.T) {
	// NOTI CHANNELINFO 的 opcode 同样是 1，但 kind=0。
	// 若适配器按 opcode 匹配就会改坏这个包 —— 本测试钉住"按 kind+opcode 双匹配"。
	adapter := NewS5A95GameAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)
	conn := newS5CollectConn()

	original := mustHex(t, s5FixtureNotiHex)
	rest := adapter.ProcessDownlink(original, conn)
	if rest != nil {
		t.Fatalf("应返回 nil，实际 % x", rest)
	}
	if string(conn.written) != string(original) {
		t.Fatalf("NOTI 帧必须原样转发\n实际 % x\n期望 % x", conn.written, original)
	}
}

// TestS5A95GameAdapterKindGuardOnNotiShapedBody 是上一个测试的加强版：
// 构造一个 kind=0、opcode=1、但 body 是**合法 Endpoint**（端口在端口表内）
// 的帧。真实 NOTI body 是垃圾、会被边界检查兜住；这个用例保证即使
// body 完全合法，kind 守卫也照样拦得住 —— 否则 "opcode 撞号" 就会
// 把一个通知包改写成地址包。
func TestS5A95GameAdapterKindGuardOnNotiShapedBody(t *testing.T) {
	ip := []byte("192.168.1.50")
	body := make([]byte, 0, 64)
	body = append(body, 1, 1, 1, 0, 1) // magic
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(ip)))
	body = append(body, ip...)
	body = binary.LittleEndian.AppendUint32(body, 23102) // 在端口表内
	body = append(body, make([]byte, 27)...)             // 尾部零块

	frame := make([]byte, s5GameFrameHeaderSize+len(body))
	frame[0] = 0 // kind=0（NOTI）
	binary.LittleEndian.PutUint16(frame[1:3], s5CmdLogin)
	binary.LittleEndian.PutUint32(frame[3:7], uint32(len(frame)))
	binary.LittleEndian.PutUint16(frame[11:13], 5)
	copy(frame[s5GameFrameHeaderSize:], body)
	binary.LittleEndian.PutUint32(frame[7:11], crc32S5A9(frame[11:]))

	adapter := NewS5A95GameAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)
	conn := newS5CollectConn()
	rest := adapter.ProcessDownlink(frame, conn)
	if rest != nil {
		t.Fatalf("应返回 nil，实际 % x", rest)
	}
	if string(conn.written) != string(frame) {
		t.Fatalf("kind=0 的帧即使 body 合法也必须原样转发（守卫被绕过？）\n实际 % x\n期望 % x",
			conn.written, frame)
	}
}

func TestS5A95GameAdapterUnmappedPortPassesThrough(t *testing.T) {
	// 后端频道端口不在端口表内：映射不存在就整体不改写
	//（改写一半比不改写更糟）。
	adapter := NewS5A95GameAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101}), nil)
	conn := newS5CollectConn()

	original := mustHex(t, s5FixtureLoginHex)
	rest := adapter.ProcessDownlink(original, conn)
	if rest != nil {
		t.Fatalf("应返回 nil，实际 % x", rest)
	}
	if string(conn.written) != string(original) {
		t.Fatalf("端口未映射时应原样转发\n实际 % x\n期望 % x", conn.written, original)
	}
}

func TestS5A95GameAdapterIllegalFramePassesThrough(t *testing.T) {
	// 帧长字段荒谬（等不出完整帧）：剩余全部原样转发并停止解析。
	frame := mustHex(t, s5FixtureLoginHex)
	binary.LittleEndian.PutUint32(frame[3:7], 0xFFFFFF)

	adapter := NewS5A95GameAdapter("203.0.113.7",
		s5TestPorts(t, map[int]int{24001: 23101, 24002: 23102}), nil)
	conn := newS5CollectConn()
	rest := adapter.ProcessDownlink(frame, conn)
	if rest != nil {
		t.Fatalf("非法帧后应返回 nil（已全部写出），实际 % x", rest)
	}
	if string(conn.written) != string(frame) {
		t.Fatalf("非法帧应原样转发\n实际 % x\n期望 % x", conn.written, frame)
	}
}

// TestS5A95AdaptersNilLogger 钉住"logger 可为 nil"：单元测试与最小装配
// 场景不传日志时不能 panic（warnOnce 内的 nil 接收者由 ConsoleLogger 兜底）。
func TestS5A95AdaptersNilLogger(t *testing.T) {
	var ports atomic.Pointer[portView]
	ports.Store(buildPortViewFromResolved(map[int]int{}))

	ch := NewS5A95ChannelAdapter("203.0.113.7", &ports, nil)
	gm := NewS5A95GameAdapter("203.0.113.7", &ports, nil)
	conn := newS5CollectConn()

	if rest := ch.ProcessDownlink(mustHex(t, s5FixtureDirectoryHex), conn); rest != nil {
		t.Fatalf("频道适配器 nil logger 场景应正常处理，实际 % x", rest)
	}
	if rest := gm.ProcessDownlink(mustHex(t, s5FixtureLoginHex), conn); rest != nil {
		t.Fatalf("游戏适配器 nil logger 场景应正常处理，实际 % x", rest)
	}
	// 两次都走"原样转发"分支，写出字节数 = 两帧原长
	want := len(mustHex(t, s5FixtureDirectoryHex)) + len(mustHex(t, s5FixtureLoginHex))
	if len(conn.written) != want {
		t.Fatalf("写出 %d 字节, want %d", len(conn.written), want)
	}
	_ = logger.Error // 保持 import 有意义（nil logger 由 ConsoleLogger 方法自身兜底）
}

var _ net.Conn = (*s5CollectConn)(nil)
