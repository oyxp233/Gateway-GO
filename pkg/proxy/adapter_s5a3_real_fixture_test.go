package proxy

// ============================================================================
// 用**真实服务端响应**验证 S5A3 适配器（2026-10-25）
//
// 夹具 testdata/s5a3_real_channelinfo.bin 是从 90CN 服务端 127.0.0.1:7001
// 直连抓到的真实 CHANNELINFO 应答（3403 字节，opcode 0x12，118 个频道）。
//
// 它比手工构造的夹具更有价值：加密密钥、zlib 输出、protobuf/布局细节
// 全部来自真实进程，任何"我以为对但其实不对"的实现都会在这里露馅。
//
// 三个不变量：
//   ① 端口全开时：输出与输入**逐字节相同**（不需要过滤就不该重编码）
//   ② 端口全开时：能成功解密并认出 118 条频道
//   ③ 关掉一个端口时：恰好少一条，其余条目逐字节不变
// ============================================================================

import (
	"bytes"
	"encoding/binary"
	"os"
	"sync/atomic"
	"testing"
)

func loadRealS5A3ChannelFrame(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/s5a3_real_channelinfo.bin")
	if err != nil {
		t.Fatalf("读真实夹具失败: %v", err)
	}
	if len(raw) < channelFrameHeaderSize {
		t.Fatalf("夹具过短: %d", len(raw))
	}
	if raw[1] != s5a3ChannelInfoMsgID {
		t.Fatalf("夹具 opcode = 0x%02x，期望 0x%02x", raw[1], s5a3ChannelInfoMsgID)
	}
	return raw
}

// newRealPortView 用"夹具里出现的全部端口"构造端口视图（= 全开）。
func newRealPortViewFromPlain(plain []byte) *portView {
	view := newPortView()
	count := int(binary.LittleEndian.Uint32(plain[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	for i := 0; i < count; i++ {
		off := s5a3ChannelPrefixSize + i*s5a3ChannelEntrySize
		if off+s5a3ChannelEntrySize > len(plain) {
			break
		}
		port := int(binary.LittleEndian.Uint32(plain[off+s5a3ChannelPortOffset : off+s5a3ChannelPortOffset+4]))
		view.backendToPublic[port] = port
	}
	return view
}

func newRealAdapter(view *portView) (*S5A3ChannelAdapter, *s5CollectConn) {
	holder := &atomic.Pointer[portView]{}
	holder.Store(view)
	return &S5A3ChannelAdapter{rewriter: NewChannelListRewriter(0), ports: holder}, &s5CollectConn{}
}

// TestS5A3RealFixtureDecrypts 真实夹具能被正确解密，且条目数符合预期。
func TestS5A3RealFixtureDecrypts(t *testing.T) {
	frame := loadRealS5A3ChannelFrame(t)
	r := NewChannelListRewriter(0)

	plain, _, ok := r.decryptAnyS5A3(frame[channelFrameHeaderSize:])
	if !ok {
		t.Fatal("真实夹具解密失败 —— 密钥派生或布局校验与服务端不一致")
	}
	count := int(binary.LittleEndian.Uint32(plain[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	// ★ 不是 118：DNFBRIDGE_DEFAULT_GROUP_LOGIN_ONLY=true 时，默认组只列
	//   "常驻城镇频道"（团本/PVP/交易/隐藏 raid 不进登录落点），
	//   90CN 实测 n=98（见 packet_log 的 channel-advertise）。
	//   118 是 channel_info.etc 的总条目数，两者不是一回事。
	if count != 98 {
		t.Fatalf("条目数 = %d，期望 98（默认组的常驻频道数）", count)
	}
	t.Logf("真实夹具: %d 条频道（默认组常驻），明文 %d 字节", count, len(plain))
}

// TestS5A3RealFixtureAllOpenIsByteIdentical 端口全开时一个字节都不改。
//
// 这是**最重要**的回归：只要这条不红，就说明新适配器在正常运营状态下
// 与原来的透传行为完全等价，不会影响任何玩家。
func TestS5A3RealFixtureAllOpenIsByteIdentical(t *testing.T) {
	frame := loadRealS5A3ChannelFrame(t)
	r := NewChannelListRewriter(0)
	plain, _, ok := r.decryptAnyS5A3(frame[channelFrameHeaderSize:])
	if !ok {
		t.Fatal("解密失败")
	}

	adapter, dst := newRealAdapter(newRealPortViewFromPlain(plain))
	if rest := adapter.ProcessDownlink(frame, dst); rest != nil {
		t.Fatalf("完整帧不该留残包，实际 %d 字节", len(rest))
	}
	if !bytes.Equal(dst.written, frame) {
		t.Fatalf("端口全开时输出必须与输入逐字节相同（got %d B, want %d B）",
			len(dst.written), len(frame))
	}
}

// TestS5A3RealFixtureDropOneChannel 关掉一个端口：恰好少一条，其余不变。
func TestS5A3RealFixtureDropOneChannel(t *testing.T) {
	frame := loadRealS5A3ChannelFrame(t)
	r := NewChannelListRewriter(0)
	plain, _, ok := r.decryptAnyS5A3(frame[channelFrameHeaderSize:])
	if !ok {
		t.Fatal("解密失败")
	}

	view := newRealPortViewFromPlain(plain)
	// 关掉最后一条频道的端口
	count := int(binary.LittleEndian.Uint32(plain[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	lastOff := s5a3ChannelPrefixSize + (count-1)*s5a3ChannelEntrySize
	closedPort := int(binary.LittleEndian.Uint32(plain[lastOff+s5a3ChannelPortOffset : lastOff+s5a3ChannelPortOffset+4]))
	delete(view.backendToPublic, closedPort)
	t.Logf("关闭端口 %d（对应最后一条频道）", closedPort)

	adapter, dst := newRealAdapter(view)
	adapter.ProcessDownlink(frame, dst)

	out, _, ok := r.decryptAnyS5A3(dst.written[channelFrameHeaderSize:])
	if !ok {
		t.Fatal("过滤后的输出无法解密 —— 重编码有误")
	}
	gotCount := int(binary.LittleEndian.Uint32(out[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	if gotCount != count-1 {
		t.Fatalf("过滤后条目数 = %d，期望 %d", gotCount, count-1)
	}

	// 前缀前 8 字节（server_count + server_id）必须原样
	if !bytes.Equal(out[0:8], plain[0:8]) {
		t.Fatalf("前缀被改动: %x vs %x", out[0:8], plain[0:8])
	}

	// 保留下来的前 count-1 条必须与原文逐字节相同
	keptBytes := (count - 1) * s5a3ChannelEntrySize
	if !bytes.Equal(out[s5a3ChannelPrefixSize:s5a3ChannelPrefixSize+keptBytes],
		plain[s5a3ChannelPrefixSize:s5a3ChannelPrefixSize+keptBytes]) {
		t.Fatal("保留下来的条目被改动了")
	}

	// 帧头声明的长度必须与实际一致
	declared := int(binary.LittleEndian.Uint32(dst.written[channelFrameLenOffset:]))
	if declared != len(dst.written) {
		t.Fatalf("帧头声明长度 %d != 实际 %d", declared, len(dst.written))
	}
}
