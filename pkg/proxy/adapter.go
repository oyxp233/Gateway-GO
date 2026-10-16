package proxy

import (
	"encoding/binary"
	"net"
)

// ─────────────────────────────────────────────────────────────────────────────
// 下行适配层（2026-10-16 双服改造）
//
// 一个网关同时带 S4A21 与 S5A9（DNF95）两个服。两个游戏客户端版本拿到
// 「服务器地址 / 频道入口端口」的方式完全不同：
//
//	S4A21：频道口下行 opcode 0x12，明文布局（条目 48B、IP@28、端口@44），
//	       zlib + AES-128-ECB **日密钥**；
//	S5A9 ：频道口下行 op 18 Directory，AES-ECB **固定密钥** + zlib
//	       （条目 64B、IP@28、端口@60），游戏口 LOGIN 回复还内嵌一份
//	       Endpoint(地址, 端口)（GameFrame 16B 头 + CRC）。
//
// 差异全部收在本包的下行适配器里（S4A21ChannelAdapter /
// S5A95ChannelAdapter / S5A95GameAdapter），转发热路径只认接口，
// 不加任何按协议的分支。
// ─────────────────────────────────────────────────────────────────────────────

// DownlinkAdapter 下行（服务端 → 客户端）字节流适配器。
//
// 实现约定：
//   - pending 可能含多个帧或半个帧：完整帧逐个处理，残包返回给调用方
//     拼到下一次读之后（与既有 processChannelData 的口径一致）；
//   - 解不开 / 对不上 / 端口未映射时**原样转发该帧**（安全阀：宁可让
//     客户端拿到未改写的数据，也不能把帧改坏或凭空吞掉帧）；
//   - 整个 pending 一个完整帧都没有时返回原 pending（调用方继续攒）。
type DownlinkAdapter interface {
	ProcessDownlink(pending []byte, dst net.Conn) []byte
}

// 两种频道口协议（S4A21 0x12 / S5A9 op18）的帧头同构：
//
//	[0]=方向标记(S4A21 下行 0x7c / S5A9 下行 0x7c、上行 0) [1]=op
//	[2:6]=总长(LE32，含 11B 头) [6:10]=0 [10]=1，body 从 11 开始
const (
	channelFrameHeaderSize = 11
	channelFrameLenOffset  = 2
)

// S5A9 游戏口帧（GameFrame.Build）：
//
//	[0]=kind [1:3]=opcode(LE16) [3:7]=总长(LE32，含 16B 头)
//	[7:11]=CRC32(对 seq+body) [11:13]=seq(LE16)，body 从 16 开始
const (
	s5GameFrameHeaderSize = 16
	s5GameFrameLenOffset  = 3
)

// frameStatus 描述一次切帧的结果。
type frameStatus int

const (
	// frameOK 切出了一个完整帧（frame 有效、rest 是剩余字节）。
	frameOK frameStatus = iota
	// frameNeedMore 还不够一个完整帧 —— 继续攒（rest 无意义）。
	frameNeedMore
	// frameIllegal 帧长非法（等不出完整帧）—— 调用方应按原样转发
	// 剩余全部字节并停止解析（与既有 S4A21 口径一致）。
	frameIllegal
)

// nextFrame 从 buf 头部切出一个完整帧。
//
// headerSize / lenOffset 两种协议不同（频道口 11B/长度@2，游戏口 16B/长度@3），
// 长度字段一律 LE32 且**含帧头**（服务端口径）。
func nextFrame(buf []byte, headerSize, lenOffset int) (frame, rest []byte, status frameStatus) {
	if len(buf) < headerSize {
		return nil, nil, frameNeedMore
	}
	total := int(binary.LittleEndian.Uint32(buf[lenOffset : lenOffset+4]))
	if total < headerSize || total > maxFrameSize {
		return nil, nil, frameIllegal
	}
	if len(buf) < total {
		return nil, nil, frameNeedMore
	}
	return buf[:total], buf[total:], frameOK
}
