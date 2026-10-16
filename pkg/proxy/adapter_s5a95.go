package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"s4a21-gateway/pkg/logger"
)

// ─────────────────────────────────────────────────────────────────────────────
// S5A95（S5A9 / DNF95）协议适配器（2026-10-16 双服改造新增）
//
// 布局全部对照 S5A9 服务端源码（ServerS5A9，namespace DfoServer）：
//   - 频道口握手/目录：Network/Protocol/ChannelProtocolHandler.cs
//     + Network/Builders/ChannelPackets.cs（Directory）
//   - 游戏口登录回包：Network/Protocol/GameProtocolHandler.cs:53
//     + Network/Parsers/NativeLoginRequest.cs + Handlers/LoginHandler.cs
//   - 帧格式：Network/Core/GameFrame.cs（Build：16B 头 + CRC）
//
// 网关要改写的只有两个包（客户端拿到的地址/端口全在这两处）：
//   改写点 A：频道口下行 op 18 Directory —— 每条频道的 IP + 端口；
//   改写点 B：游戏口下行 LOGIN 回复内嵌的 Endpoint(地址, 端口)。
// NOTI CHANNELINFO（protobuf + ROL8^0xB5）不含地址，**不用改**。
// ─────────────────────────────────────────────────────────────────────────────

// S5A9 频道口 Directory 包常量（对照 ChannelPackets.Directory）。
const (
	// s5DirectoryOpcode 是频道口下行「频道目录」的 op（对客户端 op 17 的回复）。
	s5DirectoryOpcode = 18
	// s5DirectoryHeaderSize 明文头：u32 1 + u32 serverIndex + u32 count。
	s5DirectoryHeaderSize = 12
	// s5DirectoryEntrySize 每条频道 64B。
	s5DirectoryEntrySize = 64
	// s5DirectoryIPOffset IP 在条目内的偏移（32B 字段，零填充）。
	s5DirectoryIPOffset = 28
	s5DirectoryIPSize   = 32
	// s5DirectoryPortOffset 端口在条目内的偏移。
	s5DirectoryPortOffset = 60
	// s5DirectoryKey 是 Directory 的 AES-128-ECB 密钥（服务端硬编码，
	// 与 S4A21 的「日密钥」不同，这里是固定值）。
	s5DirectoryKey = "EMU-LAB-KEY-0001"
)

// S5A9 游戏口帧常量（对照 GameFrame.Build / CmdPacketType）。
const (
	// s5CmdLogin 是 CmdPacketType.LOGIN。★ kind 必须是 1（CMD）——
	// NotiPacketType.CHANNELINFO 的 opcode 也是 1，但 kind=0（NOTI）。
	s5CmdLogin = 1
	s5CmdKind  = 1
	// s5EndpointFixedSize Endpoint 包中 IP 之前的固定部分：
	// 5B magic + u32 0 + i32 ipLen。
	s5EndpointIPLenOffset = 9
)

// s5CrcTable 是 S5A9 游戏帧的 CRC32 表。
//
// 算法逐位对照 GameFrame.CreateCrcTable：反射多项式 0x4DB89129，
// 逐字节 (x>>8) ^ table[(x^b)&0xFF]，初值 0xFFFFFFFF，结尾取反。
// ★ 与标准 CRC-32（0xEDB88320）**不是同一个多项式**，不能直接用
// hash/crc32 的 IEEE 表 —— 必须按服务端这张表算。
var s5CrcTable = func() [256]uint32 {
	var table [256]uint32
	for value := uint32(0); value < 256; value++ {
		x := value
		for bit := 0; bit < 8; bit++ {
			if x&1 != 0 {
				x = (x >> 1) ^ 0x4DB89129
			} else {
				x >>= 1
			}
		}
		table[value] = x
	}
	return table
}()

// crc32S5A9 计算 S5A9 游戏帧 CRC（对照 GameFrame.Crc：对 seq+body 计算）。
func crc32S5A9(data []byte) uint32 {
	x := uint32(0xFFFFFFFF)
	for _, b := range data {
		x = (x >> 8) ^ s5CrcTable[(x^uint32(b))&0xFF]
	}
	return ^x
}

// S5A95ChannelAdapter 改写频道口下行的 Directory 包（改写点 A）。
type S5A95ChannelAdapter struct {
	publicIP string
	ports    *atomic.Pointer[portView]
	logger   *logger.ConsoleLogger
	// warned 保证每类异常只记一次日志 —— 下行是热路径，
	// 扫描器打一堆解不开的包时不能把日志刷爆。
	warnedDecrypt atomic.Bool
	warnedFilter  atomic.Bool
}

// NewS5A95ChannelAdapter 构造 S5A9 频道口适配器。
func NewS5A95ChannelAdapter(publicIP string, ports *atomic.Pointer[portView], lg *logger.ConsoleLogger) *S5A95ChannelAdapter {
	return &S5A95ChannelAdapter{publicIP: publicIP, ports: ports, logger: lg}
}

// ProcessDownlink 实现 DownlinkAdapter。
func (a *S5A95ChannelAdapter) ProcessDownlink(pending []byte, dst net.Conn) []byte {
	view := a.ports.Load()

	offset := 0
	for offset+channelFrameHeaderSize <= len(pending) {
		frame, _, status := nextFrame(pending[offset:], channelFrameHeaderSize, channelFrameLenOffset)
		if status == frameNeedMore {
			break
		}
		if status == frameIllegal {
			dst.Write(pending[offset:])
			return nil
		}

		if frame[1] == s5DirectoryOpcode {
			if rewritten := a.rewriteDirectoryFrame(frame, view); rewritten != nil {
				dst.Write(rewritten)
			} else {
				// 解不开/对不上/全被过滤：原样转发（安全阀）
				dst.Write(frame)
			}
		} else {
			dst.Write(frame)
		}

		offset += len(frame)
	}

	if offset == 0 {
		return pending
	}
	if offset < len(pending) {
		return pending[offset:]
	}
	return nil
}

// rewriteDirectoryFrame 解出 Directory 明文，改写 IP/端口并按端口表过滤，
// 再按原算法重组。任何一步对不上返回 nil（调用方原样转发）。
func (a *S5A95ChannelAdapter) rewriteDirectoryFrame(frame []byte, view *portView) []byte {
	body := frame[channelFrameHeaderSize:]

	plain, err := zlibDecompress(body)
	if err != nil {
		a.warnOnce(&a.warnedDecrypt, "S5A9 频道目录解压失败（压缩口径不符？），本连接后续目录包原样转发")
		return nil
	}
	plain, err = aes128DecryptECB(plain, []byte(s5DirectoryKey))
	if err != nil {
		a.warnOnce(&a.warnedDecrypt, "S5A9 频道目录解密失败，本连接后续目录包原样转发")
		return nil
	}
	if len(plain) < s5DirectoryHeaderSize {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(plain[8:s5DirectoryHeaderSize]))
	if count <= 0 || s5DirectoryHeaderSize+count*s5DirectoryEntrySize > len(plain) {
		return nil
	}

	// 过滤：条目端口（服务端填的是后端监听端口）必须在端口表里有
	// Enabled=true 的公网映射，否则客户端连上去必然失败。
	keep := make([]bool, count)
	kept := 0
	for i := 0; i < count; i++ {
		off := s5DirectoryHeaderSize + i*s5DirectoryEntrySize
		backendPort := int(binary.LittleEndian.Uint32(plain[off+s5DirectoryPortOffset : off+s5DirectoryPortOffset+4]))
		if _, ok := view.publicFor(backendPort); ok {
			keep[i] = true
			kept++
		}
	}
	if kept == 0 {
		a.warnOnce(&a.warnedFilter,
			"S5A9 频道目录：全部频道都不在端口表开放范围内，已放弃过滤（请检查端口表映射口径）")
		return nil
	}

	out := make([]byte, s5DirectoryHeaderSize+kept*s5DirectoryEntrySize)
	copy(out, plain[:s5DirectoryHeaderSize]) // 1 + serverIndex 原样保留
	binary.LittleEndian.PutUint32(out[8:s5DirectoryHeaderSize], uint32(kept))

	ipBytes := []byte(a.publicIP)
	if len(ipBytes) > s5DirectoryIPSize-1 {
		ipBytes = ipBytes[:s5DirectoryIPSize-1]
	}

	dst := s5DirectoryHeaderSize
	for i := 0; i < count; i++ {
		if !keep[i] {
			continue
		}
		src := s5DirectoryHeaderSize + i*s5DirectoryEntrySize
		copy(out[dst:dst+s5DirectoryEntrySize], plain[src:src+s5DirectoryEntrySize])

		// 重写 IP（32B 字段先清零再拷贝，杜绝残留字节）
		ipOff := dst + s5DirectoryIPOffset
		for j := 0; j < s5DirectoryIPSize; j++ {
			out[ipOff+j] = 0
		}
		copy(out[ipOff:ipOff+len(ipBytes)], ipBytes)

		// 重写端口（后端 -> 公网）
		backendPort := int(binary.LittleEndian.Uint32(plain[src+s5DirectoryPortOffset : src+s5DirectoryPortOffset+4]))
		if pub, ok := view.publicFor(backendPort); ok {
			binary.LittleEndian.PutUint32(out[dst+s5DirectoryPortOffset:], uint32(pub))
		}

		dst += s5DirectoryEntrySize
	}

	// 按服务端同算法重组：AES-ECB（先补 16）→ zlib → 帧
	encrypted, err := aes128EncryptECB(padTo16(out), []byte(s5DirectoryKey))
	if err != nil {
		return nil
	}
	newBody := zlibCompress(encrypted)

	newFrame := make([]byte, channelFrameHeaderSize+len(newBody))
	copy(newFrame, frame[:channelFrameHeaderSize]) // 方向标记/op/保留位原样
	binary.LittleEndian.PutUint32(newFrame[2:6], uint32(len(newFrame)))
	copy(newFrame[channelFrameHeaderSize:], newBody)
	return newFrame
}

func (a *S5A95ChannelAdapter) warnOnce(flag *atomic.Bool, msg string) {
	if flag.CompareAndSwap(false, true) {
		if a.logger == nil {
			return // 最小装配/测试场景不传日志：静默（绝不在热路径 panic）
		}
		a.logger.Warn("[S5A9] " + msg)
	}
}

// S5A95GameAdapter 改写游戏口下行的 LOGIN 回复（改写点 B）。
//
// 不rewrite的后果：客户端拿到后端内网地址 + 后端端口，直连绕过网关
// （或根本连不上）。只认 kind=1(CMD) 且 opcode=LOGIN 的帧 ——
// NOTI CHANNELINFO 的 opcode 同为 1 但 kind=0，不会误改。
type S5A95GameAdapter struct {
	publicIP string
	ports    *atomic.Pointer[portView]
	logger   *logger.ConsoleLogger
	warned   atomic.Bool
}

// NewS5A95GameAdapter 构造 S5A9 游戏口适配器。
func NewS5A95GameAdapter(publicIP string, ports *atomic.Pointer[portView], lg *logger.ConsoleLogger) *S5A95GameAdapter {
	return &S5A95GameAdapter{publicIP: publicIP, ports: ports, logger: lg}
}

// ProcessDownlink 实现 DownlinkAdapter。
func (a *S5A95GameAdapter) ProcessDownlink(pending []byte, dst net.Conn) []byte {
	offset := 0
	for offset+s5GameFrameHeaderSize <= len(pending) {
		frame, _, status := nextFrame(pending[offset:], s5GameFrameHeaderSize, s5GameFrameLenOffset)
		if status == frameNeedMore {
			break
		}
		if status == frameIllegal {
			dst.Write(pending[offset:])
			return nil
		}

		kind := frame[0]
		opcode := int(binary.LittleEndian.Uint16(frame[1:3]))
		if kind == s5CmdKind && opcode == s5CmdLogin {
			if rewritten := a.rewriteLoginFrame(frame); rewritten != nil {
				dst.Write(rewritten)
			} else {
				dst.Write(frame)
			}
		} else {
			dst.Write(frame)
		}

		offset += len(frame)
	}

	if offset == 0 {
		return pending
	}
	if offset < len(pending) {
		return pending[offset:]
	}
	return nil
}

// rewriteLoginFrame 改写 LOGIN 回复里的 Endpoint(地址, 端口)。
//
// Endpoint 布局（对照 ChannelPackets.Endpoint，BinaryWriter 小端）：
//
//	[5B magic {1,1,1,0,1}][u32 0][i32 ipLen][ip 字节][i32 port]
//	[u32 0][7B {0,0,1,1,0,0,0}][4B 0][u32 0]
//
// IP 是长度前缀字段 ⇒ 换地址不涉及定长字段，重建即可；
// 端口必须过端口表（后端 → 公网），映射不存在就整体不改写。
func (a *S5A95GameAdapter) rewriteLoginFrame(frame []byte) []byte {
	total := int(binary.LittleEndian.Uint32(frame[3:7]))
	if total < s5GameFrameHeaderSize || total > len(frame) {
		return nil
	}
	body := frame[s5GameFrameHeaderSize:total]

	// 解析 Endpoint：至少要有固定头 + ipLen + 端口
	if len(body) < s5EndpointIPLenOffset+4 {
		return nil
	}
	ipLen := int(binary.LittleEndian.Uint32(body[s5EndpointIPLenOffset : s5EndpointIPLenOffset+4]))
	ipStart := s5EndpointIPLenOffset + 4
	if ipLen < 0 || ipStart+ipLen+4 > len(body) {
		return nil
	}
	backendPort := int(binary.LittleEndian.Uint32(body[ipStart+ipLen : ipStart+ipLen+4]))

	view := a.ports.Load()
	publicPort, ok := view.publicFor(backendPort)
	if !ok {
		if a.warned.CompareAndSwap(false, true) && a.logger != nil {
			a.logger.Warn(fmt.Sprintf(
				"[S5A9] 游戏口 LOGIN 回包：后端频道端口 %d 不在端口表内，本连接后续回包原样转发", backendPort))
		}
		return nil
	}

	// 重组 body：固定头 + 新 IP（长度前缀）+ 新端口 + 原尾部
	tail := body[ipStart+ipLen+4:]
	newIP := []byte(a.publicIP)
	newBody := make([]byte, 0, ipStart+len(newIP)+4+len(tail))
	newBody = append(newBody, body[:s5EndpointIPLenOffset]...)
	newBody = binary.LittleEndian.AppendUint32(newBody, uint32(len(newIP)))
	newBody = append(newBody, newIP...)
	newBody = binary.LittleEndian.AppendUint32(newBody, uint32(publicPort))
	newBody = append(newBody, tail...)

	// 重组帧：16B 头（长度按新 body 重算）+ 原 seq + 新 body + 重算 CRC
	// （CRC 口径对 seq+body 计算，见 GameFrame.Build）。
	newTotal := s5GameFrameHeaderSize + len(newBody)
	newFrame := make([]byte, newTotal)
	copy(newFrame, frame[:s5GameFrameHeaderSize])
	binary.LittleEndian.PutUint32(newFrame[3:7], uint32(newTotal))
	copy(newFrame[s5GameFrameHeaderSize:], newBody)
	binary.LittleEndian.PutUint32(newFrame[7:11], crc32S5A9(newFrame[11:]))
	return newFrame
}
