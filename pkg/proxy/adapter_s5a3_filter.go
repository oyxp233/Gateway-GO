package proxy

// ============================================================================
// S5A3 频道列表代理模式（2026-10-25）
//
// 目标：让"端口管理里关掉某个端口"= 客户端选频道界面里看不到那个频道。
//       S4A21 靠 S4A21ChannelAdapter 做到了（解析 0x12 帧 + 剔除条目），
//       而 S5A3 原来用纯透传适配器，关端口只是网关不再监听，
//       服务端仍在 CHANNELINFO 里通告该频道 → 玩家看得到、点进去连不上。
//
// ── 为什么这件事比预想的简单 ────────────────────────────────────────────────
//
// 查证发现 S5A3 与 S4A21 的频道列表**是同一套东西**：
//
//   1. opcode 相同：帧头 [1] == 0x12（S5A3 的 LegacyMsgChannelInfo=28434，
//      取低字节就是 0x12）。
//   2. 加密相同：zlib( AES-128-ECB( pad16(明文) ) )，
//      密钥都是 security.ChannelKey() = 日期 + "000006"。
//      → 直接复用 ChannelListRewriter 的 decrypt/encrypt，零新增密码学代码。
//   3. 条目布局相同：名字(20) + 容量(4) + 在线(4) + IP(16) + 端口(4) = 48 字节，
//      端口在条目内偏移 44 —— 与 channelListPortOffset 一致。
//
// 唯一差别在**前缀**：
//   S4A21：6 字节（组号 u16 + 条目数 u32），条目数在 [2:6]
//   S5A3 ：12 字节（server_count u32 + server_id u32 + 条目数 u32），条目数在 [8:12]
//   依据：Server-S5A3 的 channel.go:writeChannelInfoPrefix。
//
// ── 与 S4A21 的另一个差别：不改 IP ──────────────────────────────────────────
//
// S4A21 服务端把"自己看到的地址"写进条目，网关必须改写成公网 IP。
// S5A3 的条目 IP 直接来自服务端配置 DNFBRIDGE_SERVER_IP（生产取值不写进源码），
// 天然就是玩家能连的地址。所以这里**只过滤、不重写 IP/端口** ——
// 少一处改写就少一处出错的可能。
//
// ── 安全阀（任何一步失败都退回原样透传，绝不发坏帧）────────────────────────
//
//   · 帧长度非法        → 剩余字节原样转发，不再尝试分帧
//   · 解密/校验失败     → 该帧原样转发
//   · 过滤后一条不剩    → 原样转发（说明端口表与频道表口径对不上，
//                        宁可不改也不能让频道列表凭空清空）
// ============================================================================

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
)

const (
	// s5a3ChannelInfoMsgID 是 CHANNELINFO 的 opcode 字节（帧头 [1]）。
	// dnfenum.LegacyMsgChannelInfo = 28434 = 0x6F12，**下行只取低字节 0x12** ——
	// 依据 Server-S5A3 `protocol.writeLegacyHeader`：header[1] = byte(msg)。
	//
	// ★ 2026-11-18 复核：下行帧就是 **11 字节头**（不是 13）。
	//   [0]=class(0x7c)  [1]=msgID(byte)  [2:6]=总长(LE32)  [6:10]=0  [10]=1  body@11
	//   无 checksum。两条独立证据：① `BuildLegacyChannelPacket` → `LegacyChannelHeaderSize=11`
	//   ② 真实抓包夹具 `testdata/s5a3_real_channelinfo.bin`：LE32@2 == 文件长度 3403，
	//      且 body[11:13] 就是 zlib 头 78 9c。
	//   （13 字节头那条是**上行**通道包 ParseChannelPacket 的口径，别混用。）
	s5a3ChannelInfoMsgID = 0x12

	// s5a3ChannelPrefixSize 是 S5A3 频道列表明文前缀长度：
	// server_count(u32) + server_id(u32) + channel_count(u32)。
	s5a3ChannelPrefixSize = 12

	// s5a3ChannelCountOffset 是条目数字段在前缀内的偏移。
	s5a3ChannelCountOffset = 8

	// s5a3ChannelEntrySize / s5a3ChannelIPOffset / s5a3ChannelPortOffset
	// 与 S4A21 完全一致：名字20 + 容量4 + 在线4 + IP16 + 端口4 = 48，
	// IP 在 +28、端口在 +44。
	s5a3ChannelEntrySize  = channelListEntrySize
	s5a3ChannelIPOffset   = channelListIPOffset
	s5a3ChannelPortOffset = channelListPortOffset
)

// S5A3ChannelAdapter 解析下行 CHANNELINFO，剔除"所在端口已关闭"的频道条目。
type S5A3ChannelAdapter struct {
	rewriter *ChannelListRewriter
	ports    *atomic.Pointer[portView]
	logger   *logger.ConsoleLogger
}

// NewS5A3ChannelAdapter 构造 S5A3 频道列表适配器。
//
// ports 与所属 ProxyServer 共享同一个原子指针 —— 端口表热加载后立即生效。
func NewS5A3ChannelAdapter(profile config.GameServerEntry, ports *atomic.Pointer[portView], lg *logger.ConsoleLogger) *S5A3ChannelAdapter {
	return &S5A3ChannelAdapter{
		rewriter: NewChannelListRewriter(profile.KeyTimeZoneOffsetHours),
		ports:    ports,
		logger:   lg,
	}
}

// ProcessDownlink 逐帧扫描：CHANNELINFO 帧做过滤，其余帧原样转发。
//
// 契约与 S4A21 适配器一致：本函数负责把可发送字节写入 dst，
// 返回值只承载**尚未处理完的残包**（半帧）。
func (a *S5A3ChannelAdapter) ProcessDownlink(pending []byte, dst net.Conn) []byte {
	if len(pending) == 0 {
		return nil
	}
	view := a.ports.Load()

	offset := 0
	for offset+channelFrameHeaderSize <= len(pending) {
		frame, _, status := nextFrame(pending[offset:], channelFrameHeaderSize, channelFrameLenOffset)
		if status == frameNeedMore {
			break
		}
		if status == frameIllegal {
			// 帧长度非法：说明这不是我们认识的流（或已错位）。
			// 把剩余字节整块原样转发，并放弃后续分帧 —— 宁可透传也不猜。
			_, _ = dst.Write(pending[offset:])
			return nil
		}

		if frame[1] == s5a3ChannelInfoMsgID {
			a.writeFilteredFrame(frame, view, dst)
		} else {
			_, _ = dst.Write(frame)
		}
		offset += len(frame)
	}

	if offset == 0 {
		// 一个完整帧都没凑出来：等下一次 Read 补齐
		return pending
	}
	if offset < len(pending) {
		return pending[offset:]
	}
	return nil
}

// writeFilteredFrame 处理单个 CHANNELINFO 帧。
func (a *S5A3ChannelAdapter) writeFilteredFrame(frame []byte, view *portView, dst net.Conn) {
	body := frame[channelFrameHeaderSize:]

	plaintext, key, ok := a.rewriter.decryptAnyS5A3(body)
	if !ok {
		// 解密或结构校验失败：原样转发（服务端改了编码/密钥时自动降级）
		// ★ 必须留痕：这个分支一旦命中，端口改写就不生效，客户端会拿到后端口，
		//   现场表现是"选频道连不上、每 3 秒重连"——没有这条日志就完全看不出来。
		a.warn(fmt.Sprintf(
			"[S5A3 频道列表] 解密/结构校验失败（body=%d 字节），已原样透传 —— 端口改写本次未生效",
			len(body)))
		_, _ = dst.Write(frame)
		return
	}

	filtered, kept, dropped, rewritten := filterS5A3ChannelList(plaintext, view)
	if dropped > 0 && kept == 0 {
		// 安全阀：一条都没命中 ⇒ 端口表与频道表口径对不上。
		// 此时过滤会让客户端看到空列表，比"看到进不去的频道"更糟。
		a.warn(fmt.Sprintf(
			"[S5A3 频道列表] %d 条频道全部不在端口表开放范围内，已放弃过滤（请检查端口表映射）",
			dropped))
		_, _ = dst.Write(frame)
		return
	}
	// ★ 2026-11-18 BUG 修复：这里原先是 `if dropped == 0 { 原样转发 }`。
	//   端口映射场景（20006→10006）下所有端口都开着 ⇒ dropped==0，
	//   但 **条目里的端口必须改写**，否则改写结果被这一行丢掉，
	//   客户端拿到的仍是后端口 100xx（安全组不放行）⇒ 选频道连不上、每 3 秒重连。
	//   判据改成"没过滤且没改写"才原样透传。
	if dropped == 0 && !rewritten {
		// 没有需要剔除的条目、也没有端口需要改写：一个字节都不改
		_, _ = dst.Write(frame)
		return
	}

	encrypted := a.rewriter.encrypt(filtered, key)
	if len(encrypted) == 0 {
		_, _ = dst.Write(frame)
		return
	}

	// 重建 11 字节 legacy 头：只需要回填总长（[2:6]，含头）。
	// legacy 频道包**没有校验和**（服务端 writeLegacyHeader 只写 cmd/msgID/len + 固定保留位），
	// 所以这里不能凭空写 CRC —— 会把保留位写脏。
	header := make([]byte, channelFrameHeaderSize)
	copy(header, frame[:channelFrameHeaderSize])
	binary.LittleEndian.PutUint32(header[channelFrameLenOffset:], uint32(channelFrameHeaderSize+len(encrypted)))

	_, _ = dst.Write(header)
	_, _ = dst.Write(encrypted)

	if dropped > 0 {
		a.info(fmt.Sprintf("[S5A3 频道列表] 已隐藏 %d 个已关闭端口的频道，保留 %d 个", dropped, kept))
	} else {
		a.info(fmt.Sprintf("[S5A3 频道列表] 已按端口表改写 %d 个频道的对外端口（保留 %d 个）", kept, kept))
	}
}

func (a *S5A3ChannelAdapter) warn(msg string) {
	if a.logger != nil {
		a.logger.Warn(msg)
	}
}

func (a *S5A3ChannelAdapter) info(msg string) {
	if a.logger != nil {
		a.logger.Info(msg)
	}
}

// decryptAnyS5A3 尝试用今天/昨天的密钥解密，并用 S5A3 的布局校验。
//
// 跨零点回退是必需的：网关与游戏端的"今天"可能差几秒。
func (r *ChannelListRewriter) decryptAnyS5A3(data []byte) ([]byte, string, bool) {
	current := r.currentKey()
	if plaintext, err := r.decrypt(data, current); err == nil && isValidS5A3ChannelList(plaintext) {
		return plaintext, current, true
	}
	previous := r.previousDayKey()
	if plaintext, err := r.decrypt(data, previous); err == nil && isValidS5A3ChannelList(plaintext) {
		return plaintext, previous, true
	}
	return nil, "", false
}

// isValidS5A3ChannelList 校验解密结果确实是 S5A3 的频道列表。
//
// 这是**防误判**的关键：解密密钥错时 AES 不会报错，只会吐出随机字节。
// 必须靠结构自洽（前缀 + 条目数 + 长度吻合 + 端口/容量合理）来确认。
func isValidS5A3ChannelList(plain []byte) bool {
	if len(plain) < s5a3ChannelPrefixSize {
		return false
	}
	count := int(binary.LittleEndian.Uint32(plain[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	if count <= 0 || count > 512 {
		return false
	}
	// 明文按 16 字节对齐，所以实际长度 >= 前缀 + 条目数*48
	need := s5a3ChannelPrefixSize + count*s5a3ChannelEntrySize
	if len(plain) < need {
		return false
	}
	// 抽查首条与末条：名字必须是可打印的 "#xxx"，端口必须是 1..65535。
	if !validS5A3ChannelEntry(plain, 0) || !validS5A3ChannelEntry(plain, count-1) {
		return false
	}
	return true
}

func validS5A3ChannelEntry(plain []byte, index int) bool {
	off := s5a3ChannelPrefixSize + index*s5a3ChannelEntrySize
	if off+s5a3ChannelEntrySize > len(plain) {
		return false
	}
	// 名字前 20 字节：服务端写的是 "#"+名字，用 0 补齐。
	// 要求首字节是 '#'，且后面到第一个 0 之间都是可见 ASCII。
	if plain[off] != '#' {
		return false
	}
	for i := 1; i < 20; i++ {
		b := plain[off+i]
		if b == 0 {
			break
		}
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	port := int(binary.LittleEndian.Uint32(plain[off+s5a3ChannelPortOffset : off+s5a3ChannelPortOffset+4]))
	return port > 0 && port <= 65535
}

// filterS5A3ChannelList 剔除"所在端口未开放"的频道条目。
//
// 过滤口径与 ReloadPorts 的开监听口径严格一致：条目里的端口在端口表中存在
// 一条 Enabled=true 的映射才算可进。端口被停用/删除/从未纳管时网关不为它
// 开监听，客户端连上去必然失败，因此直接从列表移除。
//
// **默认不改写 IP 与端口**：S5A3 的条目 IP 来自服务端 DNFBRIDGE_SERVER_IP，
// 已是玩家可达的公网地址；端口默认是 1:1 映射，改它反而会错。
//
// 2026-11-18：新增**可选端口改写**——当端口表里 public != backend 时
// （运维要把后端 10006 对外映射成 20006），把条目端口改写成 public。
// 这是给「安全组只放行了 20000-20299，不想再开 100xx」的场景用的。
// public == backend 时行为与改动前**逐字节相同**（仍返回原 plain，不重加密）。
//
// 返回 (过滤后明文, 保留数, 剔除数)。dropped==0 且无端口改写时返回原切片（调用方据此跳过重加密）。
func filterS5A3ChannelList(plain []byte, view *portView) ([]byte, int, int, bool) {
	if len(plain) < s5a3ChannelPrefixSize {
		return plain, 0, 0, false
	}
	count := int(binary.LittleEndian.Uint32(plain[s5a3ChannelCountOffset:s5a3ChannelPrefixSize]))
	if count <= 0 {
		return plain, 0, 0, false
	}

	keep := make([]bool, count)
	publicPorts := make([]int, count)
	kept := 0
	rewritten := false
	for i := 0; i < count; i++ {
		off := s5a3ChannelPrefixSize + i*s5a3ChannelEntrySize
		if off+s5a3ChannelEntrySize > len(plain) {
			break
		}
		port := int(binary.LittleEndian.Uint32(plain[off+s5a3ChannelPortOffset : off+s5a3ChannelPortOffset+4]))
		public, ok := view.publicFor(port)
		if !ok {
			continue
		}
		keep[i] = true
		publicPorts[i] = public
		if public != port {
			rewritten = true
		}
		kept++
	}

	dropped := count - kept
	if dropped == 0 && !rewritten {
		return plain, kept, 0, false
	}
	if kept == 0 {
		return plain, 0, dropped, false
	}

	out := make([]byte, s5a3ChannelPrefixSize+kept*s5a3ChannelEntrySize)
	// 前缀原样保留（server_count + server_id），只改条目数
	copy(out[:s5a3ChannelCountOffset], plain[:s5a3ChannelCountOffset])
	binary.LittleEndian.PutUint32(out[s5a3ChannelCountOffset:s5a3ChannelPrefixSize], uint32(kept))

	dst := s5a3ChannelPrefixSize
	for i := 0; i < count; i++ {
		if !keep[i] {
			continue
		}
		src := s5a3ChannelPrefixSize + i*s5a3ChannelEntrySize
		copy(out[dst:dst+s5a3ChannelEntrySize], plain[src:src+s5a3ChannelEntrySize])
		// 端口改写：仅当端口表里 public != backend（20006:10006 这种映射）。
		// public == backend 时这行写入原值，与改动前逐字节等价。
		binary.LittleEndian.PutUint32(
			out[dst+s5a3ChannelPortOffset:dst+s5a3ChannelPortOffset+4],
			uint32(publicPorts[i]),
		)
		dst += s5a3ChannelEntrySize
	}
	return out, kept, dropped, rewritten
}
