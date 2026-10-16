package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/security"
)

// ─────────────────────────────────────────────────────────────────────────────
// S4A21 频道列适配器（2026-10-16 双服改造：由 proxy.go 原样搬迁）
//
// 搬迁是**纯搬家**：逻辑、注释、安全阀口径与搬迁前逐字节等价，
// 既有夹具测试（channel_fixture_test.go 等）继续锁死行为。
// ─────────────────────────────────────────────────────────────────────────────

// S4A21 频道列报文常量（与搬迁前一致）：
//
//	频道列明文布局（与服务端 ChannelProtocolHandler 对齐）：
//	2B 组号 + 4B 条目数，每条 20B 名称 + 4B 容量 + 4B 在线数 + 16B IP + 4B 端口。
const (
	channelListPrefixSize = 6
	channelListEntrySize  = 48
	channelListIPOffset   = 28
	channelListPortOffset = 44
	// scAskChannelInfoNew 是 S4A21 频道列下行 opcode。
	scAskChannelInfoNew = 0x12
)

// S4A21ChannelAdapter 把 S4A21 频道列（0x12）的 IP/端口改写为网关公网值，
// 并剔除已关闭端口的频道。
type S4A21ChannelAdapter struct {
	rewriter *ChannelListRewriter
	publicIP string
	// ports 与所属 ProxyServer 共享同一个原子指针 —— 端口表热加载时
	// 适配器看到的即时生效，无需重建适配器。
	ports  *atomic.Pointer[portView]
	logger *logger.ConsoleLogger
}

// NewS4A21ChannelAdapter 构造 S4A21 频道列适配器。
func NewS4A21ChannelAdapter(profile config.GameServerEntry, ports *atomic.Pointer[portView], lg *logger.ConsoleLogger) *S4A21ChannelAdapter {
	return &S4A21ChannelAdapter{
		rewriter: NewChannelListRewriter(profile.KeyTimeZoneOffsetHours),
		publicIP: profile.PublicIP,
		ports:    ports,
		logger:   lg,
	}
}

// ProcessDownlink 实现 DownlinkAdapter（原 ProxyServer.processChannelData）。
func (a *S4A21ChannelAdapter) ProcessDownlink(pending []byte, dst net.Conn) []byte {
	// 每次读到的数据块取一次端口视图快照：配置热加载对下一块数据即生效，
	// 且整个处理过程共享同一个不可变快照（无锁、无并发 map 读写风险）。
	view := a.ports.Load()

	offset := 0
	for offset+channelFrameHeaderSize <= len(pending) {
		frame, _, status := nextFrame(pending[offset:], channelFrameHeaderSize, channelFrameLenOffset)
		if status == frameNeedMore {
			break
		}
		if status == frameIllegal {
			// 帧长度非法：原样转发剩余字节
			dst.Write(pending[offset:])
			return nil
		}

		if frame[1] == scAskChannelInfoNew {
			body := frame[channelFrameHeaderSize:]
			rewritten, kept, dropped := a.rewriter.RewriteChannelInfoWithFallback(
				body, a.publicIP, view)
			if dropped > 0 && kept == 0 {
				a.logger.Warn(fmt.Sprintf(
					"[频道列表] %d 条频道全部不在端口表的开放范围内，已放弃过滤（请检查端口表映射口径）",
					dropped))
			} else if dropped > 0 {
				a.logger.Info(fmt.Sprintf(
					"[频道列表] 已隐藏 %d 个已关闭端口的频道，保留 %d 个", dropped, kept))
			}
			if rewritten != nil && len(rewritten) > 0 {
				// 输出重写后的帧头 + body
				header := make([]byte, channelFrameHeaderSize)
				copy(header, frame[:channelFrameHeaderSize])
				binary.LittleEndian.PutUint32(header[2:6], uint32(channelFrameHeaderSize+len(rewritten)))
				dst.Write(header)
				dst.Write(rewritten)
			} else {
				// 重写失败：原样转发
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

// ChannelListRewriter 频道列表端口重写器。
type ChannelListRewriter struct {
	timezoneOffset int
}

func NewChannelListRewriter(timezoneOffset int) *ChannelListRewriter {
	return &ChannelListRewriter{timezoneOffset: timezoneOffset}
}

// currentKey 返回当天有效的频道列表密钥。
//
// 密钥日期口径统一由 pkg/security 提供（含时区偏移处理），
// 本包不再自行格式化日期，避免两处实现在跨零点/跨时区时行为漂移。
func (r *ChannelListRewriter) currentKey() string {
	return security.ChannelKey(r.timezoneOffset)
}

// previousDayKey 返回昨天的频道列表密钥，用于跨零点回退。
func (r *ChannelListRewriter) previousDayKey() string {
	return security.ChannelKeyPreviousDay(r.timezoneOffset)
}

// RewriteChannelInfoWithFallback 重写频道列表：改写 IP/端口，并剔除已关闭端口的频道。
//
// 返回可直接下发的密文；kept/dropped 供调用方做审计日志。
// body 无法解密时原样返回（kept=dropped=0）。
func (r *ChannelListRewriter) RewriteChannelInfoWithFallback(
	body []byte,
	publicIP string,
	view *portView,
) ([]byte, int, int) {
	plaintext, key, ok := r.decryptAny(body)
	if !ok {
		// 解密失败，原样返回
		return body, 0, 0
	}

	rewritten, kept, dropped := rewritePlaintextAndFilter(plaintext, publicIP, view)
	if kept == 0 && dropped > 0 {
		// 安全阀：一条都没命中，说明端口表与频道列表口径对不上
		// （例如全部被写成同端口转发）。宁可不改，也不能让所有频道凭空消失。
		return body, 0, dropped
	}
	if dropped == 0 && bytes.Equal(plaintext, rewritten) {
		// 与原文一致，省掉一次压缩 + 加密
		return body, kept, 0
	}
	return r.encrypt(rewritten, key), kept, dropped
}

// decryptAny 依次尝试当天、昨天的频道列表密钥，返回明文与命中的密钥。
func (r *ChannelListRewriter) decryptAny(data []byte) ([]byte, string, bool) {
	current := r.currentKey()
	if plaintext, err := r.decrypt(data, current); err == nil && isValidChannelList(plaintext) {
		return plaintext, current, true
	}
	previous := r.previousDayKey()
	if plaintext, err := r.decrypt(data, previous); err == nil && isValidChannelList(plaintext) {
		return plaintext, previous, true
	}
	return nil, "", false
}

func (r *ChannelListRewriter) decrypt(data []byte, key string) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	// 检查 zlib 头 (0x78 0x9C)
	if len(data) > 1 && data[0] == 0x78 {
		var err error
		data, err = zlibDecompress(data)
		if err != nil {
			return nil, err
		}
	}
	return aes128DecryptECB(data, getKeyBytes(key))
}

func (r *ChannelListRewriter) encrypt(data []byte, key string) []byte {
	padded := padTo16(data)
	encrypted, err := aes128EncryptECB(padded, getKeyBytes(key))
	if err != nil {
		return data
	}
	return zlibCompress(encrypted)
}

func getKeyBytes(key string) []byte {
	keyBytes := make([]byte, 16)
	src := []byte(key)
	copy(keyBytes, src[:len(src)])
	if len(src) < 16 {
		copy(keyBytes, src)
	}
	return keyBytes
}

func isValidChannelList(plaintext []byte) bool {
	if len(plaintext) < 6 {
		return false
	}
	count := int(binary.LittleEndian.Uint32(plaintext[2:6]))
	if count < 0 {
		return false
	}
	expected := padTo16Len(6 + count*48)
	return len(plaintext) == expected
}

// rewritePlaintextAndFilter 单遍完成两件事：
//  1. 剔除"所在端口已关闭"的频道条目（回传 kept/dropped 供审计）；
//  2. 把保留条目的 IP 改写为公网 IP、端口改写为公网端口。
//
// 过滤口径与 ReloadPorts 的开监听口径严格一致：条目端口（服务端填的是后端监听
// 端口，如 10011）在端口表里存在一条 Enabled=true 的映射（如 20011:10011），
// 才算"这个频道可进"。端口被停用 / 被删除 / 从未纳管时，网关都不会为它开监听，
// 客户端连上去必然失败（connection refused），因此直接从列表里移除，
// 玩家在选频道界面既看不到、也选不到它。
//
// 安全性依据：服务端并不靠条目下标决定频道号，而是由连接落在哪个监听端口推导
// （见 DfoServer CharacterSelectHandler / GameNetworkConfig.ResolveGameChannel），
// 所以移除条目导致的列表下标平移不会造成"选 A 频道进 B 频道"。
func rewritePlaintextAndFilter(plaintext []byte, publicIP string, view *portView) ([]byte, int, int) {
	if len(plaintext) < channelListPrefixSize {
		return plaintext, 0, 0
	}
	count := int(binary.LittleEndian.Uint32(plaintext[2:channelListPrefixSize]))
	if count <= 0 {
		return plaintext, 0, 0
	}

	keep := make([]bool, count)
	kept := 0
	for i := 0; i < count; i++ {
		off := channelListPrefixSize + i*channelListEntrySize
		if off+channelListEntrySize > len(plaintext) {
			break
		}
		backendPort := int(binary.LittleEndian.Uint32(
			plaintext[off+channelListPortOffset : off+channelListPortOffset+4]))
		if _, ok := view.publicFor(backendPort); !ok {
			continue
		}
		keep[i] = true
		kept++
	}

	dropped := count - kept
	if kept == 0 {
		// 全部被过滤：交由调用方走安全阀
		return plaintext, 0, dropped
	}

	out := make([]byte, channelListPrefixSize+kept*channelListEntrySize)
	copy(out[0:2], plaintext[0:2]) // 组号原样保留
	binary.LittleEndian.PutUint32(out[2:channelListPrefixSize], uint32(kept))

	ipBytes := []byte(publicIP)
	if len(ipBytes) > 16 {
		ipBytes = ipBytes[:16]
	}

	dst := channelListPrefixSize
	for i := 0; i < count; i++ {
		if !keep[i] {
			continue
		}
		src := channelListPrefixSize + i*channelListEntrySize
		copy(out[dst:dst+channelListEntrySize], plaintext[src:src+channelListEntrySize])

		// 重写 IP
		ipOff := dst + channelListIPOffset
		clear(out[ipOff : ipOff+16])
		if len(ipBytes) > 0 {
			copy(out[ipOff:ipOff+len(ipBytes)], ipBytes)
		}

		// 重写端口（后端 -> 公网）
		backendPort := int(binary.LittleEndian.Uint32(
			plaintext[src+channelListPortOffset : src+channelListPortOffset+4]))
		if pub, ok := view.publicFor(backendPort); ok {
			binary.LittleEndian.PutUint32(out[dst+channelListPortOffset:], uint32(pub))
		}

		dst += channelListEntrySize
	}

	return out, kept, dropped
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func padTo16Len(length int) int {
	return length + (16-length%16)%16
}
