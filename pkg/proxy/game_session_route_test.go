package proxy

import (
	"encoding/binary"
	"testing"
)

// buildGameLoginFirstPacket 构造一条游戏连接首包：
// GamePacketHeader(14B, Pack=1) + i32(mIdLen) + mId + i32(pwdLen) + pwd。
func buildGameLoginFirstPacket(mId string) []byte {
	var l [4]byte
	body := make([]byte, 0, 4+len(mId)+4+8)
	binary.LittleEndian.PutUint32(l[:], uint32(len(mId)))
	body = append(body, l[:]...)
	body = append(body, mId...)
	binary.LittleEndian.PutUint32(l[:], 4)
	body = append(body, l[:]...)
	body = append(body, "hash"...)

	buf := make([]byte, gamePacketHeaderSize, gamePacketHeaderSize+len(body))
	buf[0] = 0x01                                             // cmd
	binary.LittleEndian.PutUint16(buf[1:], 0x1234)            // type
	binary.LittleEndian.PutUint32(buf[3:], uint32(len(body))) // length
	binary.LittleEndian.PutUint16(buf[11:], 1)                // seq
	buf[13] = 0                                               // extra
	return append(buf, body...)
}

// TestParseGameLoginMId 首包 m_id 解析：这是「双开同 IP 精确归属」的唯一依据，
// 解析必须严格 —— 宁可判失败让调用方回退按 IP，也不能解析出错误的 m_id。
func TestParseGameLoginMId(t *testing.T) {
	// 当前生成口径：纯数字
	if got, ok := parseGameLoginMId(buildGameLoginFirstPacket("10038")); !ok || got != "10038" {
		t.Fatalf("数字 m_id: got=%q ok=%v，期望 10038/true", got, ok)
	}

	// 存量账号名（原 .NET 网关口径：m_id 填账号名）
	if got, ok := parseGameLoginMId(buildGameLoginFirstPacket("msp")); !ok || got != "msp" {
		t.Fatalf("ASCII m_id: got=%q ok=%v，期望 msp/true", got, ok)
	}

	// 只有 header（首包被分包切碎）→ 必须失败，交给调用方回退
	if _, ok := parseGameLoginMId(make([]byte, gamePacketHeaderSize)); ok {
		t.Fatal("只有 header 时应判失败")
	}

	// header + 长度字段，但正文没到齐 → 失败
	full := buildGameLoginFirstPacket("10038")
	if _, ok := parseGameLoginMId(full[:gamePacketHeaderSize+4+2]); ok {
		t.Fatal("正文不齐时应判失败")
	}

	// 长度为 0 → 失败
	zero := buildGameLoginFirstPacket("10038")
	binary.LittleEndian.PutUint32(zero[gamePacketHeaderSize:], 0)
	if _, ok := parseGameLoginMId(zero); ok {
		t.Fatal("长度 0 时应判失败")
	}

	// 长度超上限（服务端 LoginRequestParser 也是 256）→ 失败
	tooBig := buildGameLoginFirstPacket("10038")
	binary.LittleEndian.PutUint32(tooBig[gamePacketHeaderSize:], 9999)
	if _, ok := parseGameLoginMId(tooBig); ok {
		t.Fatal("长度超限时应判失败")
	}

	// 空切片不能 panic
	if _, ok := parseGameLoginMId(nil); ok {
		t.Fatal("nil 输入应判失败")
	}
}
