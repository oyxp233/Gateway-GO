package proxy

import (
	"encoding/binary"
	"testing"
)

// buildS5A3FirstPacket 按服务端实测布局造一个 S5A3 登录首包：
// [header headerSizeB][body 602B]，其中 body+0 标记、body+1 容量、body+2 u32 长度 32、
// body+6 起 32 字符令牌。
func buildS5A3FirstPacket(headerSize int, token string) []byte {
	const bodyLen = 602
	buf := make([]byte, headerSize+bodyLen)
	body := buf[headerSize:]
	body[0] = 0x01
	body[1] = 0x30
	binary.LittleEndian.PutUint32(body[2:6], uint32(len(token)))
	copy(body[6:], token)
	return buf
}

func TestParseGameLoginTokenFindsS5A3Token(t *testing.T) {
	token := "de509f65a1b2c3d4e5f60718293a4b5c"
	// 三种 header 长度都要能认：S5A3 实测 13，网关旧口径 14，服务端逻辑 16。
	for _, headerSize := range []int{13, 14, 16} {
		buf := buildS5A3FirstPacket(headerSize, token)
		got, ok := parseGameLoginToken(buf)
		if !ok || got != token {
			t.Fatalf("headerSize=%d：应解析出 %q，实际 ok=%v got=%q", headerSize, token, ok, got)
		}
	}
}

func TestParseGameLoginTokenRejectsWrongPrefix(t *testing.T) {
	// 32 位 hex 但前缀不对 ⇒ 不是 S5A3 令牌，必须拒绝（否则可能误归属到别人会话）。
	buf := buildS5A3FirstPacket(13, "aabbccdda1b2c3d4e5f60718293a4b5c")
	if got, ok := parseGameLoginToken(buf); ok {
		t.Fatalf("前缀不符不该命中，实际返回 %q", got)
	}
}

func TestParseGameLoginTokenRejectsNonHex(t *testing.T) {
	buf := buildS5A3FirstPacket(13, "de509f65ZZZZZZZZZZZZZZZZZZZZZZZZ")
	if got, ok := parseGameLoginToken(buf); ok {
		t.Fatalf("非十六进制不该命中，实际返回 %q", got)
	}
}

func TestParseGameLoginTokenRejectsShortBuffer(t *testing.T) {
	buf := buildS5A3FirstPacket(13, "de509f65a1b2c3d4e5f60718293a4b5c")
	// 截到令牌只到一半（header 13 + body 前 6 字节头 + 20 字节令牌）⇒ 必须放弃解析，
	// 交给调用方兜底。注意不能只砍尾巴几字节：body 有 602 字节，砍 10 字节令牌仍然完整。
	if got, ok := parseGameLoginToken(buf[:13+6+20]); ok {
		t.Fatalf("缓冲区不完整不该命中，实际返回 %q", got)
	}
}

func TestParseGameLoginTokenUppercaseFolded(t *testing.T) {
	buf := buildS5A3FirstPacket(13, "DE509F65A1B2C3D4E5F60718293A4B5C")
	got, ok := parseGameLoginToken(buf)
	if !ok || got != "de509f65a1b2c3d4e5f60718293a4b5c" {
		t.Fatalf("大写应折成小写，实际 ok=%v got=%q", ok, got)
	}
}

// TestParseGameLoginTokenFallsBackToScan 覆盖 2026-11-06 补的兜底扫描。
//
// 现场：channel 28/192 的副连接在网关记成 `[归属=ip-unique]`，但服务端能正常
// 认出令牌（一次都没拒）。原因是网关只认固定 header 长度（13/14/16）+ body[6:38]，
// 头部长度一变就漏，而服务端有全文扫描兜底。这两个用例分别锁住两种漏法。
func TestParseGameLoginTokenFallsBackToScan(t *testing.T) {
	token := "de509f65a1b2c3d4e5f60718293a4b5c"

	t.Run("未知header长度", func(t *testing.T) {
		// 17 不在快路径的候选里，只能靠兜底扫描命中。
		buf := buildS5A3FirstPacket(17, token)
		got, ok := parseGameLoginToken(buf)
		if !ok || got != token {
			t.Fatalf("headerSize=17 应靠兜底命中 %q，实际 ok=%v got=%q", token, ok, got)
		}
	})

	t.Run("令牌不在body固定偏移", func(t *testing.T) {
		// body 头部正常但令牌整体后移 14 字节（模拟布局微调）。
		buf := buildS5A3FirstPacket(13, token)
		copy(buf[13+6:], make([]byte, 64))
		copy(buf[13+6+14:], token)
		got, ok := parseGameLoginToken(buf)
		if !ok || got != token {
			t.Fatalf("令牌偏移变化应靠兜底命中 %q，实际 ok=%v got=%q", token, ok, got)
		}
	})

	t.Run("兜底仍要求前缀", func(t *testing.T) {
		// 偏移变化 + 前缀不符 ⇒ 兜底也必须拒绝，避免误归属到别人会话。
		buf := buildS5A3FirstPacket(17, "aabbccdda1b2c3d4e5f60718293a4b5c")
		if got, ok := parseGameLoginToken(buf); ok {
			t.Fatalf("前缀不符不该被兜底命中，实际返回 %q", got)
		}
	})
}
