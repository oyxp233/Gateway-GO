package proxy

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"s4a21-gateway/pkg/security"
)

// serverFormatCompress 复刻服务端 EncryptTool.ZlibCompress 的产出口径：
//
//	[0x78][0x9C] + raw deflate(DeflateStream) + 4B adler32(BE)
//
// 注意与网关自己的 zlibCompress 不同：后者用 zlib.NewWriter，产出的是
// [0x78][0x9C] + 完整 zlib 流(自带 0x78 0x9C 头) + 4B adler32，即"双重头"。
func serverFormatCompress(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write([]byte{0x78, 0x9C})
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("建 deflate writer 失败: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("deflate 写入失败: %v", err)
	}
	w.Close()
	sum := adler32(plain)
	buf.Write([]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})
	return buf.Bytes()
}

// TestDiagServerZlibLayout 证明：服务端产出的压缩流，网关现有 zlibDecompress 解不开。
func TestDiagServerZlibLayout(t *testing.T) {
	plain := buildTestChannelList(t, []string{"#ch.11", "#ch.12"}, []int{10011, 10012}, "100.64.0.9")
	body := serverFormatCompress(t, plain)
	t.Logf("服务端口径压缩后 %d 字节，头=% x 尾=% x", len(body), body[:2], body[len(body)-4:])

	// A) 网关现网口径：跳过 2 字节头，交给 zlib.Reader（期望它是完整 zlib 流）
	rA, errA := zlib.NewReader(bytes.NewReader(body[2 : len(body)-4]))
	var outA []byte
	if errA == nil {
		outA, errA = io.ReadAll(rA)
		rA.Close()
	}
	t.Logf("A) 现网口径 zlib.NewReader(body[2:len-4]) -> err=%v len=%d", errA, len(outA))

	// C) 正确口径：raw deflate + 手工 adler32 校验（与服务端 ZlibDecompress 一致）
	rC := flate.NewReader(bytes.NewReader(body[2 : len(body)-4]))
	outC, errC := io.ReadAll(rC)
	rC.Close()
	stored := binary.BigEndian.Uint32(body[len(body)-4:])
	t.Logf("C) 正确口径 flate.NewReader(body[2:len-4]) -> err=%v len=%d 一致=%v adlerOK=%v",
		errC, len(outC), bytes.Equal(outC, plain), adler32(outC) == stored)

	if retryDecompress(body) == nil {
		return // 现网口径能解开就不算缺陷
	}
	if !bytes.Equal(outC, plain) {
		t.Fatalf("正确口径也没解开，服务端压缩格式需重新确认")
	}
}

// retryDecompress 用网关现有 zlib 路径解一次，返回 (是否成功, 结果)。
func retryDecompress(data []byte) []byte {
	got, err := zlibDecompress(data)
	if err != nil {
		return nil
	}
	return got
}

// TestDiagLiveChannelBody 对真机抓到的频道列表密文做口径诊断（需 S4A21_LIVE_HOST）。
func TestDiagLiveChannelBody(t *testing.T) {
	host := os.Getenv("S4A21_LIVE_HOST")
	if host == "" {
		t.Skip("未设置 S4A21_LIVE_HOST，跳过真机诊断")
	}
	backendCh := envInt("S4A21_LIVE_BACKEND_CH", 7001)

	body := fetchRawChannelBody(t, host, backendCh)
	t.Logf("抓到 0x12 body %d 字节，头=% x", len(body), body[:2])

	// 顺手把真机样本固化下来，供 TestRealServerChannelListFixture 做回归
	if os.Getenv("S4A21_LIVE_DUMP") != "" {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatalf("建 testdata 目录失败: %v", err)
		}
		name := "testdata/channel_list_" + time.Now().Format("20060102") + ".bin"
		if err := os.WriteFile(name, body, 0644); err != nil {
			t.Fatalf("写样本失败: %v", err)
		}
		t.Logf("已固化样本: %s（密钥日期 %s）", name, time.Now().Format("20060102"))
	}

	// 1) 现网口径
	viaZlib, errZlib := zlibDecompress(body)
	t.Logf("现网口径 zlibDecompress -> err=%v len=%d", errZlib, len(viaZlib))

	// 2) 正确口径
	r := flate.NewReader(bytes.NewReader(body[2 : len(body)-4]))
	viaFlate, errFlate := io.ReadAll(r)
	r.Close()
	stored := binary.BigEndian.Uint32(body[len(body)-4:])
	t.Logf("正确口径 flate+adler -> err=%v len=%d adlerOK=%v", errFlate, len(viaFlate), adler32(viaFlate) == stored)

	// 3) 再用正确的解压结果做 AES 解密，看能否得到合法频道列表
	key := security.ChannelKey(envInt("S4A21_LIVE_TZ_OFFSET", 8))
	plain, errAES := aes128DecryptECB(viaFlate, getKeyBytes(key))
	ok := errAES == nil && isValidChannelList(plain)
	t.Logf("AES(key=%s) -> err=%v 合法列表=%v", key, errAES, ok)
	if ok {
		count := int(binary.LittleEndian.Uint32(plain[2:channelListPrefixSize]))
		t.Logf("原始频道列表 %d 条:", count)
		for _, e := range parseChannelEntries(plain) {
			t.Logf("    %-10s cap=%-4d ip=%-16s port=%d", e.Name, e.Capacity, e.IP, e.Port)
		}
	}
	if !ok {
		t.Fatalf("即使按服务端口径解压也无法解出频道列表，需继续排查 AES/密钥")
	}
}

// fetchRawChannelBody 直连服务端频道端口，取 0x12 帧的原始 body（不解密）。
func fetchRawChannelBody(t *testing.T, host string, port int) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("连接 %s:%d 失败: %v", host, port, err)
	}
	defer conn.Close()

	frame := make([]byte, 11)
	frame[0] = 0x7C
	frame[1] = 0x11
	binary.LittleEndian.PutUint32(frame[2:6], 11)
	frame[10] = 1
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("发送请求失败: %v", err)
	}

	deadline := time.Now().Add(8 * time.Second)
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 16*1024)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if body, ok := extractChannelListFrame(buf); ok {
				return body
			}
		}
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				continue
			}
			break
		}
	}
	t.Fatalf("未取到 0x12 帧，收到 %d 字节", len(buf))
	return nil
}

var _ = strconv.Itoa
