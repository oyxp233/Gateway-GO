package proxy

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// 真机样本路径与对应密钥日期。
//
// 样本来自 192.168.1.202 服务端 7001 对 CS_ASK_CHANNEL_INFO_NEW 的真实应答
// （DfoServer ChannelProtocolHandler.HandleCS_ASK_CHANNEL_INFO_NEW）。
// 频道列表密钥是按服务端本地日期派生的，所以这里必须写死采集当天的密钥，
// 不能用"今天"去解昨天的样本。
const (
	realChannelListFixture = "channel_list_20260923.bin"
	realChannelListKey     = "20260923000006"
)

// TestRealServerChannelListFixture 用真机样本锁死压缩口径。
//
// 背景：网关原来的 zlibDecompress 用 zlib.NewReader 解 data[2:len-4]，
// 而服务端产出的是 [0x78 0x9C] + **裸 deflate** + adler32，于是必然
// "zlib: invalid header"。后果不是报错，而是静默回退原样下发 ——
// 频道列表改写（IP/端口重写 + 关闭端口频道隐藏）整体失效，
// 客户端拿到服务端自报的 10011 这类内网端口，直接绕开网关。
//
// 这条用例拿真机密文跑完整链路，口径一旦回退立刻失败。
func TestRealServerChannelListFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", realChannelListFixture))
	if err != nil {
		t.Skipf("无真机样本 %s: %v", realChannelListFixture, err)
	}

	// 1) 解压：必须走通服务端口径
	compressed, err := zlibDecompress(data)
	if err != nil {
		t.Fatalf("解压真机样本失败（压缩口径回退了？）: %v", err)
	}

	// 2) AES 解密
	plain, err := aes128DecryptECB(compressed, getKeyBytes(realChannelListKey))
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !isValidChannelList(plain) {
		t.Fatalf("解密结果不是合法频道列表: len=%d", len(plain))
	}

	raw := parseChannelEntries(plain)
	if len(raw) != 17 {
		t.Fatalf("样本应含 17 个频道，实际 %d", len(raw))
	}
	t.Logf("真机样本原始 %d 条: ", len(raw))
	for _, e := range raw {
		t.Logf("    %-10s cap=%-4d ip=%-16s port=%d", e.Name, e.Capacity, e.IP, e.Port)
	}

	// 3) 过滤 + 改写：口径对齐 202 现网端口表
	//    10001..10100 对应的公网端口启用；10200/10201（ch.200/ch.201）停用
	const disabledBackend1, disabledBackend2 = 10200, 10201
	mappings := make([]GamePortMapping, 0, len(raw))
	for _, e := range raw {
		mappings = append(mappings, GamePortMapping{
			Public:  e.Port + 10000, // 202 现网：公网 = 后端 + 10000
			Backend: e.Port,
			Enabled: e.Port != disabledBackend1 && e.Port != disabledBackend2,
		})
	}
	view := buildPortView(mappings)

	out, kept, dropped := rewritePlaintextAndFilter(plain, "10.0.0.1", view)
	if kept != 15 || dropped != 2 {
		t.Fatalf("应保留 15 条、隐藏 2 条，实际 kept=%d dropped=%d", kept, dropped)
	}

	count, ports, ips := parseTestChannelList(t, out)
	if count != 15 {
		t.Fatalf("过滤后条目数应为 15，实际 %d", count)
	}
	for i := range ports {
		if ports[i] < 20001 || ports[i] > 20100 {
			t.Errorf("第 %d 条端口未改写为公网端口: %d", i, ports[i])
		}
		if ips[i] != "10.0.0.1" {
			t.Errorf("第 %d 条 IP 未改写: %q", i, ips[i])
		}
	}
	// ch.200 / ch.201 必须消失
	for _, e := range parseChannelEntries(out) {
		if e.Name == "#ch.200" || e.Name == "#ch.201" {
			t.Errorf("已停用端口的频道不该出现在列表里: %s", e.Name)
		}
	}

	// 4) 再走一次完整链路（含重新加密），确保客户端拿到的一定是公网端口
	rewriter := NewChannelListRewriter(0)
	body := rewriter.encrypt(out, realChannelListKey)
	back, err := rewriter.decrypt(body, realChannelListKey)
	if err != nil {
		t.Fatalf("自产密文解不开（压缩口径不自洽）: %v", err)
	}
	if !isValidChannelList(back) {
		t.Fatalf("自产密文解出来不是合法列表: len=%d", len(back))
	}
	count2 := int(binary.LittleEndian.Uint32(back[2:channelListPrefixSize]))
	if count2 != 15 {
		t.Fatalf("自产密文条目数应为 15，实际 %d", count2)
	}
}
