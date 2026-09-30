package proxy

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"s4a21-gateway/pkg/security"
)

// 活体验收：对比"直连游戏服务端频道端口"与"经网关频道代理"拿到的频道列表，
// 验证网关确实改了 IP/端口、并把已关闭端口的频道剔除了。
//
// 需要真机，默认跳过。用法：
//
//	S4A21_LIVE_HOST=192.168.1.202 go test ./pkg/proxy/ -run LiveChannelList -v
//
// 环境变量：
//
//	S4A21_LIVE_HOST       必填，网关/服务端所在 IP（不填则跳过）
//	S4A21_LIVE_TCP_PORT   网关登录端口，默认 8000
//	S4A21_LIVE_PROXY_PORT 网关频道代理端口，默认 8001
//	S4A21_LIVE_BACKEND_CH 服务端频道端口，默认 7001
//	S4A21_LIVE_TZ_OFFSET  频道列表密钥时区偏移小时，默认 8（与客户端日期对齐）
func TestLiveChannelListRewrittenAndFiltered(t *testing.T) {
	host := os.Getenv("S4A21_LIVE_HOST")
	if host == "" {
		t.Skip("未设置 S4A21_LIVE_HOST，跳过活体验收")
	}
	tcpPort := envInt("S4A21_LIVE_TCP_PORT", 8000)
	proxyPort := envInt("S4A21_LIVE_PROXY_PORT", 8001)
	backendCh := envInt("S4A21_LIVE_BACKEND_CH", 7001)
	tzOffset := envInt("S4A21_LIVE_TZ_OFFSET", 8)

	// 1) 直连服务端频道端口：拿"未改写"的原始列表
	//    服务端也是"收到请求包才回"，所以同样要先发一个 CS_ASK_CHANNEL_INFO_NEW 帧
	raw, err := fetchChannelList(host, backendCh, tzOffset, 11)
	if err != nil {
		t.Fatalf("直连服务端 %d 取频道列表失败: %v", backendCh, err)
	}
	t.Logf("原始列表 %d 条:", len(raw))
	for _, e := range raw {
		t.Logf("    %-10s cap=%-4d ip=%-16s port=%d", e.Name, e.Capacity, e.IP, e.Port)
	}

	// 2) 登录拿会话（频道代理按 IP 放行，必须有会话）
	account := fmt.Sprintf("livetest%d", time.Now().UnixNano()%1_000_000_000)
	pwdMD5 := "5f4dcc3b5aa765d61d8327deb882cf99" // md5("password")
	if _, err := tcpJSON(host, tcpPort, map[string]interface{}{
		"cmd": "CMD_REGISTER", "account": account,
		"password_md5": pwdMD5, "launcher_version": "2.0.0",
	}); err != nil {
		t.Logf("注册（可能已存在，忽略）: %v", err)
	}
	login, err := tcpJSON(host, tcpPort, map[string]interface{}{
		"cmd": "CMD_LOGIN", "account": account,
		"password_md5": pwdMD5, "launcher_version": "2.0.0",
	})
	if err != nil {
		t.Fatalf("登录失败（频道代理需要会话）: %v", err)
	}
	if ok, _ := login["ok"].(bool); !ok {
		t.Fatalf("登录未成功: %v", login)
	}

	// 3) 经网关频道代理取列表（走真实下发路径：解密 -> 过滤 -> 改写 -> 再加密）
	//    首包必须来自已登录 IP，这里传一个最小合法帧即可（服务端不解析请求体）
	proxied, err := fetchChannelList(host, proxyPort, tzOffset, 11)
	if err != nil {
		t.Fatalf("经网关 %d 取频道列表失败: %v", proxyPort, err)
	}
	t.Logf("经网关列表 %d 条:", len(proxied))
	for _, e := range proxied {
		t.Logf("    %-10s cap=%-4d ip=%-16s port=%d", e.Name, e.Capacity, e.IP, e.Port)
	}

	if len(raw) == 0 {
		t.Fatal("原始列表为空，无法比对")
	}

	// 4) 频道名不会被改写，所以用名字判定"哪些频道被剔除了"
	proxiedNames := map[string]bool{}
	for _, e := range proxied {
		proxiedNames[e.Name] = true
	}
	hiddenNames := make([]string, 0)
	for _, e := range raw {
		if !proxiedNames[e.Name] {
			hiddenNames = append(hiddenNames, e.Name)
		}
	}
	t.Logf("被隐藏的频道: %v", hiddenNames)

	if len(proxied) > len(raw) {
		t.Fatalf("经网关的条目数不该多于原始: %d > %d", len(proxied), len(raw))
	}

	// 5) IP 必须已改写为网关对外 IP
	for _, e := range proxied {
		if e.IP != host {
			t.Errorf("频道 %s 的 IP 未改写为网关 IP: %q", e.Name, e.IP)
		}
	}

	// 6) 端口必须改写成公网端口；关闭端口的频道必须消失。
	//    给了管理密钥就按真实端口表精确比对，否则退化为区间校验。
	adminKey := os.Getenv("S4A21_LIVE_ADMIN_KEY")
	if adminKey != "" {
		enabled, disabled := fetchPortTable(t, host, adminKey)
		t.Logf("端口表：启用 %d 条，停用 %d 条 %v", len(enabled), len(disabled), disabled)

		rawPortByName := map[string]int{}
		wantKept := map[string]int{} // 频道名 -> 期望的公网端口
		wantHidden := map[string]bool{}
		for _, e := range raw {
			rawPortByName[e.Name] = e.Port
			if pub, ok := enabled[e.Port]; ok {
				wantKept[e.Name] = pub
			} else {
				wantHidden[e.Name] = true
			}
		}

		gotHidden := map[string]bool{}
		for _, n := range hiddenNames {
			gotHidden[n] = true
		}
		if !sameNameSet(wantHidden, gotHidden) {
			t.Errorf("被隐藏的频道不符\n  期望 %v\n  实际 %v", keysOfNames(wantHidden), keysOfNames(gotHidden))
		}

		for _, e := range proxied {
			want, ok := wantKept[e.Name]
			if !ok {
				t.Errorf("频道 %s 不该保留（其端口未开放或不在端口表里）", e.Name)
				continue
			}
			if e.Port != want {
				t.Errorf("频道 %s 端口应为 %d，实际 %d（原始 %d）",
					e.Name, want, e.Port, rawPortByName[e.Name])
			}
		}
		if len(wantHidden) == 0 {
			t.Log("（当前端口表里没有停用端口，隐藏集为空属正常）")
		}
	} else {
		t.Log("未提供 S4A21_LIVE_ADMIN_KEY，退化为区间校验（公网端口应在 20001-20201）")
		for _, e := range proxied {
			if e.Port < 20001 || e.Port > 20201 {
				t.Errorf("频道 %s 的端口 %d 未被改写为公网端口", e.Name, e.Port)
			}
		}
		if len(hiddenNames) == 0 {
			t.Error("没有任何频道被隐藏：改写很可能没生效（频道列表仍是服务端自报的端口）")
		}
	}
}

// fetchPortTable 取管理后台的端口表，返回 后端端口->公网端口 与 停用的公网端口集合。
func fetchPortTable(t *testing.T, host, adminKey string) (map[int]int, map[int]bool) {
	t.Helper()
	req, err := http.NewRequest("GET", "http://"+net.JoinHostPort(host, "8443")+"/api/admin/game-ports", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("X-Auth-Key", adminKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("读端口表失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("读端口表失败: HTTP %d", resp.StatusCode)
	}

	var body struct {
		Entries []struct {
			PublicPort  int  `json:"public_port"`
			BackendPort int  `json:"backend_port"`
			Enabled     bool `json:"enabled"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("解析端口表失败: %v", err)
	}

	enabled := map[int]int{}
	disabled := map[int]bool{}
	for _, e := range body.Entries {
		if e.Enabled {
			enabled[e.BackendPort] = e.PublicPort
		} else {
			disabled[e.PublicPort] = true
		}
	}
	return enabled, disabled
}

func sameNameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keysOfNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// channelEntry 解密后的频道列表条目。
type channelEntry struct {
	Name     string
	Capacity int
	IP       string
	Port     int
}

// fetchChannelList 连接指定端口取频道列表并解密。
//
// 传 0 表示直连服务端（无需首包）；传非 0 表示经网关频道代理，需要先发首包
// （长度 = firstPacketLen，按 11B 频道包头构造 CS_ASK_CHANNEL_INFO_NEW）。
func fetchChannelList(host string, port int, tzOffset int, firstPacketLen int) ([]channelEntry, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if firstPacketLen > 0 {
		// 11B 包头：classification=0x7C, msg_no=0x11, sLength=头长, check_sum=0, ack=1
		frame := make([]byte, firstPacketLen)
		frame[0] = 0x7C
		frame[1] = 0x11
		binary.LittleEndian.PutUint32(frame[2:6], uint32(firstPacketLen))
		frame[10] = 1
		if _, err := conn.Write(frame); err != nil {
			return nil, err
		}
	}

	rewriter := NewChannelListRewriter(tzOffset)
	deadline := time.Now().Add(8 * time.Second)
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 16*1024)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if body, ok := extractChannelListFrame(buf); ok {
				plain, key, ok := decryptAnyWith(rewriter, body)
				if !ok {
					return nil, fmt.Errorf("拿到 0x12 帧但解密失败（key=%q，body=%d 字节，前 24B=% x，流前 24B=% x）",
						key, len(body), body[:min(len(body), 24)], buf[:min(len(buf), 24)])
				}
				return parseChannelEntries(plain), nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if len(buf) == 0 {
				return nil, err
			}
			break
		}
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("未收到任何数据")
	}
	return nil, fmt.Errorf("未收到 0x12 频道列表帧，收到 %d 字节: % x", len(buf), buf[:min(len(buf), 64)])
}

// extractChannelListFrame 从流里切出一个完整的 0x12 帧的 body。
func extractChannelListFrame(buf []byte) ([]byte, bool) {
	offset := 0
	for offset+channelHeaderSize <= len(buf) {
		length := int(binary.LittleEndian.Uint32(buf[offset+2 : offset+6]))
		if length < channelHeaderSize || length > maxFrameSize {
			return nil, false
		}
		if len(buf)-offset < length {
			return nil, false
		}
		if buf[offset+1] == scAskChannelInfoNew {
			return buf[offset+channelHeaderSize : offset+length], true
		}
		offset += length
	}
	return nil, false
}

// decryptAnyWith 复用网关自己的解密逻辑（当天/昨天密钥）。
func decryptAnyWith(r *ChannelListRewriter, body []byte) ([]byte, string, bool) {
	return r.decryptAny(body)
}

func parseChannelEntries(plain []byte) []channelEntry {
	count := int(binary.LittleEndian.Uint32(plain[2:channelListPrefixSize]))
	entries := make([]channelEntry, 0, count)
	for i := 0; i < count; i++ {
		off := channelListPrefixSize + i*channelListEntrySize
		if off+channelListEntrySize > len(plain) {
			break
		}
		name := plain[off : off+20]
		end := 0
		for end < len(name) && name[end] != 0 {
			end++
		}
		ip := plain[off+channelListIPOffset : off+channelListIPOffset+16]
		ipEnd := 0
		for ipEnd < len(ip) && ip[ipEnd] != 0 {
			ipEnd++
		}
		entries = append(entries, channelEntry{
			Name:     string(name[:end]),
			Capacity: int(binary.LittleEndian.Uint32(plain[off+20 : off+24])),
			IP:       string(ip[:ipEnd]),
			Port:     int(binary.LittleEndian.Uint32(plain[off+channelListPortOffset : off+channelListPortOffset+4])),
		})
	}
	return entries
}

// tcpJSON 走网关登录端口（[4B 大端长度][UTF-8 JSON]）。
func tcpJSON(host string, port int, payload map[string]interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, uint32(len(raw)))
	if _, err := conn.Write(append(head, raw...)); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := readFull(conn, head); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(head))
	resp := make([]byte, n)
	if _, err := readFull(conn, resp); err != nil {
		return nil, err
	}
	var out map[string]interface{}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("响应不是 JSON: %w", err)
	}
	return out, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func envInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// 保证引用的包都被用到（ChannelKey 用于确认密钥口径与客户端一致）
var _ = security.ChannelKey
