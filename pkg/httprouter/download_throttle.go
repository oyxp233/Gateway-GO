package httprouter

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 下载通道限速（2026-11-16）
//
// 背景：90CN 服务器上行只有 12MB/s。PVF 增量 / 登录器自更新 / DNF.exe / 插件
// 四条下载链路原先都是裸 ServeFile，没有任何速率或并发约束 —— 一次发版几十个玩家
// 同时重下，上行瞬间打满，正在游戏里的玩家直接卡顿；后进来更新的人又互相拖慢，
// 形成"越更新越卡、越卡越多人重试"的正反馈。
//
// 三道闸，缺一不可：
//
//	① 全局限速：所有下载共用一个发送时间轴，总出口不超过 N MB/s
//	   （默认 8MB/s = 12MB/s 上行的 2/3，给游戏与 API 留 1/3 余量）
//	② 单 IP 限速：一个玩家最多 N MB/s（默认 2MB/s）
//	   —— 客户端新版自己也会限速，但老版本不会；这里是兜底
//	③ 并发闸门：同时最多 N 路下载（默认 8），超出的排队等待而不是立刻拒绝
//	   —— 立刻 503 会让老客户端（没有重试逻辑）直接更新失败
//
// 实现要点：
//   - 用"预留时间片"而不是固定 sleep：每个连接在写入前先向全局时间轴预约
//     n/rate 秒，等到自己的时间片再写 ⇒ 多连接并发时总速率仍然收敛到 rate；
//   - 包一层 ResponseWriter 后**不再实现 io.ReaderFrom**，所以 ServeFile 内部的
//     io.Copy 会老老实实走 Write（如果实现了 ReadFrom，io.Copy 会绕过限速）；
//   - 慢客户端不会永久拖累别人：等待量是「时间片开始 - 现在」，慢连接阻塞期间
//     真实时间在前进，积压会自然被吃掉。
//
// 参数（环境变量，改完重启网关生效；不配则用默认值）：
//
//	S5A3_DL_RATE_MBPS=8        全局限速
//	S5A3_DL_PER_IP_MBPS=2      单 IP 限速（0 = 不限）
//	S5A3_DL_CONCURRENCY=8      并发下载路数
//	S5A3_DL_GATE_WAIT_SECONDS=45   排队等待上限，超时才 503
//
// 一键关掉：S5A3_DL_RATE_MBPS=0（= 关闭限速与并发闸门，回到原行为）。
// ============================================================================

const (
	defaultDownloadRateMBps    = 8
	defaultDownloadPerIPMBps   = 2
	defaultDownloadConcurrency = 8
	defaultDownloadGateWait    = 45 * time.Second
)

// rateAxis 是一条"发送时间轴"：reserve 返回调用方应该等待多久再写。
// 同一条 axis 上的所有调用共享同一个速率。
type rateAxis struct {
	mu   sync.Mutex
	next time.Time // 上一个预约者的时间片结束时刻
	last time.Time // 最近一次使用（给 IP 表做清理）
}

// reserve 预约 n 字节的发送时间片，返回"还要等多久才开始写"。
func (a *rateAxis) reserve(n int, rate int64) time.Duration {
	if rate <= 0 || n <= 0 {
		return 0
	}
	a.mu.Lock()
	now := time.Now()
	if a.next.Before(now) {
		a.next = now
	}
	// float 计算避免 n*1e9 溢出（n 最大约 128MB，int64 够，但 float 更稳）
	dur := time.Duration(float64(n) / float64(rate) * float64(time.Second))
	start := a.next
	a.next = start.Add(dur)
	a.last = now
	a.mu.Unlock()

	if wait := start.Sub(now); wait > 0 {
		return wait
	}
	return 0
}

// downloadLimiter 是下载通道的全局状态（每个 Server 一份）。
type downloadLimiter struct {
	global    rateAxis
	rate      int64 // 全局 bytes/sec；0 = 关闭限速
	perIPRate int64 // 单 IP bytes/sec；0 = 不限

	ipMu  sync.Mutex
	ips   map[string]*rateAxis
	calls int

	gate     chan struct{}
	gateWait time.Duration
}

// newDownloadLimiter 从环境变量读参数。任何非法/缺失值都退回默认值，
// 绝不让"配错了"变成"下载全挂"。
func newDownloadLimiter() *downloadLimiter {
	rateMBps := envInt("S5A3_DL_RATE_MBPS", defaultDownloadRateMBps)
	perIPMBps := envInt("S5A3_DL_PER_IP_MBPS", defaultDownloadPerIPMBps)
	conc := envInt("S5A3_DL_CONCURRENCY", defaultDownloadConcurrency)
	waitSec := envInt("S5A3_DL_GATE_WAIT_SECONDS", int(defaultDownloadGateWait/time.Second))

	if rateMBps < 0 {
		rateMBps = 0
	}
	if perIPMBps < 0 {
		perIPMBps = 0
	}
	if conc < 1 {
		conc = 1
	}
	if waitSec < 1 {
		waitSec = int(defaultDownloadGateWait / time.Second)
	}

	return &downloadLimiter{
		rate:      int64(rateMBps) << 20,
		perIPRate: int64(perIPMBps) << 20,
		ips:       make(map[string]*rateAxis),
		gate:      make(chan struct{}, conc),
		gateWait:  time.Duration(waitSec) * time.Second,
	}
}

func envInt(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Begin 为一次下载获取并发名额，并返回带限速的 ResponseWriter。
//
// ok=false 表示名额等待超时/请求已取消，调用方必须**直接 return**（响应已经写了）。
func (l *downloadLimiter) Begin(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func(), bool) {
	if l == nil || (l.rate <= 0 && l.perIPRate <= 0) {
		// 限速被运营关掉：不占名额、不包 writer，完全回到旧行为
		return w, func() {}, true
	}

	timer := time.NewTimer(l.gateWait)
	defer timer.Stop()
	select {
	case l.gate <- struct{}{}:
	case <-timer.C:
		w.Header().Set("Retry-After", "10")
		http.Error(w, "download busy, please retry later", http.StatusServiceUnavailable)
		return nil, nil, false
	case <-r.Context().Done():
		return nil, nil, false
	}

	ip := clientIP(r)
	return &throttledWriter{ResponseWriter: w, l: l, ip: ip}, func() { <-l.gate }, true
}

// wait 同时满足「全局」与「单 IP」两条时间轴（取更长的那个等待）。
func (l *downloadLimiter) wait(ip string, n int) {
	var d time.Duration
	if l.rate > 0 {
		d = l.global.reserve(n, l.rate)
	}
	if l.perIPRate > 0 && ip != "" {
		if d2 := l.ipAxis(ip).reserve(n, l.perIPRate); d2 > d {
			d = d2
		}
	}
	if d > 0 {
		time.Sleep(d)
	}
}

// ipAxis 取（或新建）某个 IP 的时间轴；顺带做低频清理，防止 map 无限增长。
func (l *downloadLimiter) ipAxis(ip string) *rateAxis {
	l.ipMu.Lock()
	defer l.ipMu.Unlock()

	l.calls++
	if l.calls%2048 == 0 {
		l.sweepLocked()
	}

	a := l.ips[ip]
	if a == nil {
		a = &rateAxis{}
		l.ips[ip] = a
	}
	return a
}

// sweepLocked 删掉 10 分钟没用过的 IP。
// 注意不能删"正在用"的：last 在 reserve 里每次刷新，10 分钟足够长。
func (l *downloadLimiter) sweepLocked() {
	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, a := range l.ips {
		a.mu.Lock()
		stale := a.last.Before(cutoff)
		a.mu.Unlock()
		if stale {
			delete(l.ips, ip)
		}
	}
}

// throttledWriter 在每次 Write 前按字节数等待，从而把上传速率压到设定值。
//
// ★ 刻意**不**实现 io.ReaderFrom / io.WriterTo：一旦实现了，http.ServeFile 内部的
// io.Copy 会直接调用 ReadFrom 把文件内容拷进内核，完全绕过这里的 Write。
type throttledWriter struct {
	http.ResponseWriter
	l  *downloadLimiter
	ip string
}

func (t *throttledWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		t.l.wait(t.ip, len(p))
	}
	return t.ResponseWriter.Write(p)
}

// Flush 透传（长连接/分块输出时需要；ServeFile 不依赖，但别让它坏掉）。
func (t *throttledWriter) Flush() {
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 让 http.ResponseController 之类的标准工具还能拿到底层 writer。
func (t *throttledWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// clientIP 的解析**复用** register_web.go 的 clientIPOf：
// 口径与注册链路完全一致（只对回环反代信任 X-Real-IP / X-Forwarded-For 最后一段），
// 不在这里另起一套 —— 两套 IP 口径迟早会漂移，而限速一旦按错 IP 分组，
// 表现就是「某个玩家莫名被限到 2MB/s」这种极难排查的线上问题。
func clientIP(r *http.Request) string {
	return clientIPOf(r)
}
