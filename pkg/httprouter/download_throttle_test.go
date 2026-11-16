package httprouter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 2026-11-16：下载限速的三条判据。
//
// ★ 这些测试只钉「限速器本身」，不依赖网关其余状态 —— 一旦有人把
// throttledWriter 换成直接透传，或者误实现了 io.ReaderFrom，这里必须变红。

func newTestLimiter(rateMBps, perIPMBps int, concurrency int, gateWait time.Duration) *downloadLimiter {
	return &downloadLimiter{
		rate:      int64(rateMBps) << 20,
		perIPRate: int64(perIPMBps) << 20,
		ips:       make(map[string]*rateAxis),
		gate:      make(chan struct{}, concurrency),
		gateWait:  gateWait,
	}
}

func testReq(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://gw.example/api/launcher/update/exe", nil)
	r.RemoteAddr = ip + ":45678"
	return r
}

// 全局限速：1MB/s 写 256KB，至少要 ~190ms（首块不等，后 3 块各等 64ms）。
func TestThrottledWriterEnforcesGlobalRate(t *testing.T) {
	l := newTestLimiter(1, 0, 4, time.Second)
	rec := httptest.NewRecorder()
	w, release, ok := l.Begin(rec, testReq("203.0.113.7"))
	if !ok {
		t.Fatal("Begin 不该拒绝")
	}
	defer release()

	chunk := make([]byte, 64<<10)
	start := time.Now()
	for i := 0; i < 4; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	elapsed := time.Since(start)

	if elapsed < 150*time.Millisecond {
		t.Fatalf("限速未生效：256KB@1MB/s 只用了 %v", elapsed)
	}
	if rec.Body.Len() != 256<<10 {
		t.Fatalf("字节数被改动：%d", rec.Body.Len())
	}
}

// 关掉限速（rate=0 且 perIP=0）必须完全回到旧行为：不占名额、不等待。
func TestLimiterDisabledIsPassThrough(t *testing.T) {
	l := newTestLimiter(0, 0, 1, time.Second)
	rec := httptest.NewRecorder()
	w, release, ok := l.Begin(rec, testReq("203.0.113.8"))
	if !ok {
		t.Fatal("关闭状态下 Begin 必须放行")
	}
	defer release()

	chunk := make([]byte, 256<<10)
	start := time.Now()
	if _, err := w.Write(chunk); err != nil {
		t.Fatalf("write: %v", err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("关闭限速后仍被拖慢：%v", d)
	}
	if _, isThrottled := w.(*throttledWriter); isThrottled {
		t.Fatal("关闭状态下不该包 throttledWriter")
	}
}

// 并发闸门：占满 1 个名额后，第二个请求等满 gateWait 必须返回 false（= 已写 503）。
// ★ 不能改成"立刻拒绝"——老客户端没有重试逻辑，秒拒等于更新失败。
func TestConcurrencyGateWaitsThenRefuses(t *testing.T) {
	// rate=1 让限速器处于「启用」状态（rate=0 且 perIP=0 是一键关闭，连闸门一起关）
	l := newTestLimiter(1, 0, 1, 80*time.Millisecond)

	_, release1, ok1 := l.Begin(httptest.NewRecorder(), testReq("203.0.113.9"))
	if !ok1 {
		t.Fatal("第一个请求应拿到名额")
	}

	rec2 := httptest.NewRecorder()
	start := time.Now()
	_, _, ok2 := l.Begin(rec2, testReq("203.0.113.10"))
	waited := time.Since(start)

	if ok2 {
		t.Fatal("名额已满却放行了第二个请求")
	}
	if waited < 60*time.Millisecond {
		t.Fatalf("没有排队等待就直接拒绝：%v", waited)
	}
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("应回 503，实际 %d", rec2.Code)
	}
	if got := rec2.Header().Get("Retry-After"); got == "" {
		t.Fatal("503 应带 Retry-After")
	}

	release1()

	// 释放后必须能再次拿到名额
	_, release3, ok3 := l.Begin(httptest.NewRecorder(), testReq("203.0.113.11"))
	if !ok3 {
		t.Fatal("释放名额后应可再次获取")
	}
	release3()
}

// 单 IP 限速：同一 IP 两个连接的写入共享一条时间轴，总速率仍受 perIP 约束。
func TestPerIPRateSharedAcrossConnections(t *testing.T) {
	l := newTestLimiter(0, 1, 8, time.Second) // 只开单 IP 限速 1MB/s
	ip := "198.51.100.23"
	r1 := testReq(ip)
	r2 := testReq(ip)

	w1, rel1, _ := l.Begin(httptest.NewRecorder(), r1)
	w2, rel2, _ := l.Begin(httptest.NewRecorder(), r2)
	defer rel1()
	defer rel2()

	chunk := make([]byte, 64<<10)
	start := time.Now()
	for i := 0; i < 2; i++ {
		w1.Write(chunk)
	}
	for i := 0; i < 2; i++ {
		w2.Write(chunk)
	}
	// 4 × 64KB @1MB/s ≈ 192ms 的排队（首块不等）
	if d := time.Since(start); d < 120*time.Millisecond {
		t.Fatalf("同 IP 的连接没有共享限速：%v", d)
	}
}

// clientIP 的转发头信任口径直接复用 clientIPOf（register_web.go），
// 已由 TestClientIPOfTrustsForwardedHeadersOnlyFromLoopback 覆盖，这里只钉住"确实是同一口径"。
func TestClientIPDelegatesToClientIPOf(t *testing.T) {
	for _, remote := range []string{"203.0.113.50:1234", "127.0.0.1:1234", "10.1.2.3:9999"} {
		r := testReq(strings.TrimSuffix(remote, ":1234"))
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		if got, want := clientIP(r), clientIPOf(r); got != want {
			t.Fatalf("remote=%s: clientIP=%s 与 clientIPOf=%s 口径不一致", remote, got, want)
		}
	}
}
