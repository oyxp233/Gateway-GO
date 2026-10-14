package service

import (
	"sync"
	"time"
)

// onDemandBuildWait 是「等待同 key 的按需增量生成完成」的最长时长。
//
// 超过就返回 nil ⇒ 调用方回 404 ⇒ 登录器退回全量下载。宁可让个别玩家走一次
// 全量，也不把请求 goroutine 无限期挂在一次可能已卡死的重建上（G-10：原先
// 这条路径既无并发去重、也无超时）。
const onDemandBuildWait = 60 * time.Second

// keyedGroup 让「同一个 key 的并发调用」只真正执行一次，其余等待并共享结果。
//
// G-4 / G-10（2026-10-04 审查）：限流是按 IP 分桶的，**不同 IP 之间不共享** ——
// 一批同版本玩家同时上线会同时命中按需增量生成路径：
//   · 共写同一个临时文件（原先 `cache + ".tmp"`）：os.Create 截断 + 写入交错 ⇒ 产出损坏包；
//   · 同一份 75 MiB PVF 被 N 次全量重算（SHA-256 + 块索引），把网关 CPU/IO 打满。
//
// 这里把同 key 的并发合并成一次执行（singleflight 语义），并给等待设上限。
type keyedGroup struct {
	mu       sync.Mutex
	inflight map[string]*keyedCall
}

type keyedCall struct {
	done chan struct{}
	val  any
}

// do 执行 fn（key 的第一个调用者）或等待正在执行的调用（其余调用者）。
//
// 返回 (值, true)：拿到结果（可能是 fn 返回的 nil）。
// 返回 (nil, false)：等待超时，调用方应走降级路径。
func (g *keyedGroup) do(key string, wait time.Duration, fn func() any) (any, bool) {
	g.mu.Lock()
	if g.inflight == nil {
		g.inflight = make(map[string]*keyedCall)
	}
	if c, ok := g.inflight[key]; ok {
		g.mu.Unlock()
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-c.done:
			return c.val, true
		case <-timer.C:
			return nil, false
		}
	}
	c := &keyedCall{done: make(chan struct{})}
	g.inflight[key] = c
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.inflight, key)
		g.mu.Unlock()
		// close(done) 建立 happens-before：等待方 <-c.done 之后读 c.val 是安全的。
		close(c.done)
	}()
	c.val = fn()
	return c.val, true
}
