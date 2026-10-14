package service

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestKeyedGroupCoalescesSameKey 是 G-4 / G-10（2026-10-04 审查）的区分力测试。
//
// 场景：一批同版本玩家同时上线 ⇒ 同一个 from 的按需增量生成被并发触发。
// 修复前每个请求各自 os.Create 同一个 tmp 文件 + 各自全量重算；
// 修复后同 key 只让一个真去算，其余等待（并给等待设上限）。
//
// 确定性：先让 leader 进入 fn 并**卡住不放**，此时 inflight 里一定已登记；
// 再让 follower 走同 key（必然进入等待分支），用 100ms 上限超时返回。
// 全程无 race、无 sleep 猜测。
func TestKeyedGroupCoalescesSameKey(t *testing.T) {
	var g keyedGroup
	var calls int32

	leaderIn := make(chan struct{})
	unblock := make(chan struct{})
	leaderRes := make(chan any, 1)

	go func() {
		v, _ := g.do("k", 5*time.Second, func() any {
			atomic.AddInt32(&calls, 1)
			close(leaderIn)
			<-unblock
			return "shared"
		})
		leaderRes <- v
	}()
	<-leaderIn

	// follower：同 key、leader 未结束 ⇒ 不该执行 fn，只能等（这里等到超时）。
	v, ok := g.do("k", 100*time.Millisecond, func() any {
		atomic.AddInt32(&calls, 1)
		return "SHOULD-NOT-RUN"
	})
	if ok {
		t.Fatalf("leader 还在跑，follower 不该拿到结果，实得 %v", v)
	}
	if v != nil {
		t.Fatalf("等待超时应返回 nil，实得 %v", v)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("同 key 在飞行中不得重复执行 fn，实得 %d 次", n)
	}

	close(unblock)
	if got := <-leaderRes; got != "shared" {
		t.Fatalf("leader 结果应为 shared，实得 %v", got)
	}

	// 飞行结束后 inflight 必须已清理：同 key 可以重新执行（否则该 key 永久失效）。
	v2, ok2 := g.do("k", time.Second, func() any {
		atomic.AddInt32(&calls, 1)
		return "second"
	})
	if !ok2 || v2 != "second" {
		t.Fatalf("飞行结束后同 key 应能正常执行，实得 (%v, %v)", v2, ok2)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("结束后的新调用应执行 fn，累计应为 2，实得 %d", n)
	}
}

// TestKeyedGroupDifferentKeysDontBlock 证明合并只发生在**同一个 key** 内：
// 一个 key 的在飞调用绝不能挡住另一个 key。
func TestKeyedGroupDifferentKeysDontBlock(t *testing.T) {
	var g keyedGroup
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		g.do("a", 5*time.Second, func() any { close(started); <-release; return 1 })
	}()
	<-started

	done := make(chan any, 1)
	go func() {
		v, _ := g.do("b", 5*time.Second, func() any { return 2 })
		done <- v
	}()
	select {
	case v := <-done:
		if v != 2 {
			t.Fatalf("不同 key 的结果应为 2，实得 %v", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("不同 key 被另一个 key 的在飞调用挡住了")
	}
	close(release)
}
