package safego

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// 审查 G-1：TCP 认证与游戏代理的连接处理 goroutine 是**裸跑**的 ——
// 任何一个 panic 都会打挂整个网关进程（= 全体在线玩家掉线）。
// 本文件把「panic 被吞掉且被记录」变成机器可判的断言。

type fakeLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (f *fakeLogger) Error(msg string) {
	f.mu.Lock()
	f.msgs = append(f.msgs, msg)
	f.mu.Unlock()
}

func (f *fakeLogger) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.msgs...)
}

// TestGoRecoversPanic 证明 panic 的 goroutine 不会拖垮进程，且带定位信息落日志。
//
// ★ 区分力：把 safego.Go 里的 recover 去掉（换回裸 `go fn()`），
// 本用例会让整个测试二进制**崩溃**（panic 无人接管）—— 那正是 G-1 的生产形态。
func TestGoRecoversPanic(t *testing.T) {
	lg := &fakeLogger{}
	done := make(chan struct{})
	Go(lg, "test.boom", func() {
		defer close(done)
		panic("boom")
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine 未执行完")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(lg.snapshot()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	msgs := lg.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("期望 1 条 panic 日志，实际 %d 条：%v", len(msgs), msgs)
	}
	if !strings.Contains(msgs[0], "test.boom") || !strings.Contains(msgs[0], "boom") {
		t.Fatalf("日志未包含定位信息：%q", msgs[0])
	}
	if !strings.Contains(msgs[0], "goroutine") {
		t.Fatalf("日志未包含调用栈：%q", msgs[0])
	}
}

// TestGoRunsNormally 正常路径：fn 照常跑完，不留任何日志。
func TestGoRunsNormally(t *testing.T) {
	lg := &fakeLogger{}
	done := make(chan int, 1)
	Go(lg, "test.ok", func() { done <- 42 })

	select {
	case v := <-done:
		if v != 42 {
			t.Fatalf("fn 执行结果异常：%d", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine 未执行")
	}
	time.Sleep(50 * time.Millisecond)
	if msgs := lg.snapshot(); len(msgs) != 0 {
		t.Fatalf("正常路径不应产生日志：%v", msgs)
	}
}

// TestGoNilLoggerDoesNotPanic 无 logger 时 panic 仍只被丢弃，不崩溃。
func TestGoNilLoggerDoesNotPanic(t *testing.T) {
	done := make(chan struct{})
	Go(nil, "test.nil-log", func() {
		defer close(done)
		panic("boom")
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine 未执行")
	}
	time.Sleep(50 * time.Millisecond)
}
