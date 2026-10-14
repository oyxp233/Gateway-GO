package auth

import (
	"testing"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// 审查报告 G-7：Stop() 必须能立刻唤醒挂在读帧上的连接
//
// 现场：handleClient 里的 ReadFrame 是 io.ReadFull 裸阻塞读，close(shutdown)
// 唤不醒它。原先 Stop() 只关监听 + wg.Wait()，于是要等满 TcpIdleTimeoutSeconds
// （默认 600s），远超 systemd 的 TimeoutStopUSec ⇒ **每次发版都被 SIGKILL**
// （网关整体重启 = 全体在线玩家掉线）。
//
// ★ 区分力：把 Stop() 里遍历 s.conns 主动 Close 那段摘掉，本用例立刻变红
// —— Stop() 会一直耗到 idleTimeout（本用例设 8s，远大于 2s 的断言阈值）。
// ────────────────────────────────────────────────────────────────────────────

func TestStopDoesNotWaitForIdleTimeout(t *testing.T) {
	s := newTestAuthServer(t, 0)
	// 默认 600s 太长，回归时会把测试卡到超时；8s 足够出现"明显大于 2s"的红。
	s.idleTimeout = 8

	if err := s.Start(); err != nil {
		t.Fatalf("启动认证服务失败: %v", err)
	}

	// 连上但不发任何数据 ⇒ handleClient 阻塞在 ReadFrame 里
	hold := dialAndHold(t, s.config.Gateway.TcpPort)

	// 必须等它**确实**被登记进 conns，否则下面测的是"空集合上 Close 无害"，没有区分力
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.activeMu.Lock()
		n := len(s.conns)
		s.activeMu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.activeMu.Lock()
	registered := len(s.conns)
	s.activeMu.Unlock()
	if registered < 1 {
		t.Fatal("前提不成立：连接没有被登记进 s.conns，本用例测不到东西")
	}

	start := time.Now()
	s.Stop()
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("Stop() 耗时 %v —— 又在干等空闲超时了（ReadFrame 没被唤醒，审查 G-7）", elapsed)
	}

	// 连接必须是真的被服务端关掉，而不是 Stop 提前返回、连接还挂着
	if !isClosedByServer(t, hold, 800*time.Millisecond) {
		t.Fatal("Stop() 返回后客户端连接仍未被关闭 —— 只是不等待，并没有断开")
	}

	// conns 必须清空（handleClient 的 defer 里 delete），否则连接对象被 map 强引用
	s.activeMu.Lock()
	left := len(s.conns)
	s.activeMu.Unlock()
	if left != 0 {
		t.Fatalf("Stop() 后 s.conns 仍有 %d 条残留 —— defer 里漏了 delete", left)
	}
}
