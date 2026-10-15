package session

import (
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// 心跳超时的语义边界（2026-10-14 掉线事故的量化）
//
// 背景：登录器心跳周期 30s，网关超时 60s ⇒ 冗余只有 1 拍（60/30 = 2.0）。
// 判据是**严格**不等式 `LastHeartbeat < now - timeout`，且时间戳按整数秒落章。
//
//   · 漏 1 拍（间隔 60s）：整数秒给了约 1s 余量 ⇒ 正常下**不掉线**；
//   · 漏 2 拍（间隔 90s）：60~90 之间必有巡检 tick 命中 ⇒ **必掉线**。
//
// 这组用例锁死"把超时从 60 提到 120 能救回什么"：
// 停滞 90s 的会话在 60s 下被清（= 玩家在游戏里被踢），在 120s 下幸存。
// 换句话说，120 = 容忍丢 3 拍，正好覆盖"玩家侧链路整段抖一下"的场景。
//
// 断言口径刻意避开精确边界（不用 stale == timeout），否则两次 time.Now()
// 之间跨一秒会让用例变成 flaky —— 那会把真回归淹没在噪声里。
// ─────────────────────────────────────────────────────────────────────────────

func TestCleanExpiredSessions_TimeoutBoundary(t *testing.T) {
	cases := []struct {
		name     string
		staleSec int64 // 心跳停滞了多少秒
		timeout  int   // 网关超时（CleanExpiredSessions 的参数）
		want     int   // 期望被清掉的会话数
	}{
		{"停滞 90s @ 超时 60s → 被清（丢 2 拍即死）", 90, 60, 1},
		{"停滞 90s @ 超时 120s → 幸存（容忍丢 3 拍）", 90, 120, 0},
		{"停滞 40s @ 超时 60s → 幸存", 40, 60, 0},
		{"停滞 60s @ 超时 120s → 幸存", 60, 120, 0},
		{"停滞 150s @ 超时 120s → 被清", 150, 120, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sm := NewSessionManager(nil, nil)
			sess := newTestSession(t, sm, "hb_boundary")

			// 把心跳时间推到 N 秒前 —— CleanExpiredSessions 的判据就是 time.Now()。
			sm.mu.Lock()
			sess.LastHeartbeat = time.Now().Unix() - c.staleSec
			sm.mu.Unlock()

			if got := sm.CleanExpiredSessions(c.timeout); got != c.want {
				t.Fatalf("停滞 %ds、超时 %ds 下应清 %d 个，实际 %d 个",
					c.staleSec, c.timeout, c.want, got)
			}
		})
	}
}

// 反向断言：同一份会话表，同一批停滞值，只把超时从 60 提到 120 ——
// 清理数必须从 1 变 0。这条把"改超时确实能救回丢 2 拍的会话"钉死，
// 且证明了 120 与 60 之间存在**可观测差异**（否则这个配置项调了等于没调）。
func TestCleanExpiredSessions_RaisingTimeoutRescuesNinetySecondStale(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "hb_rescue")

	sm.mu.Lock()
	sess.LastHeartbeat = time.Now().Unix() - 90
	sm.mu.Unlock()

	if got := sm.CleanExpiredSessions(60); got != 1 {
		t.Fatalf("前置条件不成立：60s 超时下停滞 90s 的会话应被清，实得 %d", got)
	}

	// 重建同样的场景，改用 120s。
	sm2 := NewSessionManager(nil, nil)
	sess2 := newTestSession(t, sm2, "hb_rescue2")
	sm2.mu.Lock()
	sess2.LastHeartbeat = time.Now().Unix() - 90
	sm2.mu.Unlock()

	if got := sm2.CleanExpiredSessions(120); got != 0 {
		t.Fatalf("120s 超时下停滞 90s 的会话不该被清，实得 %d（说明提高超时没有救回丢 2 拍的会话）", got)
	}
	if sm2.SessionCount() != 1 {
		t.Fatalf("幸存会话被误删")
	}
}
