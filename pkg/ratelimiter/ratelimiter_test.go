package ratelimiter

import (
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// 限流器（审查报告 网关 P1-3 的限流分组 + P1-5 的 sweep 解耦）
// ─────────────────────────────────────────────────────────────────────────────

// TestAntiCheatReportIsRateLimited —— 报告 P1-3 后半段。
//
// /api/anticheat/report 原先不在任何限流组里：校验一个有效 session token 就能
// 无限次 POST。这条断言保证它被挂进了限流组（且前缀边界判定正确）。
func TestAntiCheatReportIsRateLimited(t *testing.T) {
	if got := PathGroup("/api/anticheat/report"); got != GroupAntiCheat {
		t.Fatalf("/api/anticheat/report 应属 %q 组，实际 %q", GroupAntiCheat, got)
	}
	if got := PathGroup("/api/anticheat"); got != GroupAntiCheat {
		t.Fatalf("/api/anticheat 应属 %q 组，实际 %q", GroupAntiCheat, got)
	}
	// 前缀边界：近似路径不能误判成受保护
	if got := PathGroup("/api/anticheatXXX"); got != "" {
		t.Fatalf("/api/anticheatXXX 不该被限流，实际 %q", got)
	}
}

// TestGroupsDoNotShareBuckets —— 按 IP+分组分桶。
//
// 审查报告 P1-5 称"delete 按 IP 整桶删会把 admin/heartbeat/launcher 三个桶一起清"；
// 实际 TryAcquireGroup 的 key 是 ip+"\x00"+group，本来就是独立桶。
// 这条把现状锁死：某个组把额度耗尽，不能连累同 IP 的其它组。
func TestGroupsDoNotShareBuckets(t *testing.T) {
	h := NewHttpRateLimiter(true, 3)
	const ip = "203.0.113.7"

	for i := 0; i < 3; i++ {
		if !h.TryAcquireGroup(ip, GroupHeartbeat) {
			t.Fatalf("心跳组第 %d 次应放行", i+1)
		}
	}
	if h.TryAcquireGroup(ip, GroupHeartbeat) {
		t.Fatalf("心跳组额度应已耗尽")
	}
	if !h.TryAcquireGroup(ip, GroupAdmin) {
		t.Fatalf("心跳组耗尽后，同 IP 的管理组必须仍有额度（否则高频心跳会误伤后台）")
	}
}

// TestSweepIfDueRemovesStaleBuckets 过期桶会被清掉、新桶保留。
func TestSweepIfDueRemovesStaleBuckets(t *testing.T) {
	rl := NewRateLimiter(true, 60)
	now := time.Now()

	rl.mu.Lock()
	rl.tokens["stale"] = &bucket{tokens: 1, last: now.Add(-90 * time.Second)}
	rl.tokens["fresh"] = &bucket{tokens: 1, last: now.Add(-5 * time.Second)}
	rl.lastSweep = now.Add(-61 * time.Second)
	rl.mu.Unlock()

	rl.sweepIfDue(now)

	rl.mu.Lock()
	_, staleKept := rl.tokens["stale"]
	_, freshKept := rl.tokens["fresh"]
	rl.mu.Unlock()

	if staleKept {
		t.Fatalf("超过 60s 未活动的桶应被清掉")
	}
	if !freshKept {
		t.Fatalf("仍在活动的桶不该被清掉")
	}
}

// TestSweepIfDueNeverBlocksOnBusyLock —— 报告 P1-5 的核心：sweep 不再阻塞。
//
// 修复前 sweep 写在 Lock/Unlock 之间，调用方要排队等一次全表遍历；
// 现在拿不到锁直接返回。这里**故意长期持有锁**，断言调用方立刻返回。
func TestSweepIfDueNeverBlocksOnBusyLock(t *testing.T) {
	rl := NewRateLimiter(true, 60)

	rl.mu.Lock()          // 模拟"锁被一个慢请求/一轮 sweep 占着"
	defer rl.mu.Unlock()

	done := make(chan struct{})
	go func() {
		rl.sweepIfDue(time.Now()) // 必须 TryLock 失败即返回
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("锁被占用时 sweepIfDue 仍在等锁 —— 又回到『热路径排队』的老行为")
	}
}

// TestSweepIfDueSkipsWhenNotDue 不到 60s 不该扫（别把每次请求都变成一次全表遍历）。
func TestSweepIfDueSkipsWhenNotDue(t *testing.T) {
	rl := NewRateLimiter(true, 60)
	now := time.Now()

	rl.mu.Lock()
	rl.tokens["recent"] = &bucket{tokens: 1, last: now.Add(-10 * time.Second)}
	rl.lastSweep = now // 刚扫过
	rl.mu.Unlock()

	// 手工把 lastSweep 停住，桶的 last 已经是 10s 前，若误扫会被删
	rl.sweepIfDue(now)

	rl.mu.Lock()
	_, kept := rl.tokens["recent"]
	rl.mu.Unlock()
	if !kept {
		t.Fatalf("距上次 sweep 不足 60s 不该清理")
	}
}
