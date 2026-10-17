package session

import (
	"net"
	"testing"

	"s4a21-gateway/pkg/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// 泡点计费口径（2026-09-23 调整）
//
// 需求原文：
//   泡点的发放需要检查到玩家真实登录游戏再发放，即玩家通过网关连接到游戏
//   频道以后开始计时，玩家退出游戏以后停止计时，不足一分钟不发放。
//   目前存在会话已清理，还发放泡点。
//
// 因此这里锁死四条不变量：
//   A. 没有游戏频道连接 → 一秒都不累计（光登录、光心跳不发钱）；
//   B. 会话被清理 / 踢下线 → 再也结算不到，不可能继续发；
//   C. 累计不足一个计费周期 → 不发，余数保留到下一轮；
//   D. 计时精度不受主循环周期影响 —— 起表/停表由连接事件驱动。
// ─────────────────────────────────────────────────────────────────────────────

const testInterval int64 = 60

// newTestSession 建一个会话并返回会话指针（token 从 sess.Token 取）。
func newTestSession(t *testing.T, sm *SessionManager, account string) *models.Session {
	t.Helper()
	token, err := sm.CreateSession(account, "10001", "127.0.0.1", "", "")
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	sess, ok := sm.ValidateToken(token)
	if !ok {
		t.Fatalf("会话创建后取不到")
	}
	return sess
}

// TestCollectBonusAwardsNoGameConnectionNoAward —— 不变量 A。
// 只登录 / 只发心跳、没连游戏频道，多久都不发钱。
func TestCollectBonusAwardsNoGameConnectionNoAward(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	now := int64(1_700_000_000)
	// 模拟 10 分钟、每 60 秒结算一次
	for i := 0; i < 10; i++ {
		now += testInterval
		if got := sm.CollectBonusAwards(now, testInterval); len(got) != 0 {
			t.Fatalf("第 %d 轮不该发放，实际发了 %+v", i+1, got)
		}
	}
	if sess.GameOnlineSeconds != 0 {
		t.Fatalf("未进游戏却累计了 %d 秒", sess.GameOnlineSeconds)
	}
	if sess.BonusGranted != 0 {
		t.Fatalf("未进游戏却发了 %d 个周期", sess.BonusGranted)
	}
	if sess.BonusTickAt != 0 {
		t.Fatalf("未进游戏不该起表，BonusTickAt=%d", sess.BonusTickAt)
	}
}

// TestCollectBonusAwardsOnlyCountsGameTime —— 进游戏才开始计时。
func TestCollectBonusAwardsOnlyCountsGameTime(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	// 先空转两轮（玩家还在登录器 / 频道列表界面）
	now += testInterval
	sm.CollectBonusAwards(now, testInterval)
	now += testInterval
	sm.CollectBonusAwards(now, testInterval)
	if sess.GameOnlineSeconds != 0 {
		t.Fatalf("进游戏前不该累计，实际 %d 秒", sess.GameOnlineSeconds)
	}

	// 玩家连上游戏频道 —— 计费时钟起表
	sm.addGameProxyConnectionAt(sess, client, now)
	if sess.BonusTickAt != now {
		t.Fatalf("起表时刻应为 %d，实际 %d", now, sess.BonusTickAt)
	}

	// 满一分钟 → 发一次
	now += testInterval
	awards := sm.CollectBonusAwards(now, testInterval)
	if len(awards) != 1 {
		t.Fatalf("进游戏满一个周期应发 1 次，实际 %d 次", len(awards))
	}
	if awards[0].Account != "alice" || awards[0].MId != "10001" || awards[0].Intervals != 1 {
		t.Fatalf("发放明细不对: %+v", awards[0])
	}
	if sess.BonusGranted != 1 {
		t.Fatalf("BonusGranted 应为 1，实际 %d", sess.BonusGranted)
	}
}

// TestCollectBonusAwardsShortSessionNoAward —— 不变量 C：不足一分钟不发。
func TestCollectBonusAwardsShortSessionNoAward(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)

	// 进游戏 59 秒 —— 不足一分钟，不发
	now += 59
	if got := sm.CollectBonusAwards(now, testInterval); len(got) != 0 {
		t.Fatalf("59 秒不该发放，实际 %+v", got)
	}
	if sess.GameOnlineSeconds != 59 {
		t.Fatalf("余数应为 59 秒，实际 %d", sess.GameOnlineSeconds)
	}
	// 再 2 秒，累计 61 秒 → 发 1 次，余 1 秒
	now += 2
	got := sm.CollectBonusAwards(now, testInterval)
	if len(got) != 1 || got[0].Intervals != 1 {
		t.Fatalf("累计 61 秒应发 1 次，实际 %+v", got)
	}
	if got[0].Remainder != 1 {
		t.Fatalf("余数应为 1 秒，实际 %d", got[0].Remainder)
	}
}

// TestCollectBonusAwardsStopsAfterSessionRemoved —— 不变量 B（用户报的原故障）。
func TestCollectBonusAwardsStopsAfterSessionRemoved(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)

	now += testInterval
	if got := sm.CollectBonusAwards(now, testInterval); len(got) != 1 {
		t.Fatalf("在游戏内应发 1 次，实际 %+v", got)
	}

	// ★ 会话被移除（踢下线 / 注销）
	sm.RemoveSession(sess.Token)

	// 之后无论过多久都不该再发放 —— 会话已不在表里
	for i := 0; i < 5; i++ {
		now += testInterval
		if got := sm.CollectBonusAwards(now, testInterval); len(got) != 0 {
			t.Fatalf("会话已清理，第 %d 轮仍在发放: %+v", i+1, got)
		}
	}
}

// TestCollectBonusAwardsStopsAfterCleanExpiredSessions —— 用户日志里的真实场景：
//
//	15:22:17 清理超时会话: 1
//	15:22:18 泡点: msp +100 cera      ← 旧实现照样发
//
// 新口径下超时清理之后必须一次都不发。
func TestCollectBonusAwardsStopsAfterCleanExpiredSessions(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)
	now += testInterval
	if got := sm.CollectBonusAwards(now, testInterval); len(got) != 1 {
		t.Fatalf("在游戏内应发 1 次，实际 %+v", got)
	}

	// 心跳停在中途 → 超时清理把会话摘掉（连接也一并断开）
	sess.LastHeartbeat = now - 3600
	if n := sm.CleanExpiredSessions(60); n != 1 {
		t.Fatalf("应清理 1 个会话，实际 %d", n)
	}

	for i := 0; i < 5; i++ {
		now += testInterval
		if got := sm.CollectBonusAwards(now, testInterval); len(got) != 0 {
			t.Fatalf("超时清理后第 %d 轮仍在发放: %+v", i+1, got)
		}
	}
}

// TestCollectBonusAwardsStopsOnGameDisconnect —— 退出游戏立即停表。
func TestCollectBonusAwardsStopsOnGameDisconnect(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)

	now += testInterval
	if got := sm.CollectBonusAwards(now, testInterval); len(got) != 1 {
		t.Fatalf("在游戏内应发 1 次，实际 %+v", got)
	}

	// 玩家退出游戏：连接断开，登录器还开着（会话仍在）
	now += 5
	sm.removeGameProxyConnectionAt(sess, client, now)
	// 退出前那 5 秒不白玩，结算进余数
	if sess.GameOnlineSeconds != 5 {
		t.Fatalf("退出时应结算最后 5 秒，实际余数 %d", sess.GameOnlineSeconds)
	}

	// 之后无论过多久都不再累计、不再发放
	for i := 0; i < 5; i++ {
		now += testInterval
		if got := sm.CollectBonusAwards(now, testInterval); len(got) != 0 {
			t.Fatalf("退出游戏后第 %d 轮仍在发放: %+v", i+1, got)
		}
	}
	if sess.GameOnlineSeconds != 5 {
		t.Fatalf("退出后余数不该变化，实际 %d", sess.GameOnlineSeconds)
	}
	if sess.BonusGranted != 1 {
		t.Fatalf("退出游戏后累计发放应停在 1，实际 %d", sess.BonusGranted)
	}
}

// TestCollectBonusAwardsRemainderAcrossGameSessions —— 余数跨"退出再进"保留。
func TestCollectBonusAwardsRemainderAcrossGameSessions(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)

	// 第一段：进游戏 30 秒后退出
	sm.addGameProxyConnectionAt(sess, client, now)
	now += 30
	sm.removeGameProxyConnectionAt(sess, client, now)
	if sess.GameOnlineSeconds != 30 {
		t.Fatalf("第一段应累计 30 秒，实际 %d", sess.GameOnlineSeconds)
	}

	// 中间空闲 70 秒（切角色 / 掉线重连），会计时钟必须停着
	now += 70
	if got := sm.CollectBonusAwards(now, testInterval); len(got) != 0 {
		t.Fatalf("空闲期间不该发放，实际 %+v", got)
	}
	if sess.GameOnlineSeconds != 30 {
		t.Fatalf("空闲期间不该累计，实际 %d", sess.GameOnlineSeconds)
	}

	// 第二段：重新进游戏 20 秒后退出 → 累计 50 秒，仍不足一分钟
	sm.addGameProxyConnectionAt(sess, client, now)
	now += 20
	sm.removeGameProxyConnectionAt(sess, client, now)
	if sess.GameOnlineSeconds != 50 {
		t.Fatalf("两段合计应 50 秒，实际 %d", sess.GameOnlineSeconds)
	}
	if got := sm.CollectBonusAwards(now, testInterval); len(got) != 0 {
		t.Fatalf("合计 50 秒不该发放，实际 %+v", got)
	}

	// 第三段：再进 10 秒 → 合计 60 秒，凑满一个周期
	sm.addGameProxyConnectionAt(sess, client, now)
	now += 10
	got := sm.CollectBonusAwards(now, testInterval)
	if len(got) != 1 || got[0].Intervals != 1 || got[0].Remainder != 0 {
		t.Fatalf("合计 60 秒应发 1 个周期，实际 %+v", got)
	}
}

// TestCollectBonusAwardsCapsSingleDelta —— 单轮最多认 2 个周期。
func TestCollectBonusAwardsCapsSingleDelta(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)
	now += testInterval
	sm.CollectBonusAwards(now, testInterval)

	// 主循环卡了 1 小时（或泡点被禁用后重新开启）：
	// 不能让那段"无人计费"的时间一次性补发。
	now += 3600
	got := sm.CollectBonusAwards(now, testInterval)
	if len(got) != 1 {
		t.Fatalf("应发 1 次，实际 %+v", got)
	}
	if got[0].Intervals != 2 {
		t.Fatalf("单轮最多累计 2 个周期，实际 %d", got[0].Intervals)
	}
	if sess.GameOnlineSeconds != 0 {
		t.Fatalf("封顶后余数应为 0，实际 %d", sess.GameOnlineSeconds)
	}
}

// TestCollectBonusAwardsRemainderCarriesOver —— 余数跨轮保留。
func TestCollectBonusAwardsRemainderCarriesOver(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)

	// 第 1 轮：满 60 秒
	now += testInterval
	got := sm.CollectBonusAwards(now, testInterval)
	if len(got) != 1 || got[0].Intervals != 1 || got[0].Remainder != 0 {
		t.Fatalf("第 1 轮应发 1 周期余 0，实际 %+v", got)
	}

	// 第 2 轮：再过 70 秒 → 1 周期 + 余 10 秒
	now += 70
	got = sm.CollectBonusAwards(now, testInterval)
	if len(got) != 1 || got[0].Intervals != 1 || got[0].Remainder != 10 {
		t.Fatalf("第 2 轮应发 1 周期余 10 秒，实际 %+v", got)
	}

	// 第 3 轮：再过 50 秒 → 余数 10+50=60，凑满第 3 个周期
	now += 50
	got = sm.CollectBonusAwards(now, testInterval)
	if len(got) != 1 || got[0].Intervals != 1 || got[0].Remainder != 0 {
		t.Fatalf("余数结转后应发第 3 个周期，实际 %+v", got)
	}
	if sess.BonusGranted != 3 {
		t.Fatalf("累计应发 3 个周期，实际 %d", sess.BonusGranted)
	}
}

// TestCollectBonusAwardsInvalidInterval —— 周期非法时宁可不发。
func TestCollectBonusAwardsInvalidInterval(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	sm.addGameProxyConnectionAt(sess, client, int64(1_700_000_000))

	if got := sm.CollectBonusAwards(int64(1_700_000_100), 0); got != nil {
		t.Fatalf("周期为 0 应直接返回空，实际 %+v", got)
	}
	if got := sm.CollectBonusAwards(int64(1_700_000_100), -5); got != nil {
		t.Fatalf("周期为负应直接返回空，实际 %+v", got)
	}
}

// TestCollectBonusAwardsClockRollback —— 系统时钟回拨时不补发、不卡死。
func TestCollectBonusAwardsClockRollback(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)

	// 时钟直接往回跳 500 秒
	got := sm.CollectBonusAwards(now-500, testInterval)
	if len(got) != 0 {
		t.Fatalf("时钟回拨不该发放，实际 %+v", got)
	}
	if sess.GameOnlineSeconds != 0 {
		t.Fatalf("时钟回拨不该累计，实际 %d", sess.GameOnlineSeconds)
	}
	// 基准被重置到回拨后的 now，之后正常推进仍能正常计费
	base := now - 500
	got = sm.CollectBonusAwards(base+testInterval, testInterval)
	if len(got) != 1 {
		t.Fatalf("回拨恢复后应正常发放，实际 %+v", got)
	}
}

// TestReplaceAccountSessionsCarriesBonusRemainder —— 重复登录结转余数。
func TestReplaceAccountSessionsCarriesBonusRemainder(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "alice")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := int64(1_700_000_000)
	sm.addGameProxyConnectionAt(sess, client, now)

	// 进门 25 秒后重复登录（force）：未满一个周期的余数应该结转
	now += 25
	sm.CollectBonusAwards(now, testInterval)
	if sess.GameOnlineSeconds != 25 {
		t.Fatalf("旧会话应累计 25 秒，实际 %d", sess.GameOnlineSeconds)
	}

	newToken, err := sm.ReplaceAccountSessions("alice", "10002", "127.0.0.1", "", "", true)
	if err != nil {
		t.Fatalf("重复登录失败: %v", err)
	}
	newSess, ok := sm.ValidateToken(newToken)
	if !ok {
		t.Fatalf("新会话取不到")
	}
	if newSess.GameOnlineSeconds != 25 {
		t.Fatalf("余数未结转: %d", newSess.GameOnlineSeconds)
	}
	if newSess.MId != "10002" {
		t.Fatalf("m_id 未按新会话写入: %s", newSess.MId)
	}
	// 新会话的游戏频道连接是全新的：结算基准要重新起算，不能继承旧时间点
	if newSess.BonusTickAt != 0 {
		t.Fatalf("新会话 BonusTickAt 应为 0，实际 %d", newSess.BonusTickAt)
	}

	// 新会话还没重新连游戏频道 → 不累计、不发放，余数原样保留
	now += 300
	got := sm.CollectBonusAwards(now, testInterval)
	if len(got) != 0 {
		t.Fatalf("新会话未进游戏不该发放，实际 %+v", got)
	}
	if newSess.GameOnlineSeconds != 25 {
		t.Fatalf("新会话未进游戏不该累计，余数应仍为 25，实际 %d", newSess.GameOnlineSeconds)
	}
}
