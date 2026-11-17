package session

import (
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// 90CN 挂机批量掉线根治（2026-11-17 复盘）
//
// 现场：11-17 09:57:30 网关一次清了 3 个会话，其中 001459 的明细是
//   "心跳停滞=76s 游戏连接=1" —— 玩家还在游戏频道里，却被 HTTP 心跳
//   超时连同游戏 TCP 连接一起强关了。
//
// 根因：会话的 LastHeartbeat 只由登录器 HTTP 心跳更新；玩家把登录器
//   关掉/休眠、只留游戏客户端挂着时，HTTP 心跳停了但游戏连接还活着。
//   清理逻辑只看 LastHeartbeat，60s 一到就把在玩游戏的人踢掉。
//
// 修法（两条，互相兜底）：
//   1. 游戏代理连接建立时把心跳打到现在 —— 解决"刚建连却被按 80s 停滞清理"
//      （fh480512 09:56:44 建连、09:57:30 被按心跳停滞 80s 清）。
//   2. 清理时把活跃游戏连接当作"在线"的权威判据 —— 与泡点计费口径一致
//      （GameProxyConnections 才是"玩家真在游戏频道内"的唯一依据）。
//
// 这组测试先把目标行为钉成红的，再让实现变绿。
// ─────────────────────────────────────────────────────────────────────────────

// 有活跃游戏连接的会话，即使 HTTP 心跳停滞远超超时，也不能被清理。
func TestCleanExpiredSessionsKeepsActiveGameConnection(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "ingame", "1.2.3.4", "s1")
	ageSession(sess, 300) // HTTP 心跳停了 300s（超时只设 60s）

	gameSide, peerSide := pipePair(t)
	defer gameSide.Close()
	defer peerSide.Close()
	sm.AddGameProxyConnection(sess, gameSide)

	if got := sm.CleanExpiredSessions(60); got != 0 {
		t.Fatalf("有活跃游戏连接的会话不该被清理，实际清了 %d 个", got)
	}
	if _, ok := sm.ValidateToken(sess.Token); !ok {
		t.Fatal("有活跃游戏连接的会话被误删 —— 玩家还在游戏里就被踢了")
	}
}

// 反向断言：游戏连接断开后，心跳不再被游戏活动刷新，
// 超时后会话仍会被清 —— 避免"只要连过游戏就永不清理"的资源泄漏。
func TestCleanExpiredSessionsRemovesStaleSessionAfterGameConnGone(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "left_game", "1.2.3.4", "s1")

	gameSide, peerSide := pipePair(t)
	sm.AddGameProxyConnection(sess, gameSide)
	sm.RemoveGameProxyConnection(sess, gameSide)
	gameSide.Close()
	peerSide.Close()
	ageSession(sess, 300)

	if got := sm.CleanExpiredSessions(60); got != 1 {
		t.Fatalf("游戏连接已断且心跳停滞，应被清理，实际 %d 个", got)
	}
}

// 游戏连接建立时心跳必须刷新到现在。
// 现场矛盾：fh480512 09:56:44 刚建连，09:57:30 却被按"心跳停滞 80s"清理 ——
// 新连接挂到了一个心跳很旧的会话上，却没有把心跳归零。
func TestAddGameProxyConnectionRefreshesHeartbeat(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newSessionWith(t, sm, "reconnect", "1.2.3.4", "s1")
	ageSession(sess, 300)

	before := sess.LastHeartbeat
	gameSide, peerSide := pipePair(t)
	defer gameSide.Close()
	defer peerSide.Close()
	sm.AddGameProxyConnection(sess, gameSide)

	if sess.LastHeartbeat <= before {
		t.Fatalf("建立游戏连接应刷新心跳：before=%d after=%d", before, sess.LastHeartbeat)
	}
	if now := time.Now().Unix(); now-sess.LastHeartbeat > 2 {
		t.Fatalf("心跳未刷新到当前时刻: last=%d now=%d", sess.LastHeartbeat, now)
	}
}

// 明细里不该再出现"心跳停滞但有游戏连接"的会话 —— 那是修好的误清，
// 不是该被清的对象。这条防止运维判据被旧行为污染。
func TestCleanExpiredDetailsNeverReportsActiveGameConn(t *testing.T) {
	sm := NewSessionManager(nil, nil)

	stale := newSessionWith(t, sm, "stale_no_game", "1.2.3.4", "s1")
	ageSession(stale, 300)
	ingame := newSessionWith(t, sm, "ingame", "5.6.7.8", "s2")
	ageSession(ingame, 300)
	gameSide, peerSide := pipePair(t)
	defer gameSide.Close()
	defer peerSide.Close()
	sm.AddGameProxyConnection(ingame, gameSide)

	n, details := sm.CleanExpiredSessionsWithDetails(60)
	if n != 1 || len(details) != 1 {
		t.Fatalf("只应清掉无游戏连接的那个会话，实际 n=%d details=%d", n, len(details))
	}
	if details[0].Account != "stale_no_game" {
		t.Fatalf("清错了会话: %s", details[0].Account)
	}
}
