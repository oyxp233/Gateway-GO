package session

import (
	"net"
	"testing"
	"time"

	"s4a21-gateway/pkg/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// 会话清理路径必须真断连接（审查报告 网关 P1-1）
//
// 背景：RemoveSession / CleanExpiredSessions 是唯一两个"只从表里删、不断连接"的路径，
// 而同文件的 KickAccount / KickAll / KickNonAdminAccounts / ReplaceAccountSessions
// 全部都是锁内 collectSessionConns + 锁外 closeConns。
//
// 实际后果：
//   1. 心跳里发现 banned → RemoveSession → 会话没了但玩家的 TCP 代理链路还活着，
//      要等游戏侧 idle 超时（默认 1800s）才断 —— 封禁在玩家侧表现为"还能玩半小时"；
//   2. 客户端崩溃 → 会话被过期清理删除，代理 goroutine 仍双向 copy，资源回收推迟半小时。
//
// 断言口径：用 net.Pipe 当代理连接，对端在会话被移除后**必须**读到 EOF；
// 若没关（修复前的行为），对端只会在读超时上挂住 —— 这两种结果可区分。
// ─────────────────────────────────────────────────────────────────────────────

// pipePair 造一对内存连接，返回"挂在会话上的那端"和"玩家侧的那端"。
func pipePair(t *testing.T) (sessionSide, peerSide net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// isPeerClosed 判断对端是否已被关闭：读到 EOF/其它错误 = 已关；读超时 = 没关。
func isPeerClosed(t *testing.T, peer net.Conn) bool {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := peer.Read(make([]byte, 1))
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return true
}

// registeredConns 读会话上登记的连接数（Channel 代理 + 游戏代理）。
func registeredConns(sm *SessionManager, s *models.Session) (proxy, game int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(s.ProxyConnections), len(s.GameProxyConnections)
}

// TestRemoveSessionClosesProxyConn —— 报告 P1-1 的正路径。
func TestRemoveSessionClosesProxyConn(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	sess := newTestSession(t, sm, "banned_guy")

	proxySide, proxyPeer := pipePair(t)
	gameSide, gamePeer := pipePair(t)
	sm.AddProxyConnection(sess, proxySide)
	sm.AddGameProxyConnection(sess, gameSide)

	if p, g := registeredConns(sm, sess); p != 1 || g != 1 {
		t.Fatalf("前置条件不成立：登记数为 proxy=%d game=%d", p, g)
	}

	sm.RemoveSession(sess.Token)

	if got := sm.SessionCount(); got != 0 {
		t.Fatalf("会话未被移除：剩余 %d 个", got)
	}
	if p, g := registeredConns(sm, sess); p != 0 || g != 0 {
		t.Fatalf("连接登记表未清空：proxy=%d game=%d", p, g)
	}
	if !isPeerClosed(t, proxyPeer) {
		t.Fatalf("RemoveSession 后代理连接仍未被关闭（Channel 链路还活着）")
	}
	if !isPeerClosed(t, gamePeer) {
		t.Fatalf("RemoveSession 后游戏连接仍未被关闭（玩家可继续游戏到 idle 超时）")
	}
}

// TestCleanExpiredSessionsClosesProxyConn —— 报告 P1-1 的过期清理路径，
// 同时锁死"只关过期那个、别误伤新会话"。
func TestCleanExpiredSessionsClosesProxyConn(t *testing.T) {
	sm := NewSessionManager(nil, nil)

	expired := newTestSession(t, sm, "crashed_guy")
	staleSide, stalePeer := pipePair(t)
	sm.AddGameProxyConnection(expired, staleSide)

	fresh := newTestSession(t, sm, "still_alive")
	freshSide, freshPeer := pipePair(t)
	sm.AddGameProxyConnection(fresh, freshSide)

	// 把 expired 的心跳时间推到一个小时前（CleanExpiredSessions 的判据是 time.Now()）
	expired.LastHeartbeat = time.Now().Unix() - 3600

	if got := sm.CleanExpiredSessions(60); got != 1 {
		t.Fatalf("应清理 1 个过期会话，实际 %d 个", got)
	}

	if !isPeerClosed(t, stalePeer) {
		t.Fatalf("过期会话的游戏连接未被关闭（代理 goroutine 要等 1800s 才回收）")
	}
	if isPeerClosed(t, freshPeer) {
		t.Fatalf("未过期的会话被判过期并断连 —— 误伤在线玩家")
	}
	if _, ok := sm.ValidateToken(fresh.Token); !ok {
		t.Fatalf("未过期的会话被删掉了")
	}
}
