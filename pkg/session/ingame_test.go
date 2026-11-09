package session

import "testing"

// 「在线」必须等于「真的在游戏里」。
//
// 现场问题（2026-11-09）：会话是**登录器登录**时建的，玩家开着登录器但游戏没启动、
// 甚至游戏已经退出，会话仍在表里且照常心跳 —— 于是后台/登录器的在线列表把人算成在线。
// 真正的判据是这条会话有没有活着的游戏频道连接（GameProxyConnections）。
func TestInGameCountIgnoresLauncherOnlySessions(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	if _, err := sm.CreateSession("msp", "dnf:10002", "1.1.1.1", "", ""); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// 只登录了登录器：会话存在，但不算在线。
	if got := sm.SessionCount(); got != 1 {
		t.Fatalf("SessionCount = %d, want 1（会话数含只开登录器的）", got)
	}
	if got := sm.SessionCountInGame(); got != 0 {
		t.Fatalf("SessionCountInGame = %d, want 0（还没连游戏频道）", got)
	}
	if counts := sm.InGameConnCounts(); len(counts) != 0 {
		t.Fatalf("InGameConnCounts = %v, want 空", counts)
	}

	// 连上游戏频道之后才算在线。
	sess, ok := sm.FindSessionByAccount("msp")
	if !ok {
		t.Fatal("找不到刚建的会话")
	}
	conn, _ := pipePair(t)
	sm.AddGameProxyConnection(sess, conn)
	if got := sm.SessionCountInGame(); got != 1 {
		t.Fatalf("连上游戏后 SessionCountInGame = %d, want 1", got)
	}
	if counts := sm.InGameConnCounts(); counts[sess.Token] != 1 {
		t.Fatalf("InGameConnCounts[token] = %v, want 1", counts)
	}

	// 退出游戏：会话还在（登录器没关），但必须立刻不算在线。
	sm.RemoveGameProxyConnection(sess, conn)
	if got := sm.SessionCountInGame(); got != 0 {
		t.Fatalf("退出游戏后 SessionCountInGame = %d, want 0", got)
	}
	if counts := sm.InGameConnCounts(); len(counts) != 0 {
		t.Fatalf("退出游戏后 InGameConnCounts = %v, want 空", counts)
	}
}
