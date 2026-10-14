package session

import (
	"testing"
)

// TestGetAllSessionsReturnsSnapshot 是 G-9（2026-10-04 审查）的区分力测试。
//
// 修复前 GetAllSessions 返回会话对象**裸指针**：快照里的 LastHeartbeat 与
// sm.sessions 里的**同一份内存**，后续心跳写入会直接改到"已经取出去的快照"。
// 修复后是值拷贝，快照必须与后续写入隔离。
//
// 区分力：把 GetAllSessions 改回 `result = append(result, s)`（返回指针）后，
// 本用例的第一个断言必然变红。
func TestGetAllSessionsReturnsSnapshot(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	token, err := sm.ReplaceAccountSessions("alice", "10038", "1.2.3.4", "dev", false)
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}

	snaps := sm.GetAllSessions()
	if len(snaps) != 1 {
		t.Fatalf("应有 1 个会话快照，实得 %d", len(snaps))
	}
	before := snaps[0].LastHeartbeat

	// 模拟 UpdateHeartbeat / CollectBonusAwards 的并发写入：它们都在 sm.mu
	// 保护下直接改 sm.sessions[token] 的字段。这里用同一把锁做等价写入。
	sm.mu.Lock()
	sm.sessions[token].LastHeartbeat = before + 12345
	sm.sessions[token].BonusGranted = 7
	sm.mu.Unlock()

	if snaps[0].LastHeartbeat != before {
		t.Fatalf("快照被后续写入污染：LastHeartbeat %d -> %d（说明返回的是裸指针，不是值拷贝）",
			before, snaps[0].LastHeartbeat)
	}
	if snaps[0].BonusGranted != 0 {
		t.Fatalf("快照被后续写入污染：BonusGranted = %d（应为 0）", snaps[0].BonusGranted)
	}
	// 正面：重新取快照必须能看到最新值（证明不是"什么都读不到"）。
	again := sm.GetAllSessions()
	if again[0].LastHeartbeat != before+12345 || again[0].BonusGranted != 7 {
		t.Fatalf("重新取快照应看到最新值，实得 LastHeartbeat=%d BonusGranted=%d",
			again[0].LastHeartbeat, again[0].BonusGranted)
	}
}
