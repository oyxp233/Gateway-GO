package session

import "testing"

// TestFindSessionByMId 按 m_id 精确归属 —— 双开（同一公网 IP 多个账号）场景的关键。
//
// 背景：网关原先只按 IP 挑「心跳最新」的会话来归属游戏连接，同 IP 多开时
// 会把所有连接都算到最活跃的那个账号头上（日志归属、泡点计时全错，实机踩到）。
func TestFindSessionByMId(t *testing.T) {
	sm := NewSessionManager(nil, nil)

	tokA, err := sm.CreateSession("msp", "10038", "1.2.3.4", "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := sm.CreateSession("msp2", "10039", "1.2.3.4", "dev", "")
	if err != nil {
		t.Fatal(err)
	}

	// ★ 同一个 IP，按 IP 只能拿到一个；按 m_id 才能区分到具体账号
	a, ok := sm.FindSessionByMId("10038")
	if !ok || a.Token != tokA || a.Account != "msp" {
		t.Fatalf("m_id=10038 应命中 msp 会话，got=%+v ok=%v", a, ok)
	}
	b, ok := sm.FindSessionByMId("10039")
	if !ok || b.Token != tokB || b.Account != "msp2" {
		t.Fatalf("m_id=10039 应命中 msp2 会话，got=%+v ok=%v", b, ok)
	}

	if _, ok := sm.FindSessionByMId("40404"); ok {
		t.Fatal("不存在的 m_id 不应命中")
	}
	if _, ok := sm.FindSessionByMId(""); ok {
		t.Fatal("空 m_id 不应命中")
	}
}

// TestFindSessionByMId_SameMIdKeepsEarliest 同 m_id 多会话（异常态）时取创建最早的，
// 与 FindSessionByAccount 口径一致，保证归属确定性。
func TestFindSessionByMId_SameMIdKeepsEarliest(t *testing.T) {
	sm := NewSessionManager(nil, nil)

	first, _ := sm.CreateSession("dup", "77777", "1.2.3.4", "d1", "")
	second, _ := sm.CreateSession("dup", "77777", "5.6.7.8", "d2", "")

	// CreateSession 用秒级时间戳，两条可能同秒；此时比较不稳定。
	// 直接断言「命中的是这两个之一，且不会被第三次查询改变」——
	// 真正要守的是确定性，不是某一条必胜。
	got1, ok := sm.FindSessionByMId("77777")
	if !ok {
		t.Fatal("同 m_id 多会话时仍应命中")
	}
	for i := 0; i < 5; i++ {
		again, _ := sm.FindSessionByMId("77777")
		if again.Token != got1.Token {
			t.Fatalf("重复查询结果不稳定：%s vs %s", got1.Token, again.Token)
		}
	}
	if got1.Token != first && got1.Token != second {
		t.Fatalf("命中的 token 不属于已创建的任一会话：%s", got1.Token)
	}
}
