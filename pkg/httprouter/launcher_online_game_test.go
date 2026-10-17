package httprouter

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// ============================================================================
// 在线视图的 game 维度（2026-10-17 双服）
//
// 三条不变量：
//   ① 汇总视图（不带 game）必须给出按服分组的计数，且总数 = 全部在线；
//   ② 单服视图（?game=s5a95）只含该服玩家，且回显 game；
//   ③ 两种视图的缓存分槽 —— 共用一个槽会把 A 服视角的 body 返给另一个视角。
// ============================================================================

func mixedGamePlayers(now int64) []OnlinePlayer {
	return []OnlinePlayer{
		{Account: "s4a", OnlineMinutes: 10, LastHeartbeat: now, GameId: "s4a21"},
		{Account: "s4b", OnlineMinutes: 20, LastHeartbeat: now, GameId: "s4a21"},
		{Account: "d95a", OnlineMinutes: 30, LastHeartbeat: now, GameId: "s5a95"},
		{Account: "legacy", OnlineMinutes: 40, LastHeartbeat: now, GameId: ""}, // 老会话（默认服）
	}
}

func TestBuildLauncherOnlineGroupsByGame(t *testing.T) {
	now := time.Now().Unix()
	s := newLauncherOnlineServer(t, mixedGamePlayers(now))

	payload, err := s.buildLauncherOnline("")
	if err != nil {
		t.Fatalf("buildLauncherOnline 失败: %v", err)
	}

	if payload["count"].(int) != 4 {
		t.Fatalf("汇总视图 count 应为 4，实得 %v", payload["count"])
	}
	if _, ok := payload["game"]; ok {
		t.Fatalf("汇总视图不应带 game 回显")
	}

	games, ok := payload["games"].(map[string]int)
	if !ok {
		t.Fatalf("汇总视图应带 games 分组，实得 %T", payload["games"])
	}
	if games["s4a21"] != 2 || games["s5a95"] != 1 || games[""] != 1 {
		t.Fatalf("games 分组错: %v", games)
	}
	total := 0
	for _, n := range games {
		total += n
	}
	if total != 4 {
		t.Fatalf("games 分组总数应为 4，实得 %d", total)
	}
}

func TestBuildLauncherOnlineFiltersByGame(t *testing.T) {
	now := time.Now().Unix()
	s := newLauncherOnlineServer(t, mixedGamePlayers(now))

	payload, err := s.buildLauncherOnline("s5a95")
	if err != nil {
		t.Fatalf("buildLauncherOnline(s5a95) 失败: %v", err)
	}

	if payload["game"].(string) != "s5a95" {
		t.Fatalf("单服视图应回显 game=s5a95，实得 %v", payload["game"])
	}
	if payload["count"].(int) != 1 {
		t.Fatalf("s5a95 视图 count 应为 1，实得 %v", payload["count"])
	}
	if _, ok := payload["games"]; ok {
		t.Fatalf("单服视图不该带 games 分组")
	}
	players := payload["players"].([]launcherOnlinePlayer)
	if len(players) != 1 || players[0].OnlineMinutes != 30 {
		t.Fatalf("s5a95 视图应只含 d95a（30 分钟），实得 %+v", players)
	}
}

func TestBuildLauncherOnlineUnknownGameEmpty(t *testing.T) {
	now := time.Now().Unix()
	s := newLauncherOnlineServer(t, mixedGamePlayers(now))

	payload, err := s.buildLauncherOnline("nosuchgame")
	if err != nil {
		t.Fatalf("buildLauncherOnline(nosuchgame) 失败: %v", err)
	}
	// 未知服 = 空视图（不是报错、也不是回落全部）—— 登录器选了网关不认识的
	// 服时看到 0 人在线，比看到别的服的人更诚实。
	if payload["count"].(int) != 0 {
		t.Fatalf("未知 game 的 count 应为 0，实得 %v", payload["count"])
	}
}

// TestHandleLauncherOnlineCachePerGame 缓存分槽：
// 先拉汇总、再拉 s5a95、再拉汇总（第二次汇总必须命中自己槽的缓存，
// 拿到与第一次一致的 body，而不是被 s5a95 视图污染）。
func TestHandleLauncherOnlineCachePerGame(t *testing.T) {
	now := time.Now().Unix()
	s := newLauncherOnlineServer(t, mixedGamePlayers(now))

	get := func(query string) []byte {
		rec := httptest.NewRecorder()
		s.handleLauncherOnline(rec, httptest.NewRequest("GET", "/api/launcher/online"+query, nil))
		if rec.Code != 200 {
			t.Fatalf("HTTP %d", rec.Code)
		}
		return rec.Body.Bytes()
	}

	all1 := get("")
	s5 := get("?game=s5a95")
	all2 := get("") // 命中缓存

	if string(all1) == string(s5) {
		t.Fatalf("汇总与单服视图的 body 相同，缓存串了")
	}
	if string(all1) != string(all2) {
		t.Fatalf("汇总视图两次响应不一致（缓存未按 game 分槽）:\n%s\n%s", all1, all2)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(all2, &payload); err != nil {
		t.Fatalf("解析汇总响应失败: %v", err)
	}
	if payload["count"].(float64) != 4 {
		t.Fatalf("缓存里的汇总 count 应为 4，实得 %v", payload["count"])
	}
}
