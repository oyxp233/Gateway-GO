package httprouter

import "testing"

// 所有对外的「在线」展示都要过 filterInGame：
// 只开了登录器、游戏没启动/已退出的会话不能被算成在线。
func TestFilterInGameDropsLauncherOnlySessions(t *testing.T) {
	players := []OnlinePlayer{
		{Account: "a", InGame: true, GameConns: 1},
		{Account: "b"}, // 只开登录器
		{Account: "c", InGame: true, GameConns: 2}, // 多开
	}
	got := filterInGame(players)
	if len(got) != 2 {
		t.Fatalf("filterInGame 结果 %d 条，want 2", len(got))
	}
	if got[0].Account != "a" || got[1].Account != "c" {
		t.Fatalf("filterInGame = %+v，want 只留 a / c", got)
	}
	if len(players) != 3 {
		t.Fatal("filterInGame 不该改动入参切片")
	}
}

// 登录器在线列表是玩家可见的「谁在线上」：只开了登录器、游戏没启动的人
// 必须不出现，否则列表里全是"在线但找不到人"。
func TestBuildLauncherOnlineExcludesLauncherOnlySessions(t *testing.T) {
	s := &Server{sessions: &fakeSessionBackend{players: []OnlinePlayer{
		{Account: "ingame", InGame: true, GameConns: 1},
		{Account: "launcheronly"}, // 登录器开着，游戏已退出
	}}}
	payload, err := s.buildLauncherOnline("")
	if err != nil {
		t.Fatalf("buildLauncherOnline 失败: %v", err)
	}
	if got := payload["count"]; got != 1 {
		t.Fatalf("count 应为 1（只算在游戏里的），实得 %v", got)
	}
}
