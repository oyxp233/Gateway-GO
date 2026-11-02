package auth

// 封禁对 S5A3 服必须生效。
//
// ── 这个测试锁定的是一个真实 bug（2026-10-29 修复）────────────────────────
//
// handleLogin 里原本的顺序是：
//
//	if h.isS5A3Server(gameId) { return h.handleLoginS5A3(...) }   // ← 先 return
//	...
//	if banned, _ := h.accountSvc.IsBannedForServer(account, gameId); banned { ... }
//
// S5A3 分支直接 return，封禁检查永远走不到 ⇒ 后台「封禁」对 S5A3 服**完全无效**：
// 库里写进去了，玩家照样能登。后台列表还显示"已封禁"，极具欺骗性。
//
// 修法是把封禁检查前移到 S5A3 分支之前。本测试确保它不会被改回去。

import (
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/models"
)

// s5a3BanFixture 单服 S5A3 配置（账号 API 指向一个必定不可达的地址）。
//
// 不可达是刻意的：封禁命中时**根本不该**发起账号 API 请求。
// 如果测试走到"账号服务不可用"，说明封禁又被绕过了。
func s5a3BanFixture(t *testing.T) (*Handler, *database.Database) {
	t.Helper()
	cfg := config.DefaultConfig()
	enabled := true
	cfg.GameServers = []config.GameServerEntry{
		{
			Id: "s5a3", Name: "S5A3", Protocol: config.ProtocolS5A3,
			Enabled: &enabled,
			GameServerSection: config.GameServerSection{
				PublicIP:                 "203.0.113.7",
				AccountApiUrl:            "http://127.0.0.1:1", // 不可达
				AccountApiTimeoutSeconds: 1,
			},
		},
	}
	h, _, db := newLoginFixtureWithDB(t, cfg)
	return h, db
}

func TestS5A3BannedAccountRejected(t *testing.T) {
	h, db := s5a3BanFixture(t)

	account := "s5a3-banned-user"
	if err := db.BanAccountScoped(account, "测试封禁", "global"); err != nil {
		t.Fatalf("写封禁记录失败: %v", err)
	}

	ver := testLauncherVer
	pwd := "plaintext-password" // S5A3 要明文；但封禁应该在此之前拦住
	game := "s5a3"
	req := &models.GatewayRequest{
		Cmd:             models.Cmd.Login,
		Account:         &account,
		Password:        &pwd,
		LauncherVersion: &ver,
		Game:            &game,
	}
	resp, err := h.Handle(req, "203.0.113.7")
	if err != nil {
		t.Fatalf("登录返回错误: %v", err)
	}
	if resp == nil {
		t.Fatal("响应为 nil")
	}
	if resp.Ok {
		t.Fatal("被封禁的账号不该登录成功")
	}
	if codeOf(resp) != models.Err.Banned {
		t.Fatalf("应返回封禁错误码 %d，实得 %d（说明封禁检查被 S5A3 分支绕过了）",
			models.Err.Banned, codeOf(resp))
	}
}

// TestS5A3UnbannedAccountReachesUpstream 反向对照：
// 没被封的账号应该真的去请求 S5A3 账号 API（这里不可达 ⇒ 返回上游错误）。
//
// 它证明"上面那个测试的失败原因确实是封禁"，而不是别的东西在拦。
func TestS5A3UnbannedAccountReachesUpstream(t *testing.T) {
	h, _ := s5a3BanFixture(t)

	ver := testLauncherVer
	pwd := "plaintext-password"
	game := "s5a3"
	account := "s5a3-clean-user"
	req := &models.GatewayRequest{
		Cmd:             models.Cmd.Login,
		Account:         &account,
		Password:        &pwd,
		LauncherVersion: &ver,
		Game:            &game,
	}
	resp, err := h.Handle(req, "203.0.113.7")
	if err != nil {
		t.Fatalf("登录返回错误: %v", err)
	}
	if resp == nil || resp.Ok {
		t.Fatal("账号 API 不可达时不该登录成功")
	}
	if codeOf(resp) == models.Err.Banned {
		t.Fatal("未封禁的账号不该返回封禁错误")
	}
	t.Logf("未封禁账号走到上游，错误码 = %d（预期 AccountUpstream）", codeOf(resp))
}
