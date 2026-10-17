package auth

import (
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/session"
)

// ============================================================================
// CMD_LOGIN 的 game 字段贯通（2026-10-17 双服）
//
// 走真实 Handler.Handle 调用点（与掉线重连测试同一纪律）：字段从
// GatewayRequest 一路带到 service.Login 的 LaunchArgs 与 session.GameId。
// ============================================================================

// dualGameLoginFixture 双服配置：s4a21 默认 + s5a95 显式频道口。
func dualGameLoginFixture(t *testing.T) (*Handler, *session.SessionManager) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Gateway.ProxyPort = 8001
	cfg.GameServer.PublicIP = "203.0.113.7"
	enabled := true
	disabled := false
	cfg.GameServers = []config.GameServerEntry{
		{
			Id: "s4a21", Name: "S4A21", Protocol: config.ProtocolS4A21,
			Enabled:           &enabled,
			GameServerSection: cfg.GameServer,
		},
		{
			Id: "s5a95", Name: "DNF95", Protocol: config.ProtocolS5A95,
			Enabled:             &enabled,
			ChannelListenerPort: 23100,
			GameServerSection: config.GameServerSection{
				PublicIP:           "198.51.100.9",
				BackendHost:        "127.0.0.1",
				BackendChannelPort: 23100,
				LaunchArgsFormat:   config.DefaultS5A95LaunchArgsFormat,
			},
		},
		{
			Id: "s5a95-old", Name: "DNF95 旧服", Protocol: config.ProtocolS5A95,
			Enabled:             &disabled,
			ChannelListenerPort: 23110,
			GameServerSection:   config.GameServerSection{PublicIP: "198.51.100.10"},
		},
	}
	h, sm := newLoginFixtureWithConfig(t, cfg)
	return h, sm
}

// loginWithGame 注册（如需要）+ 带 game 字段登录，返回响应。
func loginWithGame(t *testing.T, h *Handler, account, game string) *models.GatewayResponse {
	t.Helper()
	ver := testLauncherVer
	pwd := testPwdMd5

	reg := &models.GatewayRequest{
		Cmd: models.Cmd.Register, Account: &account, PasswordMd5: &pwd, LauncherVersion: &ver,
	}
	if resp, err := h.Handle(reg, "203.0.113.7"); err != nil || !resp.Ok {
		t.Fatalf("注册失败: ok=%v code=%d err=%v", resp != nil && resp.Ok, codeOf(resp), err)
	}

	login := &models.GatewayRequest{
		Cmd: models.Cmd.Login, Account: &account, PasswordMd5: &pwd, LauncherVersion: &ver,
	}
	if game != "" {
		login.Game = &game
	}
	resp, err := h.Handle(login, "203.0.113.7")
	if err != nil {
		t.Fatalf("登录返回错误: %v", err)
	}
	return resp
}

// TestLoginWithoutGameFieldLegacyPath 老登录器不带 game：必须成功，
// LaunchArgs 是默认服格式，会话 GameId 为空串。
func TestLoginWithoutGameFieldLegacyPath(t *testing.T) {
	h, sm := dualGameLoginFixture(t)

	resp := loginWithGame(t, h, "legacygamer", "")
	if !resp.Ok {
		t.Fatalf("不带 game 的登录应成功，实得 code=%d msg=%s", codeOf(resp), msgOf(resp))
	}
	if resp.LaunchArgs == nil || !strings.HasPrefix(*resp.LaunchArgs, "9?203.0.113.7?8001?") {
		t.Fatalf("LaunchArgs 应是默认服格式，实得 %v", resp.LaunchArgs)
	}
	sess, ok := sm.ValidateToken(*resp.Token)
	if !ok {
		t.Fatal("会话未建立")
	}
	if sess.GameId != "" {
		t.Fatalf("老登录器会话 GameId 应为空，实得 %q", sess.GameId)
	}
}

// TestLoginWithGameS5A95WritesSessionGameId 带 game=s5a95：LaunchArgs 是
// 99?…digest 格式，且会话 GameId 落成 s5a95（在线统计靠它分服）。
func TestLoginWithGameS5A95WritesSessionGameId(t *testing.T) {
	h, sm := dualGameLoginFixture(t)

	resp := loginWithGame(t, h, "dnf95gamer", "s5a95")
	if !resp.Ok {
		t.Fatalf("选服登录应成功，实得 code=%d msg=%s", codeOf(resp), msgOf(resp))
	}
	if resp.LaunchArgs == nil || !strings.HasPrefix(*resp.LaunchArgs, "99?198.51.100.9?23100?") {
		t.Fatalf("LaunchArgs 应是 s5a95 格式，实得 %v", resp.LaunchArgs)
	}
	digest := strings.Split(*resp.LaunchArgs, "?")[4]
	if len(digest) != 32 {
		t.Fatalf("digest 段应为 32 位，实得 %q", digest)
	}
	sess, ok := sm.ValidateToken(*resp.Token)
	if !ok {
		t.Fatal("会话未建立")
	}
	if sess.GameId != "s5a95" {
		t.Fatalf("会话 GameId 应为 s5a95，实得 %q", sess.GameId)
	}
}

// TestLoginUnknownGameRejected 未知 game 明确拒绝（1038），不发 token。
func TestLoginUnknownGameRejected(t *testing.T) {
	h, _ := dualGameLoginFixture(t)

	resp := loginWithGame(t, h, "badgamer", "nosuch")
	if resp.Ok {
		t.Fatal("未知 game 不应登录成功")
	}
	if codeOf(resp) != models.Err.GameNotFound {
		t.Fatalf("应返回 GameNotFound(%d)，实得 %d", models.Err.GameNotFound, codeOf(resp))
	}
	if resp.Token != nil {
		t.Fatalf("拒绝时不应发 token，实得 %v", *resp.Token)
	}
}

// TestLoginDisabledGameRejected 停用 game 明确拒绝（1039）。
func TestLoginDisabledGameRejected(t *testing.T) {
	h, _ := dualGameLoginFixture(t)

	resp := loginWithGame(t, h, "oldgamer", "s5a95-old")
	if resp.Ok {
		t.Fatal("停用 game 不应登录成功")
	}
	if codeOf(resp) != models.Err.GameDisabled {
		t.Fatalf("应返回 GameDisabled(%d)，实得 %d", models.Err.GameDisabled, codeOf(resp))
	}
}

// TestLoginSwitchGameReplacesSession 同账号切服：单账号单令牌天然覆盖 ——
// 旧会话被踢、新会话带新服 GameId，旧 token 失效。
func TestLoginSwitchGameReplacesSession(t *testing.T) {
	h, sm := dualGameLoginFixture(t)

	first := loginWithGame(t, h, "switcher", "")
	if !first.Ok {
		t.Fatalf("首次登录失败: code=%d", codeOf(first))
	}
	oldToken := *first.Token

	// 切到 s5a95 需要 force_login（账号已在线）。
	ver := testLauncherVer
	pwd := testPwdMd5
	game := "s5a95"
	force := true
	login := &models.GatewayRequest{
		Cmd: models.Cmd.Login, Account: strPtrLocal("switcher"), PasswordMd5: &pwd,
		LauncherVersion: &ver, Game: &game, ForceLogin: &force,
	}
	resp, err := h.Handle(login, "203.0.113.7")
	if err != nil || !resp.Ok {
		t.Fatalf("切服登录失败: ok=%v code=%d err=%v", resp != nil && resp.Ok, codeOf(resp), err)
	}

	if _, ok := sm.ValidateToken(oldToken); ok {
		t.Fatal("旧 token 应已失效（单账号单令牌）")
	}
	sess, ok := sm.ValidateToken(*resp.Token)
	if !ok {
		t.Fatal("新会话未建立")
	}
	if sess.GameId != "s5a95" {
		t.Fatalf("新会话 GameId 应为 s5a95，实得 %q", sess.GameId)
	}
}

func strPtrLocal(s string) *string { return &s }
