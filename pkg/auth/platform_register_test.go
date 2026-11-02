package auth

// ============================================================================
// 平台账号注册（三服合一，2026-10-24）
//
// 产品决策：注册入口必须唯一 —— 只在主网关注册"平台账号"，
// 从网关拒绝注册。这样不需要"从网关注册的号反向同步到主网关"
// （那条路要明文密码跨服传，代价太大）。
//
// 覆盖五条不变量：
//   ① 从网关拒绝注册（返回明确文案，不建号）
//   ② 主网关建平台账号成功（不带明文也能建，老登录器兼容）
//   ③ 带明文时转发给所有启用的 S5A3 服
//   ④ S5A3 转发失败 → 平台账号仍成功，文案说明哪个服没建成
//   ⑤ PlatformOnly=false → 保留改造前的按 game 分流行为
// ============================================================================

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/models"
)

// registerViaHandlerWith 是 registerViaHandlerFull 的简写（不带 machineID）。
//
// 参数顺序与 Full 的前 6 个一致，invite 留空 = 自动取码池里的下一个。
func registerViaHandlerWith(t *testing.T, h *Handler, account, ip, game, password string) (int, string) {
	t.Helper()
	return registerViaHandlerFull(t, h, account, ip, game, password, "", "")
}

// TestRegisterRejectedOnSlaveGateway 锁定"从网关拒绝注册"。
//
// ★ 这是"注册入口唯一"的技术保证：即使玩家绕过登录器直接调从网关的
//   注册接口，也不会产生"只在从网关有的号"。
func TestRegisterRejectedOnSlaveGateway(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	// 配了 PeerInternalUrl = 从网关
	cfg.Signing.PeerInternalUrl = "http://10.0.0.1:18080"
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code, msg := registerViaHandlerWith(t, h, "slaveuser", "5.5.5.1", "", "")
	if code == models.Err.Ok {
		t.Fatal("从网关竟然允许注册 —— 注册入口不唯一")
	}
	if !strings.Contains(msg, "主网关") {
		t.Fatalf("拒绝文案应指导玩家去主网关，实得: %q", msg)
	}
}

// TestRegisterPlatformOnPrimary 锁定"主网关建平台账号"。
func TestRegisterPlatformOnPrimary(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code, _ := registerViaHandlerWith(t, h, "primaryuser", "5.5.5.2", "", "")
	if code != models.Err.Ok {
		t.Fatalf("主网关注册应成功，实得 %d", code)
	}
}

// TestRegisterForwardsToS5A3 锁定"带明文时转发给所有 S5A3 服"。
//
// 用 httptest 假扮 S5A3 账号服务，验证主网关真的把明文发过去了。
func TestRegisterForwardsToS5A3(t *testing.T) {
	var gotAccount, gotPassword string
	var called int

	fakeS5A3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		// 字段名与 service.s5a3CredentialRequest 的 json tag 一致（account / password）
		gotAccount = body["account"]
		gotPassword = body["password"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer fakeS5A3.Close()

	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.GameServers = []config.GameServerEntry{{
		Id: "s5a3", Name: "90CN", Protocol: config.ProtocolS5A3,
		GameServerSection: config.GameServerSection{PublicIP: "2.2.2.2", AccountApiUrl: fakeS5A3.URL},
	}}
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code, msg := registerViaHandlerWith(t, h, "fwuser", "5.5.5.3", "", "plainPwd123")
	if code != models.Err.Ok {
		t.Fatalf("注册应成功，实得 %d（msg=%s）", code, msg)
	}
	if called != 1 {
		t.Fatalf("应转发给 S5A3 一次，实际 %d 次", called)
	}
	if gotAccount != "fwuser" {
		t.Fatalf("转发的账号不对: %q", gotAccount)
	}
	if gotPassword != "plainPwd123" {
		t.Fatalf("转发的明文密码不对: %q", gotPassword)
	}
}

// TestRegisterS5A3FailureStillSucceeds 锁定"S5A3 转发失败但平台账号成功"。
//
// 失败方向：能用的部分先给玩家（S4A21/S5A95 立刻能登），
// 但文案必须说清哪个服没建成，不能让玩家以为全部成功。
func TestRegisterS5A3FailureStillSucceeds(t *testing.T) {
	fakeS5A3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500) // 故意让 S5A3 侧失败
	}))
	defer fakeS5A3.Close()

	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.GameServers = []config.GameServerEntry{{
		Id: "s5a3", Name: "90CN", Protocol: config.ProtocolS5A3,
		GameServerSection: config.GameServerSection{PublicIP: "2.2.2.2", AccountApiUrl: fakeS5A3.URL},
	}}
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code, msg := registerViaHandlerWith(t, h, "partialuser", "5.5.5.4", "", "pwd123456")
	if code != models.Err.Ok {
		t.Fatalf("平台账号建成时整体应成功，实得 %d", code)
	}
	if !strings.Contains(msg, "s5a3") {
		t.Fatalf("文案应点名没建成的服，实得: %q", msg)
	}
}

// TestRegisterWithoutPasswordSkipsS5A3 锁定"老登录器不带明文时跳过转发，仍成功"。
//
// 老登录器只发 MD5。平台账号照建（能登非 S5A3 服），
// S5A3 侧建不了 —— 但这不该让注册失败。
func TestRegisterWithoutPasswordSkipsS5A3(t *testing.T) {
	var called int
	fakeS5A3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer fakeS5A3.Close()

	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.GameServers = []config.GameServerEntry{{
		Id: "s5a3", Name: "90CN", Protocol: config.ProtocolS5A3,
		GameServerSection: config.GameServerSection{PublicIP: "2.2.2.2", AccountApiUrl: fakeS5A3.URL},
	}}
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code, _ := registerViaHandlerWith(t, h, "oldclientuser", "5.5.5.5", "", "")
	if code != models.Err.Ok {
		t.Fatalf("无明文时平台账号仍应建成，实得 %d", code)
	}
	if called != 0 {
		t.Fatalf("无明文时不该调 S5A3，实际 %d 次", called)
	}
}

// TestRegisterLegacyModeWhenPlatformOnlyOff 锁定"PlatformOnly=false 保留旧行为"。
//
// 旧行为：选中 S5A3 服时注册只建 S5A3 账号（不建平台账号）。
func TestRegisterLegacyModeWhenPlatformOnlyOff(t *testing.T) {
	var called int
	fakeS5A3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer fakeS5A3.Close()

	off := false
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.Register.PlatformOnly = &off // 回退开关
	cfg.GameServers = []config.GameServerEntry{{
		Id: "s5a3", Name: "90CN", Protocol: config.ProtocolS5A3,
		GameServerSection: config.GameServerSection{PublicIP: "2.2.2.2", AccountApiUrl: fakeS5A3.URL},
	}}
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code, _ := registerViaHandlerWith(t, h, "legacyuser", "5.5.5.6", "s5a3", "pwd123456")
	if code != models.Err.Ok {
		t.Fatalf("旧行为下注册 S5A3 应成功，实得 %d", code)
	}
	if called != 1 {
		t.Fatalf("旧行为应调 S5A3 一次，实际 %d 次", called)
	}
}

// TestRegisterPlatformOnlyDefaultTrue 锁定"不配 Register 段时默认走平台账号"。
func TestRegisterPlatformOnlyDefaultTrue(t *testing.T) {
	var def config.RegisterSection
	if !def.PlatformOnlyEnabled() {
		t.Fatal("RegisterSection 零值应默认 PlatformOnly=true")
	}
	on := true
	def.PlatformOnly = &on
	if !def.PlatformOnlyEnabled() {
		t.Fatal("显式 true 应生效")
	}
	off := false
	def.PlatformOnly = &off
	if def.PlatformOnlyEnabled() {
		t.Fatal("显式 false 应生效")
	}
}

// ============================================================================
// 邀请码（2026-10-24）
// ============================================================================

// TestRegisterRequiresInvite 锁定"不带码 → 1040，且不建号"。
func TestRegisterRequiresInvite(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	h, _ := newLoginFixtureWithConfig(t, cfg)

	// 显式传一个空码（registerViaHandlerFull 的 invite="" 会自动取码，
	// 所以这里直接构造请求）
	ver := testLauncherVer
	pwd := testPwdMd5
	account := "noinviteuser"
	empty := ""
	req := &models.GatewayRequest{
		Cmd: models.Cmd.Register, Account: &account, PasswordMd5: &pwd,
		LauncherVersion: &ver, InviteCode: &empty,
	}
	resp, err := h.Handle(req, "7.7.7.1")
	if err != nil {
		t.Fatalf("请求出错: %v", err)
	}
	if codeOf(resp) != models.Err.InviteRequired {
		t.Fatalf("不带邀请码应返回 1040，实得 %d", codeOf(resp))
	}
}

// TestRegisterRejectsBadInvite 锁定"错码 → 1041"。
func TestRegisterRejectsBadInvite(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code, msg := registerViaHandlerFull(t, h, "badinviteuser", "7.7.7.2", "", "", "NOSUCHCD", "")
	if code != models.Err.InviteInvalid {
		t.Fatalf("错码应返回 1041，实得 %d（msg=%q）", code, msg)
	}
	if !strings.Contains(msg, "邀请码") {
		t.Fatalf("文案应提到邀请码，实得 %q", msg)
	}
}

// TestRegisterInviteOneTimeUse 锁定"同一个码不能用两次"。
func TestRegisterInviteOneTimeUse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	h, _ := newLoginFixtureWithConfig(t, cfg)

	code := testInviteCodeAt(1) // 用码池里的固定一个

	c1, _ := registerViaHandlerFull(t, h, "inviteuser1", "7.7.7.3", "", "", code, "")
	if c1 != models.Err.Ok {
		t.Fatalf("首次用码应成功，实得 %d", c1)
	}

	c2, msg2 := registerViaHandlerFull(t, h, "inviteuser2", "7.7.7.4", "", "", code, "")
	if c2 != models.Err.InviteInvalid {
		t.Fatalf("同码二次使用应被拒(1041)，实得 %d（msg=%q）", c2, msg2)
	}
}

// TestRegisterInviteNormalized 锁定"带连字符/小写也能用"。
//
// 玩家从群里复制码时大小写混乱、带连字符是常态。
func TestRegisterInviteNormalized(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	h, _ := newLoginFixtureWithConfig(t, cfg)

	// 码池里是 "TST00002"，玩家输入 "tst-00002"（小写 + 连字符）
	code, msg := registerViaHandlerFull(t, h, "normuser", "7.7.7.5", "", "", "tst-00002", "")
	if code != models.Err.Ok {
		t.Fatalf("归一化后应通过，实得 %d（msg=%q）", code, msg)
	}
}

// TestRegisterInviteDisabledSwitch 锁定"RequireInvite=false 时不带码也能注册"。
func TestRegisterInviteDisabledSwitch(t *testing.T) {
	off := false
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.Register.RequireInvite = &off
	h, _ := newLoginFixtureWithConfig(t, cfg)

	ver := testLauncherVer
	pwd := testPwdMd5
	account := "freeuser"
	req := &models.GatewayRequest{
		Cmd: models.Cmd.Register, Account: &account, PasswordMd5: &pwd,
		LauncherVersion: &ver,
	}
	resp, err := h.Handle(req, "7.7.7.6")
	if err != nil {
		t.Fatalf("请求出错: %v", err)
	}
	if codeOf(resp) != models.Err.Ok {
		t.Fatalf("关掉 RequireInvite 后应能注册，实得 %d", codeOf(resp))
	}
}

// TestRequireInviteDefaultTrue 锁定"不配 Register 段时默认要求邀请码"。
//
// ★ 默认 true 是刻意的：默认 false 等于"配了但没生效"，
//   运营以为开了、实际谁都能注册 —— 那种静默失效比"注册不了"危险得多。
func TestRequireInviteDefaultTrue(t *testing.T) {
	var def config.RegisterSection
	if !def.RequireInviteEnabled() {
		t.Fatal("RegisterSection 零值应默认 RequireInvite=true")
	}
	off := false
	def.RequireInvite = &off
	if def.RequireInviteEnabled() {
		t.Fatal("显式 false 应生效")
	}
}
