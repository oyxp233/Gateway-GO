package auth

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/service"
	"s4a21-gateway/pkg/session"
)

// ─────────────────────────────────────────────────────────────────────────────
// 掉线重连自动放行 —— 走真实登录处理器（2026-10-10 生产 18:30 卡顿掉线复盘）
//
// 场景：玩家掉线后重开登录器登录，旧会话还没到心跳超时就被判"已在线"，
// 返回 1023 让登录器弹窗等确认 —— 人不在电脑前就一直进不去。
// 修复：旧会话"心跳已停滞 + 新登录来自同一端"时直接踢旧会话放行。
//
// ★ 这里刻意走 `Handler.Handle`（真实调用点）而不是直接调 session 层：
// 本项目吃过"单测传的措辞和真实调用点不一致"的亏（NormalizeGameEventText
// 传英文名、调用点传中文名，测试一路绿灯而功能坏着）。判据一样要成对：
// 放行路径绿 + 三条不该放行的路径必须仍然红（1023）。
// ─────────────────────────────────────────────────────────────────────────────

// testPwdMd5 是 "123456" 的 MD5。
const testPwdMd5 = "e10adc3949ba59abbe56e057f20f883e"

// testLauncherVer 必须显式带版本号：Handle 先过版本门禁，不带一律 1016。
const testLauncherVer = "9.9.9"

func newLoginFixture(t *testing.T, staleSeconds int) (*Handler, *session.SessionManager) {
	t.Helper()

	dir, err := os.MkdirTemp("", "s4a21-login-test-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	log, err := logger.NewConsoleLogger(dir, logger.Error)
	if err != nil {
		t.Fatalf("日志初始化失败: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	// 游戏库要先有 accounts 表：登录链路会去同步密码哈希。
	gamePath := filepath.Join(dir, "inventory.db")
	game, err := sql.Open("sqlite", "file:"+gamePath)
	if err != nil {
		t.Fatalf("创建游戏库失败: %v", err)
	}
	if _, err := game.Exec(`CREATE TABLE accounts (
		account_id INTEGER PRIMARY KEY AUTOINCREMENT,
		m_id       TEXT NOT NULL UNIQUE,
		cera       INTEGER DEFAULT 0,
		token_cera INTEGER DEFAULT 0,
		happy_token_cera INTEGER DEFAULT 0);`); err != nil {
		game.Close()
		t.Fatalf("建游戏库 schema 失败: %v", err)
	}
	game.Close()

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           gamePath,
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开网关库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("建网关库表失败: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Heartbeat.StaleForceSeconds = staleSeconds
	cfg.RateLimit.Enabled = false

	sm := session.NewSessionManager(nil, nil)
	h := NewHandler(
		service.NewAccountService(db, cfg, log),
		nil,
		sm,
		service.NewRegisterBonusService(db, cfg, log),
		nil,
		cfg,
		log,
	)
	return h, sm
}

// registerAndLogin 走完整注册 + 首次登录，返回首次登录的 token。
func registerAndLogin(t *testing.T, h *Handler, account, ip string) string {
	t.Helper()

	ver := testLauncherVer
	pwd := testPwdMd5
	reg := &models.GatewayRequest{
		Cmd:             models.Cmd.Register,
		Account:         &account,
		PasswordMd5:     &pwd,
		LauncherVersion: &ver,
	}
	if resp, err := h.Handle(reg, ip); err != nil || !resp.Ok {
		t.Fatalf("注册失败: ok=%v code=%d err=%v", resp != nil && resp.Ok, codeOf(resp), err)
	}

	login := &models.GatewayRequest{
		Cmd:             models.Cmd.Login,
		Account:         &account,
		PasswordMd5:     &pwd,
		LauncherVersion: &ver,
	}
	resp, err := h.Handle(login, ip)
	if err != nil {
		t.Fatalf("登录返回错误: %v", err)
	}
	if !resp.Ok {
		t.Fatalf("首次登录应成功，实际 code=%d msg=%s", codeOf(resp), msgOf(resp))
	}
	if resp.Token == nil || *resp.Token == "" {
		t.Fatal("首次登录没有拿到 token")
	}
	return *resp.Token
}

// relogin 再发一次登录（不带 force_login，模拟玩家重开登录器）。
func relogin(h *Handler, account, ip string) *models.GatewayResponse {
	ver := testLauncherVer
	pwd := testPwdMd5
	resp, _ := h.Handle(&models.GatewayRequest{
		Cmd:             models.Cmd.Login,
		Account:         &account,
		PasswordMd5:     &pwd,
		LauncherVersion: &ver,
	}, ip)
	return resp
}

func codeOf(resp *models.GatewayResponse) int {
	if resp == nil {
		return 0
	}
	return resp.ErrorCode
}

func msgOf(resp *models.GatewayResponse) string {
	if resp == nil || resp.Message == nil {
		return ""
	}
	return *resp.Message
}

// ageSession 把会话心跳推回 seconds 秒前，模拟客户端进程已死。
func ageSession(t *testing.T, sm *session.SessionManager, account string, seconds int64) *models.Session {
	t.Helper()
	sess, ok := sm.FindSessionByAccount(account)
	if !ok {
		t.Fatalf("找不到 %s 的会话", account)
	}
	sess.LastHeartbeat = time.Now().Unix() - seconds
	return sess
}

// ── 正路径：同 IP + 心跳停滞 ⇒ 自动放行 ─────────────────────────────────────

func TestStaleReloginSameIPIsAutoAllowed(t *testing.T) {
	h, sm := newLoginFixture(t, 35)
	old := registerAndLogin(t, h, "zhouyang", "1.2.3.4")

	sess := ageSession(t, sm, "zhouyang", 40)
	oldCreatedAt := sess.CreatedAt

	resp := relogin(h, "zhouyang", "1.2.3.4")
	if !resp.Ok {
		t.Fatalf("掉线重连（同 IP + 心跳停滞 40s）应自动放行，实际 code=%d msg=%s",
			codeOf(resp), msgOf(resp))
	}
	if resp.Token == nil || *resp.Token == "" {
		t.Fatal("放行后没拿到新 token")
	}
	if *resp.Token == old {
		t.Fatal("放行后 token 没换，旧会话可能没被踢掉")
	}
	if _, ok := sm.ValidateToken(old); ok {
		t.Fatal("旧会话仍在会话表里 —— 没被真踢掉，玩家会双端在线")
	}
	// 结转口径：在线时长与泡点进度不能因为这次重登清零
	// （走的是 ReplaceAccountSessions 的 carryOver 分支）。
	now, ok := sm.ValidateToken(*resp.Token)
	if !ok {
		t.Fatal("新 token 取不到会话")
	}
	if now.CreatedAt != oldCreatedAt {
		t.Fatalf("在线时长未结转：新会话 CreatedAt=%d 旧会话=%d", now.CreatedAt, oldCreatedAt)
	}
}

// ── 负路径一：心跳还新鲜（只是丢了一次心跳）⇒ 仍然弹窗 ──────────────────────

func TestFreshSessionReloginStillRejected(t *testing.T) {
	h, sm := newLoginFixture(t, 35)
	registerAndLogin(t, h, "aliveguy", "1.2.3.4")
	ageSession(t, sm, "aliveguy", 10)

	resp := relogin(h, "aliveguy", "1.2.3.4")
	if resp.Ok {
		t.Fatal("心跳仅停滞 10s 就自动放行了 —— 会把丢一次心跳的活人踢下线")
	}
	if codeOf(resp) != models.Err.AccountOnline {
		t.Fatalf("应返回 1023 AccountOnline，实际 %d", codeOf(resp))
	}
}

// ── 负路径二：异地顶号（IP 与设备都不同）⇒ 仍然弹窗 ────────────────────────

func TestStaleButDifferentEndpointStillRejected(t *testing.T) {
	h, sm := newLoginFixture(t, 35)
	registerAndLogin(t, h, "stolenguy", "1.2.3.4")
	ageSession(t, sm, "stolenguy", 300)

	resp := relogin(h, "stolenguy", "9.9.9.9")
	if resp.Ok {
		t.Fatal("异地登录（IP 与设备都不同）被自动放行 —— 顶号保护被打穿")
	}
	if codeOf(resp) != models.Err.AccountOnline {
		t.Fatalf("应返回 1023 AccountOnline，实际 %d", codeOf(resp))
	}
}

// ── 负路径三：阈值 0 = 功能关闭 ⇒ 退回老行为 ────────────────────────────────

func TestStaleReloginDisabledWhenThresholdZero(t *testing.T) {
	h, sm := newLoginFixture(t, 0)
	registerAndLogin(t, h, "legacyguy", "1.2.3.4")
	ageSession(t, sm, "legacyguy", 300)

	resp := relogin(h, "legacyguy", "1.2.3.4")
	if resp.Ok {
		t.Fatal("阈值 0 表示关闭，不应自动放行")
	}
	if codeOf(resp) != models.Err.AccountOnline {
		t.Fatalf("应返回 1023 AccountOnline，实际 %d", codeOf(resp))
	}
}

// ── 显式 force_login 的既有行为不能被这次改动碰坏 ───────────────────────────

func TestExplicitForceLoginStillWorks(t *testing.T) {
	h, sm := newLoginFixture(t, 35)
	old := registerAndLogin(t, h, "forceguy", "1.2.3.4")

	ver := testLauncherVer
	pwd := testPwdMd5
	force := true
	resp, _ := h.Handle(&models.GatewayRequest{
		Cmd:             models.Cmd.Login,
		Account:         strPtr("forceguy"),
		PasswordMd5:     &pwd,
		LauncherVersion: &ver,
		ForceLogin:      &force,
	}, "1.2.3.4")
	if !resp.Ok || resp.Token == nil || *resp.Token == old {
		t.Fatalf("带 force_login 的重复登录应放行并换新 token: ok=%v code=%d",
			resp != nil && resp.Ok, codeOf(resp))
	}
	if _, ok := sm.ValidateToken(old); ok {
		t.Fatal("force 登录后旧会话仍在")
	}
}
