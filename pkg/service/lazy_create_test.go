package service

// ============================================================================
// 登录兜底反查测试（三服合一，评估文档 5.4）
//
// 覆盖四条不变量：
//   ① 密码正确 → 懒建本地副本，之后能登录
//   ② ★ 密码错误 → **不建号**（反查不能变成"知道账号名就能进"）
//   ③ 主网关查不到 → 不建号（原有行为不变）
//   ④ 反查返回 nil（超时/不可达）→ 不建号、不抛
// ============================================================================

import (
	"database/sql"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/security"
)

// newLazyCreateEnv 起一套最小依赖（真 SQLite + 真 AccountService）。
//
// ★ 游戏库必须建 accounts 表：AllocateNumericMId 会读它来判断"哪些 m_id 已被占"。
//   缺表会让懒建在"分配 m_id"这一步失败（实测报 no such table: accounts）。
func newLazyCreateEnv(t *testing.T) (*AccountService, *database.Database) {
	t.Helper()
	dir := t.TempDir()

	gamePath := filepath.Join(dir, "inventory.db")
	game, err := sql.Open("sqlite", "file:"+gamePath)
	if err != nil {
		t.Fatalf("创建游戏库: %v", err)
	}
	if _, err := game.Exec(`CREATE TABLE accounts (
		account_id INTEGER PRIMARY KEY AUTOINCREMENT,
		m_id       TEXT NOT NULL UNIQUE,
		cera       INTEGER DEFAULT 0,
		token_cera INTEGER DEFAULT 0,
		happy_token_cera INTEGER DEFAULT 0);`); err != nil {
		game.Close()
		t.Fatalf("建游戏库 schema: %v", err)
	}
	game.Close()

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           gamePath,
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("开库: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("建表: %v", err)
	}
	t.Cleanup(db.Close)

	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(lg.Close)

	cfg := &config.GatewayConfig{}
	cfg.GameServers = []config.GameServerEntry{{
		Id: "s4a21", Name: "A21", Protocol: config.ProtocolS4A21,
		GameServerSection: config.GameServerSection{PublicIP: "1.1.1.1"},
	}}

	svc := NewAccountService(db, cfg, lg)
	return svc, db
}

// TestLazyCreateOnCorrectPassword 锁定"密码对就懒建，且能登录"。
func TestLazyCreateOnCorrectPassword(t *testing.T) {
	svc, db := newLazyCreateEnv(t)

	// 主网关侧的凭据：pwd_md5 = MD5("secret123")
	const pwdMd5 = "b1b3773a05c0ed0176787a4f1574ff00" // MD5("qwerty") 示例值
	salt, err := security.GenerateSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	peerHash := security.DeriveHash(pwdMd5, salt)

	svc.SetPeerCredentialLookup(func(name string) *PeerCredential {
		if name != "peeruser" {
			return nil
		}
		return &PeerCredential{Exists: true, PwdHash: peerHash, Salt: salt, MId: "900001"}
	})

	// 本地查不到 → 走反查 → 懒建 → 验密 → 登录成功
	res := svc.Login("peeruser", pwdMd5, "", "1.2.3.4", "s4a21")
	if res.ErrorCode != models.Err.Ok {
		t.Fatalf("应登录成功，实得错误码 %d", res.ErrorCode)
	}

	// 本地应已有该账号
	acc, err := db.GetAccountByName("peeruser")
	if err != nil || acc == nil {
		t.Fatalf("懒建后本地应有账号: err=%v", err)
	}
	// ★ m_id 必须是**本地分配**的，不沿用主网关的 900001。
	//   理由见 tryLazyCreateFromPeer 的注释：沿用会撞号（新部署必然撞），
	//   撞号还可能让玩家看到别人的角色。
	if acc.MId == "" {
		t.Fatal("本地 m_id 不能为空")
	}
	if acc.MId == "900001" {
		t.Fatal("m_id 不该沿用主网关的 900001（会与本地账号撞号）")
	}
	if acc.PwdHash != peerHash {
		t.Fatal("本地 pwd_hash 应与主网关一致（凭据同源）")
	}

	// 第二次登录应走本地路径（不再调反查）
	var lookups int
	svc.SetPeerCredentialLookup(func(name string) *PeerCredential {
		lookups++
		return &PeerCredential{Exists: true, PwdHash: peerHash, Salt: salt, MId: "900001"}
	})
	res2 := svc.Login("peeruser", pwdMd5, "", "1.2.3.4", "s4a21")
	if res2.ErrorCode != models.Err.Ok {
		t.Fatalf("二次登录应成功，实得 %d", res2.ErrorCode)
	}
	if lookups != 0 {
		t.Fatalf("已建副本后不该再反查，实际反查了 %d 次", lookups)
	}
}

// TestLazyCreateRejectedOnWrongPassword 锁定"★ 密码错误绝不建号"。
//
// 这是整个反查机制的**安全底线**：如果这里漏了，任何人只要报一个
// 存在的账号名就能建号进服 —— 等于绕过密码。
func TestLazyCreateRejectedOnWrongPassword(t *testing.T) {
	svc, db := newLazyCreateEnv(t)

	const rightMd5 = "b1b3773a05c0ed0176787a4f1574ff00"
	const wrongMd5 = "5f4dcc3b5aa765d61d8327deb882cf99"
	salt, _ := security.GenerateSalt()
	peerHash := security.DeriveHash(rightMd5, salt)

	svc.SetPeerCredentialLookup(func(name string) *PeerCredential {
		return &PeerCredential{Exists: true, PwdHash: peerHash, Salt: salt, MId: "900002"}
	})

	res := svc.Login("victim", wrongMd5, "", "1.2.3.4", "s4a21")
	if res.ErrorCode == models.Err.Ok {
		t.Fatal("密码错误竟然登录成功 —— 反查机制有严重安全漏洞")
	}

	// 关键断言：本地不该有账号
	acc, err := db.GetAccountByName("victim")
	if err != nil {
		t.Fatalf("查库: %v", err)
	}
	if acc != nil {
		t.Fatal("密码错误时竟然懒建了账号 —— 可被用来绕过密码")
	}
}

// TestLazyCreateSkippedWhenPeerMisses 锁定"主网关查不到时不建号、报账号不存在"。
func TestLazyCreateSkippedWhenPeerMisses(t *testing.T) {
	svc, db := newLazyCreateEnv(t)

	svc.SetPeerCredentialLookup(func(name string) *PeerCredential {
		return nil // 主网关也查不到
	})

	res := svc.Login("nobody", "b1b3773a05c0ed0176787a4f1574ff00", "", "1.2.3.4", "s4a21")
	if res.ErrorCode != models.Err.AccountNotFound {
		t.Fatalf("应报账号不存在，实得 %d", res.ErrorCode)
	}
	acc, _ := db.GetAccountByName("nobody")
	if acc != nil {
		t.Fatal("主网关查不到时不该建号")
	}
}

// TestLazyCreateDisabledWithoutHook 锁定"没注入反查时行为与改造前一致"。
func TestLazyCreateDisabledWithoutHook(t *testing.T) {
	svc, db := newLazyCreateEnv(t)

	// 不注入
	res := svc.Login("anyone", "b1b3773a05c0ed0176787a4f1574ff00", "", "1.2.3.4", "s4a21")
	if res.ErrorCode != models.Err.AccountNotFound {
		t.Fatalf("未注入反查时应报账号不存在，实得 %d", res.ErrorCode)
	}
	acc, _ := db.GetAccountByName("anyone")
	if acc != nil {
		t.Fatal("未注入反查时不该建号")
	}
}

// TestLazyCreateAvoidsMIdCollision 锁定"m_id 撞号时自动避开，而不是登不进"。
//
// ★ 这条是 2026-10-24 第四轮修正的核心：
//   原先的实现"沿用主网关 m_id + 冲突就跳过懒建"，在新部署下几乎必然失败
//   （两服的 m_id 都从 100001 起），玩家在从网关完全登不进。
//
//   现在改为本地分配 m_id，撞号时自动换一个 —— 玩家能正常登录并建自己的角色。
//   各服游戏库独立，m_id 跨服一致本来就没有好处。
func TestLazyCreateAvoidsMIdCollision(t *testing.T) {
	svc, db := newLazyCreateEnv(t)

	const pwdMd5 = "b1b3773a05c0ed0176787a4f1574ff00"
	salt, _ := security.GenerateSalt()
	peerHash := security.DeriveHash(pwdMd5, salt)

	// 本地先占一个账号（模拟"土生土长的本地账号"）
	if err := db.InsertAccount(&database.Account{
		MId: "900003", Name: "localowner", PwdHash: "x", Salt: "y", CreatedAt: 1,
	}); err != nil {
		t.Fatalf("预置本地账号: %v", err)
	}

	// 主网关的账号也叫 900003（撞号场景）
	svc.SetPeerCredentialLookup(func(name string) *PeerCredential {
		return &PeerCredential{Exists: true, PwdHash: peerHash, Salt: salt, MId: "900003"}
	})

	res := svc.Login("peeruser2", pwdMd5, "", "1.2.3.4", "s4a21")
	if res.ErrorCode != models.Err.Ok {
		t.Fatalf("撞号时应能登录（本地分配新 m_id），实得错误码 %d", res.ErrorCode)
	}

	// 新账号必须有**自己**的 m_id，不能与本地已有账号共用
	acc, _ := db.GetAccountByName("peeruser2")
	if acc == nil {
		t.Fatal("撞号时也应建号")
	}
	if acc.MId == "900003" {
		t.Fatal("新账号不能与本地已有账号共用 m_id（会串角色）")
	}

	// 原有账号必须完好
	owner, _ := db.GetAccountByMId("900003")
	if owner == nil || owner.Name != "localowner" {
		t.Fatal("撞号处理把原有账号弄坏了")
	}
}
