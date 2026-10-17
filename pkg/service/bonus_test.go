package service

import (
	"database/sql"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/session"
)

// fakeConn 只用来充当"会话上挂着一条游戏频道连接"的占位：
// 泡点计费只数连接条数，不会真的读写 (见 session.CollectBonusAwards)。
type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (fakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// ─────────────────────────────────────────────────────────────────────────────
// 泡点发放的服务层接线测试（2026-09-23）
//
// 会话层的计费口径由 pkg/session/bonus_test.go 覆盖；这里只锁"接线"：
//   A. 没注入会话管理器 → 一个字节都不写（绝不退回"凭心跳发钱"的旧口径）；
//   B. 只有"真的连着游戏频道"的会话才拿到点券；
//   C. 网关库镜像 + 游戏库双写都按周期数发放。
// ─────────────────────────────────────────────────────────────────────────────

const testGrantInterval = 60

// setupBonusWorld 建一套临时库（网关库 + 游戏库）并返回它们。
func setupBonusWorld(t *testing.T) (*database.Database, string) {
	t.Helper()
	dir := t.TempDir()
	gwPath := filepath.Join(dir, "gateway.db")
	gamePath := filepath.Join(dir, "inventory.db")

	// 游戏库要先有 accounts 表，网关侧只做 UPDATE，不会建表。
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
		Path:               gwPath,
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
	return db, gamePath
}

// execOnGame 在游戏库上执行一条写语句。
func execOnGame(t *testing.T, gamePath, query string, args ...interface{}) {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+gamePath)
	if err != nil {
		t.Fatalf("打开游戏库失败: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(query, args...); err != nil {
		t.Fatalf("游戏库写失败 (%s): %v", query, err)
	}
}

// queryOnGame 在游戏库上取一个整数。
func queryOnGame(t *testing.T, gamePath, query string, args ...interface{}) int64 {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+gamePath)
	if err != nil {
		t.Fatalf("打开游戏库失败: %v", err)
	}
	defer conn.Close()
	var v int64
	if err := conn.QueryRow(query, args...).Scan(&v); err != nil {
		t.Fatalf("游戏库读失败 (%s): %v", query, err)
	}
	return v
}

// newBonusSvcForTest 组一个 BonusService（不读磁盘配置，直接喂 cfg）。
func newBonusSvcForTest(t *testing.T, db *database.Database, gwPath string) *BonusService {
	t.Helper()
	log, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("建日志失败: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	cfg := &config.GatewayConfig{Database: config.DatabaseSection{Path: gwPath}}
	return NewBonusService(db, cfg, log)
}

// seedAccount 在网关库（和可选的游戏库）里造一个账号。
func seedAccount(t *testing.T, db *database.Database, mId, name string) {
	t.Helper()
	if err := db.InsertAccount(&database.Account{
		MId:       mId,
		Name:      name,
		PwdHash:   "x",
		Salt:      "",
		CreatedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("造账号 %s 失败: %v", name, err)
	}
}

// TestGrantBonusSkipsWithoutSessionManager —— 不变量 A。
// 没注入会话管理器时必须一次都不发，且网关库 cera 保持不变。
func TestGrantBonusSkipsWithoutSessionManager(t *testing.T) {
	db, gamePath := setupBonusWorld(t)
	execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES ('10001', 0)")
	seedAccount(t, db, "10001", "alice")

	svc := newBonusSvcForTest(t, db, filepath.Join(t.TempDir(), "gateway.db"))
	// 故意不调 svc.SetSessionManager(...)
	svc.grantBonus(&BonusConfig{Enabled: true, IntervalSeconds: testGrantInterval, AmountPerInterval: 100})

	acc, err := db.GetAccountByName("alice")
	if err != nil || acc == nil {
		t.Fatalf("读账号失败: %v", err)
	}
	if acc.Cera != 0 {
		t.Fatalf("未注入会话管理器却发了点券，cera=%d", acc.Cera)
	}
	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10001'"); got != 0 {
		t.Fatalf("未注入会话管理器却写了游戏库，cera=%d", got)
	}
}

// TestGrantBonusOnlyGrantsSessionsInGame —— 不变量 B。
// 同一时刻两个会话：一个真的连着游戏频道，一个只登录了，只有前者拿钱。
func TestGrantBonusOnlyGrantsSessionsInGame(t *testing.T) {
	db, gamePath := setupBonusWorld(t)
	execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES ('10001', 0)")
	execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES ('10002', 0)")
	seedAccount(t, db, "10001", "ingame")
	seedAccount(t, db, "10002", "idle")

	sm := session.NewSessionManager(nil, nil)
	tokenIn, err := sm.CreateSession("ingame", "10001", "10.0.0.1", "", "")
	if err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	tokenIdle, err := sm.CreateSession("idle", "10002", "10.0.0.2", "", "")
	if err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	sessIn, _ := sm.ValidateToken(tokenIn)
	sessIdle, _ := sm.ValidateToken(tokenIdle)

	// 只有 ingame 有"游戏频道连接"；idle 停在登录器/频道列表界面
	conn := fakeConn{}
	sm.AddGameProxyConnection(sessIn, conn)

	// 把两个会话的计费基准都往回拨 65 秒：只有 ingame 那 65 秒算数
	base := time.Now().Unix() - 65
	sessIn.BonusTickAt = base
	sessIdle.BonusTickAt = base

	svc := newBonusSvcForTest(t, db, filepath.Join(t.TempDir(), "gateway.db"))
	svc.SetSessionManager(sm)
	svc.grantBonus(&BonusConfig{Enabled: true, IntervalSeconds: testGrantInterval, AmountPerInterval: 100})

	gotIn, err := db.GetAccountByName("ingame")
	if err != nil || gotIn == nil {
		t.Fatalf("读账号失败: %v", err)
	}
	if gotIn.Cera != 100 {
		t.Fatalf("在游戏内的账号应发 100，实际 %d", gotIn.Cera)
	}
	gotIdle, err := db.GetAccountByName("idle")
	if err != nil || gotIdle == nil {
		t.Fatalf("读账号失败: %v", err)
	}
	if gotIdle.Cera != 0 {
		t.Fatalf("没进游戏的账号不该发，实际 %d", gotIdle.Cera)
	}

	// 双写：游戏库那份也要有（否则游戏内看不到点券）
	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10001'"); got != 100 {
		t.Fatalf("游戏库应写入 100，实际 %d", got)
	}
	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10002'"); got != 0 {
		t.Fatalf("游戏库不该给 idle 写点券，实际 %d", got)
	}
}

// TestGrantBonusAppliesPerIntervalAndStopsAfterSessionRemoved —— 不变量 B 的端到端版。
//
// 复刻用户日志里的场景：会话被清理之后，下一轮不能继续发。
func TestGrantBonusStopsAfterSessionRemoved(t *testing.T) {
	db, gamePath := setupBonusWorld(t)
	execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES ('10001', 0)")
	seedAccount(t, db, "10001", "alice")

	sm := session.NewSessionManager(nil, nil)
	token, err := sm.CreateSession("alice", "10001", "10.0.0.1", "", "")
	if err != nil {
		t.Fatalf("建会话失败: %v", err)
	}
	sess, _ := sm.ValidateToken(token)
	sm.AddGameProxyConnection(sess, fakeConn{})
	sess.BonusTickAt = time.Now().Unix() - 65

	svc := newBonusSvcForTest(t, db, filepath.Join(t.TempDir(), "gateway.db"))
	svc.SetSessionManager(sm)
	cfg := &BonusConfig{Enabled: true, IntervalSeconds: testGrantInterval, AmountPerInterval: 100}

	svc.grantBonus(cfg)
	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10001'"); got != 100 {
		t.Fatalf("第一轮应发 100，实际 %d", got)
	}

	// 会话被清理（超时 / 踢下线）
	sm.RemoveSession(token)

	// 后面连发 5 轮都不该再写
	for i := 0; i < 5; i++ {
		svc.grantBonus(cfg)
	}
	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10001'"); got != 100 {
		t.Fatalf("会话已清理后仍在发放，游戏库 cera=%d（应停在 100）", got)
	}
	acc, err := db.GetAccountByName("alice")
	if err != nil || acc == nil {
		t.Fatalf("读账号失败: %v", err)
	}
	if acc.Cera != 100 {
		t.Fatalf("会话已清理后仍在发放，网关库 cera=%d（应停在 100）", acc.Cera)
	}
}

// TestGrantBonusRewritesLogWithAccountName —— 日志必须打账号名（用户报过 m_id 看不懂）。
// 这里只保证不 panic 且账号名进得去；文本断言由 202 上的专项脚本做。
func TestGrantBonusLogsAccountNameWithoutPanic(t *testing.T) {
	db, gamePath := setupBonusWorld(t)
	execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES ('10001', 0)")
	seedAccount(t, db, "10001", "显示名")

	sm := session.NewSessionManager(nil, nil)
	token, _ := sm.CreateSession("显示名", "10001", "10.0.0.1", "", "")
	sess, _ := sm.ValidateToken(token)
	sm.AddGameProxyConnection(sess, fakeConn{})
	sess.BonusTickAt = time.Now().Unix() - 65

	svc := newBonusSvcForTest(t, db, filepath.Join(t.TempDir(), "gateway.db"))
	svc.SetSessionManager(sm)
	svc.grantBonus(&BonusConfig{Enabled: true, IntervalSeconds: testGrantInterval, AmountPerInterval: 100})

	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10001'"); got != 100 {
		t.Fatalf("应发 100，实际 %d", got)
	}
}
