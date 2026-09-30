package httprouter

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"s4a21-gateway/pkg/database"

	_ "modernc.org/sqlite"
)

// ============================================================================
// /api/launcher/online 与 /api/launcher/notice 的单元测试
//
// Python 侧的双进程 E2E（_e2e/local_admin_test.py）跑的是真进程，但本机没有真实
// 登录会话，所以那条路径只能验证「count=0」的空态。这里用假的会话后端把
// 「会话 → 账号名 → m_id → 游戏库角色」这条解析链真正跑一遍。
// ============================================================================

// fakeSessionBackend 用固定列表冒充网关内存会话表，避免起真实 TCP 登录握手。
type fakeSessionBackend struct{ players []OnlinePlayer }

func (f *fakeSessionBackend) List() ([]OnlinePlayer, error)      { return f.players, nil }
func (f *fakeSessionBackend) Kick(string) (int, error)           { return 0, nil }
func (f *fakeSessionBackend) KickNonAdmin([]string) (int, error) { return 0, nil }
func (f *fakeSessionBackend) Count() (int, error)                { return len(f.players), nil }

// newLauncherOnlineDB 造「网关库 + 游戏库」两库：
//
//	网关库 accounts：msp → 10038，阿亮 → 2030，孤儿账号 → 无 m_id
//	游戏库 characters：10038 名下有 500「兔兔」(最近) / 501「毒奶」(较早) / 502 已删除
//
// 角色名刻意写成 GBK 裸字节（typeof(name)='blob'），与正式服一致。
func newLauncherOnlineDB(t *testing.T) *database.Database {
	t.Helper()
	dir := t.TempDir()
	gwPath := filepath.Join(dir, "gateway.db")
	gamePath := filepath.Join(dir, "inventory.db")

	gw, err := sql.Open("sqlite", gwPath)
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	if _, err := gw.Exec(`
		CREATE TABLE accounts (
			m_id       TEXT PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE,
			pwd_hash   TEXT NOT NULL DEFAULT '',
			salt       TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO accounts(m_id, name, created_at) VALUES
			('10038', 'msp',  1000),
			('2030',  '阿亮', 2000),
			('4004',  'bobokiss', 3000);`); err != nil {
		gw.Close()
		t.Fatalf("建测试网关库失败: %v", err)
	}
	gw.Close()

	game, err := sql.Open("sqlite", gamePath)
	if err != nil {
		t.Fatalf("打开测试游戏库失败: %v", err)
	}
	defer game.Close()
	if _, err := game.Exec(`
		CREATE TABLE accounts (
			account_id    INTEGER PRIMARY KEY AUTOINCREMENT,
			m_id          TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE characters (
			character_id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id   INTEGER NOT NULL,
			name         TEXT NOT NULL,
			level        INTEGER NOT NULL DEFAULT 1,
			job          INTEGER NOT NULL DEFAULT 0,
			exp          INTEGER NOT NULL DEFAULT 0,
			delete_flag  INTEGER NOT NULL DEFAULT 0,
			updated_at   TEXT
		);
		INSERT INTO accounts(account_id, m_id) VALUES (1, '10038'), (2, '2030');`); err != nil {
		t.Fatalf("建测试游戏库 schema 失败: %v", err)
	}

	tuTu := []byte{0xcd, 0xc3, 0xcd, 0xc3}  // 兔兔
	duNai := []byte{0xb6, 0xbe, 0xc4, 0xcc} // 毒奶
	ins := `INSERT INTO characters(character_id, account_id, name, level, job, exp, delete_flag, updated_at)
	        VALUES (?,?,?,?,?,?,?,?)`
	rows := []struct {
		cid, acc, lv, job, exp, del int
		name                        []byte
		up                          string
	}{
		{500, 1, 86, 5, 1046561640, 0, tuTu, "2026-09-24 01:24:59"},
		{501, 1, 70, 4, 1000, 0, duNai, "2026-09-20 10:00:00"},
		{502, 1, 40, 1, 500, 1, tuTu, "2026-09-25 23:59:59"}, // 已删除，但时间最新
		{600, 2, 86, 0, 1046561640, 0, []byte("Msp"), "2026-09-24 01:24:36"},
	}
	for _, r := range rows {
		if _, err := game.Exec(ins, r.cid, r.acc, r.name, r.lv, r.job, r.exp, r.del, r.up); err != nil {
			t.Fatalf("插入测试角色 %d 失败: %v", r.cid, err)
		}
	}

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path: gwPath, GamePath: gamePath, BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func newLauncherOnlineServer(t *testing.T, players []OnlinePlayer) *Server {
	t.Helper()
	return &Server{
		db:       newLauncherOnlineDB(t),
		sessions: &fakeSessionBackend{players: players},
	}
}

// TestBuildLauncherOnlineResolvesCurrentRole 是这条链路的正面用例：
// 会话 → 账号名 → m_id → 当前角色（GBK 角色名必须解对）。
func TestBuildLauncherOnlineResolvesCurrentRole(t *testing.T) {
	now := time.Now().Unix()
	s := newLauncherOnlineServer(t, []OnlinePlayer{
		{Account: "msp", IP: "10.0.0.1", OnlineMinutes: 12, LastHeartbeat: now},
		{Account: "阿亮", IP: "10.0.0.2", OnlineMinutes: 40, LastHeartbeat: now},
	})

	payload, err := s.buildLauncherOnline()
	if err != nil {
		t.Fatalf("buildLauncherOnline 失败: %v", err)
	}
	if got := payload["count"]; got != 2 {
		t.Fatalf("count 应为 2，实得 %v", got)
	}
	if got := payload["role_count"]; got != 2 {
		t.Fatalf("role_count 应为 2，实得 %v", got)
	}

	players, _ := payload["players"].([]launcherOnlinePlayer)
	if len(players) != 2 {
		t.Fatalf("players 应有 2 条，实得 %d", len(players))
	}

	// 按在线时长倒序：阿亮(40) 应排在 msp(12) 前面
	if players[0].OnlineMinutes != 40 || players[1].OnlineMinutes != 12 {
		t.Fatalf("应按在线时长倒序，实得 %d / %d", players[0].OnlineMinutes, players[1].OnlineMinutes)
	}

	// 阿亮 → m_id 2030 → 角色 600「Msp」
	if players[0].Role == nil || players[0].Role.Name != "Msp" || players[0].Role.Level != 86 {
		t.Fatalf("阿亮 当前角色解析错: %+v", players[0].Role)
	}
	// msp → m_id 10038 → 最新的存活角色是 500「兔兔」（502 已删除但时间更新，必须排除）
	role := players[1].Role
	if role == nil {
		t.Fatal("msp 应解析出当前角色")
	}
	if role.CharacterId != 500 {
		t.Fatalf("当前角色应为 500（502 已删除），实得 %d", role.CharacterId)
	}
	if role.Name != "兔兔" {
		t.Fatalf("角色名应解成「兔兔」，实得 %q —— GBK 解码没生效", role.Name)
	}
	if strings.ContainsRune(role.Name, '\uFFFD') {
		t.Fatalf("角色名含替换字符，说明按 UTF-8 硬读了: %q", role.Name)
	}
	if players[1].RoleCount != 2 {
		t.Fatalf("msp 存活角色数应为 2，实得 %d", players[1].RoleCount)
	}
}

// TestBuildLauncherOnlineWithoutGameAccount 账号在游戏库没有 m_id 时，
// 必须仍然出现在列表里（人确实在线），只是 role 为 null，不能整条丢掉。
func TestBuildLauncherOnlineWithoutGameAccount(t *testing.T) {
	s := newLauncherOnlineServer(t, []OnlinePlayer{
		{Account: "查无此人", OnlineMinutes: 3},
	})

	payload, err := s.buildLauncherOnline()
	if err != nil {
		t.Fatalf("buildLauncherOnline 失败: %v", err)
	}
	if payload["count"] != 1 {
		t.Fatalf("未知账号仍应计入在线数，实得 %v", payload["count"])
	}
	if payload["role_count"] != 0 {
		t.Fatalf("role_count 应为 0，实得 %v", payload["role_count"])
	}
	players, _ := payload["players"].([]launcherOnlinePlayer)
	if len(players) != 1 || players[0].Role != nil {
		t.Fatalf("未知账号的 role 应为 null: %+v", players)
	}
}

// TestHandleLauncherOnlineNoPrivacyLeak 免鉴权接口不能下发账号名与 IP。
func TestHandleLauncherOnlineNoPrivacyLeak(t *testing.T) {
	s := newLauncherOnlineServer(t, []OnlinePlayer{
		{Account: "msp", IP: "10.0.0.1", OnlineMinutes: 5},
	})

	rec := httptest.NewRecorder()
	s.handleLauncherOnline(rec, httptest.NewRequest("GET", "/api/launcher/online?force=1", nil))

	if rec.Code != 200 {
		t.Fatalf("应 200，实得 %d", rec.Code)
	}
	raw := rec.Body.String()
	for _, key := range []string{`"account"`, `"ip"`, `"m_id"`} {
		// 判 JSON 键，不判裸子串 —— precision 的取值里也含 account 字样
		if strings.Contains(raw, key) {
			t.Fatalf("公开接口不该下发 %s: %s", key, raw)
		}
	}
	var got map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if got["ok"] != true {
		t.Fatalf("ok 应为 true: %v", got)
	}
	if got["precision"] == nil {
		t.Fatal("应带 precision 字段如实说明口径")
	}
}

// TestHandleLauncherOnlineCache 缓存窗口内不重查，force=1 必须绕过缓存。
func TestHandleLauncherOnlineCache(t *testing.T) {
	s := newLauncherOnlineServer(t, []OnlinePlayer{{Account: "msp", OnlineMinutes: 5}})

	rec1 := httptest.NewRecorder()
	s.handleLauncherOnline(rec1, httptest.NewRequest("GET", "/api/launcher/online", nil))

	// 会话变了，但没带 force → 应命中缓存，仍是旧结果
	s.sessions = &fakeSessionBackend{players: nil}
	rec2 := httptest.NewRecorder()
	s.handleLauncherOnline(rec2, httptest.NewRequest("GET", "/api/launcher/online", nil))
	if rec2.Body.String() != rec1.Body.String() {
		t.Fatalf("缓存窗口内响应应完全一致\n第一次: %s\n第二次: %s", rec1.Body.String(), rec2.Body.String())
	}

	// force=1 → 绕过缓存，看到最新的空列表
	rec3 := httptest.NewRecorder()
	s.handleLauncherOnline(rec3, httptest.NewRequest("GET", "/api/launcher/online?force=1", nil))
	if rec3.Body.String() == rec1.Body.String() {
		t.Fatal("force=1 应绕过缓存重新查询")
	}
	var got map[string]interface{}
	_ = json.Unmarshal(rec3.Body.Bytes(), &got)
	if got["count"] != float64(0) {
		t.Fatalf("force=1 后 count 应为 0，实得 %v", got["count"])
	}
}

// TestSortOnlinePlayers 在线时长倒序（同时保证相等时不打乱）。
func TestSortOnlinePlayers(t *testing.T) {
	list := []launcherOnlinePlayer{
		{OnlineMinutes: 5}, {OnlineMinutes: 40}, {OnlineMinutes: 12}, {OnlineMinutes: 40}, {OnlineMinutes: 0},
	}
	sortOnlinePlayers(list)
	got := make([]int, len(list))
	for i, p := range list {
		got[i] = p.OnlineMinutes
	}
	want := []int{40, 40, 12, 5, 0}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("排序结果应为 %v，实得 %v", want, got)
		}
	}
}
