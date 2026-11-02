package httprouter

// ============================================================================
// Web 注册测试（三服合一，2026-10-24）
//
// 覆盖六条不变量：
//   ① GET 返回 HTML 表单（主网关）
//   ② GET 在从网关返回"请到主网关注册"说明页（含主网关地址）
//   ③ POST 在从网关 403
//   ④ POST 正常注册成功（账号进库，可用 MD5 验密）
//   ⑤ POST 参数校验（长度/字符集/密码长度）
//   ⑥ 跨站 Origin 被拒（CSRF）
// ============================================================================

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/service"
)

// webRegisterEnv 是 Web 注册测试的环境。
//
// ★ invite 是**一个可用的邀请码**（归一化形式）：
//   Register.RequireInvite 默认开启，不带码的注册请求一律 1040。
//   每个测试用自己的临时库，所以同一个码在不同测试里互不影响。
type webRegisterEnv struct {
	srv    *Server
	db     *database.Database
	invite string
}

// newWebRegisterEnv 起一套最小依赖（真 SQLite + 真 AccountService + 一个邀请码）。
//
// ★ 游戏库必须建 accounts 表：注册链路会经 AllocateNumericMId 读它判断
//   "哪些 m_id 已被占"。缺表会让注册在分配 m_id 时失败（DatabaseError）。
func newWebRegisterEnv(t *testing.T, slave bool) webRegisterEnv {
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
	// 注册限额关掉：本组测试关心的是"接线对不对"，不是限额（限额另有专门测试）
	cfg.RegisterLimit.Enabled = false
	if slave {
		cfg.Signing.PeerInternalUrl = "http://10.0.0.1:18080"
		cfg.Signing.PeerBaseUrl = "http://10.0.0.1:8080"
	}

	// 生成一个可用邀请码（RequireInvite 默认开）
	codes, err := db.GenerateInvites(1, "test", "admin:test", 0)
	if err != nil {
		t.Fatalf("生成邀请码: %v", err)
	}

	svc := service.NewAccountService(db, cfg, lg)
	return webRegisterEnv{
		srv:    &Server{config: cfg, db: db, logger: lg, accountSvc: svc},
		db:     db,
		invite: database.FormatInviteCode(codes[0]), // 用展示形式（带连字符），顺便验证归一化
	}
}

// regBody 构造 Web 注册请求体（带邀请码）。
//
// 用 json.Marshal 而不是拼字符串：密码/邀请码里的特殊字符不会破坏 JSON。
func regBody(account, password, invite string) string {
	b, _ := json.Marshal(map[string]string{
		"account":     account,
		"password":    password,
		"invite_code": invite,
	})
	return string(b)
}

// TestWebRegisterPageReturnsHTML 锁定"主网关 GET 返回表单页"。
func TestWebRegisterPageReturnsHTML(t *testing.T) {
	env := newWebRegisterEnv(t, false)
	s := env.srv

	req := httptest.NewRequest("GET", "/api/register", nil)
	w := httptest.NewRecorder()
	s.handleWebRegisterPage(w, req)

	if w.Code != 200 {
		t.Fatalf("状态码应为 200，实得 %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type 应为 text/html，实得 %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "注册账号") {
		t.Fatal("页面里应有「注册账号」标题")
	}
	if !strings.Contains(body, "/api/register") {
		t.Fatal("页面应 POST 到 /api/register")
	}
	// 防点击劫持
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("应设置 X-Frame-Options: DENY")
	}
}

// TestWebRegisterPageOnSlaveShowsPrimary 锁定"从网关返回说明页 + 主网关地址"。
func TestWebRegisterPageOnSlaveShowsPrimary(t *testing.T) {
	env := newWebRegisterEnv(t, true)
	s := env.srv

	req := httptest.NewRequest("GET", "/api/register", nil)
	w := httptest.NewRecorder()
	s.handleWebRegisterPage(w, req)

	if w.Code != 200 {
		t.Fatalf("说明页状态码应为 200，实得 %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "主网关") {
		t.Fatal("说明页应提到主网关")
	}
	// PeerBaseUrl 应被拼进链接
	if !strings.Contains(body, "10.0.0.1:8080/api/register") {
		t.Fatalf("说明页应给出主网关注册地址，实得:\n%s", body)
	}
}

// TestWebRegisterRejectedOnSlave 锁定"从网关 POST 403"。
func TestWebRegisterRejectedOnSlave(t *testing.T) {
	env := newWebRegisterEnv(t, true)
	s, db := env.srv, env.db

	body := regBody("slaveuser", "pwd123456", env.invite)
	req := httptest.NewRequest("POST", "/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleWebRegister(w, req)

	if w.Code != 403 {
		t.Fatalf("从网关应 403，实得 %d（body=%s）", w.Code, w.Body.String())
	}

	// 关键：不该建号
	acc, _ := db.GetAccountByName("slaveuser")
	if acc != nil {
		t.Fatal("从网关竟然建了号 —— 注册入口不唯一")
	}
}

// TestWebRegisterSuccess 锁定"注册成功且账号可验密"。
func TestWebRegisterSuccess(t *testing.T) {
	env := newWebRegisterEnv(t, false)
	s, db := env.srv, env.db

	body := regBody("webuser", "pwd123456", env.invite)
	req := httptest.NewRequest("POST", "/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleWebRegister(w, req)

	if w.Code != 200 {
		t.Fatalf("应 200，实得 %d（body=%s）", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Fatalf("应 ok=true，实得 %v", resp)
	}

	// 账号应进库
	acc, err := db.GetAccountByName("webuser")
	if err != nil || acc == nil {
		t.Fatalf("注册后应有账号: err=%v", err)
	}

	// ★ 关键：存的哈希必须能用 MD5(明文) 验过
	//   （网关算的是 MD5，若 Web 端自己算 MD5 而编码不一致，这里会红）
	wantHash := security.DeriveHash(security.HashMD5("pwd123456"), acc.Salt)
	if acc.PwdHash != wantHash {
		t.Fatal("Web 注册存的哈希用 MD5(明文) 验不过 —— 登录器将无法登录这个号")
	}
}

// TestWebRegisterValidation 锁定参数校验（都给可操作文案）。
func TestWebRegisterValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"账号太短", `{"account":"ab","password":"pwd123456"}`, "3"},
		{"账号太长", `{"account":"` + strings.Repeat("a", 21) + `","password":"pwd123456"}`, "20"},
		{"账号含非法字符", `{"account":"user_name","password":"pwd123456"}`, "字母或数字"},
		{"密码太短", `{"account":"okuser","password":"12345"}`, "6"},
		{"密码太长", `{"account":"okuser","password":"` + strings.Repeat("x", 33) + `"}`, "32"},
		{"账号为空", `{"account":"","password":"pwd123456"}`, "账号"},
		{"非法 JSON", `{`, "格式"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newWebRegisterEnv(t, false)
	s, db := env.srv, env.db
			req := httptest.NewRequest("POST", "/api/register", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.handleWebRegister(w, req)

			if w.Code != 400 {
				t.Fatalf("%s 应 400，实得 %d", tc.name, w.Code)
			}
			var resp map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			msg, _ := resp["message"].(string)
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("%s 的文案应含 %q，实得 %q", tc.name, tc.want, msg)
			}

			// 校验失败不该建号
			if acc, _ := db.GetAccountByName("okuser"); acc != nil {
				t.Fatalf("%s 校验失败却建了号", tc.name)
			}
		})
	}
}

// TestWebRegisterRejectsCrossOrigin 锁定"跨站 POST 被拒"。
func TestWebRegisterRejectsCrossOrigin(t *testing.T) {
	env := newWebRegisterEnv(t, false)
	s, db := env.srv, env.db

	body := regBody("csrfuser", "pwd123456", env.invite)
	req := httptest.NewRequest("POST", "/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "gw.example.com:8080"
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()
	s.handleWebRegister(w, req)

	if w.Code != 403 {
		t.Fatalf("跨站应 403，实得 %d", w.Code)
	}
	if acc, _ := db.GetAccountByName("csrfuser"); acc != nil {
		t.Fatal("跨站请求竟然建了号")
	}
}

// TestWebRegisterAllowsSameOrigin 锁定"同源 POST 放行"。
func TestWebRegisterAllowsSameOrigin(t *testing.T) {
	env := newWebRegisterEnv(t, false)
	s := env.srv

	body := regBody("sameuser", "pwd123456", env.invite)
	req := httptest.NewRequest("POST", "/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "gw.example.com:8080"
	req.Header.Set("Origin", "https://gw.example.com:8080")
	w := httptest.NewRecorder()
	s.handleWebRegister(w, req)

	if w.Code != 200 {
		t.Fatalf("同源应放行，实得 %d（body=%s）", w.Code, w.Body.String())
	}
}

// TestWebRegisterForwardsToS5A3 锁定"Web 注册也转发给 S5A3"。
//
// Web 表单收的是明文，所以能转发 —— 与登录器同一份实现（RegisterPlatform）。
func TestWebRegisterForwardsToS5A3(t *testing.T) {
	var gotPassword string
	fakeS5A3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotPassword = body["password"]
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer fakeS5A3.Close()

	env := newWebRegisterEnv(t, false)
	s := env.srv
	s.config.GameServers = []config.GameServerEntry{{
		Id: "s5a3", Name: "90CN", Protocol: config.ProtocolS5A3,
		GameServerSection: config.GameServerSection{AccountApiUrl: fakeS5A3.URL},
	}}

	body := regBody("webfw", "plainWebPwd", env.invite)
	req := httptest.NewRequest("POST", "/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleWebRegister(w, req)

	if w.Code != 200 {
		t.Fatalf("应 200，实得 %d（body=%s）", w.Code, w.Body.String())
	}
	if gotPassword != "plainWebPwd" {
		t.Fatalf("应把明文转发给 S5A3，实得 %q", gotPassword)
	}
}

// TestWebRegisterExistingAccount 锁定"重名返回明确文案"。
func TestWebRegisterExistingAccount(t *testing.T) {
	env := newWebRegisterEnv(t, false)
	s, db := env.srv, env.db

	if err := db.InsertAccount(&database.Account{
		MId: "500001", Name: "dupuser", PwdHash: "x", Salt: "y", CreatedAt: 1,
	}); err != nil {
		t.Fatalf("预置账号: %v", err)
	}

	body := regBody("dupuser", "pwd123456", env.invite)
	req := httptest.NewRequest("POST", "/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleWebRegister(w, req)

	if w.Code != 400 {
		t.Fatalf("重名应 400，实得 %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	msg, _ := resp["message"].(string)
	if !strings.Contains(msg, "已被注册") {
		t.Fatalf("文案应说明重名，实得 %q", msg)
	}
	if resp["code"] != float64(models.Err.AccountExists) {
		t.Fatalf("应返回 AccountExists 错误码，实得 %v", resp["code"])
	}
}

// TestWebRegisterBodyLimit 锁定"超大 body 被拒"。
func TestWebRegisterBodyLimit(t *testing.T) {
	env := newWebRegisterEnv(t, false)
	s := env.srv

	// 8 KiB > 4 KiB 上限
	big := `{"account":"biguser","password":"` + strings.Repeat("x", 8000) + `"}`
	req := httptest.NewRequest("POST", "/api/register", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleWebRegister(w, req)

	if w.Code != 400 {
		t.Fatalf("超大 body 应 400，实得 %d", w.Code)
	}
}
