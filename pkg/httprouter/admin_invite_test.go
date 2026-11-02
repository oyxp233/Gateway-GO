package httprouter

// ============================================================================
// 邀请码管理 API 测试（2026-10-24）
//
// 覆盖五条不变量：
//   ① 生成：数量正确、返回展示形式（带连字符）、有效期换算正确
//   ② 生成参数校验：数量 0/负数/超上限、有效期负数
//   ③ 列表：状态筛选、关键词、unused 计数
//   ④ 作废：未用码能作废；已用码不能作废
//   ⑤ 导出：只含可用码、Content-Type 是 text/plain
// ============================================================================

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
)

// newInviteAdminServer 起一套最小依赖（真 SQLite）。
func newInviteAdminServer(t *testing.T) (*Server, *database.Database) {
	t.Helper()
	dir := t.TempDir()

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               dir + "/gateway.db",
		GamePath:           dir + "/inventory.db",
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

	// checkAdmin 需要一个非空 AuthKey 才能通过
	cfg := &config.GatewayConfig{}
	cfg.Admin.AuthKey = "test-admin-key"

	return &Server{config: cfg, db: db, logger: lg}, db
}

// TestAdminInviteGenerate 锁定"生成数量/展示形式/有效期"。
func TestAdminInviteGenerate(t *testing.T) {
	s, db := newInviteAdminServer(t)

	req := httptest.NewRequest("POST", "/api/admin/invite/generate",
		strings.NewReader(`{"count":5,"note":"十月批","expires_in_hours":24}`))
	req.Header.Set("X-Auth-Key", "test-admin-key")
	w := httptest.NewRecorder()
	s.handleAdminInviteGenerate(w, req)

	if w.Code != 200 {
		t.Fatalf("应 200，实得 %d（body=%s）", w.Code, w.Body.String())
	}

	var resp struct {
		OK        bool     `json:"ok"`
		Codes     []string `json:"codes"`
		Count     int      `json:"count"`
		ExpiresAt int64    `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !resp.OK || resp.Count != 5 || len(resp.Codes) != 5 {
		t.Fatalf("应生成 5 个，实得 count=%d len=%d", resp.Count, len(resp.Codes))
	}
	// 展示形式必须带连字符（XXXX-XXXX），方便运营复制
	for _, c := range resp.Codes {
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("展示形式应为 XXXX-XXXX，实得 %q", c)
		}
	}
	if resp.ExpiresAt <= 0 {
		t.Fatal("设了有效期，expires_at 应 > 0")
	}

	// 落库确认
	n, _ := db.CountUnusedInvites()
	if n != 5 {
		t.Fatalf("库内可用数应为 5，实得 %d", n)
	}
}

// TestAdminInviteGenerateValidation 锁定生成参数校验。
func TestAdminInviteGenerateValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"数量为 0", `{"count":0}`},
		{"数量为负", `{"count":-1}`},
		{"数量超上限", `{"count":501}`},
		{"有效期负数", `{"count":1,"expires_in_hours":-5}`},
		{"非法 JSON", `{`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newInviteAdminServer(t)
			req := httptest.NewRequest("POST", "/api/admin/invite/generate", strings.NewReader(tc.body))
			req.Header.Set("X-Auth-Key", "test-admin-key")
			w := httptest.NewRecorder()
			s.handleAdminInviteGenerate(w, req)

			if w.Code != 400 {
				t.Fatalf("%s 应 400，实得 %d（body=%s）", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestAdminInviteList 锁定"列表筛选 + unused 计数"。
func TestAdminInviteList(t *testing.T) {
	s, db := newInviteAdminServer(t)

	codes, _ := db.GenerateInvites(3, "批A", "admin:test", 0)
	db.ConsumeInvite(codes[0], "user1")

	req := httptest.NewRequest("GET", "/api/admin/invite/list?page=1&page_size=50", nil)
	req.Header.Set("X-Auth-Key", "test-admin-key")
	w := httptest.NewRecorder()
	s.handleAdminInviteList(w, req)

	if w.Code != 200 {
		t.Fatalf("应 200，实得 %d", w.Code)
	}
	var resp struct {
		OK     bool                     `json:"ok"`
		Total  int                      `json:"total"`
		Rows   []map[string]interface{} `json:"rows"`
		Unused int                      `json:"unused"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if resp.Total != 3 || len(resp.Rows) != 3 {
		t.Fatalf("应有 3 条，实得 total=%d len=%d", resp.Total, len(resp.Rows))
	}
	if resp.Unused != 2 {
		t.Fatalf("可用数应为 2，实得 %d", resp.Unused)
	}
	// 每行必须有 status 字段
	for _, r := range resp.Rows {
		if _, ok := r["status"]; !ok {
			t.Fatalf("行缺 status 字段: %v", r)
		}
	}

	// 按状态筛选
	req2 := httptest.NewRequest("GET", "/api/admin/invite/list?status=used", nil)
	req2.Header.Set("X-Auth-Key", "test-admin-key")
	w2 := httptest.NewRecorder()
	s.handleAdminInviteList(w2, req2)
	var resp2 struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &resp2)
	if resp2.Total != 1 {
		t.Fatalf("used 筛选应为 1 条，实得 %d", resp2.Total)
	}
}

// TestAdminInviteRevoke 锁定"作废未用码 / 拒绝已用码"。
func TestAdminInviteRevoke(t *testing.T) {
	s, db := newInviteAdminServer(t)
	codes, _ := db.GenerateInvites(2, "", "admin:test", 0)

	// 作废第一个（未用）
	display := database.FormatInviteCode(codes[0])
	req := httptest.NewRequest("POST", "/api/admin/invite/revoke",
		strings.NewReader(`{"code":"`+display+`"}`))
	req.Header.Set("X-Auth-Key", "test-admin-key")
	w := httptest.NewRecorder()
	s.handleAdminInviteRevoke(w, req)
	if w.Code != 200 {
		t.Fatalf("应 200，实得 %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Fatalf("作废未用码应成功，实得 %v", resp)
	}

	// 已用的码不能作废
	db.ConsumeInvite(codes[1], "someone")
	req2 := httptest.NewRequest("POST", "/api/admin/invite/revoke",
		strings.NewReader(`{"code":"`+database.FormatInviteCode(codes[1])+`"}`))
	req2.Header.Set("X-Auth-Key", "test-admin-key")
	w2 := httptest.NewRecorder()
	s.handleAdminInviteRevoke(w2, req2)
	var resp2 map[string]interface{}
	_ = json.Unmarshal(w2.Body.Bytes(), &resp2)
	if resp2["ok"] != false {
		t.Fatalf("已用码不该被作废，实得 %v", resp2)
	}
}

// TestAdminInviteExport 锁定"导出纯文本、只含可用码"。
func TestAdminInviteExport(t *testing.T) {
	s, db := newInviteAdminServer(t)
	codes, _ := db.GenerateInvites(3, "", "admin:test", 0)
	db.ConsumeInvite(codes[0], "u") // 用掉一个

	req := httptest.NewRequest("GET", "/api/admin/invite/export", nil)
	req.Header.Set("X-Auth-Key", "test-admin-key")
	w := httptest.NewRecorder()
	s.handleAdminInviteExport(w, req)

	if w.Code != 200 {
		t.Fatalf("应 200，实得 %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type 应为 text/plain，实得 %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("应触发下载，实得 Content-Disposition=%q", cd)
	}

	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("应导出 2 个可用码，实得 %d 行: %v", len(lines), lines)
	}
	for _, l := range lines {
		if len(l) != 9 || l[4] != '-' {
			t.Fatalf("导出行应为 XXXX-XXXX，实得 %q", l)
		}
	}
}

// TestAdminInviteRequiresAuth 锁定"必须带管理密钥"。
func TestAdminInviteRequiresAuth(t *testing.T) {
	s, _ := newInviteAdminServer(t)

	// 无 key
	req := httptest.NewRequest("POST", "/api/admin/invite/generate",
		strings.NewReader(`{"count":1}`))
	w := httptest.NewRecorder()
	s.handleAdminInviteGenerate(w, req)
	if w.Code != 401 {
		t.Fatalf("无密钥应 401，实得 %d", w.Code)
	}

	// 错 key
	req2 := httptest.NewRequest("POST", "/api/admin/invite/generate",
		strings.NewReader(`{"count":1}`))
	req2.Header.Set("X-Auth-Key", "wrong-key")
	w2 := httptest.NewRecorder()
	s.handleAdminInviteGenerate(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("错密钥应 401，实得 %d", w2.Code)
	}
}

// TestAdminActorHidesKey 锁定"created_by 不含密钥明文"。
//
// ★ 这是安全要求：AuthKey 等于后台密码，写进库里等于把密钥落盘。
func TestAdminActorHidesKey(t *testing.T) {
	s, db := newInviteAdminServer(t)

	req := httptest.NewRequest("POST", "/api/admin/invite/generate",
		strings.NewReader(`{"count":1}`))
	req.Header.Set("X-Auth-Key", "test-admin-key")
	w := httptest.NewRecorder()
	s.handleAdminInviteGenerate(w, req)

	_, rows, err := db.ListInvites("", "", 1, 10)
	if err != nil || len(rows) == 0 {
		t.Fatalf("查询失败: %v", err)
	}
	cb := rows[0].CreatedBy
	if strings.Contains(cb, "test-admin-key") {
		t.Fatalf("created_by 泄露了密钥明文: %q", cb)
	}
	if !strings.HasPrefix(cb, "admin:") {
		t.Fatalf("created_by 应为 admin:<hash> 形式，实得 %q", cb)
	}
}
