package httprouter

// ============================================================================
// 账号凭据反查接口测试（三服合一，评估文档 5.4）
//
// GET /internal/account/credential?name=X
//
// 三条不变量：
//   ① 账号存在 → 200 + exists=true + pwd_hash/salt/m_id
//   ② 账号不存在 → 200 + exists=false（★ 不是 404：让从网关只有一条判定分支）
//   ③ name 为空 → 400
// ============================================================================

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
)

func newCredentialServer(t *testing.T) (*Server, *database.Database) {
	t.Helper()
	dir := t.TempDir()

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           filepath.Join(dir, "inventory.db"),
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

	return &Server{config: &config.GatewayConfig{}, db: db, logger: lg}, db
}

// TestInternalAccountCredentialFound 锁定"存在时返回凭据三件套"。
func TestInternalAccountCredentialFound(t *testing.T) {
	s, db := newCredentialServer(t)

	if err := db.InsertAccount(&database.Account{
		MId: "600001", Name: "alice", PwdHash: "hash-abc", Salt: "salt-xyz", CreatedAt: 1,
	}); err != nil {
		t.Fatalf("预置账号: %v", err)
	}

	req := httptest.NewRequest("GET", "/internal/account/credential?name=alice", nil)
	w := httptest.NewRecorder()
	s.handleInternalAccountCredential(w, req)

	if w.Code != 200 {
		t.Fatalf("状态码应为 200，实得 %d（body=%s）", w.Code, w.Body.String())
	}

	var resp AccountCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !resp.OK || !resp.Exists {
		t.Fatalf("应 exists=true，实得 %+v", resp)
	}
	if resp.PwdHash != "hash-abc" || resp.Salt != "salt-xyz" || resp.MId != "600001" {
		t.Fatalf("凭据字段不对: %+v", resp)
	}
}

// TestInternalAccountCredentialNotFound 锁定"不存在时 200 + exists=false"。
//
// ★ 刻意不用 404：从网关的判定逻辑应该只有"exists 是 true 还是 false"一条分支。
//   404 会逼调用方额外区分"网络错 / 404 / 200"，多一处分支就多一处漏判。
func TestInternalAccountCredentialNotFound(t *testing.T) {
	s, _ := newCredentialServer(t)

	req := httptest.NewRequest("GET", "/internal/account/credential?name=ghost", nil)
	w := httptest.NewRecorder()
	s.handleInternalAccountCredential(w, req)

	if w.Code != 200 {
		t.Fatalf("不存在时应返回 200，实得 %d", w.Code)
	}

	var resp AccountCredentialResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.OK {
		t.Fatal("ok 应为 true（查询成功，只是没有这个账号）")
	}
	if resp.Exists {
		t.Fatal("exists 应为 false")
	}
	if resp.PwdHash != "" {
		t.Fatalf("不存在时不该返回哈希，实得 %q", resp.PwdHash)
	}
}

// TestInternalAccountCredentialEmptyName 锁定参数校验。
func TestInternalAccountCredentialEmptyName(t *testing.T) {
	s, _ := newCredentialServer(t)

	for _, url := range []string{
		"/internal/account/credential",
		"/internal/account/credential?name=",
		"/internal/account/credential?name=%20%20",
	} {
		req := httptest.NewRequest("GET", url, nil)
		w := httptest.NewRecorder()
		s.handleInternalAccountCredential(w, req)
		if w.Code != 400 {
			t.Fatalf("%s 应返回 400，实得 %d", url, w.Code)
		}
	}
}

// TestInternalAccountCredentialRequiresKey 锁定"必须带 X-Internal-Key"。
//
// 这个接口会返回密码哈希，绝不能免鉴权暴露（虽然内部端口只绑 loopback，
// 但 loopback 上的其它进程也是威胁）。
func TestInternalAccountCredentialRequiresKey(t *testing.T) {
	s, _ := newCredentialServer(t)
	s.config.Admin.InternalKey = "the-internal-key"

	// 无 key → 401
	req := httptest.NewRequest("GET", "/internal/account/credential?name=x", nil)
	w := httptest.NewRecorder()
	s.checkInternal(s.handleInternalAccountCredential)(w, req)
	if w.Code != 401 {
		t.Fatalf("无 key 时应 401，实得 %d", w.Code)
	}

	// 错 key → 401
	req2 := httptest.NewRequest("GET", "/internal/account/credential?name=x", nil)
	req2.Header.Set("X-Internal-Key", "wrong")
	w2 := httptest.NewRecorder()
	s.checkInternal(s.handleInternalAccountCredential)(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("错 key 时应 401，实得 %d", w2.Code)
	}

	// 对 key → 200
	req3 := httptest.NewRequest("GET", "/internal/account/credential?name=x", nil)
	req3.Header.Set("X-Internal-Key", "the-internal-key")
	w3 := httptest.NewRecorder()
	s.checkInternal(s.handleInternalAccountCredential)(w3, req3)
	if w3.Code != 200 {
		t.Fatalf("对 key 时应 200，实得 %d", w3.Code)
	}
}
