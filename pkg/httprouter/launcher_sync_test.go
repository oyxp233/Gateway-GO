package httprouter

// ============================================================================
// 登录器包同步测试（三服合一，2026-10-24）
//
// 覆盖三条不变量：
//   ① 未配 PeerBaseUrl 时 push 返回 501（不假装成功）
//   ② 已有同 hash 时 push 幂等跳过（不重复下载）
//   ③ 从 peer 拉取后本地版本生效，且序号对齐到 peer 的值
// ============================================================================

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/service"
)

// fakeExe 造一个"够大且带 MZ 头"的假登录器 exe。
//
// ReplaceLauncher 要求 ≥1 MiB 且前两字节是 MZ，否则拒绝。
func fakeExe(size int) []byte {
	buf := make([]byte, size)
	buf[0] = 'M'
	buf[1] = 'Z'
	// 填一些非零内容，保证 hash 稳定且不像全零
	for i := 2; i < size; i++ {
		buf[i] = byte(i % 251)
	}
	return buf
}

func newSyncServer(t *testing.T, cfg *config.GatewayConfig) *Server {
	t.Helper()
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("构造 logger 失败: %v", err)
	}
	t.Cleanup(lg.Close)
	return &Server{
		config:         cfg,
		logger:         lg,
		launcherUpdate: service.NewLauncherUpdateService(cfg, lg),
	}
}

// TestLauncherPushRejectsWithoutPeerConfig 锁定"未配 peer 时明确回 501"。
//
// ★ 这条是刻意的：早先的实现返回 200 + "pulling async" 但什么都没做，
//   那是撒谎 —— 运维会以为同步成功。宁可回 501 让人一眼看出没配。
func TestLauncherPushRejectsWithoutPeerConfig(t *testing.T) {
	cfg := &config.GatewayConfig{}
	s := newSyncServer(t, cfg)

	body, _ := json.Marshal(LauncherPushRequest{Hash: strings.Repeat("A", 64), Revision: 1})
	req := httptest.NewRequest("POST", "/internal/launcher/push", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.handleInternalLauncherPush(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("未配 peer 时应返回 501，实得 %d（body=%s）", w.Code, w.Body.String())
	}
}

// TestLauncherPushIdempotent 锁定"已有同 hash 时跳过，不重复下载"。
func TestLauncherPushIdempotent(t *testing.T) {
	dir := t.TempDir()
	exe := fakeExe(1 << 20)

	// 先把 exe 铺成"当前版"
	cfg := &config.GatewayConfig{}
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	cfg.Signing.PeerBaseUrl = "http://127.0.0.1:1" // 故意指向不可达地址
	s := newSyncServer(t, cfg)

	src := bytes.NewReader(exe)
	entry, err := s.launcherUpdate.ReplaceLauncher(src, "2.5.12", "test", "")
	if err != nil {
		t.Fatalf("ReplaceLauncher: %v", err)
	}

	// 推送同一个 hash → 应跳过（且不会去连那个不可达的 peer）
	body, _ := json.Marshal(LauncherPushRequest{
		Hash: entry.Hash, Version: "2.5.12", Revision: 7,
	})
	req := httptest.NewRequest("POST", "/internal/launcher/push", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleInternalLauncherPush(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码应为 200，实得 %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["skipped"] != true {
		t.Fatalf("已有同 hash 时应 skipped=true，实得 %v（body=%s）", resp["skipped"], w.Body.String())
	}
}

// TestLauncherPushRejectsBadBody 锁定参数校验。
func TestLauncherPushRejectsBadBody(t *testing.T) {
	cfg := &config.GatewayConfig{}
	cfg.Signing.PeerBaseUrl = "http://127.0.0.1:1"
	s := newSyncServer(t, cfg)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"缺 hash", `{"revision":1}`},
		{"缺 revision", `{"hash":"AAAA"}`},
		{"revision 为 0", `{"hash":"AAAA","revision":0}`},
		{"非法 JSON", `{`},
	} {
		req := httptest.NewRequest("POST", "/internal/launcher/push", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		s.handleInternalLauncherPush(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 应返回 400，实得 %d", tc.name, w.Code)
		}
	}
}

// TestLauncherSyncReturnsRevisionFiltered 锁定 since 过滤按 AuthorityRevision。
func TestLauncherSyncReturnsRevisionFiltered(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.GatewayConfig{}
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	s := newSyncServer(t, cfg)

	// 铺两个版本
	if _, err := s.launcherUpdate.ReplaceLauncher(bytes.NewReader(fakeExe(1<<20)), "2.5.11", "v1", ""); err != nil {
		t.Fatalf("ReplaceLauncher v1: %v", err)
	}
	// 第二版内容必须不同（否则 hash 相同，ReplaceLauncher 会当同一版）
	exe2 := fakeExe(1 << 20)
	exe2[100] = 0xFF
	if _, err := s.launcherUpdate.ReplaceLauncher(bytes.NewReader(exe2), "2.5.12", "v2", ""); err != nil {
		t.Fatalf("ReplaceLauncher v2: %v", err)
	}

	// since=0 → 全部历史（最多 updateKeep 条）
	req := httptest.NewRequest("GET", "/internal/launcher/sync?since=0", nil)
	w := httptest.NewRecorder()
	s.handleInternalLauncherSync(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码应为 200，实得 %d", w.Code)
	}
	var resp LauncherSyncResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !resp.OK || resp.Current == nil {
		t.Fatalf("响应应 ok=true 且带 current: %+v", resp)
	}
	if len(resp.History) == 0 {
		t.Fatal("since=0 应返回历史条目")
	}

	// 每个历史条目的 AuthorityRevision 必须 > 0
	for _, e := range resp.History {
		if e.AuthorityRevision <= 0 {
			t.Fatalf("历史条目缺 AuthorityRevision: %+v", e)
		}
	}

	// since=很大 → 应无历史
	req2 := httptest.NewRequest("GET", "/internal/launcher/sync?since=999999", nil)
	w2 := httptest.NewRecorder()
	s.handleInternalLauncherSync(w2, req2)
	var resp2 LauncherSyncResponse
	_ = json.Unmarshal(w2.Body.Bytes(), &resp2)
	if len(resp2.History) != 0 {
		t.Fatalf("since=999999 应无历史条目，实得 %d 条", len(resp2.History))
	}
}

// TestPullLauncherFromPeer 锁定完整的"从 peer 拉取 → 本地生效 → 序号对齐"链路。
//
// 用 httptest 起一个假 peer 提供 /api/launcher/update/exe。
func TestPullLauncherFromPeer(t *testing.T) {
	exe := fakeExe(1 << 20)
	exeHash := security.HashSHA256(exe)

	// 假 peer
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/launcher/update/exe" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(exe)
	}))
	defer peer.Close()

	dir := t.TempDir()
	cfg := &config.GatewayConfig{}
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	cfg.Signing.PeerBaseUrl = peer.URL
	s := newSyncServer(t, cfg)

	// 同步执行拉取（生产里是 goroutine，测试里直接调）
	s.pullLauncherFromPeer(peer.URL, LauncherPushRequest{
		Hash: exeHash, Version: "2.5.12", Size: int64(len(exe)), Revision: 42,
	})

	// 本地当前版必须是拉下来的那份
	cur := s.launcherUpdate.Current()
	if cur == nil || cur.Hash == "" {
		t.Fatal("拉取后本地没有当前版")
	}
	if !strings.EqualFold(cur.Hash, exeHash) {
		t.Fatalf("本地当前版 hash 不对: 期望 %s 实得 %s", exeHash[:8], cur.Hash[:8])
	}

	// 序号必须对齐到 peer 的 42（不是本地分配的 1 或 2）
	if cur.AuthorityRevision != 42 {
		t.Fatalf("AuthorityRevision 应同步为 42，实得 %d", cur.AuthorityRevision)
	}
}

// TestPullLauncherRejectsHashMismatch 锁定"指纹不匹配必须丢弃"。
//
// 这是同步链路的完整性硬约束：peer 给什么字节不重要，
// 重要的是字节的 SHA-256 必须等于声明值。
func TestPullLauncherRejectsHashMismatch(t *testing.T) {
	exe := fakeExe(1 << 20)
	wrongHash := strings.Repeat("A", 64) // 故意给错的

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(exe)
	}))
	defer peer.Close()

	dir := t.TempDir()
	cfg := &config.GatewayConfig{}
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	cfg.Signing.PeerBaseUrl = peer.URL
	s := newSyncServer(t, cfg)

	s.pullLauncherFromPeer(peer.URL, LauncherPushRequest{
		Hash: wrongHash, Version: "2.5.12", Revision: 1,
	})

	// 本地不该有任何版本（校验失败，丢弃）
	cur := s.launcherUpdate.Current()
	if cur != nil && cur.Hash != "" {
		t.Fatalf("指纹不匹配时应丢弃，但本地出现了版本: %s", cur.Hash[:8])
	}

	// 临时文件也必须清掉
	entries, _ := os.ReadDir(cfg.Launcher.UpdateDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".sync-") {
			t.Fatalf("临时文件未清理: %s", e.Name())
		}
	}
}

// TestPullLauncherHandlesPeerDown 锁定"peer 不可达时保持现有版本"。
func TestPullLauncherHandlesPeerDown(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.GatewayConfig{}
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	s := newSyncServer(t, cfg)

	// 先铺一个现有版本
	oldExe := fakeExe(1 << 20)
	oldEntry, err := s.launcherUpdate.ReplaceLauncher(bytes.NewReader(oldExe), "2.5.11", "old", "")
	if err != nil {
		t.Fatalf("ReplaceLauncher: %v", err)
	}

	// 指向不可达的 peer 拉新版 → 必须失败但不影响现有版本
	s.pullLauncherFromPeer("http://127.0.0.1:1", LauncherPushRequest{
		Hash: strings.Repeat("B", 64), Version: "2.5.12", Revision: 2,
	})

	cur := s.launcherUpdate.Current()
	if cur == nil || !strings.EqualFold(cur.Hash, oldEntry.Hash) {
		t.Fatal("peer 不可达时现有版本被破坏了 —— 降级策略失效")
	}
}
