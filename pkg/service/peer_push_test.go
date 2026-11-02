package service

// ============================================================================
// 主→从推送登录器版本测试（2026-10-24 第七轮）
//
// 覆盖五条不变量：
//   ① 配了 Peers 时，上传后每台从网关都收到 POST /internal/launcher/push
//   ② 请求体字段与 httprouter.LauncherPushRequest 的 JSON 契约一致
//   ③ 用从网关自己的 InternalKey（不是主网关的）
//   ④ 没配 Peers → 一个请求都不发
//   ⑤ ★ 某台从网关连不上 → 其它台照样收到，且**不 panic/不返回错误**
//      （推送是加速手段，轮询兜底还在，失败绝不能影响上传成功）
// ============================================================================

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
)

// newPushTestSvc 起一套最小依赖（真 SQLite + 真 PeerSyncService）。
func newPushTestSvc(t *testing.T, cfg *config.GatewayConfig) *PeerSyncService {
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

	cfg.Database.Path = filepath.Join(dir, "gateway.db")
	cfg.Database.GamePath = filepath.Join(dir, "inventory.db")
	return NewPeerSyncService(cfg, lg, db, nil, nil)
}

// TestPushLauncherToPeers 锁定"每台从网关都收到、字段契约正确"。
func TestPushLauncherToPeers(t *testing.T) {
	var mu sync.Mutex
	got := map[string]map[string]interface{}{} // 端口 → 请求体
	gotKey := map[string]string{}              // 端口 → X-Internal-Key

	// 起两个假从网关
	newSlave := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/internal/launcher/push" {
				w.WriteHeader(404)
				return
			}
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			got[name] = body
			gotKey[name] = r.Header.Get("X-Internal-Key")
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true,"skipped":false}`))
		}))
	}
	s1 := newSlave("slave1")
	s2 := newSlave("slave2")
	defer s1.Close()
	defer s2.Close()

	cfg := &config.GatewayConfig{}
	cfg.Signing.Peers = []config.PeerSection{
		{Name: "slave1", InternalUrl: s1.URL, InternalKey: "key-1"},
		{Name: "slave2", InternalUrl: s2.URL, InternalKey: "key-2"},
	}
	svc := newPushTestSvc(t, cfg)

	svc.PushLauncherToPeers("ABCDEF0123456789", "2.5.12", 42)

	// 等异步？不 —— PushLauncherToPeers 是同步遍历的（调用方才需要 go）。
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("两台从网关都应收到，实得 %d 台", len(got))
	}
	for _, name := range []string{"slave1", "slave2"} {
		body := got[name]
		if body["hash"] != "ABCDEF0123456789" {
			t.Fatalf("%s 的 hash 不对: %v", name, body["hash"])
		}
		if body["version"] != "2.5.12" {
			t.Fatalf("%s 的 version 不对: %v", name, body["version"])
		}
		// JSON 数字会解成 float64
		if rev, _ := body["revision"].(float64); rev != 42 {
			t.Fatalf("%s 的 revision 不对: %v", name, body["revision"])
		}
	}
	// 各用自己那把 key
	if gotKey["slave1"] != "key-1" {
		t.Fatalf("slave1 应收到 key-1，实得 %q", gotKey["slave1"])
	}
	if gotKey["slave2"] != "key-2" {
		t.Fatalf("slave2 应收到 key-2，实得 %q", gotKey["slave2"])
	}
}

// TestPushLauncherNoPeers 锁定"没配 Peers 时一个请求都不发"。
func TestPushLauncherNoPeers(t *testing.T) {
	var called int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := &config.GatewayConfig{}
	// 故意配成"从网关形态"（有 PeerInternalUrl）但没有 Peers
	cfg.Signing.PeerInternalUrl = srv.URL
	svc := newPushTestSvc(t, cfg)

	if svc.HasPeers() {
		t.Fatal("没配 Peers 时 HasPeers 应为 false")
	}
	svc.PushLauncherToPeers("H", "1.0.0", 1)

	if called != 0 {
		t.Fatalf("没配 Peers 时不该发任何请求，实得 %d", called)
	}
}

// TestPushLauncherSurvivesDeadPeer 锁定"一台从网关挂了不影响其它台"。
//
// ★ 这是推送设计的关键：它只是**加速**，失败必须完全无害。
//   如果一台连不上就让整批失败（或 panic），那"上传成功"就会被拖成失败。
func TestPushLauncherSurvivesDeadPeer(t *testing.T) {
	var okCalled int
	var mu sync.Mutex
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		okCalled++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer good.Close()

	// 占一个端口然后立刻关掉，拿到一个必然连不上的地址
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	cfg := &config.GatewayConfig{}
	cfg.Signing.Peers = []config.PeerSection{
		{Name: "dead", InternalUrl: deadURL, InternalKey: "k"},
		{Name: "good", InternalUrl: good.URL, InternalKey: "k"},
		{Name: "nokey", InternalUrl: good.URL, InternalKey: ""}, // 缺 key 也要跳过而不是崩
	}
	svc := newPushTestSvc(t, cfg)

	// 不能 panic
	svc.PushLauncherToPeers("H", "1.0.0", 1)

	mu.Lock()
	defer mu.Unlock()
	if okCalled != 1 {
		t.Fatalf("好的那台只应被推 1 次，实得 %d", okCalled)
	}
}

// TestPushLauncherPeerReturnsError 锁定"从网关返回非 200 也只是记日志"。
func TestPushLauncherPeerReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(501) // 从网关没配 PeerBaseUrl 时的真实响应
		_, _ = w.Write([]byte(`{"ok":false,"message":"未配置 PeerBaseUrl"}`))
	}))
	defer srv.Close()

	cfg := &config.GatewayConfig{}
	cfg.Signing.Peers = []config.PeerSection{
		{Name: "notslave", InternalUrl: srv.URL, InternalKey: "k"},
	}
	svc := newPushTestSvc(t, cfg)

	// 501 不该 panic、不该让调用方失败
	svc.PushLauncherToPeers("H", "1.0.0", 1)
}

// TestPushLauncherTrailingSlash 锁定"InternalUrl 带尾斜杠也能正确拼路径"。
func TestPushLauncherTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := &config.GatewayConfig{}
	// 故意带尾斜杠 —— 运维手滑很常见
	cfg.Signing.Peers = []config.PeerSection{
		{Name: "slash", InternalUrl: srv.URL + "/", InternalKey: "k"},
	}
	svc := newPushTestSvc(t, cfg)

	svc.PushLauncherToPeers("H", "1.0.0", 1)

	if gotPath != "/internal/launcher/push" {
		t.Fatalf("尾斜杠应被去掉，实得路径 %q", gotPath)
	}
}

// TestPushLauncherTimeout 锁定"慢从网关不会让调用方永久卡住"。
//
// 10s 超时：慢到这个程度说明链路有问题，轮询兜底会处理。
func TestPushLauncherTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // 挂住不响应
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	cfg := &config.GatewayConfig{}
	cfg.Signing.Peers = []config.PeerSection{
		{Name: "slow", InternalUrl: srv.URL, InternalKey: "k"},
	}
	svc := newPushTestSvc(t, cfg)

	done := make(chan struct{})
	go func() {
		svc.PushLauncherToPeers("H", "1.0.0", 1)
		close(done)
	}()

	select {
	case <-done:
		// 正常返回（10s 超时后）
	case <-time.After(15 * time.Second):
		t.Fatal("推送在慢从网关上卡住超过 15s —— 超时没生效")
	}
}
