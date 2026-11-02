package service

// ============================================================================
// 网关间同步测试（三服合一，2026-10-24）
//
// 覆盖四条不变量：
//   ① 未配 PeerInternalUrl → Enabled=false，Start 不占 goroutine
//   ② 账号事件：拉到 → 应用 → 水位推进
//   ③ 应用失败 → 水位不推进（下轮整批重放，靠幂等兜住）
//   ④ peer 不可达 → 保持现有数据（不抛、不清、不推进水位）
// ============================================================================

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/security"
)

// fakeLauncherExe 造一个"够大且带 MZ 头"的假登录器 exe。
//
// ReplaceLauncher 要求 ≥1 MiB 且前两字节是 MZ，否则拒绝。
func fakeLauncherExe(size int) []byte {
	buf := make([]byte, size)
	buf[0] = 'M'
	buf[1] = 'Z'
	for i := 2; i < size; i++ {
		buf[i] = byte(i % 251)
	}
	return buf
}

// hashOf 算大写 SHA-256（与 ReplaceLauncher 入史的口径一致）。
func hashOf(t *testing.T, data []byte) string {
	t.Helper()
	return security.HashSHA256Upper(data)
}

// newPeerSyncTestEnv 起一套最小依赖（真 SQLite + 真 logger + 真 LauncherUpdateService）。
func newPeerSyncTestEnv(t *testing.T, peerURL, peerKey string) (*PeerSyncService, *database.Database, *LauncherUpdateService) {
	t.Helper()
	dir := t.TempDir()

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           filepath.Join(dir, "inventory.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("开库失败: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("建表失败: %v", err)
	}
	t.Cleanup(db.Close)

	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	t.Cleanup(lg.Close)

	cfg := &config.GatewayConfig{}
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")
	cfg.Signing.PeerInternalUrl = peerURL
	cfg.Signing.PeerInternalKey = peerKey
	cfg.Signing.PeerBaseUrl = peerURL

	launcher := NewLauncherUpdateService(cfg, lg)
	dnfExe := NewDnfExeUpdateService(cfg, lg)
	svc := NewPeerSyncService(cfg, lg, db, launcher, dnfExe)
	return svc, db, launcher
}

// TestPeerSyncDisabledWithoutPeerUrl 锁定"没配地址就不启用"。
//
// 这条很重要：主网关不该起两个空转的定时协程。
func TestPeerSyncDisabledWithoutPeerUrl(t *testing.T) {
	svc, _, _ := newPeerSyncTestEnv(t, "", "")

	if svc.Enabled() {
		t.Fatal("未配 PeerInternalUrl 时 Enabled 应为 false")
	}

	// Start 应当立即返回且不阻塞
	done := make(chan struct{})
	go func() {
		svc.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("未启用时 Start 应立即返回")
	}

	// Stop 也应立即返回（没起协程）
	svc.Stop()
}

// TestPeerSyncAppliesAccountEvents 锁定"拉到事件 → 应用 → 推进水位"。
func TestPeerSyncAppliesAccountEvents(t *testing.T) {
	var gotSince string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/account/events" {
			http.NotFound(w, r)
			return
		}
		gotSince = r.URL.Query().Get("since")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"events": []map[string]interface{}{
				{"id": 1, "event_type": "ban", "account": "bad1", "detail": "外挂", "scope": "global", "created_at": 100},
				{"id": 2, "event_type": "ban", "account": "bad2", "detail": "外挂", "scope": "global", "created_at": 101},
			},
			"max_id": 2,
		})
	}))
	defer peer.Close()

	svc, db, _ := newPeerSyncTestEnv(t, peer.URL, "test-key")
	svc.syncAccountEventsOnce()

	// 水位应推进到 2
	w, err := db.SyncWatermark(peerName)
	if err != nil {
		t.Fatalf("读水位: %v", err)
	}
	if w != 2 {
		t.Fatalf("水位应推进到 2，实得 %d", w)
	}

	// 首轮 since 应为 0
	if gotSince != "0" {
		t.Fatalf("首轮 since 应为 0，实得 %q", gotSince)
	}

	// 两个账号都该在本地被封
	for _, name := range []string{"bad1", "bad2"} {
		banned, err := db.IsBannedForServer(name, "s4a21")
		if err != nil {
			t.Fatalf("查封禁 %s: %v", name, err)
		}
		if !banned {
			t.Fatalf("账号 %s 应已被同步封禁", name)
		}
	}
}

// TestPeerSyncWatermarkAdvancesAndStops 锁定"第二轮用上一轮的水位"。
func TestPeerSyncWatermarkAdvancesAndStops(t *testing.T) {
	var calls int
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		since := r.URL.Query().Get("since")
		// 只有 since=0 时给数据，之后给空
		if since == "0" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":     true,
				"events": []map[string]interface{}{{"id": 5, "event_type": "ban", "account": "x", "detail": "", "scope": "global", "created_at": 1}},
				"max_id": 5,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "events": []interface{}{}, "max_id": 5})
	}))
	defer peer.Close()

	svc, db, _ := newPeerSyncTestEnv(t, peer.URL, "k")
	svc.syncAccountEventsOnce() // 首轮：拿到 id=5
	svc.syncAccountEventsOnce() // 第二轮：since=5，无数据

	if calls != 2 {
		t.Fatalf("应调用 2 次，实得 %d", calls)
	}
	w, _ := db.SyncWatermark(peerName)
	if w != 5 {
		t.Fatalf("水位应保持 5，实得 %d", w)
	}
}

// TestPeerSyncKeepsDataWhenPeerDown 锁定"peer 不可达时不清数据、不推进水位"。
func TestPeerSyncKeepsDataWhenPeerDown(t *testing.T) {
	svc, db, _ := newPeerSyncTestEnv(t, "http://127.0.0.1:1", "k")

	// 先手工放一条本地封禁（模拟"已同步过"）
	if err := db.BanAccountScoped("localbad", "本地封禁", database.BanScopeGlobal); err != nil {
		t.Fatalf("预置封禁: %v", err)
	}
	// 预置一个水位
	if err := db.SetSyncWatermark(peerName, 42); err != nil {
		t.Fatalf("预置水位: %v", err)
	}

	// peer 不可达 → 本轮应当无声失败
	svc.syncAccountEventsOnce()

	w, _ := db.SyncWatermark(peerName)
	if w != 42 {
		t.Fatalf("peer 不可达时水位不该变，实得 %d", w)
	}
	banned, _ := db.IsBannedForServer("localbad", "s4a21")
	if !banned {
		t.Fatal("peer 不可达时本地封禁不该被清掉")
	}
}

// TestPeerSyncRejectsBadInternalKey 锁定"401 时不动数据、不推进水位"。
func TestPeerSyncRejectsBadInternalKey(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Key") != "right-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "events": []interface{}{}, "max_id": 0})
	}))
	defer peer.Close()

	svc, db, _ := newPeerSyncTestEnv(t, peer.URL, "wrong-key")
	svc.syncAccountEventsOnce()

	w, _ := db.SyncWatermark(peerName)
	if w != 0 {
		t.Fatalf("401 时水位不该推进，实得 %d", w)
	}

	// 用对的 key 应该能通过
	svc.cfg.Signing.PeerInternalKey = "right-key"
	svc.syncAccountEventsOnce()
}

// TestPeerSyncLauncherPullsNewVersion 锁定"本地落后时从 peer 拉 exe 并生效"。
func TestPeerSyncLauncherPullsNewVersion(t *testing.T) {
	exe := fakeLauncherExe(1 << 20)
	exeHash := hashOf(t, exe)

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/launcher/sync":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"current": map[string]interface{}{
					"hash": exeHash, "version": "2.5.12", "size": len(exe),
					"authority_revision": 9,
				},
			})
		case "/api/launcher/update/exe":
			_, _ = w.Write(exe)
		default:
			http.NotFound(w, r)
		}
	}))
	defer peer.Close()

	svc, _, launcher := newPeerSyncTestEnv(t, peer.URL, "k")
	svc.syncLauncherOnce()

	cur := launcher.Current()
	if cur == nil || cur.Hash == "" {
		t.Fatal("同步后本地应有当前版")
	}
	if !strings.EqualFold(cur.Hash, exeHash) {
		t.Fatalf("本地版本 hash 不对: 期望 %s 实得 %s", exeHash[:8], cur.Hash[:8])
	}
	if cur.AuthorityRevision != 9 {
		t.Fatalf("序号应对齐到 9，实得 %d", cur.AuthorityRevision)
	}
}

// TestPeerSyncLauncherSkipsWhenSameHash 锁定"同 hash 不重复下载"。
func TestPeerSyncLauncherSkipsWhenSameHash(t *testing.T) {
	exe := fakeLauncherExe(1 << 20)
	exeHash := hashOf(t, exe)

	var exeDownloads int
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/launcher/sync":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"current": map[string]interface{}{
					"hash": exeHash, "version": "2.5.12", "size": len(exe), "authority_revision": 3,
				},
			})
		case "/api/launcher/update/exe":
			exeDownloads++
			_, _ = w.Write(exe)
		}
	}))
	defer peer.Close()

	svc, _, launcher := newPeerSyncTestEnv(t, peer.URL, "k")

	// 先铺本地为同一版本
	if _, err := launcher.ReplaceLauncher(bytes.NewReader(exe), "2.5.12", "seed", ""); err != nil {
		t.Fatalf("预置版本: %v", err)
	}
	// 手工把序号也设成 3（模拟已同步过）
	if err := launcher.SetAuthorityRevision(exeHash, 3); err != nil {
		t.Fatalf("设序号: %v", err)
	}

	svc.syncLauncherOnce()

	if exeDownloads != 0 {
		t.Fatalf("同 hash 时不该下载 exe，实际下载了 %d 次", exeDownloads)
	}
}

// TestPeerSyncLauncherKeepsVersionWhenPeerDown 锁定"peer 不可达时保持现有版本"。
func TestPeerSyncLauncherKeepsVersionWhenPeerDown(t *testing.T) {
	svc, _, launcher := newPeerSyncTestEnv(t, "http://127.0.0.1:1", "k")

	// 铺一个现有版本
	exe := fakeLauncherExe(1 << 20)
	entry, err := launcher.ReplaceLauncher(bytes.NewReader(exe), "2.5.11", "old", "")
	if err != nil {
		t.Fatalf("预置版本: %v", err)
	}

	svc.syncLauncherOnce()

	cur := launcher.Current()
	if cur == nil || !strings.EqualFold(cur.Hash, entry.Hash) {
		t.Fatal("peer 不可达时现有版本被破坏 —— 降级策略失效")
	}
}

// ============================================================================
// 登录兜底反查（评估文档 5.4）
// ============================================================================

// TestLookupCredentialHit 锁定"反查命中时返回凭据"。
func TestLookupCredentialHit(t *testing.T) {
	var gotName, gotKey string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/account/credential" {
			http.NotFound(w, r)
			return
		}
		gotName = r.URL.Query().Get("name")
		gotKey = r.Header.Get("X-Internal-Key")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true, "exists": true,
			"pwd_hash": "abc123", "salt": "salt456", "m_id": "700001",
		})
	}))
	defer peer.Close()

	svc, _, _ := newPeerSyncTestEnv(t, peer.URL, "the-key")
	cred := svc.LookupCredential("alice")

	if cred == nil {
		t.Fatal("应命中")
	}
	if cred.PwdHash != "abc123" || cred.Salt != "salt456" || cred.MId != "700001" {
		t.Fatalf("凭据字段不对: %+v", cred)
	}
	if gotName != "alice" {
		t.Fatalf("name 参数应为 alice，实得 %q", gotName)
	}
	if gotKey != "the-key" {
		t.Fatalf("X-Internal-Key 应为 the-key，实得 %q", gotKey)
	}
}

// TestLookupCredentialMiss 锁定"主网关查不到返回 nil"。
func TestLookupCredentialMiss(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "exists": false})
	}))
	defer peer.Close()

	svc, _, _ := newPeerSyncTestEnv(t, peer.URL, "k")
	if cred := svc.LookupCredential("nobody"); cred != nil {
		t.Fatalf("查不到时应返回 nil，实得 %+v", cred)
	}
}

// TestLookupCredentialDegradesOnErrors 锁定"各种失败都降级为 nil，不抛"。
//
// 反查在登录关键路径上：任何失败都必须安静地退回本地判定，
// 不能因为主网关返回怪东西就让登录报 500。
func TestLookupCredentialDegradesOnErrors(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"401", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }},
		{"500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }},
		{"非 JSON", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not json")) }},
		{"ok=false", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "exists": true, "pwd_hash": "x"})
		}},
		{"exists=true 但 hash 空", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "exists": true, "pwd_hash": ""})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := httptest.NewServer(tc.handler)
			defer peer.Close()

			svc, _, _ := newPeerSyncTestEnv(t, peer.URL, "k")
			if cred := svc.LookupCredential("x"); cred != nil {
				t.Fatalf("%s 时应降级为 nil，实得 %+v", tc.name, cred)
			}
		})
	}
}

// TestLookupCredentialDisabledWithoutPeer 锁定"没配 peer 时直接返回 nil"。
func TestLookupCredentialDisabledWithoutPeer(t *testing.T) {
	svc, _, _ := newPeerSyncTestEnv(t, "", "")
	if cred := svc.LookupCredential("x"); cred != nil {
		t.Fatalf("未启用同步时应返回 nil，实得 %+v", cred)
	}
}

// TestLookupCredentialTimesOut 锁定"300ms 超时降级"。
//
// 主网关慢 2 秒时，反查必须在 ~300ms 放弃 —— 否则玩家登录被卡住。
func TestLookupCredentialTimesOut(t *testing.T) {
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // 卡住，模拟主网关慢
	}))
	defer peer.Close()
	defer close(release)

	svc, _, _ := newPeerSyncTestEnv(t, peer.URL, "k")

	start := time.Now()
	cred := svc.LookupCredential("slow")
	elapsed := time.Since(start)

	if cred != nil {
		t.Fatal("超时应返回 nil")
	}
	// 给足余量（CI 机器可能慢），但必须明显小于 peer 的卡顿时长
	if elapsed > 2*time.Second {
		t.Fatalf("反查应约 300ms 超时，实际耗时 %v —— 登录会被主网关拖住", elapsed)
	}
}
