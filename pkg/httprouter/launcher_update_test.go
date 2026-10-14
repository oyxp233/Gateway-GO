package httprouter

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/service"
)

// ────────────────────────────────────────────────────────────────────────
// 登录器自更新路由（2026-10-01）
//
// 钉死的静默失效路径：
//   · 清单 404/缺字段   → 登录器误判「网关没升级」或拿不到强更阈值；
//   · 全量/delta 内容错 → 玩家下载的字节与清单 hash 对不上（校验失败卡人）；
//   · 上传未过 bodylimit → 134 MiB exe 被 8 MiB 全局上限打死（P0 功能不可用）；
//   · 无 key 也能传     → 任何人可给全体玩家发 exe（最严重的安全问题）。
// ────────────────────────────────────────────────────────────────────────

func newLauncherUpdateTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Admin.AuthKey = testAdminKey
	cfg.Launcher.MinVersion = "2.3.8"
	cfg.Launcher.UpdateDir = filepath.Join(dir, "launcher_update")

	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })

	return &Server{
		config:         cfg,
		logger:         lg,
		launcherUpdate: service.NewLauncherUpdateService(cfg, lg),
	}
}

// randTestExe 造一个能过 PE 校验的假登录器（MZ 头 + 随机体，>1 MiB）。
func randTestExe(seed int64, n int) []byte {
	b := make([]byte, n)
	// 简易 LCG：测试不需要密码学随机，只要两次调用产出不同内容即可。
	x := seed*6364136223846793005 + 1442695040888963407
	for i := range b {
		x = x*6364136223846793005 + 1442695040888963407
		b[i] = byte(x >> 56)
	}
	b[0] = 'M'
	b[1] = 'Z'
	return b
}

func launcherUploadReq(t *testing.T, body []byte, version, name string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if name != "" {
		_ = mw.WriteField("name", name)
	}
	_ = mw.WriteField("version", version)
	fw, err := mw.CreateFormFile("file", "SimpleLauncher_test.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(body); err != nil {
		t.Fatal(err)
	}
	mw.Close()
	req := httptest.NewRequest("POST", "/api/admin/launcher/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// ① 清单：空部署不带版本信息（登录器据此跳过）；上传后字段齐全；
//    enabled=false 是一键回滚开关。
func TestLauncherUpdateManifestStates(t *testing.T) {
	s := newLauncherUpdateTestServer(t)

	// 空部署：200 + enabled=true + 空 version/hash（不能 404 —— 登录器会把
	// 404 当「网关没升级」）
	rec := httptest.NewRecorder()
	s.handleLauncherUpdateManifest(rec, httptest.NewRequest("GET", "/api/launcher/update", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("空部署清单应 200，实得 %d", rec.Code)
	}
	var m struct {
		OK         bool   `json:"ok"`
		Enabled    bool   `json:"enabled"`
		Version    string `json:"version"`
		Hash       string `json:"hash"`
		MinVersion string `json:"min_version"`
		FullURL    string `json:"full_url"`
		DeltaURL   string `json:"delta_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if !m.OK || !m.Enabled {
		t.Fatalf("空部署应 ok+enabled，实得 %+v", m)
	}
	if m.Version != "" || m.Hash != "" {
		t.Fatalf("空部署不该带 version/hash，实得 %q/%q", m.Version, m.Hash)
	}
	if m.MinVersion != "2.3.8" || m.FullURL == "" || m.DeltaURL == "" {
		t.Fatalf("min_version/full_url/delta_url 必须始终下发，实得 %+v", m)
	}

	// 上传后：version/hash/size 齐全
	rec = httptest.NewRecorder()
	s.handleAdminLauncherUpload(rec, withAdminKey(launcherUploadReq(t, randTestExe(1, 1<<20+4096), "2.4.0", "首个自更新版")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.handleLauncherUpdateManifest(rec, httptest.NewRequest("GET", "/api/launcher/update", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "2.4.0" || m.Hash == "" {
		t.Fatalf("上传后清单应带 v2.4.0 + hash，实得 %+v", m)
	}

	// enabled=false（一键回滚）：清单仍 200，但 enabled=false
	f := false
	s.config.Launcher.UpdateEnabled = &f
	rec = httptest.NewRecorder()
	s.handleLauncherUpdateManifest(rec, httptest.NewRequest("GET", "/api/launcher/update", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Enabled {
		t.Fatal("关闭开关后清单 enabled 必须为 false")
	}
	// 全量/delta 端点在关闭时必须 404（不再下发任何字节）
	if rec := func() *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		s.handleLauncherUpdateExe(r, httptest.NewRequest("GET", "/api/launcher/update/exe", nil))
		return r
	}(); rec.Code != http.StatusNotFound {
		t.Fatalf("关闭开关后全量端点应 404，实得 %d", rec.Code)
	}
}

// ② 全量下载：字节与 current.exe 逐字节一致；空部署 404。
func TestLauncherUpdateExeServesCurrent(t *testing.T) {
	s := newLauncherUpdateTestServer(t)

	rec := httptest.NewRecorder()
	s.handleLauncherUpdateExe(rec, httptest.NewRequest("GET", "/api/launcher/update/exe", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("空部署全量端点应 404，实得 %d", rec.Code)
	}

	body := randTestExe(2, 1<<20+4096)
	rec = httptest.NewRecorder()
	s.handleAdminLauncherUpload(rec, withAdminKey(launcherUploadReq(t, body, "2.4.0", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.handleLauncherUpdateExe(rec, httptest.NewRequest("GET", "/api/launcher/update/exe", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("全量下载应 200，实得 %d", rec.Code)
	}
	got, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("全量下载字节 != 上传内容（%d vs %d）", len(got), len(body))
	}
	if rec.Header().Get("X-Launcher-Version") != "2.4.0" {
		t.Fatalf("X-Launcher-Version 应为 2.4.0，实得 %q", rec.Header().Get("X-Launcher-Version"))
	}
}

// ③ delta：合法 from 200 + X-Delta-* 头；未知/缺 from 404（绝不 200 空体）。
func TestLauncherUpdateDeltaHandler(t *testing.T) {
	s := newLauncherUpdateTestServer(t)

	v1 := randTestExe(3, 1<<20+4096)
	rec := httptest.NewRecorder()
	s.handleAdminLauncherUpload(rec, withAdminKey(launcherUploadReq(t, v1, "2.3.8", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传 v1 失败: %s", rec.Body.String())
	}
	v1Hash := s.launcherUpdate.Current().Hash

	v2 := randTestExe(4, 1<<20+4096)
	rec = httptest.NewRecorder()
	s.handleAdminLauncherUpload(rec, withAdminKey(launcherUploadReq(t, v2, "2.4.0", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传 v2 失败: %s", rec.Body.String())
	}

	// 缺 from → 404
	rec = httptest.NewRecorder()
	s.handleLauncherUpdateDelta(rec, httptest.NewRequest("GET", "/api/launcher/update/delta", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("缺 from 应 404，实得 %d", rec.Code)
	}
	// 未知 from → 404
	rec = httptest.NewRecorder()
	s.handleLauncherUpdateDelta(rec, httptest.NewRequest("GET", "/api/launcher/update/delta?from="+strings.Repeat("E", 64), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知 from 应 404，实得 %d", rec.Code)
	}
	// 合法 from → 200 + 头 + 非空体
	rec = httptest.NewRecorder()
	s.handleLauncherUpdateDelta(rec, httptest.NewRequest("GET", "/api/launcher/update/delta?from="+v1Hash, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("合法 from 应 200，实得 %d", rec.Code)
	}
	if rec.Header().Get("X-Delta-From") != v1Hash {
		t.Fatalf("X-Delta-From 应是 v1 hash，实得 %q", rec.Header().Get("X-Delta-From"))
	}
	if rec.Body.Len() == 0 {
		t.Fatal("delta 不得是 200 空体")
	}
}

// ④ admin 鉴权：无 key 的上传/回退/列表全部 401。
func TestLauncherUpdateAdminAuthRequired(t *testing.T) {
	s := newLauncherUpdateTestServer(t)

	rec := httptest.NewRecorder()
	s.handleAdminLauncherUpload(rec, launcherUploadReq(t, randTestExe(5, 1<<20+4096), "2.4.0", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 key 上传应 401，实得 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleAdminLauncherRollback(rec, httptest.NewRequest("POST", "/api/admin/launcher/rollback",
		strings.NewReader(`{"hash":"`+strings.Repeat("0", 64)+`"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 key 回退应 401，实得 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleAdminLauncherVersions(rec, httptest.NewRequest("GET", "/api/admin/launcher/versions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 key 列表应 401，实得 %d", rec.Code)
	}

	// 被拒后盘上必须一个字节都没动（只看状态码会被「先写盘再报错」骗过）
	if _, err := os.Stat(s.launcherUpdate.CurrentPath()); !os.IsNotExist(err) {
		t.Fatal("全部被拒后 current.exe 不应存在")
	}
}

// ⑤ 上传必须能过 bodylimit 白名单：>8 MiB 的 body 走 uploadBodyLimitFor
//    必须取到 512 MiB 档（路径级断言，防白名单静默失效 —— PVF 那批的 P0 事故重演）。
func TestLauncherUploadPathInBodyLimitWhitelist(t *testing.T) {
	if !uploadPaths["/api/admin/launcher/upload"] {
		t.Fatal("/api/admin/launcher/upload 不在 uploadPaths 白名单：134 MiB 的 exe 会被 8 MiB 全局上限打死")
	}
	if got := uploadBodyLimitFor("/api/admin/launcher/upload", maxRequestBodyBytes); got != maxUploadBodyBytes {
		t.Fatalf("upload 路径应取 512 MiB 档，实得 %d", got)
	}
}

// withAdminKey 给请求带上后台鉴权头（与既有测试的 X-Auth-Key 口径一致）。
func withAdminKey(req *http.Request) *http.Request {
	req.Header.Set("X-Auth-Key", testAdminKey)
	return req
}
