package httprouter

// ────────────────────────────────────────────────────────────────────────
// DNF.EXE 增量更新路由（2026-10-25）
//
// 与 launcher_update_test.go 同构，钉死同一批静默失效路径：
//   · 清单 404/缺字段   → 登录器误判「网关没升级」或拿不到强更阈值；
//   · 全量/delta 内容错 → 玩家下载的字节与清单 hash 对不上（校验失败卡人）；
//   · 上传未过 bodylimit → exe 被 8 MiB 全局上限打死（功能不可用）；
//   · 无 key 也能传     → 任何人可给全体玩家发 exe（最严重的安全问题）。
//
// 额外钉一条本模块独有的口径：version **选填**，但填了必须 x.y.z
//（否则 DnfExe.MinVersion 的语义化比较失效）。
// ────────────────────────────────────────────────────────────────────────

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

func newDnfExeUpdateTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Admin.AuthKey = testAdminKey
	cfg.DnfExe.MinVersion = "1.0.0"
	cfg.DnfExe.UpdateDir = filepath.Join(dir, "dnfexe_update")

	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })

	return &Server{
		config:       cfg,
		logger:       lg,
		dnfExeUpdate: service.NewDnfExeUpdateService(cfg, lg),
	}
}

func dnfExeUploadReq(t *testing.T, body []byte, version, name string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if name != "" {
		_ = mw.WriteField("name", name)
	}
	if version != "" {
		_ = mw.WriteField("version", version)
	}
	fw, err := mw.CreateFormFile("file", "DNF_test.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(body); err != nil {
		t.Fatal(err)
	}
	mw.Close()
	req := httptest.NewRequest("POST", "/api/admin/dnfexe/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// ① 清单：空部署不带版本信息（登录器据此跳过）；上传后字段齐全；
//    enabled=false 是一键回滚开关（清单仍 200，字节端点 404）。
func TestDnfExeUpdateManifestStates(t *testing.T) {
	s := newDnfExeUpdateTestServer(t)

	var m struct {
		OK         bool   `json:"ok"`
		Enabled    bool   `json:"enabled"`
		Version    string `json:"version"`
		Hash       string `json:"hash"`
		Size       int64  `json:"size"`
		MinVersion string `json:"min_version"`
		FullURL    string `json:"full_url"`
		DeltaURL   string `json:"delta_url"`
	}

	// 空部署：200 + enabled=true + 空 version/hash（不能 404）
	rec := httptest.NewRecorder()
	s.handleDnfExeUpdateManifest(rec, httptest.NewRequest("GET", "/api/dnfexe/update", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("空部署清单应 200，实得 %d", rec.Code)
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
	if m.MinVersion != "1.0.0" || m.FullURL == "" || m.DeltaURL == "" {
		t.Fatalf("min_version/full_url/delta_url 必须始终下发，实得 %+v", m)
	}
	if m.DeltaURL != "/api/dnfexe/update/delta" {
		t.Fatalf("delta_url 必须指向 DNF.EXE 的端点，实得 %q", m.DeltaURL)
	}

	// 上传后：version/hash/size 齐全
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, randTestExe(11, 1<<20+4096), "1.0.1", "首个分发版")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateManifest(rec, httptest.NewRequest("GET", "/api/dnfexe/update", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "1.0.1" || m.Hash == "" || m.Size <= 0 {
		t.Fatalf("上传后清单应带 v1.0.1 + hash + size，实得 %+v", m)
	}

	// enabled=false（一键回滚）：清单仍 200 但 enabled=false，全量端点 404
	f := false
	s.config.DnfExe.UpdateEnabled = &f
	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateManifest(rec, httptest.NewRequest("GET", "/api/dnfexe/update", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Enabled {
		t.Fatal("关闭开关后清单 enabled 必须为 false")
	}
	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateExe(rec, httptest.NewRequest("GET", "/api/dnfexe/update/exe", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("关闭开关后全量端点应 404，实得 %d", rec.Code)
	}
}

// ② 全量下载：字节与 current.exe 逐字节一致；空部署 404。
func TestDnfExeUpdateExeServesCurrent(t *testing.T) {
	s := newDnfExeUpdateTestServer(t)

	rec := httptest.NewRecorder()
	s.handleDnfExeUpdateExe(rec, httptest.NewRequest("GET", "/api/dnfexe/update/exe", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("空部署全量端点应 404，实得 %d", rec.Code)
	}

	body := randTestExe(12, 1<<20+4096)
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, body, "1.0.1", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传失败: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateExe(rec, httptest.NewRequest("GET", "/api/dnfexe/update/exe", nil))
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
	if rec.Header().Get("X-DnfExe-Version") != "1.0.1" {
		t.Fatalf("X-DnfExe-Version 应为 1.0.1，实得 %q", rec.Header().Get("X-DnfExe-Version"))
	}
}

// ③ delta：合法 from 200 + X-Delta-* 头；未知/缺 from/已是最新 404（绝不 200 空体）。
func TestDnfExeUpdateDeltaHandler(t *testing.T) {
	s := newDnfExeUpdateTestServer(t)

	v1 := randTestExe(13, 1<<20+4096)
	rec := httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, v1, "1.0.0", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传 v1 失败: %s", rec.Body.String())
	}
	v1Hash := s.dnfExeUpdate.Current().Hash

	// v2 只改少量字节：真实增量场景，包应远小于全量
	v2 := randTestExe(13, 1<<20+4096)
	copy(v2[1024:], []byte("DNF-EXE-DELTA-PROBE"))
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, v2, "1.0.1", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传 v2 失败: %s", rec.Body.String())
	}
	v2Hash := s.dnfExeUpdate.Current().Hash
	if v1Hash == v2Hash {
		t.Fatal("两版内容不同，hash 不该相同")
	}

	// 缺 from → 404
	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateDelta(rec, httptest.NewRequest("GET", "/api/dnfexe/update/delta", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("缺 from 应 404，实得 %d", rec.Code)
	}
	// 未知 from → 404
	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateDelta(rec, httptest.NewRequest("GET", "/api/dnfexe/update/delta?from="+strings.Repeat("E", 64), nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未知 from 应 404，实得 %d", rec.Code)
	}
	// 已是最新（from == 当前 hash）→ 404（没有"增量"这回事）
	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateDelta(rec, httptest.NewRequest("GET", "/api/dnfexe/update/delta?from="+v2Hash, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("已是最新应 404，实得 %d", rec.Code)
	}
	// 合法 from → 200 + 头 + 非空体 + 体积确实比全量小
	rec = httptest.NewRecorder()
	s.handleDnfExeUpdateDelta(rec, httptest.NewRequest("GET", "/api/dnfexe/update/delta?from="+v1Hash, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("合法 from 应 200，实得 %d", rec.Code)
	}
	if rec.Header().Get("X-Delta-From") != v1Hash {
		t.Fatalf("X-Delta-From 应是 v1 hash，实得 %q", rec.Header().Get("X-Delta-From"))
	}
	if rec.Header().Get("X-Delta-To") != v2Hash {
		t.Fatalf("X-Delta-To 应是 v2 hash，实得 %q", rec.Header().Get("X-Delta-To"))
	}
	if rec.Body.Len() == 0 {
		t.Fatal("delta 不得是 200 空体")
	}
	if rec.Body.Len() >= len(v2) {
		t.Fatalf("只改了一小段，增量包（%d）不该大于等于全量（%d）", rec.Body.Len(), len(v2))
	}
}

// ④ admin 鉴权：无 key 的上传/回退/列表全部 401，且盘上一个字节都没动。
func TestDnfExeUpdateAdminAuthRequired(t *testing.T) {
	s := newDnfExeUpdateTestServer(t)

	rec := httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, dnfExeUploadReq(t, randTestExe(14, 1<<20+4096), "1.0.1", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 key 上传应 401，实得 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleAdminDnfExeRollback(rec, httptest.NewRequest("POST", "/api/admin/dnfexe/rollback",
		strings.NewReader(`{"hash":"`+strings.Repeat("0", 64)+`"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 key 回退应 401，实得 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.handleAdminDnfExeVersions(rec, httptest.NewRequest("GET", "/api/admin/dnfexe/versions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 key 列表应 401，实得 %d", rec.Code)
	}

	// 被拒后盘上必须一个字节都没动（只看状态码会被「先写盘再报错」骗过）
	if _, err := os.Stat(s.dnfExeUpdate.CurrentPath()); !os.IsNotExist(err) {
		t.Fatal("全部被拒后 current.exe 不应存在")
	}
}

// ⑤ 上传必须能过 bodylimit 白名单（路径级断言，防白名单静默失效）。
func TestDnfExeUploadPathInBodyLimitWhitelist(t *testing.T) {
	if !uploadPaths["/api/admin/dnfexe/upload"] {
		t.Fatal("/api/admin/dnfexe/upload 不在 uploadPaths 白名单：exe 会被 8 MiB 全局上限打死")
	}
	if got := uploadBodyLimitFor("/api/admin/dnfexe/upload", maxRequestBodyBytes); got != maxUploadBodyBytes {
		t.Fatalf("upload 路径应取 512 MiB 档，实得 %d", got)
	}
}

// ⑥ 版本号口径：选填；填了必须是 x.y.z（否则 MinVersion 语义化比较失效）。
func TestDnfExeVersionOptionalButValidated(t *testing.T) {
	s := newDnfExeUpdateTestServer(t)

	// 留空 → 接受
	rec := httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, randTestExe(15, 1<<20+4096), "", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("版本号留空应被接受，实得 %d: %s", rec.Code, rec.Body.String())
	}

	// 非法格式 → 拒绝，且不覆盖已生效的版本
	before := s.dnfExeUpdate.Current().Hash
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, randTestExe(16, 1<<20+4096), "abc", "")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法版本号应 400，实得 %d", rec.Code)
	}
	if after := s.dnfExeUpdate.Current().Hash; after != before {
		t.Fatal("被拒的上传不得改动当前版")
	}

	// 非 exe（缺 MZ 头）→ 拒绝
	notExe := make([]byte, 1<<20+16)
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, notExe, "1.0.2", "")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 MZ 头应 400，实得 %d", rec.Code)
	}
}

// ⑦ 回退：回到历史版后 Current 跟着变；回退到当前版被拒。
func TestDnfExeRollback(t *testing.T) {
	s := newDnfExeUpdateTestServer(t)

	v1 := randTestExe(17, 1<<20+4096)
	rec := httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, v1, "1.0.0", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传 v1 失败: %s", rec.Body.String())
	}
	v1Hash := s.dnfExeUpdate.Current().Hash

	v2 := randTestExe(18, 1<<20+4096)
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeUpload(rec, withAdminKey(dnfExeUploadReq(t, v2, "1.0.1", "")))
	if rec.Code != http.StatusOK {
		t.Fatalf("上传 v2 失败: %s", rec.Body.String())
	}
	v2Hash := s.dnfExeUpdate.Current().Hash

	// 回退到当前版 → 400
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeRollback(rec, withAdminKey(httptest.NewRequest("POST", "/api/admin/dnfexe/rollback",
		strings.NewReader(`{"hash":"`+v2Hash+`"}`))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("回退到当前版应 400，实得 %d", rec.Code)
	}

	// 回退到 v1 → 200，Current 变回 v1
	rec = httptest.NewRecorder()
	s.handleAdminDnfExeRollback(rec, withAdminKey(httptest.NewRequest("POST", "/api/admin/dnfexe/rollback",
		strings.NewReader(`{"hash":"`+v1Hash+`"}`))))
	if rec.Code != http.StatusOK {
		t.Fatalf("回退到 v1 应 200，实得 %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.dnfExeUpdate.Current().Hash; got != v1Hash {
		t.Fatalf("回退后当前版应为 v1（%s），实得 %s", v1Hash, got)
	}
}
