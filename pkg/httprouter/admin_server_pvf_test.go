package httprouter

import (
	"bytes"
	"encoding/json"
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

// 服务端 PVF 与客户端基准 PVF 的分工（2026-09-30 方案调整）。
//
// 这一层最容易写错的地方是「两个上传入口写同一个文件」：那样「替换服务端 PVF」
// 会把客户端的增量基线 `.bak` 覆盖成新版自己，rebuildDelta 产出 from==to 的
// 自差分，旧版客户端全部进不去（09-30 线上事故）。
//
// 所以断言必须两头都看：状态码 + **磁盘有没有被动过**。只看状态码会被
// 「先写盘再报错」的实现骗过去。

func newServerPvfTestServer(t *testing.T, unseparated bool) (*Server, string, string) {
	t.Helper()
	dir := t.TempDir()

	// 客户端基准（网关侧保存，客户端校验与增量更新以它为准）
	clientPath := filepath.Join(dir, "gateway", "Script.pvf")
	if err := os.MkdirAll(filepath.Dir(clientPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, []byte("CLIENT-BASE-v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 服务端 PVF（DfoServer 读的明文那份）
	serverDir := filepath.Join(dir, "server")
	serverPath := filepath.Join(serverDir, "Data", "Pvf", "Script.pvf")
	if err := os.MkdirAll(filepath.Dir(serverPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverPath, []byte("SERVER-DFO-v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Admin.AuthKey = testAdminKey
	cfg.Pvf.FilePath = clientPath
	cfg.Pvf.DeltaDir = filepath.Join(dir, "pvf_delta")
	cfg.Pvf.HistoryDir = filepath.Join(dir, "pvf_history")
	cfg.Server.WorkDir = serverDir
	if unseparated {
		// 故意造出「未分离」的坏配置：服务端 PVF 与客户端基准指向同一文件。
		cfg.Server.PvfPath = clientPath
	} else {
		cfg.Server.PvfPath = serverPath
	}

	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	// ★ 显式关掉：ConsoleLogger 持有 error.log 句柄，Windows 上不关会让
	// t.TempDir() 清理失败 ⇒ 断言全过、用例却报 FAIL。
	t.Cleanup(func() { lg.Close() })

	return &Server{
		config:    cfg,
		logger:    lg,
		pvfSvc:    service.NewPvfService(cfg, lg),
		serverMgr: service.NewServerManager(cfg, lg),
	}, clientPath, serverPath
}

func serverPvfUploadReq(t *testing.T, body []byte, filename string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/admin/server/pvf", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Auth-Key", testAdminKey)
	return req
}

// ① 路径分离：替换只写服务端那份；客户端基准一字不动、也不产生 .bak。
//
//	.bak 这一条最关键：它同时是固定增量的基线输入，被覆盖就毁掉整条增量链路。
func TestServerPvfReplaceKeepsClientSideUntouched(t *testing.T) {
	s, clientPath, serverPath := newServerPvfTestServer(t, false)
	before, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.handleAdminServerPvf(w, serverPvfUploadReq(t, []byte("SERVER-DFO-v2"), "Script-20260930-服务端.pvf"))

	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实得 %d：%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("ok 应为 true：%v", resp)
	}
	if h, _ := resp["hash"].(string); h == "" {
		t.Fatal("应返回落盘后的指纹（后台要能核对服务端那份是哪个版本）")
	}
	if p, _ := resp["path"].(string); p != serverPath {
		t.Fatalf("path 应是服务端那份：%q != %q", p, serverPath)
	}

	got, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SERVER-DFO-v2" {
		t.Fatalf("服务端 PVF 应已替换，实得 %q", got)
	}

	after, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("客户端基准不得被改动：%q → %q", before, after)
	}
	if _, err := os.Stat(clientPath + ".bak"); err == nil {
		t.Fatal("客户端 .bak 不得被创建（它是固定增量的基线输入）")
	}
	if _, err := os.Stat(clientPath + ".tmp"); err == nil {
		t.Fatal("不得在客户端侧留下 .tmp")
	}
}

// ② 未分离（两个路径同一文件）：必须 400 拒绝，且磁盘一字未动。
//
//	这正是 09-30 那次事故的配置形态 —— 拦不住就会原样再发生一次。
func TestServerPvfReplaceRejectsUnseparatedPaths(t *testing.T) {
	s, clientPath, _ := newServerPvfTestServer(t, true)
	before, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.handleAdminServerPvf(w, serverPvfUploadReq(t, []byte("SHOULD-NOT-LAND"), "x.pvf"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("同文件配置下应 400 拒绝，实得 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "同一个文件") {
		t.Fatalf("拒绝文案应说清原因，实得：%s", w.Body.String())
	}

	after, err := os.ReadFile(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("被拒绝时文件不得被改动")
	}
	if _, err := os.Stat(clientPath + ".bak"); err == nil {
		t.Fatal("被拒绝时不得留下 .bak")
	}
}

// ③ info 端点展示「服务端那份」，并把客户端基准路径一并给出便于对照。
func TestServerPvfInfoReportsServerSideOnly(t *testing.T) {
	s, clientPath, serverPath := newServerPvfTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/admin/server/pvf/info", nil)
	req.Header.Set("X-Auth-Key", testAdminKey)
	w := httptest.NewRecorder()
	s.handleAdminServerPvfInfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实得 %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if p, _ := resp["path"].(string); p != serverPath {
		t.Fatalf("path 应是服务端那份：%q != %q", p, serverPath)
	}
	if p, _ := resp["client_path"].(string); p != clientPath {
		t.Fatalf("client_path 应是客户端基准：%q != %q", p, clientPath)
	}
	if h, _ := resp["hash"].(string); h == "" {
		t.Fatal("应给出服务端那份的指纹")
	}
	if sz, _ := resp["size"].(float64); int64(sz) <= 0 {
		t.Fatalf("应给出文件大小，实得 %v", resp["size"])
	}
}

// ④ 未分离时 info 仍可用（只读，不写盘）—— 让运维能看出两个路径撞了。
func TestServerPvfInfoShowsPathCollision(t *testing.T) {
	s, _, _ := newServerPvfTestServer(t, true)

	req := httptest.NewRequest("GET", "/api/admin/server/pvf/info", nil)
	req.Header.Set("X-Auth-Key", testAdminKey)
	w := httptest.NewRecorder()
	s.handleAdminServerPvfInfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实得 %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	p, _ := resp["path"].(string)
	c, _ := resp["client_path"].(string)
	if p != c {
		t.Fatalf("坏配置下两个路径应相同（页面据此暴露问题）：%q vs %q", p, c)
	}
}
