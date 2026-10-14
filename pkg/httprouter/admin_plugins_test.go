package httprouter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/ratelimiter"
)

// 管理后台插件接口的单测。
//
// 重点是三条**会造成线上事故**的路径：
//   · 鉴权漏挂 → 任何人能往插件目录写文件；
//   · 删除被引用的文件 → 清单立刻 degraded、登录器全体拒绝启动；
//   · 保存未校验的清单 → 同一个原因，且后台还显示"保存成功"。

// testAdminKey 复用 game_events_test.go 里的同包常量（值相同），避免重复声明。

func newAdminPluginServer(t *testing.T, dir string) *Server {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Admin.AuthKey = testAdminKey
	cfg.Launcher.PluginDir = dir
	return &Server{config: cfg, plugins: newPluginStore(dir)}
}

func adminReq(method, target string, body *bytes.Buffer) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, body)
	}
	req.Header.Set("X-Auth-Key", testAdminKey)
	return req
}

func seedPluginDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writePluginFile(t, dir, "az.dll", []byte("AZ"))
	writePluginFile(t, dir, "NF.dll", []byte("NF"))
	writePluginFile(t, dir, "GameGaurd.dll", []byte("GG"))
	writePluginFile(t, dir, "NF.ini", []byte("nf-ini"))
	writeMeta(t, dir, pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
		{Key: "NF", DLL: "NF.dll", Ini: "NF.ini", Order: 30, ConfigKind: "Configured"},
	}})
	return dir
}

// TestAdminPluginsRequiresAuth 五个接口都必须鉴权。
func TestAdminPluginsRequiresAuth(t *testing.T) {
	dir := seedPluginDir(t)
	s := newAdminPluginServer(t, dir)

	cases := []struct {
		name   string
		method string
		target string
		call   func(w http.ResponseWriter, r *http.Request)
	}{
		{"list", "GET", "/api/admin/plugins", s.handleAdminPluginsList},
		{"upload", "POST", "/api/admin/plugins/upload", s.handleAdminPluginUpload},
		{"delete", "POST", "/api/admin/plugins/delete", s.handleAdminPluginDelete},
		{"meta", "POST", "/api/admin/plugins/meta", s.handleAdminPluginMetaSave},
		// ★ 2026-09-30 移除 "draft"（/api/admin/plugins/meta/draft）：按目录生成清单草稿
		//   会整体覆盖 plugins.json，后台误触一次就要手工重排全部顺序，已整条删掉。
		//   ⇒ 往这里加新端点时记住：这张表同时承担"未鉴权必须 401"的契约。
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 不带 X-Auth-Key
			req := httptest.NewRequest(c.method, c.target, nil)
			rec := httptest.NewRecorder()
			c.call(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s 未鉴权应 401，实得 %d", c.name, rec.Code)
			}
		})
	}

	// 反向证明：带上正确密钥就该通（否则上面的 401 可能只是因为 handler 全坏了）
	rec := httptest.NewRecorder()
	s.handleAdminPluginsList(rec, adminReq("GET", "/api/admin/plugins", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("带正确密钥应 200，实得 %d（body=%s）", rec.Code, rec.Body.String())
	}
}

// TestAdminPluginsList 列表要能区分"已登记"与"未登记"文件。
func TestAdminPluginsList(t *testing.T) {
	dir := seedPluginDir(t)
	writePluginFile(t, dir, "orphan.dll", []byte("没人引用我"))
	s := newAdminPluginServer(t, dir)

	rec := httptest.NewRecorder()
	s.handleAdminPluginsList(rec, adminReq("GET", "/api/admin/plugins", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，实得 %d", rec.Code)
	}

	var resp struct {
		OK           bool            `json:"ok"`
		Dir          string          `json:"dir"`
		MetaExists   bool            `json:"meta_exists"`
		Files        []pluginFileRow `json:"files"`
		Unregistered []string        `json:"unregistered"`
		Degraded     bool            `json:"degraded"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !resp.OK || !resp.MetaExists {
		t.Fatalf("状态不对: %+v", resp)
	}
	if resp.Degraded {
		t.Fatalf("清单合法时不该 degraded")
	}
	if resp.Dir != dir {
		t.Fatalf("dir 应为 %s，实得 %s", dir, resp.Dir)
	}

	byName := map[string]pluginFileRow{}
	for _, f := range resp.Files {
		byName[f.Name] = f
	}
	if byName["az.dll"].Role != "dll" || !byName["az.dll"].Referenced {
		t.Fatalf("az.dll 应登记为 dll: %+v", byName["az.dll"])
	}
	if byName["NF.ini"].Role != "ini" || !byName["NF.ini"].Referenced {
		t.Fatalf("NF.ini 应登记为 ini: %+v", byName["NF.ini"])
	}
	if byName["orphan.dll"].Referenced {
		t.Fatalf("orphan.dll 不该被标记为已引用")
	}
	// plugins.json 自身不该出现在文件列表里（它不是插件文件）
	if _, ok := byName[pluginMetaFileName]; ok {
		t.Fatalf("文件列表不该包含 %s", pluginMetaFileName)
	}
	// seedPluginDir 里的 GameGaurd.dll 刻意**没有**写进 plugins.json，
	// 所以它和 orphan.dll 都该出现在"未登记"里。
	if len(resp.Unregistered) != 2 ||
		resp.Unregistered[0] != "GameGaurd.dll" || resp.Unregistered[1] != "orphan.dll" {
		t.Fatalf("unregistered 应含 GameGaurd.dll 与 orphan.dll，实得 %v", resp.Unregistered)
	}
	// 列表里的 sha256 必须与文件真实内容一致（后台显示的 hash 会被运维拿来比对）
	want := sha256.Sum256([]byte("AZ"))
	if byName["az.dll"].SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("az.dll 的 sha256 不对: %s", byName["az.dll"].SHA256)
	}
}

// TestAdminPluginUpload 上传：合法名成功、非法名拒绝、空文件拒绝。
func TestAdminPluginUpload(t *testing.T) {
	dir := seedPluginDir(t)
	s := newAdminPluginServer(t, dir)

	upload := func(filename string, content []byte) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("构造 multipart 失败: %v", err)
		}
		fw.Write(content)
		mw.Close()

		req := httptest.NewRequest("POST", "/api/admin/plugins/upload", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Auth-Key", testAdminKey)
		rec := httptest.NewRecorder()
		s.handleAdminPluginUpload(rec, req)
		return rec
	}

	// ① 合法上传
	rec := upload("NewPlug.dll", []byte("NEW-PLUGIN-BYTES"))
	if rec.Code != http.StatusOK {
		t.Fatalf("合法上传应 200，实得 %d（%s）", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, "NewPlug.dll"))
	if err != nil || string(got) != "NEW-PLUGIN-BYTES" {
		t.Fatalf("文件没落盘或内容不对: %v / %q", err, got)
	}
	var up struct {
		SHA256 string `json:"sha256"`
	}
	json.Unmarshal(rec.Body.Bytes(), &up)
	want := sha256.Sum256([]byte("NEW-PLUGIN-BYTES"))
	if up.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("返回的 sha256 不对: %s", up.SHA256)
	}

	// ② 带路径部分的名字：剥掉路径后落进插件目录。
	//    这是刻意的兼容处理（浏览器尤其 IE 会把完整路径塞进 filename），
	//    不是漏洞 —— 关键是**绝不能落到插件目录之外**。
	//    `/` 与 `\` 两种分隔符都放进用例：本机是 Windows、线上是 Linux，
	//    这两组必须表现一致（用 filepath.Base 就会不一致）。
	for _, in := range []string{"../evil.dll", `..\evil.dll`, "a/b.dll", `C:\x\y.dll`} {
		if rec := upload(in, []byte("x")); rec.Code != http.StatusOK {
			t.Fatalf("%q 应被剥成文件名后接受，实得 %d（%s）", in, rec.Code, rec.Body.String())
		}
	}
	// 逐个确认没有落到插件目录外
	parent := filepath.Dir(dir)
	for _, leaked := range []string{"evil.dll", "y.dll", "b.dll"} {
		if _, err := os.Stat(filepath.Join(parent, leaked)); err == nil {
			t.Fatalf("上传写出了插件目录：%s", leaked)
		}
	}

	// ③ 剥完路径仍非法的名字必须拒绝
	for _, bad := range []string{"..", ".", ":x.dll", "a*b.dll", "a?b.dll"} {
		if rec := upload(bad, []byte("x")); rec.Code != http.StatusBadRequest {
			t.Fatalf("非法文件名 %q 应 400，实得 %d", bad, rec.Code)
		}
	}

	// ④ 空文件
	if rec := upload("Empty.dll", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("空文件应 400，实得 %d", rec.Code)
	}

	// ⑤ 覆盖已存在文件是正常操作（更新插件）
	rec = upload("az.dll", []byte("AZ-V2"))
	if rec.Code != http.StatusOK {
		t.Fatalf("覆盖上传应 200，实得 %d", rec.Code)
	}
	got, _ = os.ReadFile(filepath.Join(dir, "az.dll"))
	if string(got) != "AZ-V2" {
		t.Fatalf("覆盖失败: %q", got)
	}
	// 覆盖后清单必须立刻反映新的 sha256（签名里含 size/mtime，所以会重扫）
	snap := s.plugins.Snapshot()
	want2 := sha256.Sum256([]byte("AZ-V2"))
	if snap.byName["az.dll"] != hex.EncodeToString(want2[:]) {
		t.Fatalf("覆盖后清单里的 sha256 没更新: %s", snap.byName["az.dll"])
	}
}

// TestAdminPluginDeleteBlocksReferenced 删除保护：被清单引用的文件默认不许删。
//
// 这条是"手一抖让全体玩家进不去游戏"的直接防线：
// 删掉被引用的 DLL → 清单 degraded → 登录器拒绝启动。
func TestAdminPluginDeleteBlocksReferenced(t *testing.T) {
	dir := seedPluginDir(t)
	s := newAdminPluginServer(t, dir)

	del := func(name string, force bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]interface{}{"name": name, "force": force})
		rec := httptest.NewRecorder()
		s.handleAdminPluginDelete(rec, adminReq("POST", "/api/admin/plugins/delete", bytes.NewBuffer(body)))
		return rec
	}

	// ① 被引用 → 拒绝，且文件仍在
	if rec := del("az.dll", false); rec.Code != http.StatusBadRequest {
		t.Fatalf("删除被引用文件应 400，实得 %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "az.dll")); err != nil {
		t.Fatalf("被拒绝的删除不该真的删掉文件: %v", err)
	}

	// ② 未引用 → 允许（orphan 场景）
	writePluginFile(t, dir, "orphan.dll", []byte("x"))
	if rec := del("orphan.dll", false); rec.Code != http.StatusOK {
		t.Fatalf("删除未引用文件应 200，实得 %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "orphan.dll")); err == nil {
		t.Fatalf("文件应已删除")
	}

	// ③ force=true → 允许删（运维明确知道后果）
	if rec := del("az.dll", true); rec.Code != http.StatusOK {
		t.Fatalf("force 删除应 200，实得 %d", rec.Code)
	}

	// ④ 不存在 → 404
	if rec := del("nope.dll", false); rec.Code != http.StatusNotFound {
		t.Fatalf("不存在的文件应 404，实得 %d", rec.Code)
	}

	// ⑤ 元数据文件不许从这里删
	if rec := del(pluginMetaFileName, false); rec.Code != http.StatusBadRequest {
		t.Fatalf("删 %s 应 400，实得 %d", pluginMetaFileName, rec.Code)
	}
	// ⑥ 路径穿越名
	if rec := del("../az.dll", true); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法名应 400，实得 %d", rec.Code)
	}
}

// TestAdminPluginMetaSave 保存清单：校验不过必须**不落盘**，且不能显示成功。
func TestAdminPluginMetaSave(t *testing.T) {
	dir := seedPluginDir(t)
	s := newAdminPluginServer(t, dir)

	save := func(doc pluginMetaDoc) (*httptest.ResponseRecorder, map[string]interface{}) {
		body, _ := json.Marshal(doc)
		rec := httptest.NewRecorder()
		s.handleAdminPluginMetaSave(rec, adminReq("POST", "/api/admin/plugins/meta", bytes.NewBuffer(body)))
		var out map[string]interface{}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	// ① 合法：新增一条引用已存在文件
	rec, out := save(pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
		{Key: "NF", DLL: "NF.dll", Ini: "NF.ini", Order: 30, ConfigKind: "Configured"},
		{Key: "GameGaurd", DLL: "GameGaurd.dll", IsCore: true, Order: 20},
	}})
	if rec.Code != http.StatusOK || out["ok"] != true {
		t.Fatalf("合法清单应保存成功，实得 %d %v", rec.Code, out)
	}
	if out["degraded"] != false {
		t.Fatalf("保存后不该 degraded: %v", out)
	}
	if out["downstream_count"] != float64(3) {
		t.Fatalf("下发给登录器的插件数应为 3，实得 %v", out["downstream_count"])
	}

	// ② 引用不存在的文件 → 400，且**文件不能被改动**
	before, _ := os.ReadFile(filepath.Join(dir, pluginMetaFileName))
	rec, out = save(pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "X", DLL: "missing.dll", Order: 1},
	}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("引用缺失文件应 400，实得 %d", rec.Code)
	}
	if _, has := out["problems"]; !has {
		t.Fatalf("应返回具体问题列表: %v", out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, pluginMetaFileName))
	if !bytes.Equal(before, after) {
		t.Fatalf("校验失败时不能落盘！")
	}

	// ③ 空清单 → 400（客户端拿不到加载链核心）
	rec, _ = save(pluginMetaDoc{Version: 1})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("空清单应 400，实得 %d", rec.Code)
	}

	// ④ key 重复 → 400
	rec, _ = save(pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "A", DLL: "az.dll", Order: 1},
		{Key: "a", DLL: "NF.dll", Order: 2},
	}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("key 重复应 400，实得 %d", rec.Code)
	}
}

// TestAdminPluginMetaSaveThenScanIsNotDegraded 保存期与扫描期必须给出一致结论。
//
// ★ 这条是"双真源漂移"的防线：如果保存用的校验比扫描用的松，
//   就会出现「后台提示保存成功，登录器那边立刻 degraded、全体拒绝启动」。
func TestAdminPluginMetaSaveThenScanIsNotDegraded(t *testing.T) {
	dir := seedPluginDir(t)
	writePluginFile(t, dir, "PreventMinimize.dll", []byte("pm"))
	writePluginFile(t, dir, "PreventMinimize.ini", []byte("pm-ini"))
	s := newAdminPluginServer(t, dir)

	doc := pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
		{Key: "GameGaurd", DLL: "GameGaurd.dll", IsCore: true, Order: 20},
		{Key: "NF", DLL: "NF.dll", Ini: "NF.ini", Order: 30, DefaultEnabled: true},
		{Key: "PreventMinimize", DLL: "PreventMinimize.dll", Ini: "PreventMinimize.ini",
			Order: 40, DefaultEnabled: true},
	}}
	body, _ := json.Marshal(doc)
	rec := httptest.NewRecorder()
	s.handleAdminPluginMetaSave(rec, adminReq("POST", "/api/admin/plugins/meta", bytes.NewBuffer(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("保存应成功，实得 %d（%s）", rec.Code, rec.Body.String())
	}

	// 关键断言：保存成功后，网关下发给登录器的那份清单**必须是干净的**
	snap := s.plugins.Snapshot()
	if snap.degraded {
		t.Fatalf("保存成功却 degraded = 两套校验不一致：%v", snap.messages)
	}
	if len(snap.plugins) != 4 {
		t.Fatalf("应下发 4 个插件，实得 %d", len(snap.plugins))
	}

	// 顺序必须按 Order 而不是数组顺序
	want := []string{"AZ", "GameGaurd", "NF", "PreventMinimize"}
	for i, k := range want {
		if snap.plugins[i].Key != k {
			t.Fatalf("顺序应为 %v，实得第 %d 位 %s", want, i, snap.plugins[i].Key)
		}
	}
}

// ★ 2026-09-30 移除 TestAdminPluginMetaDraft：对应的 handler 与路由已整条删掉
// （后台"按目录生成清单草稿"按钮会整体覆盖 plugins.json 且全部写成非核心/默认关闭，
//   误触一次就要手工重排 12 条顺序，安南要求去掉）。
// 降级清单本身的覆盖仍在 launcher_plugins_test.go —— degradedMetas 是运行期兜底，没动。

// TestPluginPublicRoutesEndToEnd 走真实 router + 中间件，确认路由真的挂在了
// 玩家端口该有的位置上，并顺带**反证**「插件不能走静态文件路径」。
//
// ★ 这条反证对应评估文档的一处更正：评估文档 §2.4 写「wwwroot 静态文件服务
//   可直接当下载承载」，但双进程生产形态下 usePublicOnlyMiddleware 会把玩家端口
//   上所有非 /api 路径一律 404。如果哪天有人"顺手"把 wwwroot 挂回玩家端口，
//   第三条断言会变红 —— 那正是需要被拦住的回归。
func TestPluginPublicRoutesEndToEnd(t *testing.T) {
	dir := seedPluginDir(t)
	s := newAdminPluginServer(t, dir)
	// 中间件链要用限流器（NewServer 里会初始化，手动构造 Server 必须补上）
	s.httpLimiter = ratelimiter.NewHttpRateLimiter(true, 120)

	r := mux.NewRouter()
	s.registerPublicRoutes(r)
	s.usePublicOnlyMiddleware(r)

	srv := httptest.NewServer(r)
	defer srv.Close()

	// ① 清单
	resp, err := http.Get(srv.URL + "/api/launcher/plugins")
	if err != nil {
		t.Fatalf("取清单失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("清单应 200，实得 %d", resp.StatusCode)
	}
	var m PluginManifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("清单不是合法 JSON: %v", err)
	}
	if !m.OK {
		t.Fatalf("ok 应为 true")
	}
	if m.Degraded {
		t.Fatalf("合法清单不该 degraded: %v", m.Messages)
	}
	if len(m.Plugins) != 2 {
		t.Fatalf("应下发 2 个插件，实得 %d", len(m.Plugins))
	}

	// 顺序按 order：AZ(10) 在 NF(30) 前
	if m.Plugins[0].Key != "AZ" || m.Plugins[1].Key != "NF" {
		t.Fatalf("顺序应按 order 升序: %s, %s", m.Plugins[0].Key, m.Plugins[1].Key)
	}

	// 未配 PluginBaseUrl → url 必须是**相对路径**：
	// scheme 由登录器按自己的 TLS 配置决定，网关不能替它写死 http/https。
	f := m.Plugins[0].Files[0]
	if f.Name != "az.dll" || f.URL != "/api/launcher/plugins/file/az.dll" {
		t.Fatalf("文件条目不对: %+v", f)
	}

	// ② 按清单给的 url 真下一次，内容必须与清单里的 sha256 一致
	dl, err := http.Get(srv.URL + f.URL)
	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}
	defer dl.Body.Close()
	if dl.StatusCode != http.StatusOK {
		t.Fatalf("下载应 200，实得 %d", dl.StatusCode)
	}
	body, _ := io.ReadAll(dl.Body)
	got := sha256.Sum256(body)
	if hex.EncodeToString(got[:]) != f.SHA256 {
		t.Fatalf("下载内容与清单 sha256 不符：清单 %s，实得 %s", f.SHA256, hex.EncodeToString(got[:]))
	}

	// ③ 反证：静态文件路径在玩家端口必须 404
	for _, p := range []string{"/plugins/az.dll", "/wwwroot/index.html", "/index.html"} {
		pr, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("请求 %s 失败: %v", p, err)
		}
		pr.Body.Close()
		if pr.StatusCode != http.StatusNotFound {
			t.Fatalf("玩家端口上 %s 必须 404（插件下载只走 /api 路由），实得 %d",
				p, pr.StatusCode)
		}
	}
}

// TestAtomicWriteFileNoPartial 原子写不该在目标路径留下中间态。
func TestAtomicWriteFileNoPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.dll")

	if err := atomicWriteFile(path, []byte("v1"), 0o644); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if err := atomicWriteFile(path, []byte("v2-longer"), 0o644); err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "v2-longer" {
		t.Fatalf("内容不对: %q", got)
	}

	// 临时文件必须被清干净，不能在插件目录里留下 .tmp-plugin-* ——
	// 它们会被目录签名扫到（每次上传都让缓存失效），而且会出现在后台列表里。
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-plugin-") {
			t.Fatalf("残留了临时文件: %s", e.Name())
		}
	}
}
