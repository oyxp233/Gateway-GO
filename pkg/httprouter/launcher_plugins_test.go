package httprouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"s4a21-gateway/pkg/config"
)

// 插件下发的单测。
//
// 重点不是"能跑通"，而是把几条**静默失效**路径钉死：
//   · 目录签名缓存不失效 → 改了插件下发出去的还是旧 sha256 → 客户端校验失败进不去游戏；
//   · 清单退化却没人拦 → 客户端拿一份"猜出来的"清单去改玩家游戏目录；
//   · 下载准入表被绕过 → 插件目录里的任何文件都能被读走。

func writePluginFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", name, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func writeMeta(t *testing.T, dir string, doc pluginMetaDoc) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("序列化 plugins.json 失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, pluginMetaFileName), b, 0o644); err != nil {
		t.Fatalf("写入 plugins.json 失败: %v", err)
	}
}

func newPluginTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	cfg := config.DefaultConfig()
	return &Server{config: cfg, plugins: newPluginStore(dir)}
}

func findEntry(snap *pluginSnapshot, key string) *PluginManifestEntry {
	for i := range snap.plugins {
		if snap.plugins[i].Key == key {
			return &snap.plugins[i]
		}
	}
	return nil
}

// TestPluginSnapshotBuildsFromMetaFile 正常路径：按 plugins.json 组装，Order 决定顺序。
func TestPluginSnapshotBuildsFromMetaFile(t *testing.T) {
	dir := t.TempDir()

	sumAZ := writePluginFile(t, dir, "az.dll", []byte("AZ-PAYLOAD"))
	sumGN := writePluginFile(t, dir, "GameNative.dll", []byte("GAMENATIVE-PAYLOAD"))
	sumGNIni := writePluginFile(t, dir, "GameNative.ini", []byte("ini-body"))
	sumNF := writePluginFile(t, dir, "NF.dll", []byte("NF-PAYLOAD"))

	// 刻意把 Order 写反、数组顺序也打乱，验证排序真的按 Order 而不是目录/数组顺序。
	writeMeta(t, dir, pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "NF", DLL: "NF.dll", DisplayName: "NF 内辅", Order: 30,
			DefaultEnabled: true, ConfigKind: "Configured"},
		{Key: "AZ", DLL: "az.dll", DisplayName: "AZ 补丁", IsCore: true, Order: 10},
		{Key: "GameNative", DLL: "GameNative.dll", Ini: "GameNative.ini",
			DisplayName: "基础库", IsCore: true, Order: 20},
	}})

	snap := newPluginStore(dir).Snapshot()

	if snap.degraded {
		t.Fatalf("正常清单不该 degraded，messages=%v", snap.messages)
	}
	if len(snap.plugins) != 3 {
		t.Fatalf("应有 3 个插件，实得 %d", len(snap.plugins))
	}
	wantOrder := []string{"AZ", "GameNative", "NF"}
	for i, k := range wantOrder {
		if snap.plugins[i].Key != k {
			t.Fatalf("加载顺序应为 %v，实得第 %d 位 %s", wantOrder, i, snap.plugins[i].Key)
		}
	}

	az := findEntry(snap, "AZ")
	if az == nil || len(az.Files) != 1 || az.Files[0].SHA256 != sumAZ {
		t.Fatalf("AZ 文件条目不对: %+v", az)
	}
	if !az.IsCore || !az.DefaultEnabled {
		t.Fatalf("IsCore 条目必须强制 DefaultEnabled=true: %+v", az)
	}
	if az.Files[0].Size != int64(len("AZ-PAYLOAD")) {
		t.Fatalf("size 应为 %d，实得 %d", len("AZ-PAYLOAD"), az.Files[0].Size)
	}

	gn := findEntry(snap, "GameNative")
	if gn == nil || len(gn.Files) != 2 {
		t.Fatalf("GameNative 应有 dll+ini 两个文件: %+v", gn)
	}
	if gn.Files[0].Role != "dll" || gn.Files[1].Role != "ini" {
		t.Fatalf("role 顺序应为 dll,ini: %+v", gn.Files)
	}
	if gn.Files[1].SHA256 != sumGNIni {
		t.Fatalf("ini 的 sha256 不对")
	}

	nf := findEntry(snap, "NF")
	if nf == nil || nf.ConfigKind != "Configured" || nf.IsCore {
		t.Fatalf("NF 条目不对: %+v", nf)
	}
	if nf.Files[0].SHA256 != sumNF {
		t.Fatalf("NF 的 sha256 不对")
	}

	// 下载准入表必须与清单同源
	if snap.byName["az.dll"] != sumAZ || snap.byName["GameNative.ini"] != sumGNIni {
		t.Fatalf("byName 准入表不完整: %v", snap.byName)
	}
	if snap.byName["GameNative.dll"] != sumGN {
		t.Fatalf("byName 缺少 GameNative.dll")
	}

	if snap.revision == "" {
		t.Fatalf("revision 不该为空")
	}
}

// TestPluginSnapshotDegradedWhenMetaMissing 没有 plugins.json → 必须 degraded。
//
// 这是本改造的核心安全约定：清单必须由网关权威控制，拿一份"按文件名猜的"清单
// 去改玩家游戏目录是不允许的，登录器见到 degraded 会拒绝启动。
func TestPluginSnapshotDegradedWhenMetaMissing(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, dir, "az.dll", []byte("a"))
	writePluginFile(t, dir, "NF.dll", []byte("b"))
	writePluginFile(t, dir, "readme.txt", []byte("不是插件"))

	snap := newPluginStore(dir).Snapshot()

	if !snap.degraded {
		t.Fatalf("缺少 plugins.json 时必须 degraded")
	}
	if len(snap.messages) == 0 {
		t.Fatalf("degraded 必须给出可读原因")
	}
	// 推导结果只作人工核对用：必须全部是非核心、非默认启用，绝不能让某个插件
	// 意外变成"恒部署"。
	if len(snap.plugins) != 2 {
		t.Fatalf("应推导出 2 个 dll（readme.txt 不算），实得 %d", len(snap.plugins))
	}
	for _, p := range snap.plugins {
		if p.IsCore || p.DefaultEnabled {
			t.Fatalf("推导条目绝不能是核心/默认启用: %+v", p)
		}
	}
}

// TestPluginSnapshotDegradedOnBadMeta 非法元数据必须 degraded，且不能 panic。
func TestPluginSnapshotDegradedOnBadMeta(t *testing.T) {
	cases := []struct {
		name string
		meta string
	}{
		{"非法 JSON", `{"plugins": [`},
		{"引用不存在的文件", `{"plugins":[{"key":"X","dll":"nope.dll","order":1}]}`},
		{"缺 key", `{"plugins":[{"dll":"az.dll","order":1}]}`},
		{"缺 dll", `{"plugins":[{"key":"X","order":1}]}`},
		{"key 重复", `{"plugins":[{"key":"X","dll":"az.dll"},{"key":"x","dll":"NF.dll"}]}`},
		{"文件重复引用", `{"plugins":[{"key":"A","dll":"az.dll"},{"key":"B","dll":"az.dll"}]}`},
		{"文件名带路径分隔符", `{"plugins":[{"key":"A","dll":"../az.dll"}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writePluginFile(t, dir, "az.dll", []byte("a"))
			writePluginFile(t, dir, "NF.dll", []byte("b"))
			if err := os.WriteFile(filepath.Join(dir, pluginMetaFileName), []byte(c.meta), 0o644); err != nil {
				t.Fatalf("写入失败: %v", err)
			}

			snap := newPluginStore(dir).Snapshot()
			if !snap.degraded {
				t.Fatalf("必须 degraded")
			}
			if len(snap.messages) == 0 {
				t.Fatalf("必须给出原因")
			}
			// 关键：非法条目不能进准入表，否则路径穿越/未登记文件会被下载走。
			for name := range snap.byName {
				if !validPluginFileName(name) {
					t.Fatalf("非法文件名进了准入表: %q", name)
				}
			}
		})
	}
}

// TestPluginSnapshotCacheInvalidates 目录一变，缓存必须失效。
//
// ★ 这条是"改了插件但玩家拿到的还是旧 sha256"的防线：
//   签名只含 (name,size,mtime)，所以改内容不改大小也要能被发现 —— 靠 mtime。
func TestPluginSnapshotCacheInvalidates(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, dir, "az.dll", []byte("AAAA"))
	writeMeta(t, dir, pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
	}})

	st := newPluginStore(dir)
	rev1 := st.Snapshot().revision
	if rev1 == "" {
		t.Fatalf("revision 不该为空")
	}
	// 缓存命中：同一份内容再取一次应完全相同（同一个底层对象）
	if st.Snapshot() != st.Snapshot() {
		t.Fatalf("签名不变时应复用同一份快照")
	}

	// 改成同样长度但不同内容，并把 mtime 推到未来（Windows 的 mtime 精度可能较粗，
	// 同秒内写入会让签名不变 —— 显式 Chtimes 才是这个用例想验证的东西）。
	writePluginFile(t, dir, "az.dll", []byte("BBBB"))
	future := time.Now().Add(3 * time.Second)
	if err := os.Chtimes(filepath.Join(dir, "az.dll"), future, future); err != nil {
		t.Fatalf("Chtimes 失败: %v", err)
	}

	snap2 := st.Snapshot()
	if snap2.revision == rev1 {
		t.Fatalf("文件内容已变，revision 必须变（否则客户端会拿到旧 hash）")
	}
	want := sha256.Sum256([]byte("BBBB"))
	if snap2.byName["az.dll"] != hex.EncodeToString(want[:]) {
		t.Fatalf("重算后的 sha256 不对: %s", snap2.byName["az.dll"])
	}
}

// TestHandleLauncherPluginsURL 地址拼接：留空走网关相对路径，非空走 CDN 绝对地址。
func TestHandleLauncherPluginsURL(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, dir, "az.dll", []byte("x"))
	writeMeta(t, dir, pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
	}})

	// ① 留空 → 相对路径，登录器用自己配置的网关地址（含 TLS 开关）拼 scheme
	s := newPluginTestServer(t, dir)
	rec := httptest.NewRecorder()
	s.handleLauncherPlugins(rec, httptest.NewRequest("GET", "/api/launcher/plugins", nil))

	if rec.Code != 200 {
		t.Fatalf("应 200，实得 %d", rec.Code)
	}
	var m PluginManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !m.OK || !m.Enabled || m.Degraded {
		t.Fatalf("响应状态不对: %+v", m)
	}
	if got := m.Plugins[0].Files[0].URL; got != "/api/launcher/plugins/file/az.dll" {
		t.Fatalf("相对 url 不对: %s", got)
	}

	// ② 配了 CDN → 绝对地址，且 sha256 仍是网关自己算的
	s2 := newPluginTestServer(t, dir)
	s2.config.Launcher.PluginBaseUrl = "https://cdn.example.com/plugins/"
	rec2 := httptest.NewRecorder()
	s2.handleLauncherPlugins(rec2, httptest.NewRequest("GET", "/api/launcher/plugins", nil))

	var m2 PluginManifest
	if err := json.Unmarshal(rec2.Body.Bytes(), &m2); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if got := m2.Plugins[0].Files[0].URL; got != "https://cdn.example.com/plugins/az.dll" {
		t.Fatalf("绝对 url 不对（尾斜杠应被归一）: %s", got)
	}
	if m2.Plugins[0].Files[0].SHA256 == "" {
		t.Fatalf("走 CDN 也必须带网关算出的 sha256")
	}
}

// TestHandleLauncherPluginsDisabledSwitch 总开关关闭时仍 200，但 enabled=false。
//
// 这是一键回滚开关：登录器见到 enabled=false 就退回内置插件、完全不下载，
// 所以它必须是一个**可正常解析的响应**，不能是 500 或 404。
func TestHandleLauncherPluginsDisabledSwitch(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, dir, "az.dll", []byte("x"))
	writeMeta(t, dir, pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
	}})

	s := newPluginTestServer(t, dir)
	off := false
	s.config.Launcher.PluginEnabled = &off

	rec := httptest.NewRecorder()
	s.handleLauncherPlugins(rec, httptest.NewRequest("GET", "/api/launcher/plugins", nil))

	if rec.Code != 200 {
		t.Fatalf("回滚开关应回 200（可解析的响应），实得 %d", rec.Code)
	}
	var m PluginManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if m.Enabled {
		t.Fatalf("enabled 应为 false")
	}
	if len(m.Plugins) != 0 {
		t.Fatalf("关闭时不该下发任何插件条目")
	}
	if len(m.Messages) == 0 {
		t.Fatalf("关闭时应给出说明")
	}
}

// TestHandleLauncherPluginFileAccess 下载准入：命中可下，未登记/穿越一律 404。
func TestHandleLauncherPluginFileAccess(t *testing.T) {
	dir := t.TempDir()
	body := []byte("AZ-BINARY-PAYLOAD")
	sum := writePluginFile(t, dir, "az.dll", body)
	// 目录里放一个**没登记**的文件：它绝不能经下载接口被读走。
	writePluginFile(t, dir, "secret.txt", []byte("不该被下载"))
	writeMeta(t, dir, pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
	}})

	s := newPluginTestServer(t, dir)

	get := func(name string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/launcher/plugins/file/"+name, nil)
		req = mux.SetURLVars(req, map[string]string{"name": name})
		rec := httptest.NewRecorder()
		s.handleLauncherPluginFile(rec, req)
		return rec
	}

	rec := get("az.dll")
	if rec.Code != 200 {
		t.Fatalf("已登记文件应 200，实得 %d", rec.Code)
	}
	if got := rec.Body.Bytes(); string(got) != string(body) {
		t.Fatalf("下载内容不一致: %q", got)
	}
	if rec.Header().Get("ETag") != `"`+sum+`"` {
		t.Fatalf("ETag 应等于 sha256，实得 %q", rec.Header().Get("ETag"))
	}
	if rec.Header().Get("X-Content-SHA256") != sum {
		t.Fatalf("应回带 X-Content-SHA256")
	}
	// 必须 no-store：登录器自己有内容寻址缓存，服务端再缓存会引入"中间层旧字节"风险
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control 应为 no-store，实得 %q", cc)
	}

	// 未登记的文件
	if rec := get("secret.txt"); rec.Code != 404 {
		t.Fatalf("未登记文件必须 404，实得 %d", rec.Code)
	}
	// 路径穿越
	for _, bad := range []string{"..", "../az.dll", "..%2Faz.dll", "sub/az.dll", `..\az.dll`, "."} {
		if rec := get(bad); rec.Code != 404 {
			t.Fatalf("非法文件名 %q 必须 404，实得 %d", bad, rec.Code)
		}
	}
}

// TestPluginFileURL 地址拼接的边界：空 base / 带尾斜杠 / 需转义的文件名。
func TestPluginFileURL(t *testing.T) {
	if got := pluginFileURL("", "az.dll"); got != "/api/launcher/plugins/file/az.dll" {
		t.Fatalf("空 base 应给相对路径，实得 %s", got)
	}
	if got := pluginFileURL("https://cdn.x/p", "az.dll"); got != "https://cdn.x/p/az.dll" {
		t.Fatalf("实得 %s", got)
	}
	if got := pluginFileURL("https://cdn.x/p/", "az.dll"); got != "https://cdn.x/p/az.dll" {
		t.Fatalf("尾斜杠应被归一，实得 %s", got)
	}
	// PathEscape 用 %20（不是 QueryEscape 的 +）。
	// 链路是通的：mux 匹配的是已解码的 URL.Path，所以 %20 会还原成空格再进准入表。
	if got := pluginFileURL("", "a b.dll"); !strings.HasSuffix(got, "a%20b.dll") {
		t.Fatalf("文件名应被转义，实得 %s", got)
	}
}

// TestPluginManifestDirMissing 插件目录不存在时也要给出可解析的 degraded 响应。
//
// 首次部署（还没建目录/还没放文件）就属于这种场景，登录器会拒绝启动并显示原因。
func TestPluginManifestDirMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-created-yet")
	s := newPluginTestServer(t, dir)

	rec := httptest.NewRecorder()
	s.handleLauncherPlugins(rec, httptest.NewRequest("GET", "/api/launcher/plugins", nil))

	if rec.Code != 200 {
		t.Fatalf("应 200 且带 degraded，实得 %d", rec.Code)
	}
	var m PluginManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !m.Degraded || len(m.Messages) == 0 {
		t.Fatalf("目录不可读必须 degraded 且给原因: %+v", m)
	}

	// 目录建起来后就该恢复正常（签名从 <unreadable> 变成真实签名）
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	writePluginFile(t, dir, "az.dll", []byte("x"))
	writeMeta(t, dir, pluginMetaDoc{Version: 1, Plugins: []pluginMetaEntry{
		{Key: "AZ", DLL: "az.dll", IsCore: true, Order: 10},
	}})
	if snap := s.plugins.Snapshot(); snap.degraded || len(snap.plugins) != 1 {
		t.Fatalf("建好目录后应恢复正常: degraded=%v n=%d", snap.degraded, len(snap.plugins))
	}
}

// TestValidPluginFileName 文件名白名单的边界。
func TestValidPluginFileName(t *testing.T) {
	ok := []string{"az.dll", "AntiCheatPlugin.dll", "EquipmentSwap.xui", "a-b_c.1.ini", "中文名.dll"}
	for _, n := range ok {
		if !validPluginFileName(n) {
			t.Fatalf("%q 应被接受", n)
		}
	}
	bad := []string{"", ".", "..", "a/b.dll", `a\b.dll`, "../x.dll", "a:b.dll",
		"a*b.dll", "a?b.dll", "a\x01b.dll"}
	for _, n := range bad {
		if validPluginFileName(n) {
			t.Fatalf("%q 应被拒绝", n)
		}
	}
}
