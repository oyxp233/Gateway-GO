package httprouter

import (
	"bytes"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/service"
)

// PVF 增量下载端点的单测。
//
// 关键区分力：「没有增量」这件事必须用 **404** 表达，而不是 200 + 空体。
// 后者看起来"接口正常"，客户端却会拿到一份长度 0 的"合法包"白跑一次合成 ——
// 这类实现不会让任何用例变红，只有把状态码写死才能拦住。

func pvfRandBody(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func newPvfDeltaTestServer(t *testing.T) (*Server, *service.PvfService, string) {
	t.Helper()
	dir := t.TempDir()
	pvfPath := filepath.Join(dir, "Script.pvf")
	cfg := config.DefaultConfig()
	cfg.Pvf.FilePath = pvfPath
	cfg.Pvf.DeltaDir = filepath.Join(dir, "pvf_delta")
	// ★ 历史目录同样钉进 TempDir（漏了会污染包目录下的真实 ./pvf_history）。
	cfg.Pvf.HistoryDir = filepath.Join(dir, "pvf_history")
	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	// ★ 必须显式关掉：ConsoleLogger 持有 logs/error.log 句柄，Windows 上不关会让
	// t.TempDir() 的清理失败 ⇒ 断言全过、用例却报 FAIL（见 pkg/service/qqbind_test.go 同款注释）。
	t.Cleanup(func() { lg.Close() })
	svc := service.NewPvfService(cfg, lg)
	return &Server{
		config:       cfg,
		pvfSvc:       svc,
		integritySvc: service.NewIntegrityStore(filepath.Join(dir, "integrity"), lg),
	}, svc, pvfPath
}

// 造出「v1 → v2」的增量包，返回 (旧内容路径, 期望的新内容)。
func seedDelta(t *testing.T, svc *service.PvfService, pvfPath string) []byte {
	t.Helper()
	v1 := pvfRandBody(10, 1<<20)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}
	v2 := append([]byte(nil), v1...)
	v2[999] ^= 0x77
	if _, err := svc.ReplacePvf(bytes.NewReader(v2), "", ""); err != nil {
		t.Fatal(err)
	}
	if svc.GetDelta() == nil {
		t.Fatal("前置条件不成立：应当已生成增量包")
	}
	return v2
}

// ① 没有可用增量 ⇒ 404（不是 200 空体）。
func TestPvfDeltaEndpointNotFoundWhenNoDelta(t *testing.T) {
	s, _, _ := newPvfDeltaTestServer(t)

	w := httptest.NewRecorder()
	s.handleLauncherPvfDelta(w, httptest.NewRequest("GET", "/api/launcher/pvf/delta", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("没有增量时应当 404，实得 %d（响应体 %d 字节）", w.Code, w.Body.Len())
	}
}

// ② 没有 pvfSvc（单进程降级/未注入）时也必须 404，不能 panic。
func TestPvfDeltaEndpointNotFoundWhenServiceMissing(t *testing.T) {
	s := &Server{config: config.DefaultConfig()}

	w := httptest.NewRecorder()
	s.handleLauncherPvfDelta(w, httptest.NewRequest("GET", "/api/launcher/pvf/delta", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("未注入 PVF 服务时应当 404，实得 %d", w.Code)
	}
}

// ③ 有增量 ⇒ 200、响应体与磁盘上的包逐字节一致、三个头部齐备。
//    ★ 只断言"200"是不够的：头部缺一个，登录器就没法判断"这包是给哪个版本用的"。
func TestPvfDeltaEndpointServesBytesAndHeaders(t *testing.T) {
	s, svc, pvfPath := newPvfDeltaTestServer(t)
	seedDelta(t, svc, pvfPath)
	d := svc.GetDelta()

	w := httptest.NewRecorder()
	s.handleLauncherPvfDelta(w, httptest.NewRequest("GET", "/api/launcher/pvf/delta", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("有增量时应当 200，实得 %d", w.Code)
	}
	got, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(d.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("响应体（%d 字节）与磁盘上的增量包（%d 字节）不一致", len(got), len(want))
	}
	if w.Header().Get("X-Delta-From") != d.FromHash {
		t.Fatalf("X-Delta-From 不符: %s", w.Header().Get("X-Delta-From"))
	}
	if w.Header().Get("X-Delta-To") != d.ToHash {
		t.Fatalf("X-Delta-To 不符: %s", w.Header().Get("X-Delta-To"))
	}
	if w.Header().Get("X-Delta-To-Size") != strconv.FormatInt(d.ToSize, 10) {
		t.Fatalf("X-Delta-To-Size 不符: %s", w.Header().Get("X-Delta-To-Size"))
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("必须是 no-store（否则中间层可能留着旧字节），实得 %q", cc)
	}
}

// ④ 内存里有、盘上没了（被手工删掉）⇒ 404，绝不返回半截文件。
func TestPvfDeltaEndpointNotFoundWhenFileGone(t *testing.T) {
	s, svc, pvfPath := newPvfDeltaTestServer(t)
	seedDelta(t, svc, pvfPath)
	d := svc.GetDelta()

	if err := os.Remove(d.Path); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.handleLauncherPvfDelta(w, httptest.NewRequest("GET", "/api/launcher/pvf/delta", nil))

	// 注意：GetDelta 仍然会返回内存里那份（它只校 to_hash），所以这条走的是
	// handler 里的 FileExists 分支 —— 正是要测的那个分支。
	if w.Code != http.StatusNotFound {
		t.Fatalf("增量包文件已删时应当 404，实得 %d", w.Code)
	}
}

// ⑤ ★ 把策略响应里 delta 的字段名钉死。
//
// 登录器侧（Plugins/SecurityPolicy.cs）靠 [JsonPropertyName] 逐字对齐这些 key。
// 网关这边改个名字（from_hash → fromHash / url → download_url），Go 侧全部用例
// 照样全绿、接口照样 200 —— 而玩家那边的增量更新会**静默失效**（Delta 为 null，
// 永远走"没有可用增量"分支）。跨实现一致性夹具用的是手写 JSON，也拦不住这种漂移。
//
// 这里直接对真实响应做结构断言：少一个 key、拼错一个字母都必须变红。
func TestLauncherPolicyDeltaKeysArePinned(t *testing.T) {
	s, svc, pvfPath := newPvfDeltaTestServer(t)
	seedDelta(t, svc, pvfPath)
	d := svc.GetDelta()

	w := httptest.NewRecorder()
	s.handleLauncherPolicy(w, httptest.NewRequest("GET", "/api/launcher/policy", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("策略接口应当 200，实得 %d", w.Code)
	}

	var resp struct {
		Pvf map[string]json.RawMessage `json:"pvf"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("策略响应不是合法 JSON: %v", err)
	}
	raw, ok := resp.Pvf["delta"]
	if !ok {
		t.Fatalf("pvf 对象里没有 delta 键（有增量时必须下发）；pvf 现有键: %v", keysOf(resp.Pvf))
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &delta); err != nil {
		t.Fatalf("delta 不是对象: %v", err)
	}

	// key → 期望的字符串值（空串表示只校验存在性）
	wantStr := map[string]string{
		"from_hash":   d.FromHash,
		"to_hash":     d.ToHash,
		"url":         "/api/launcher/pvf/delta",
		"algo":        "block2048",
		"created_utc": d.CreatedUtc,
	}
	for k, want := range wantStr {
		v, ok := delta[k]
		if !ok {
			t.Fatalf("delta 缺字段 %q；现有字段: %v", k, keysOf(delta))
		}
		var got string
		if err := json.Unmarshal(v, &got); err != nil {
			t.Fatalf("delta.%s 不是字符串: %v", k, err)
		}
		if got != want {
			t.Fatalf("delta.%s = %q，期望 %q", k, got, want)
		}
	}
	for k, want := range map[string]int64{"to_size": d.ToSize, "size": d.Size} {
		v, ok := delta[k]
		if !ok {
			t.Fatalf("delta 缺字段 %q；现有字段: %v", k, keysOf(delta))
		}
		var got int64
		if err := json.Unmarshal(v, &got); err != nil {
			t.Fatalf("delta.%s 不是数字: %v", k, err)
		}
		if got != want {
			t.Fatalf("delta.%s = %d，期望 %d", k, got, want)
		}
	}

	// ★ 反向断言：没增量时 pvf 对象里**不能**出现 delta 键。
	//   否则登录器会看到一个 Delta != null、但 from_hash 为空的对象，
	//   白白走一遍下载流程再失败。
	s2, _, _ := newPvfDeltaTestServer(t)
	w2 := httptest.NewRecorder()
	s2.handleLauncherPolicy(w2, httptest.NewRequest("GET", "/api/launcher/policy", nil))
	var resp2 struct {
		Pvf map[string]json.RawMessage `json:"pvf"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp2.Pvf["delta"]; ok {
		t.Fatalf("没有增量包时 pvf 不应带 delta 键；实得 %s", resp2.Pvf["delta"])
	}
}

// keysOf 把 map 的键排序后返回，用于失败信息里打出"实际有哪些键"。
func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ⑥ ?from=<hash> 按需增量（2026-09-30 方案①）：落后两版的客户端也能拿到
//    「自己那版 → 当前版」的可用包，且头部就是按需包的真实 from/to。
func TestPvfDeltaEndpointOnDemand(t *testing.T) {
	s, svc, pvfPath := newPvfDeltaTestServer(t)

	// v1（磁盘直放）→ v2 → v3：客户端在 v1，固定 delta 是 v2→v3，对不上 ⇒ 只能走按需。
	v1 := pvfRandBody(30, 1<<20)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshCache(); err != nil {
		t.Fatal(err)
	}
	v1Hash := svc.GetPvfInfo().Hash

	v2 := append([]byte(nil), v1...)
	v2[111] ^= 0x01
	if _, err := svc.ReplacePvf(bytes.NewReader(v2), "", ""); err != nil {
		t.Fatal(err)
	}
	v3 := append([]byte(nil), v2...)
	v3[222] ^= 0x02
	if _, err := svc.ReplacePvf(bytes.NewReader(v3), "", ""); err != nil {
		t.Fatal(err)
	}
	v3Hash := svc.GetPvfInfo().Hash

	// 前置：固定 delta 是 v2→v3，v1 客户端对不上（正是按需要解决的场景）
	if d := svc.GetDelta(); d == nil || d.FromHash == v1Hash {
		t.Fatal("前置条件不成立：固定 delta 应存在且 from != v1")
	}

	w := httptest.NewRecorder()
	s.handleLauncherPvfDelta(w, httptest.NewRequest("GET", "/api/launcher/pvf/delta?from="+v1Hash, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("历史里有 v1，按需请求应 200，实得 %d", w.Code)
	}
	if got := w.Header().Get("X-Delta-From"); got != v1Hash {
		t.Fatalf("X-Delta-From 应是请求的 v1，实得 %s", got)
	}
	if got := w.Header().Get("X-Delta-To"); got != v3Hash {
		t.Fatalf("X-Delta-To 应是当前版 v3，实得 %s", got)
	}
}

// ⑦ 按需的拒绝路径全部 404：历史没有的版本 / 非法参数 / 已是最新。
//    ★ 拒绝类断言天生是假绿 —— 前置必须有 200 正对照（⑥ 就是），这里只补否定面。
func TestPvfDeltaEndpointOnDemandRejections(t *testing.T) {
	s, svc, pvfPath := newPvfDeltaTestServer(t)
	seedDelta(t, svc, pvfPath) // 产生 v1→v2

	cur := svc.GetPvfInfo().Hash
	cases := map[string]string{
		"历史没有的版本": strings.Repeat("C", 64),
		"非法-短":     "abc",
		"非法-穿越":    "../../etc/passwd",
		"已是最新":     cur,
	}
	for name, from := range cases {
		w := httptest.NewRecorder()
		s.handleLauncherPvfDelta(w, httptest.NewRequest("GET", "/api/launcher/pvf/delta?from="+from, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("[%s] ?from=%s 应 404，实得 %d", name, from, w.Code)
		}
	}
}
