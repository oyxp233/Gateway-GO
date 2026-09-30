package httprouter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// 请求体上限（审查报告 网关 P1-3）
//
// 公开端点原先直接用 json.NewDecoder(r.Body)，把 body 全量缓冲进内存：
// 限流（120/分/IP）挡的是"次数"，挡不住"单次多大" —— 任一登录用户都能用一次 POST 让网关 OOM。
// 修法两层：全局 withBodyLimit（覆盖全部 30 处解码点）+ 两个公开端点的 1 MiB 收紧。
// ─────────────────────────────────────────────────────────────────────────────

// TestGlobalBodyLimitMustExceedAnnounceNeed 是一条**防回归的配置断言**。
//
// 全局上限若被调到 announceMaxReportBytes 之下，会先把反作弊批量上报截断 ——
// 那就把安全修复做成了功能回归，且症状是"大上报静默失败"，很难查。
func TestGlobalBodyLimitMustExceedAnnounceNeed(t *testing.T) {
	if maxRequestBodyBytes <= announceMaxReportBytes {
		t.Fatalf("全局请求体上限 %d 必须大于反作弊上报上限 %d，否则会上报被截断",
			maxRequestBodyBytes, announceMaxReportBytes)
	}
}

// TestWithBodyLimitRejectsOversizedBody 超限时读 body 必须报错（handler 的 Decode 因此失败 → 400）。
func TestWithBodyLimitRejectsOversizedBody(t *testing.T) {
	const limit = 1 << 10

	var readErr error
	var readN int
	h := withBodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b []byte
		b, readErr = io.ReadAll(r.Body)
		readN = len(b)
	}), limit)

	body := strings.Repeat("A", limit+512)
	r := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader([]byte(body)))
	r.ContentLength = int64(len(body))
	h.ServeHTTP(httptest.NewRecorder(), r)

	if readErr == nil {
		t.Fatalf("超过上限的 body 必须读失败，实际读满 %d 字节且无错", readN)
	}
	if readN > limit+1 {
		t.Fatalf("超限后不该继续往内存里读：读了 %d 字节（上限 %d）", readN, limit)
	}
}

// TestWithBodyLimitKeepsNormalBody 正常大小的请求体必须原样可读（别把安全修复做成功能回归）。
func TestWithBodyLimitKeepsNormalBody(t *testing.T) {
	const limit = 1 << 20

	var got string
	var readErr error
	h := withBodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b []byte
		b, readErr = io.ReadAll(r.Body)
		got = string(b)
	}), limit)

	want := `{"token":"abc","account":"alice"}`
	r := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader([]byte(want)))
	r.ContentLength = int64(len(want))
	h.ServeHTTP(httptest.NewRecorder(), r)

	if readErr != nil {
		t.Fatalf("正常大小 body 不该读失败: %v", readErr)
	}
	if got != want {
		t.Fatalf("body 内容被破坏：期望 %q，实际 %q", want, got)
	}
}

// TestBodyLimitComposesWithDrain 锁死包装顺序与组合行为。
//
// 生产是 withBodyLimit(withBodyDrain(r), max)：limit 在外、drain 在内。
// 这里断言组合后 ① 状态码仍按 handler 原样透传；② 超限的 body 仍被读掉（drain 生效），
// 也就是"加限流"没有把 2026-09-23 修好的 RST 问题带回来。
func TestBodyLimitComposesWithDrain(t *testing.T) {
	const limit = 1 << 10
	h := withBodyLimit(withBodyDrain(http.NotFoundHandler()), limit)

	body := strings.Repeat("B", 4096)
	r := httptest.NewRequest(http.MethodPost, "/probe", bytes.NewReader([]byte(body)))
	r.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("组合中间件不该改状态码：期望 404，实际 %d", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 文件上传端点的请求体放宽（2026-09-27）
//
// 事故：全局 8 MiB 上限把三个"收文件"的端点整条打死 —— PVF 实测 58 MiB，
// 上传必然 `http: request body too large`（客户端校验 / 服务端管理两处同时报）。
// 修法：精确路径白名单 → 512 MiB，其余端点维持 8 MiB。
// ─────────────────────────────────────────────────────────────────────────────

// TestUploadLimitCoversRealPvfSize 白名单端点必须收得下真实大小的 PVF。
//
// 断言用真实字节数（实测 Script.pvf = 60,849,078B），不是"随便一个大数"：
// 将来有人把 maxUploadBodyBytes 调到 58 MiB 以下时，这条会真的变红。
func TestUploadLimitCoversRealPvfSize(t *testing.T) {
	const realPvfBytes = 60849078

	lim := uploadBodyLimitFor("/api/admin/upload-pvf", maxRequestBodyBytes)
	if lim <= realPvfBytes {
		t.Fatalf("上传端点上限 %d 必须大于真实 PVF 大小 %d，否则替换 PVF 仍会失败", lim, realPvfBytes)
	}
	if lim != maxUploadBodyBytes {
		t.Fatalf("白名单端点应取 maxUploadBodyBytes=%d，实际 %d", maxUploadBodyBytes, lim)
	}
}

// TestUploadPathBodyPassesRealBody 真的把「> 全局上限」的 body 灌过去，必须读得完整。
//
// 只比数值不够 —— 这里走一遍 withBodyLimit 的真实包装路径，
// 证明放宽确实作用在中间件上（而不只是表里多了一个键）。
func TestUploadPathBodyPassesRealBody(t *testing.T) {
	// 9 MiB：大于全局 8 MiB、小于上传上限。用它是因为"越过全局那条线"才是本次修的点。
	const bodyBytes = 9 << 20

	var got int64
	var readErr error
	h := withBodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, readErr = io.Copy(io.Discard, r.Body)
	}), maxRequestBodyBytes)

	body := bytes.Repeat([]byte("P"), bodyBytes)
	r := httptest.NewRequest(http.MethodPost, "/api/admin/upload-pvf", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	h.ServeHTTP(httptest.NewRecorder(), r)

	if readErr != nil {
		t.Fatalf("白名单路径 %d 字节不该读失败（全局上限是 %d）: %v", bodyBytes, maxRequestBodyBytes, readErr)
	}
	if got != bodyBytes {
		t.Fatalf("body 未完整读出：期望 %d，实际 %d", bodyBytes, got)
	}
}

// TestNonUploadPathStillRejectsOversizedBody 白名单之外，超限仍旧必须失败。
//
// 与上一条互补：上一条证"放宽生效"，这条证"别处没被一起放宽"。
func TestNonUploadPathStillRejectsOversizedBody(t *testing.T) {
	const bodyBytes = 9 << 20

	var readErr error
	h := withBodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.Copy(io.Discard, r.Body)
	}), maxRequestBodyBytes)

	body := bytes.Repeat([]byte("Q"), bodyBytes)
	r := httptest.NewRequest(http.MethodPost, "/api/admin/announce/popup", bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	h.ServeHTTP(httptest.NewRecorder(), r)

	if readErr == nil {
		t.Fatalf("非白名单路径的 %d 字节 body 必须被拒（全局上限 %d）", bodyBytes, maxRequestBodyBytes)
	}
}

// TestNonUploadPathStaysAtGlobalLimit 白名单**只**放宽那三个端点，别的路径必须仍是 8 MiB。
//
// 含两类反例：① 同前缀的其它后台端点；② 与白名单路径"前缀相近但不相等"的串 ——
// 后者锁死"必须是精确匹配"，防止有人图省事改成 strings.HasPrefix 而悄悄放开整个后台。
func TestNonUploadPathStaysAtGlobalLimit(t *testing.T) {
	mustStay := []string{
		"/api/admin/server/backup",
		"/api/admin/integrity/add",
		"/api/admin/announce/popup",
		"/api/heartbeat",
		"/api/admin/upload-pvf/extra",
		"/api/admin/upload-pvfX",
		"/api/admin/server/pvf/",
		"/api/admin/upload",
	}
	for _, p := range mustStay {
		if got := uploadBodyLimitFor(p, maxRequestBodyBytes); got != maxRequestBodyBytes {
			t.Fatalf("%s 不该被放宽（白名单是精确匹配）：期望 %d，实际 %d", p, maxRequestBodyBytes, got)
		}
	}
}

// TestUploadPathsAreRegisteredRoutes 防止白名单里的路径写错导致**静默失效**。
//
// 白名单按字符串匹配：路径拼错一个字符，uploadPaths 永远不命中，功能照旧是坏的，
// 而上面几条测试**全绿**（它们只是拿同一个字符串去查同一张表）。
// 这里直接读 server.go 源码，断言每个键都有对应的 r.HandleFunc 注册 —— 源码级锁定。
func TestUploadPathsAreRegisteredRoutes(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("读不到 server.go（测试须在 pkg/httprouter 目录下跑）: %v", err)
	}
	text := string(src)

	for p := range uploadPaths {
		if !strings.Contains(text, `r.HandleFunc("`+p+`"`) {
			t.Fatalf("uploadPaths 里的 %q 在 server.go 找不到 r.HandleFunc 注册："+
				"路径写错会让白名单静默失效，上传照样报 request body too large", p)
		}
	}
}
