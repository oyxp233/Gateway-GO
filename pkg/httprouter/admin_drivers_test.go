package httprouter

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/security/petest"
	"s4a21-gateway/pkg/service"
)

// ============================================================================
// 驱动白名单（2026-10-16）的单测。
//
// 三块必须钉死的东西：
//  ① 上传闸门 —— 未签名、签名后被改过的文件一律拒，且**名单一字未变**（假绿的天敌：
//     只看返回码，不看"库里有没有被污染"）；
//  ② 放行理由必填 —— 加白即对全网放行，没有理由的加白事后无从追溯；
//  ③ 跨实现一致性 —— driver_digest 的口径必须与登录器 SecurityPolicy.DriverDigest
//     逐字节一致，条目字段名必须与登录器 DTO 的 [JsonPropertyName] 对齐；
//     错一个字符 Go 侧全绿、而驱动白名单在玩家机器上**静默失效**。
// ============================================================================

const testDriverAdminKey = "test-admin-key-driver"

// newDriverTestServer 造一个只带完整性存储的 Server（管理端点只需它 + Admin.AuthKey）。
func newDriverTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policy")
	// 必须先把目录建出来：saveLocked 往 <dir>/integrity_policy.json 写临时文件，
	// 目录不存在会静默只记一条 ERROR 日志 —— 于是"持久化"相关的断言全变成假绿。
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Admin.AuthKey = testDriverAdminKey
	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	// ★ 必须显式关掉：ConsoleLogger 持有 error.log 句柄，Windows 上不关会让
	// t.TempDir() 清理失败 ⇒ 断言全过、用例却报 FAIL。
	t.Cleanup(func() { lg.Close() })
	return &Server{
		config:       cfg,
		logger:       lg,
		integritySvc: service.NewIntegrityStore(policyDir, lg),
	}
}

// ensurePolicyDir 把策略文件所在目录建出来。
//
// 为什么需要：newPvfDeltaTestServer 传的是 `filepath.Join(dir, "integrity")` 这个
// **还不存在的**目录，而 saveLocked 往 `<dir>/integrity_policy.json.tmp` 写盘 ——
// 目录不在就只在日志里留一条 ERROR、策略照旧"失忆"。凡是会写名单的用例都必须先补这一步，
// 否则"持久化/热加载"相关的断言全是假绿（写失败静默发生）。
func ensurePolicyDir(t *testing.T, s *Server) {
	t.Helper()
	p := s.integritySvc.ConfigPath()
	if p == "" {
		t.Fatal("策略存储没配持久化路径，本用例的前提不成立")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
}

// driverUploadRequest 造一个驱动上传请求。
func driverUploadRequest(t *testing.T, content []byte, filename, reason string, includeReason bool) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if includeReason {
		if err := mw.WriteField("reason", reason); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/admin/drivers/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Auth-Key", testDriverAdminKey)
	return req
}

// uploadResult 解析上传响应里我们关心的字段。
type uploadResult struct {
	OK         bool     `json:"ok"`
	Added      int      `json:"added"`
	TotalFiles int      `json:"total_files"`
	Errors     []string `json:"errors"`
	Rejected   []string `json:"rejected"`
	Count      int      `json:"count"`
	Message    string   `json:"message"`
}

func doDriverUpload(t *testing.T, s *Server, req *http.Request) (int, uploadResult) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleAdminDriversUpload(w, req)
	var got uploadResult
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &got)
	}
	return w.Code, got
}

// ─────────────────────── ① 上传闸门 ───────────────────────

// TestAdminDriversUploadAcceptsSignedDriver 合法签名驱动必须被收下，并带上签名者与理由。
func TestAdminDriversUploadAcceptsSignedDriver(t *testing.T) {
	s := newDriverTestServer(t)
	pe, err := petest.SignedPE([]byte("amd-like driver"), petest.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	code, res := doDriverUpload(t, s, driverUploadRequest(t, pe, "AMDRyzenMasterDriver.sys", "玩家申诉：AMD Ryzen Master 正规组件", true))
	if code != http.StatusOK {
		t.Fatalf("上传应 200，实得 %d（%s）", code, res.Message)
	}
	if !res.OK || res.Added != 1 {
		t.Fatalf("应新增 1 条，实得 ok=%v added=%d errors=%v rejected=%v", res.OK, res.Added, res.Errors, res.Rejected)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("不该有错误：%v", res.Errors)
	}

	snap := s.integritySvc.Snapshot()
	if len(snap.DriverAllow) != 1 {
		t.Fatalf("名单应有 1 条，实得 %d", len(snap.DriverAllow))
	}
	e := snap.DriverAllow[0]
	wantHash, _ := security.ComputeFileFingerprint(bytes.NewReader(pe))
	if e.Hash != wantHash {
		t.Fatalf("哈希应为文件 SHA-256 %s，实得 %s", wantHash, e.Hash)
	}
	if e.Size != int64(len(pe)) {
		t.Fatalf("大小应为 %d，实得 %d", len(pe), e.Size)
	}
	if !strings.Contains(e.Signer, "Test Vendor") {
		t.Fatalf("签名者应来自内嵌签名，实得 %q", e.Signer)
	}
	if e.Reason == "" {
		t.Fatal("放行理由必须落库")
	}
	if e.AddedUtc == "" {
		t.Fatal("加入时间必须落库")
	}
}

// TestAdminDriversUploadRejectsUnsigned ★ 未签名文件必须拒，且名单一字未变。
//
// 「名单一字未变」这半句是重点：只判返回码，实现里"先入库再校验"的写法照样绿。
func TestAdminDriversUploadRejectsUnsigned(t *testing.T) {
	s := newDriverTestServer(t)
	before := len(s.integritySvc.Snapshot().DriverAllow)

	code, res := doDriverUpload(t, s, driverUploadRequest(t,
		petest.UnsignedPE([]byte("evil unsigned driver")), "evil.sys", "看着像驱动", true))

	if code != http.StatusOK {
		t.Fatalf("上传端点应 200 并在体内报告失败，实得 %d", code)
	}
	if res.OK || res.Added != 0 {
		t.Fatalf("未签名文件不该入库：ok=%v added=%d", res.OK, res.Added)
	}
	if len(res.Errors) == 0 {
		t.Fatal("必须给出失败原因（未签名），否则后台只显示「没反应」")
	}
	if got := len(s.integritySvc.Snapshot().DriverAllow); got != before {
		t.Fatalf("被拒的上传不能改动名单：之前 %d 条，现在 %d 条", before, got)
	}
}

// TestAdminDriversUploadRejectsTampered ★ 签名后被改一个字节的文件必须拒。
//
// 这是「验签」这道闸的唯一实际价值所在（能力边界见 security/authenticode.go 头部）。
func TestAdminDriversUploadRejectsTampered(t *testing.T) {
	s := newDriverTestServer(t)
	pe, err := petest.SignedPE([]byte("driver payload"), petest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pe[petest.PayloadOffset] ^= 0xFF // 签名之后再改内容

	_, res := doDriverUpload(t, s, driverUploadRequest(t, pe, "tampered.sys", "改过的文件", true))
	if res.OK || res.Added != 0 {
		t.Fatalf("被改过的文件不该入库：ok=%v added=%d", res.OK, res.Added)
	}
	if len(res.Errors) == 0 || !strings.Contains(strings.Join(res.Errors, " "), "不一致") {
		t.Fatalf("失败原因应指出「内容与签名不一致」；实得 %v", res.Errors)
	}
	if n := len(s.integritySvc.Snapshot().DriverAllow); n != 0 {
		t.Fatalf("被拒的上传不能改动名单，实得 %d 条", n)
	}
}

// TestAdminDriversUploadRequiresReason 放行理由必填。
func TestAdminDriversUploadRequiresReason(t *testing.T) {
	s := newDriverTestServer(t)
	pe, err := petest.SignedPE([]byte("driver payload"), petest.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// ① 完全没带 reason 字段
	code, res := doDriverUpload(t, s, driverUploadRequest(t, pe, "a.sys", "", false))
	if code != http.StatusBadRequest {
		t.Fatalf("没填理由应 400，实得 %d", code)
	}
	if res.Message == "" {
		t.Fatal("400 必须给出可读的原因")
	}
	// ② 只填空格
	code2, _ := doDriverUpload(t, s, driverUploadRequest(t, pe, "a.sys", "   ", true))
	if code2 != http.StatusBadRequest {
		t.Fatalf("空白理由应 400（TrimSpace 后为空），实得 %d", code2)
	}
	if n := len(s.integritySvc.Snapshot().DriverAllow); n != 0 {
		t.Fatalf("理由不合法时不能入库，实得 %d 条", n)
	}
}

// TestAdminDriversEndpointsRequireAuth 三个端点都必须鉴权（漏一个就是"任意人可加白驱动"）。
func TestAdminDriversEndpointsRequireAuth(t *testing.T) {
	s := newDriverTestServer(t)

	get := httptest.NewRequest("GET", "/api/admin/drivers", nil)
	w := httptest.NewRecorder()
	s.handleAdminDrivers(w, get)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/admin/drivers 无密钥应 401，实得 %d", w.Code)
	}

	bad := driverUploadRequest(t, petest.UnsignedPE([]byte("x")), "x.sys", "r", true)
	bad.Header.Del("X-Auth-Key")
	w2 := httptest.NewRecorder()
	s.handleAdminDriversUpload(w2, bad)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("上传无密钥应 401，实得 %d", w2.Code)
	}

	rm := httptest.NewRequest("POST", "/api/admin/drivers/remove", strings.NewReader(`{"file":"a","hash":"b"}`))
	w3 := httptest.NewRecorder()
	s.handleAdminDriversRemove(w3, rm)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("移除无密钥应 401，实得 %d", w3.Code)
	}
}

// TestAdminDriversDuplicateUploadIsReportedAsRejected 同一份文件重复上传必须明说"已在名单中"，
// 不能让运营以为"点了一次没反应"。
func TestAdminDriversDuplicateUploadIsReportedAsRejected(t *testing.T) {
	s := newDriverTestServer(t)
	pe, err := petest.SignedPE([]byte("driver payload"), petest.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if code, res := doDriverUpload(t, s, driverUploadRequest(t, pe, "dup.sys", "第一次", true)); code != 200 || res.Added != 1 {
		t.Fatalf("第一次上传应成功，实得 code=%d added=%d", code, res.Added)
	}
	code, res := doDriverUpload(t, s, driverUploadRequest(t, pe, "dup.sys", "第二次", true))
	if code != http.StatusOK {
		t.Fatalf("重复上传应 200（在体内说明原因），实得 %d", code)
	}
	if res.Added != 0 || len(res.Rejected) != 1 {
		t.Fatalf("重复上传应 added=0 且进 rejected，实得 added=%d rejected=%v", res.Added, res.Rejected)
	}
	if n := len(s.integritySvc.Snapshot().DriverAllow); n != 1 {
		t.Fatalf("名单不该出现重复条目，实得 %d 条", n)
	}
}

// TestAdminDriversRemove 移除后再查为空，且移除未知条目返回 ok=false（不是假成功）。
func TestAdminDriversRemove(t *testing.T) {
	s := newDriverTestServer(t)
	s.integritySvc.AddDriverEntries([]models.DriverEntry{
		{FileName: "a.sys", Hash: strings.Repeat("A", 64), Reason: "测试"},
	})

	body := `{"file":"a.sys","hash":"` + strings.Repeat("a", 64) + `"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/drivers/remove", strings.NewReader(body))
	req.Header.Set("X-Auth-Key", testDriverAdminKey)
	s.handleAdminDriversRemove(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("移除应 200，实得 %d", w.Code)
	}
	if n := len(s.integritySvc.Snapshot().DriverAllow); n != 0 {
		t.Fatalf("移除后应为空，实得 %d 条", n)
	}

	// 再移一次：必须 ok=false（大小写不敏感匹配，但条目已经没了）
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/admin/drivers/remove", strings.NewReader(body))
	req2.Header.Set("X-Auth-Key", testDriverAdminKey)
	s.handleAdminDriversRemove(w2, req2)
	if !strings.Contains(w2.Body.String(), `"ok":false`) {
		t.Fatalf("移除不存在的条目应 ok=false，实得 %s", w2.Body.String())
	}
}

// TestDriverAllowPersistsAndReloads 驱动名单必须落盘并在"重启"（新开一个 store）后读回。
//
// 为什么值得单独一条：名单如果只活在内存里，运营在后台加白、网关重启一次就全没了 ——
// 症状是"玩家过两天又被拦"，而所有接口都是 200。
func TestDriverAllowPersistsAndReloads(t *testing.T) {
	s := newDriverTestServer(t)
	dir := filepath.Dir(s.integritySvc.ConfigPath())

	added, rejected := s.integritySvc.AddDriverEntries([]models.DriverEntry{
		{FileName: "AMDRyzenMasterDriver.sys", Hash: strings.Repeat("C", 64), Reason: "玩家申诉"},
	})
	if added != 1 || len(rejected) != 0 {
		t.Fatalf("前置条件不成立：added=%d rejected=%v", added, rejected)
	}

	// 同一个目录上再开一个 store == 进程重启后的第一次加载。
	lg2, err := logger.NewConsoleLogger(filepath.Join(dir, "logs2"), logger.Error)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg2.Close() })
	reloaded := service.NewIntegrityStore(dir, lg2)

	snap := reloaded.Snapshot()
	if len(snap.DriverAllow) != 1 {
		t.Fatalf("重启后驱动名单应仍有 1 条，实得 %d 条", len(snap.DriverAllow))
	}
	e := snap.DriverAllow[0]
	if e.FileName != "AMDRyzenMasterDriver.sys" || !strings.EqualFold(e.Hash, strings.Repeat("C", 64)) {
		t.Fatalf("读回的条目不对: %+v", e)
	}
	if e.Reason != "玩家申诉" {
		t.Fatalf("放行理由必须持久化（否则事后无从追溯），实得 %q", e.Reason)
	}
	if e.Display == "" || e.AddedUtc == "" {
		t.Fatalf("展示名与加入时间都该在落盘时补齐: %+v", e)
	}
}

// ─────────────────────── ② 摘要口径（跨实现） ───────────────────────

// fixtureDriverDigest 是「两条固定条目」的规范摘要，**由独立实现（Python hashlib）
// 按文档口径算出**，两侧各自钉成常量：
//
//	payload = "AMDRyzenMasterDriver.sys\t7250DDCB…\nMessageTransfer.sys\tD5842295…"
//	digest  = SHA-256(payload) 小写十六进制
//
// ★ 登录器侧的对应断言**不在 Go 仓库、也不在登录器工程里**（登录器没有测试工程，
// 它的验收一直是 _work 下那套外部探针，见 check_p1_launcher.py 一类）：跑
//   E:\GO网关\_work\scripts\e2e\verify_launcher_driver_digest_reproducible.py
// 它用反射加载登录器**真实的编译产物**（bin/Debug/.../SimpleLauncher.dll）、调真实的
// SecurityPolicy.DriverDigest，打的就是下面这个 fixtureDriverDigest；
// 并额外对拍了三条反向对照（分隔符 / 换行 / 大小写各改一版，摘要必须都变），
// 保证这条断言不是"任何输入都算出同一个值"的平凡通过。
// 任何一侧改了格式（分隔符、大小写、排序、加字段），两边必有一条变红。
const fixtureDriverDigest = "3eebd0b0cd4ab36292b51516e858853dc9082630daee739ebe2b872a3640ba2c"

func TestDriverDigestMatchesCrossImplementationFixture(t *testing.T) {
	got := driverDigest([]models.DriverEntry{
		{FileName: "AMDRyzenMasterDriver.sys", Hash: "7250DDCB9B04E7E00694C9D5AE3AA2B37CAAE367A4125BB84D8AC0B0DFAB8624"},
		{FileName: "MessageTransfer.sys", Hash: "D584229597A7051E2542CEB8DE4C987A34CD02BFB101B8BFB7585260C6FA6A67"},
	})
	if got != fixtureDriverDigest {
		t.Fatalf("driver_digest 口径漂了：\n  实得 %s\n  期望 %s\n"+
			"（改动口径必须同时改登录器 SecurityPolicy.DriverDigest 与两侧的夹具常量）", got, fixtureDriverDigest)
	}

	// 空名单是 "-"（与 white/black 的口径一致），**不哈希**。
	if got := driverDigest(nil); got != "-" {
		t.Fatalf("空名单应为 \"-\"，实得 %q", got)
	}

	// 展示/审计字段**不参与**摘要：改了不该变。
	withExtra := []models.DriverEntry{{
		FileName:  "AMDRyzenMasterDriver.sys",
		Hash:      "7250DDCB9B04E7E00694C9D5AE3AA2B37CAAE367A4125BB84D8AC0B0DFAB8624",
		Algorithm: "SHA-256", Size: 61832, Display: "x [7250DDCB]",
		Signer: "Advanced Micro Devices", Reason: "玩家申诉", AddedUtc: "2026-10-16T00:00:00Z",
	}}
	single := []models.DriverEntry{{
		FileName: "AMDRyzenMasterDriver.sys",
		Hash:     "7250DDCB9B04E7E00694C9D5AE3AA2B37CAAE367A4125BB84D8AC0B0DFAB8624",
	}}
	if driverDigest(withExtra) != driverDigest(single) {
		t.Fatal("Signer/Reason/Display 等展示字段不该参与摘要（否则以后加字段就会打乱所有客户端缓存）")
	}
}

// ─────────────────────── ③ 下发链路 ───────────────────────

// TestLauncherPolicyPinsDriverKeys 把 policy 响应里驱动相关的字段名与取值钉死。
//
// 登录器靠 [JsonPropertyName] 逐字对齐这些 key；网关改个名字（driver_digest → driverDigest），
// Go 侧用例全绿、接口照样 200，而玩家那边的驱动白名单**静默失效**。
func TestLauncherPolicyPinsDriverKeys(t *testing.T) {
	s, _, _ := newPvfDeltaTestServer(t)
	ensurePolicyDir(t, s)
	s.integritySvc.AddDriverEntries([]models.DriverEntry{
		{FileName: "AMDRyzenMasterDriver.sys", Hash: "7250DDCB9B04E7E00694C9D5AE3AA2B37CAAE367A4125BB84D8AC0B0DFAB8624",
			Size: 61832, Signer: "Advanced Micro Devices", Reason: "玩家申诉：AMD Ryzen Master 组件"},
	})

	w := httptest.NewRecorder()
	s.handleLauncherPolicy(w, httptest.NewRequest("GET", "/api/launcher/policy", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("策略接口应 200，实得 %d", w.Code)
	}

	var resp struct {
		Changed     bool                         `json:"changed"`
		Fingerprint string                       `json:"fingerprint"`
		DriverDg    *string                      `json:"driver_digest"`
		DriverCount *int                         `json:"driver_count"`
		Driver      []map[string]json.RawMessage `json:"driver"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("策略响应不是合法 JSON: %v", err)
	}
	if resp.DriverDg == nil {
		t.Fatal("policy 响应缺 driver_digest（登录器靠它判断缓存有没有被改）")
	}
	if resp.DriverCount == nil || *resp.DriverCount != 1 {
		t.Fatalf("driver_count 应为 1，实得 %v", resp.DriverCount)
	}
	if !resp.Changed {
		t.Fatal("首次拉取（无 rev）必须 changed=true")
	}
	if len(resp.Driver) != 1 {
		t.Fatalf("changed 时应下发 driver 数组（1 条），实得 %d 条", len(resp.Driver))
	}

	// 条目字段名逐个钉死 —— 登录器 DTO 按这些名字读。
	ent := resp.Driver[0]
	for _, k := range []string{"file", "hash", "algo", "size", "display", "signer", "reason", "added_utc"} {
		if _, ok := ent[k]; !ok {
			t.Fatalf("驱动条目缺字段 %q（登录器按这个名字读）；现有字段: %v", k, keysOf(ent))
		}
	}
	var gotFile string
	_ = json.Unmarshal(ent["file"], &gotFile)
	if gotFile != "AMDRyzenMasterDriver.sys" {
		t.Fatalf("file 字段值不对: %q", gotFile)
	}
	var gotReason string
	_ = json.Unmarshal(ent["reason"], &gotReason)
	if gotReason == "" {
		t.Fatal("reason 必须随下发体一起给登录器（运营追溯）")
	}

	// 带 rev 再拉一次 ⇒ changed=false 且**不再下发 driver 数组**（省带宽）。
	//
	// ★ rev 必须**按 URL 编码**传：组合指纹里有 `;`，而 Go 1.17 起
	// `url.ParseQuery` 遇到未编码的分号会直接丢弃该参数（登录器侧用
	// `Uri.EscapeDataString` 编码，这里也必须照着做，否则测的是"rev 没传"）。
	w2 := httptest.NewRecorder()
	s.handleLauncherPolicy(w2, httptest.NewRequest("GET", "/api/launcher/policy?rev="+url.QueryEscape(resp.Fingerprint), nil))
	var resp2 struct {
		Changed bool                         `json:"changed"`
		Driver  []map[string]json.RawMessage `json:"driver"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	if resp2.Changed {
		t.Fatalf("带正确 rev 时必须 changed=false（指纹往返失败）；指纹=%s", resp.Fingerprint)
	}
	if len(resp2.Driver) != 0 {
		t.Fatalf("changed=false 时不该下发 driver 数组，实得 %d 条", len(resp2.Driver))
	}
}

// TestLauncherPolicyFingerprintChangesWithDriverList 驱动名单变化必须改变组合指纹。
//
// 不改指纹的后果：登录器 rev 命中 ⇒ changed=false ⇒ **永远拿不到新名单**，
// 运营在后台加了白却"没有效果"，而且没有任何报错。
func TestLauncherPolicyFingerprintChangesWithDriverList(t *testing.T) {
	s, _, _ := newPvfDeltaTestServer(t)
	ensurePolicyDir(t, s)

	readFP := func() string {
		w := httptest.NewRecorder()
		s.handleLauncherPolicy(w, httptest.NewRequest("GET", "/api/launcher/policy", nil))
		var r struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r.Fingerprint
	}

	before := readFP()
	added, rejected := s.integritySvc.AddDriverEntries([]models.DriverEntry{
		{FileName: "x.sys", Hash: strings.Repeat("B", 64), Reason: "测试"},
	})
	if added != 1 || len(rejected) != 0 {
		t.Fatalf("前置条件不成立：added=%d rejected=%v", added, rejected)
	}
	after := readFP()

	if before == after {
		t.Fatalf("加了驱动白名单后组合指纹必须变化（否则登录器不会重拉）：%s", after)
	}

	// ★★ 上面那条断言的**区分力是不够的**，2026-10-16 回退验证实测：
	//    AddDriverEntries 顺带把 revision 抬了，指纹里的 `I%d` 段本来就会变 ——
	//    即使 D 段完全不参与指纹，这条断言照样是绿的（第一次跑 R3 就是这样漏过去的）。
	//
	//    所以真正锁住 D 段的判据必须**把 revision 钉住、只让驱动名单变**。
	//    下面两条一起上：一条纯函数、一条走完整接口（防止 handleLauncherPolicy
	//    把 drvDigest 传成空串 —— 那样纯函数断言照样绿）。

	// (a) 纯函数：同一 revision、不同 D 段 ⇒ 指纹必须不同。
	fpD1 := composeFingerprint(7, nil, "w", "b", "a", "DRIVER-A")
	fpD2 := composeFingerprint(7, nil, "w", "b", "a", "DRIVER-B")
	if fpD1 == fpD2 {
		t.Fatalf("同 revision 下 D 段不同、指纹却相同 ⇒ D 段没接进组合指纹：%s", fpD1)
	}
	if !strings.Contains(fpD1, ";DDRIVER-A;") {
		t.Fatalf("组合指纹里的 D 段位置/标签变了（登录器按同一格式合成，必须两侧同步改）：%s", fpD1)
	}

	// (b) 走接口：两台夹具各加**一条不同的**驱动 ⇒ 两边 revision 都是 1（同值），
	//     指纹若相同就说明接口没把驱动摘要喂进指纹。
	mk := func(file, hash string) (string, int) {
		t.Helper()
		srv, _, _ := newPvfDeltaTestServer(t)
		ensurePolicyDir(t, srv)
		if n, rej := srv.integritySvc.AddDriverEntries([]models.DriverEntry{
			{FileName: file, Hash: hash, Reason: "同 revision 对照"},
		}); n != 1 || len(rej) != 0 {
			t.Fatalf("前置条件不成立：file=%s added=%d rejected=%v", file, n, rej)
		}
		w := httptest.NewRecorder()
		srv.handleLauncherPolicy(w, httptest.NewRequest("GET", "/api/launcher/policy", nil))
		var r struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r.Fingerprint, int(srv.integritySvc.Snapshot().Revision)
	}
	fpA, revA := mk("alpha.sys", strings.Repeat("A", 64))
	fpB, revB := mk("beta.sys", strings.Repeat("C", 64))

	// 前提本身也要成为断言：revision 不等时下面这条断言就没有区分力（§6.4）。
	if revA != revB {
		t.Fatalf("前置条件不成立：两台夹具的 revision 应相同，实得 %d / %d", revA, revB)
	}
	if fpA == fpB {
		t.Fatalf("revision 相同(%d)、仅驱动名单不同，组合指纹却相同 ⇒ 接口没把驱动摘要接进指纹：%s",
			revA, fpA)
	}
}
