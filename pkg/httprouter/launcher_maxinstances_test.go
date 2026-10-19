package httprouter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// 单机多开上限 MaxInstances（2026-10-19）
//
// 需求：管理后台「客户端配置」可改单台机器允许同时开启的登录器数量，
// 登录器启动时按该值抢占命名槽位（执行方在客户端，见 MultiInstanceGuard）。
//
// 本文件三条断言分别锁：
//   1. 合法值（含 0 = 不限制）能热改内存 + 落盘 override（重启不还原）；
//   2. 越界值被拒**且不落盘** —— 写进 override 下次启动原样读回，重启也修不好；
//   3. 公开接口 /api/launcher/notice 确实带着这个字段（登录器唯一的权威来源）。
//
// 缺省语义：0 = 不限制。老 appsettings.json 没有这个键，Go 零值即 0 ——
// 未配置时与改造前行为完全一致，不误伤现有双开玩家。
// ─────────────────────────────────────────────────────────────────────────────

// 热改 + 落盘 + 值域校验（复用心跳运行时的同款夹具：本地后端 + override 编辑器）。
func TestLauncherRuntimeMaxInstances_SetValidatesAndPersists(t *testing.T) {
	_, be, dir := newHeartbeatRuntimeFixture(t)

	// ① 缺省 = 0（不限制）：与"老网关没有这个键"同义。
	lv, err := be.Launcher()
	if err != nil {
		t.Fatalf("读 Launcher 配置失败: %v", err)
	}
	if lv.MaxInstances != 0 {
		t.Fatalf("缺省 MaxInstances 应为 0（不限制），实得 %d", lv.MaxInstances)
	}

	// ② 合法值热改：内存立刻看得到（notice 端点读的就是这份快照）。
	v := 3
	changed, err := be.SetLauncher(nil, nil, nil, &v)
	if err != nil {
		t.Fatalf("热改 MaxInstances=3 失败: %v", err)
	}
	if !changed {
		t.Fatalf("热改 MaxInstances=3 应报告有变更")
	}
	lv2, err := be.Launcher()
	if err != nil {
		t.Fatalf("读 Launcher 配置失败: %v", err)
	}
	if lv2.MaxInstances != 3 {
		t.Fatalf("内存未热改：期望 3，实得 %d", lv2.MaxInstances)
	}

	// ③ 0 是合法值（= 不限制，一键回滚用），不是"没传"。
	zero := 0
	if _, err := be.SetLauncher(nil, nil, nil, &zero); err != nil {
		t.Fatalf("MaxInstances=0 应被接受（不限制），实得 %v", err)
	}
	if lv3, _ := be.Launcher(); lv3.MaxInstances != 0 {
		t.Fatalf("MaxInstances 应热改成 0，实得 %d", lv3.MaxInstances)
	}

	// ④ 落盘（重启后不还原）。先改回 3 再落盘检查，顺便证明"改回去"也走同一条路。
	if _, err := be.SetLauncher(nil, nil, nil, &v); err != nil {
		t.Fatalf("再次热改 MaxInstances=3 失败: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "appsettings.override.json"))
	if err != nil {
		t.Fatalf("override 文件未写出: %v", err)
	}
	var parsed struct {
		Launcher struct {
			MaxInstances int `json:"MaxInstances"`
		} `json:"Launcher"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("override 不是合法 JSON: %v", err)
	}
	if parsed.Launcher.MaxInstances != 3 {
		t.Fatalf("override 未写入 MaxInstances=3（重启会还原成 0）：实得 %d",
			parsed.Launcher.MaxInstances)
	}

	// ⑤ 越界值：拒绝 + **不落盘** + 不动内存。
	//    上限 32 的由来：登录器侧每个上限值对应一个命名互斥体槽位，启动时探测 1..N。
	for _, bad := range []int{-1, 33, 99} {
		b := bad
		_, err := be.SetLauncher(nil, nil, nil, &b)
		if err == nil {
			t.Fatalf("MaxInstances=%d 应被拒", bad)
		}
		// 后台按错误文本里的「取值必须在」回 400，所以这条文案是契约的一部分。
		if !containsRangeHint(err.Error()) {
			t.Fatalf("错误信息应含『取值必须在』，实得: %v", err)
		}
	}
	if lv4, _ := be.Launcher(); lv4.MaxInstances != 3 {
		t.Fatalf("被拒的越界值不该改动现有值：期望 3，实得 %d", lv4.MaxInstances)
	}
	raw2, err := os.ReadFile(filepath.Join(dir, "appsettings.override.json"))
	if err != nil {
		t.Fatalf("override 文件应仍在: %v", err)
	}
	var parsed2 struct {
		Launcher struct {
			MaxInstances int `json:"MaxInstances"`
		} `json:"Launcher"`
	}
	if err := json.Unmarshal(raw2, &parsed2); err != nil {
		t.Fatalf("override 不是合法 JSON: %v", err)
	}
	if parsed2.Launcher.MaxInstances != 3 {
		t.Fatalf("越界值被写进了 override（重启也修不好）：实得 %d", parsed2.Launcher.MaxInstances)
	}

	// ⑥ 全 nil = 无变更（与 SetLauncher 其余字段同约定）。
	if changed, err := be.SetLauncher(nil, nil, nil, nil); err != nil || changed {
		t.Fatalf("全 nil 应无变更：changed=%v err=%v", changed, err)
	}
}

// 公开接口必须带着 max_instances —— 这是登录器唯一的权威来源。
// 缺省（0）也要显式下发：登录器据此区分"不限制"与"老网关没这个字段"，
// 两者行为恰好一致（都不拦），但显式 0 让排查时能看出"网关是新的、只是没配"。
func TestLauncherNoticeIncludesMaxInstances(t *testing.T) {
	s, _, _ := newPvfDeltaTestServer(t)

	// 缺省 0。
	w := httptest.NewRecorder()
	s.handleLauncherNotice(w, httptest.NewRequest("GET", "/api/launcher/notice", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("notice 应 200，实得 %d", w.Code)
	}
	var resp struct {
		MaxInstances int `json:"max_instances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("notice 响应不是合法 JSON: %v", err)
	}
	if resp.MaxInstances != 0 {
		t.Fatalf("缺省 max_instances 应为 0（不限制），实得 %d", resp.MaxInstances)
	}

	// 后台改完后，公开接口立刻能看到（同一辆 LauncherSnapshot 热改链路）。
	v := 5
	s.config.SetLauncherRuntime(nil, nil, nil, &v)
	w2 := httptest.NewRecorder()
	s.handleLauncherNotice(w2, httptest.NewRequest("GET", "/api/launcher/notice", nil))
	var resp2 struct {
		MaxInstances int `json:"max_instances"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("notice 响应不是合法 JSON: %v", err)
	}
	if resp2.MaxInstances != 5 {
		t.Fatalf("notice 未带热改后的 max_instances=5，实得 %d", resp2.MaxInstances)
	}
}

// containsRangeHint 判断错误文案是否含值域提示（与 server.go 回 400 的判据一致）。
func containsRangeHint(msg string) bool {
	return strings.Contains(msg, "取值必须在")
}
