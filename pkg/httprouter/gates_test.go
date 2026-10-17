package httprouter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"s4a21-gateway/pkg/config"
)

// ensureGatePolicyDir 把策略文件所在目录建出来（本文件自带，不依赖其它测试文件的 helper）。
//
// 为什么需要：newPvfDeltaTestServer 传的是 `filepath.Join(dir, "integrity")` 这个
// **还不存在的**目录，写盘失败只在日志里留一条 ERROR，策略照旧"失忆"。
// 自带一份是为了让本文件的用例在只检出部分文件时也能编译 —— 依赖别人测试文件里的
// 私有 helper 会让"干净检出编译不过"这种坑在别处复现。
func ensureGatePolicyDir(t *testing.T, s *Server) {
	t.Helper()
	p := s.integritySvc.ConfigPath()
	if p == "" {
		t.Fatal("策略存储没配持久化路径，本用例的前提不成立")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
}

// gatePolicyJSON 是 policy 响应里 gates 段的形状（与登录器 GateDto 逐字对齐）。
type gatePolicyJSON struct {
	Game      string `json:"game"`
	GameFound bool   `json:"game_found"`
	Gates     *struct {
		Policy    bool `json:"policy"`
		Pvf       bool `json:"pvf"`
		Plugins   bool `json:"plugins"`
		Integrity bool `json:"integrity"`
		Kernel    bool `json:"kernel"`
	} `json:"gates"`
}

// ─────────────────────── ① 纯函数：按协议给开关 ───────────────────────

func TestGateSwitchesForProtocol(t *testing.T) {
	cases := []struct {
		name  string
		entry config.GameServerEntry
		found bool
		want  GateSwitches
	}{
		{
			name:  "S4A21 全开",
			entry: config.GameServerEntry{Id: "s4a21", Protocol: config.ProtocolS4A21},
			found: true,
			want:  GateSwitches{Policy: true, Pvf: true, Plugins: true, Integrity: true, Kernel: true},
		},
		{
			// DNF95 客户端没有登记 PVF、没有受管插件，内核扫描误伤面未评估（设计文档 §5.3 的 v1 口径）。
			name:  "S5A95 只留策略",
			entry: config.GameServerEntry{Id: "s5a95", Protocol: config.ProtocolS5A95},
			found: true,
			want:  GateSwitches{Policy: true, Pvf: false, Plugins: false, Integrity: false, Kernel: false},
		},
		{
			// 未知服 → 全开（fail-closed）。未知服本该被登录面 1038 拒掉，
			// 万一走到这里也绝不能给出更宽松的门禁。
			name:  "未知服回落全开",
			entry: config.GameServerEntry{},
			found: false,
			want:  GateSwitches{Policy: true, Pvf: true, Plugins: true, Integrity: true, Kernel: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := gateSwitchesFor(c.entry, c.found); got != c.want {
				t.Fatalf("门禁开关不符\n实际 %+v\n期望 %+v", got, c.want)
			}
		})
	}
}

// ─────────────────────── ② 下发链路 ───────────────────────

// dualGamePolicyServer 造一个双服策略端点（s4a21 默认 + s5a95）。
func dualGamePolicyServer(t *testing.T) *Server {
	t.Helper()
	s, _, _ := newPvfDeltaTestServer(t)
	ensureGatePolicyDir(t, s)
	s.config.GameServers = []config.GameServerEntry{
		{Id: "s4a21", Name: "S4A21", Protocol: config.ProtocolS4A21},
		{Id: "s5a95", Name: "DNF95", Protocol: config.ProtocolS5A95, ChannelListenerPort: 18002},
	}
	return s
}

func getPolicyGates(t *testing.T, s *Server, query string) gatePolicyJSON {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleLauncherPolicy(w, httptest.NewRequest("GET", "/api/launcher/policy"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("策略接口应 200，实得 %d（query=%q）", w.Code, query)
	}

	var resp gatePolicyJSON
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("策略响应不是合法 JSON: %v", err)
	}
	if resp.Gates == nil {
		// 登录器对缺失的 gates 是"全开"，所以这里丢了不会让 S4A21 出问题，
		// 但会让 S5A95 被按 S4A21 的门禁拦下 —— 表现为"选了 DNF95 却要求校验 S4A21 的 PVF"。
		t.Fatalf("policy 响应缺 gates 段（query=%q）", query)
	}
	return resp
}

func TestLauncherPolicyGatesPerGame(t *testing.T) {
	s := dualGamePolicyServer(t)

	// 不带 game = 默认服（老登录器的报文，行为必须与改造前一致）
	def := getPolicyGates(t, s, "")
	if def.Game != "s4a21" || !def.GameFound {
		t.Fatalf("默认服应为 s4a21/found，实得 game=%q found=%v", def.Game, def.GameFound)
	}
	if !def.Gates.Pvf || !def.Gates.Plugins || !def.Gates.Integrity || !def.Gates.Kernel || !def.Gates.Policy {
		t.Fatalf("默认服（S4A21）门禁必须全开，实得 %+v", def.Gates)
	}

	s5 := getPolicyGates(t, s, "?game=s5a95")
	if s5.Game != "s5a95" || !s5.GameFound {
		t.Fatalf("应解析到 s5a95/found，实得 game=%q found=%v", s5.Game, s5.GameFound)
	}
	if !s5.Gates.Policy {
		t.Fatal("S5A95 仍需拉策略（白名单/驱动名单同源下发），policy 开关不能关")
	}
	if s5.Gates.Pvf || s5.Gates.Plugins || s5.Gates.Integrity || s5.Gates.Kernel {
		t.Fatalf("S5A95 的 PVF/插件/完整性/内核四项必须关闭，实得 %+v", s5.Gates)
	}

	// 未知服：game_found=false + 全开（不能因为"查不到"而放宽）
	unknown := getPolicyGates(t, s, "?game=nope")
	if unknown.GameFound {
		t.Fatal("未知服 Id 应回 game_found=false")
	}
	if !unknown.Gates.Pvf || !unknown.Gates.Integrity {
		t.Fatalf("未知服必须回落全门禁，实得 %+v", unknown.Gates)
	}
}

// TestLauncherPolicyGatesSurviveChangedFalse 钉住"gates 不受 changed 短路影响"。
//
// 这是切服场景的必测项：fingerprint 里不含 game，玩家从 S4A21 切到 S5A95 时
// rev 仍然命中（changed=false）。若把 gates 塞进 changed 分支，切服后登录器会继续
// 按上一服的开关跑 —— 玩家看到"选了 DNF95 却要求校验 S4A21 的 PVF"。
func TestLauncherPolicyGatesSurviveChangedFalse(t *testing.T) {
	s := dualGamePolicyServer(t)

	w := httptest.NewRecorder()
	s.handleLauncherPolicy(w, httptest.NewRequest("GET", "/api/launcher/policy", nil))
	var first struct {
		Fingerprint string `json:"fingerprint"`
		Changed     bool   `json:"changed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("首次响应不是合法 JSON: %v", err)
	}
	if !first.Changed {
		t.Fatal("前置条件不成立：无 rev 时必须 changed=true")
	}

	// ★ 必须转义：fingerprint 里含 ';'（I%d;W%s;B%s;...），不转义会被 net/http 当成
	//   查询串分隔符切开 ⇒ rev 变成半截 ⇒ 服务端判 changed=true，本用例就失去意义了
	//   （第一版正是这样，导致"把 gates 挪进 changed 分支"的变异抓不住）。
	s5 := getPolicyGates(t, s, "?rev="+url.QueryEscape(first.Fingerprint)+"&game=s5a95")
	if s5.Gates.Pvf || s5.Gates.Plugins || s5.Gates.Integrity || s5.Gates.Kernel {
		t.Fatalf("changed=false 时 gates 仍必须按 game 下发，实得 %+v", s5.Gates)
	}
}
