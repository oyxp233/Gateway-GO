package config

import "testing"

// TestGateSwitchesForS5A3AllOff 锁死 S5A3 的口径：五项门禁全关。
//
// 这条断言是"玩家能进游戏"的前提：S5A3 客户端没有在网关登记 PVF、
// 没有受管插件清单、没有完整性白名单，任何一项打开都只会把玩家拦在门外。
func TestGateSwitchesForS5A3AllOff(t *testing.T) {
	entry := GameServerEntry{Id: "s5a3", Protocol: ProtocolS5A3}
	gates := GateSwitchesFor(entry, true)
	if gates.Policy || gates.Pvf || gates.Plugins || gates.Integrity || gates.Kernel {
		t.Fatalf("S5A3 应五项全关，实际 %+v", gates)
	}
}

// TestGateSwitchesForS5A95PolicyOnly S5A95 维持既有口径（只留策略拉取）。
func TestGateSwitchesForS5A95PolicyOnly(t *testing.T) {
	gates := GateSwitchesFor(GameServerEntry{Protocol: ProtocolS5A95}, true)
	if !gates.Policy || gates.Pvf || gates.Plugins || gates.Integrity || gates.Kernel {
		t.Fatalf("S5A95 应只开 policy，实际 %+v", gates)
	}
}

// TestGateSwitchesForS4A21AllOn 与未知服一律全开（fail-closed）。
func TestGateSwitchesForS4A21AllOn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry GameServerEntry
		found bool
	}{
		{"s4a21", GameServerEntry{Protocol: ProtocolS4A21}, true},
		{"unknown", GameServerEntry{}, false},
		{"empty-protocol", GameServerEntry{Id: "x"}, true},
	} {
		gates := GateSwitchesFor(tc.entry, tc.found)
		if !(gates.Policy && gates.Pvf && gates.Plugins && gates.Integrity && gates.Kernel) {
			t.Fatalf("%s 应全开，实际 %+v", tc.name, gates)
		}
	}
}

// TestGateSwitchesForDoesNotMutateGlobal 返回值是副本：
// 调用方改了不能影响 AllGatesOn（否则一次误改会让所有服的判定永久放宽）。
func TestGateSwitchesForDoesNotMutateGlobal(t *testing.T) {
	gates := GateSwitchesFor(GameServerEntry{Protocol: ProtocolS4A21}, true)
	gates.Pvf = false
	if !AllGatesOn.Pvf {
		t.Fatal("修改返回值污染了 AllGatesOn 全局值")
	}
}

// ── caps[] 覆盖协议默认值（三服合一，2026-10-24）─────────────────────

// TestGateSwitchesCapsOverrideProtocol 锁定"caps 优先于协议默认"。
//
// 这是评估文档缺口 B 的修复：S5A3 原先是写死五项全关，
// 运营显式配了 caps 后必须能逐项打开。
func TestGateSwitchesCapsOverrideProtocol(t *testing.T) {
	// S5A3 + 显式只开 policy 和 integrity
	entry := GameServerEntry{
		Id: "s5a3", Protocol: ProtocolS5A3,
		ListCaps: []string{"policy", "integrity"},
	}
	gates := GateSwitchesFor(entry, true)

	if !gates.Policy || !gates.Integrity {
		t.Fatalf("显式开启的 policy/integrity 应生效，实际 %+v", gates)
	}
	if gates.Pvf || gates.Plugins || gates.Kernel {
		t.Fatalf("未列出的 pvf/plugins/kernel 应关闭，实际 %+v", gates)
	}
}

// TestGateSwitchesEmptyCapsAllOff 锁定"caps 为空切片（非 nil）= 全关"。
//
// 空切片与 nil 语义不同：
//   - nil   → 走协议默认值
//   - []    → 显式全关（运营就是要全关）
func TestGateSwitchesEmptyCapsAllOff(t *testing.T) {
	entry := GameServerEntry{
		Id: "s4a21", Protocol: ProtocolS4A21,
		ListCaps: []string{}, // 显式空：全关
	}
	gates := GateSwitchesFor(entry, true)
	if gates.Policy || gates.Pvf || gates.Plugins || gates.Integrity || gates.Kernel {
		t.Fatalf("空 caps 应全关（即使协议是 S4A21），实际 %+v", gates)
	}
}

// TestGateSwitchesNilCapsUsesProtocol 锁定"caps 为 nil 时走协议默认"。
func TestGateSwitchesNilCapsUsesProtocol(t *testing.T) {
	// S4A21 + nil → 全开
	g := GateSwitchesFor(GameServerEntry{Protocol: ProtocolS4A21, ListCaps: nil}, true)
	if !(g.Policy && g.Pvf && g.Plugins && g.Integrity && g.Kernel) {
		t.Fatalf("nil caps + S4A21 应全开，实际 %+v", g)
	}
	// S5A3 + nil → 全关
	g = GateSwitchesFor(GameServerEntry{Protocol: ProtocolS5A3, ListCaps: nil}, true)
	if g.Policy || g.Pvf || g.Plugins || g.Integrity || g.Kernel {
		t.Fatalf("nil caps + S5A3 应全关，实际 %+v", g)
	}
}

// TestGateSwitchesUnknownCapIgnored 锁定"未知能力位被忽略，不 panic"。
func TestGateSwitchesUnknownCapIgnored(t *testing.T) {
	entry := GameServerEntry{
		Protocol: ProtocolS5A3,
		ListCaps: []string{"policy", "unknown_cap_xyz"},
	}
	gates := GateSwitchesFor(entry, true)
	if !gates.Policy {
		t.Fatal("policy 应生效")
	}
	if gates.Pvf || gates.Plugins || gates.Integrity || gates.Kernel {
		t.Fatalf("未知能力位不该打开任何门禁，实际 %+v", gates)
	}
}
