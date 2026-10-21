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
