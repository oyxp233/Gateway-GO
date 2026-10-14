package httprouter

import "testing"

// TestPickPlayerName 角色名优先级：客户端自报 > 网关解析。
//
// 为什么值得单独测：插件当前**读不到**角色名（客户端里账号/角色名加密存放，且明文副本
// 没有任何对齐指针指向 —— 见 database.CurrentRoleName 的注释），所以线上实际走的永远是
// 「网关解析」这一支。真正容易写错的是两端都有值时的处理：
//
//	反例 —— 若静默挑一个、不比不报，就再也看不出「插件终于读到角色名、但和网关推定不一致」。
//	那条日志是唯一能把「角色名从哪来」这件事暴露出来的信号，不能埋。
func TestPickPlayerName(t *testing.T) {
	cases := []struct {
		name         string
		client       string
		fromDB       string
		want         string
		wantMismatch bool
	}{
		{"插件读不到时用网关解析", "", "兔兔", "兔兔", false},
		{"两边都拿不到就留空，不编一个", "", "", "", false},
		{"客户端有值、网关查不到，用客户端的", "毒奶", "", "毒奶", false},
		{"两边一致，不算 mismatch", "毒奶", "毒奶", "毒奶", false},
		{"两边不一致：用客户端的，但必须报 mismatch", "毒奶", "兔兔", "毒奶", true},
		{"两端各自去空白后再比（不因空格误报）", "  毒奶  ", "毒奶", "毒奶", false},
		{"网关值带空白也一样", "毒奶", " 毒奶 ", "毒奶", false},
		{"空白的客户端自报等于没自报", "   ", "兔兔", "兔兔", false},
	}
	for _, c := range cases {
		got, mism := pickPlayerName(c.client, c.fromDB)
		if got != c.want || mism != c.wantMismatch {
			t.Errorf("%s: pickPlayerName(%q, %q) = (%q, %v)，期望 (%q, %v)",
				c.name, c.client, c.fromDB, got, mism, c.want, c.wantMismatch)
		}
	}
}
