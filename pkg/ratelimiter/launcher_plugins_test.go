package ratelimiter

import "testing"

// TestPathGroupLauncherPlugins 锁定插件下发两个路由的分桶归属。
//
// ★ 为什么必须有这条测试：PathGroup 是**线性扫描、命中即返回**，
// 而 /api/launcher/plugins 是 /api/launcher/plugins/file 的前缀。
// 一旦有人把两条的顺序调换，插件下载就会被归进清单那一桶 ——
// 不会报错、不会 panic，只会让"一次冷启动拉 12 个文件"去挤策略(policy)的额度。
// 这类错误只能靠断言钉住。
func TestPathGroupLauncherPlugins(t *testing.T) {
	cases := []struct {
		path string
		want string
		why  string
	}{
		{"/api/launcher/plugins", GroupLauncher, "清单与 policy 同类，归 launcher 桶"},
		{"/api/launcher/plugins/file/az.dll", GroupLauncherBinary, "下载必须独立成桶"},
		{"/api/launcher/plugins/file/a%20b.dll", GroupLauncherBinary, "转义后的文件名同样归下载桶"},
		{"/api/launcher/policy", GroupLauncher, "既有行为不变"},
		{"/api/launcher/item-ranking", GroupLauncher, "既有行为不变"},
		{"/api/launcher/online", GroupLauncher, "既有行为不变"},
		{"/api/launcher/plugin", "", "前缀边界：不是 /plugins 就不该命中"},
		{"/api/launcher/pluginsXYZ", "", "前缀边界：/pluginsXYZ 不是 /plugins 的子路径"},
		{"/api/launcher/plugins/file", GroupLauncherBinary, "裸目录路径也归下载桶"},
		// PVF 增量包（2026-09-30）：与插件下载同桶 —— 两者都是启动阶段的一次性大文件，
		// 且都与 policy 同前缀（/api/launcher/p...），别被误归进 launcher 桶。
		{"/api/launcher/pvf/delta", GroupLauncherBinary, "PVF 增量包必须归下载桶"},
		{"/api/launcher/pvf/delta/x", GroupLauncherBinary, "子路径同样归下载桶"},
		{"/api/launcher/pvf", "", "前缀边界：裸 /pvf 不是下载路径"},
		{"/api/launcher/pvfXYZ", "", "前缀边界：/pvfXYZ 不是 /pvf 的子路径"},
	}
	for _, c := range cases {
		if got := PathGroup(c.path); got != c.want {
			t.Errorf("PathGroup(%q) = %q，期望 %q（%s）", c.path, got, c.want, c.why)
		}
	}
}
