package ratelimiter

import "testing"

// TestPathGroupLauncherUpdate 锁定 /api/launcher/update 系列的限流分组。
//
// ★ 为什么必须有这条测试（2026-10-04 审查 G-3）：这三条端点原先**完全不在**
// pathGroups 里，PathGroup() 返回空串 ⇒ 限流中间件直接放行。而
//   · /api/launcher/update/exe   —— 无鉴权的 134 MiB 大文件下载（打满出口带宽）
//   · /api/launcher/update/delta —— 会对整个 exe 重算 SHA-256 + 块索引
// 有人把表里那一条删掉，本用例必须变红。
func TestPathGroupLauncherUpdate(t *testing.T) {
	cases := []struct {
		path string
		want string
		why  string
	}{
		{"/api/launcher/update", GroupLauncherBinary, "自更新清单"},
		{"/api/launcher/update/exe", GroupLauncherBinary, "全量 exe 下载"},
		{"/api/launcher/update/delta", GroupLauncherBinary, "差分包下载"},
		// 前缀边界：PathGroup 的匹配必须要求前缀后紧跟 '/' 或结束
		{"/api/launcher/updatex", "", "不应被 /api/launcher/update 误命中"},
	}
	for _, c := range cases {
		if got := PathGroup(c.path); got != c.want {
			t.Errorf("PathGroup(%q) = %q，期望 %q（%s）", c.path, got, c.want, c.why)
		}
	}
}
