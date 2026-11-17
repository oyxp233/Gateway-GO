package database

import (
	"errors"
	"testing"
)

// TestGetCeraMapS5A3ResolvesAccountIDBeforeLookup 是审查报告 H1（2026-11-17）的区分力测试。
//
// 现场：在线列表 30 名 S5A3 玩家 cera 全为 0，但泡点日志显示他们正常获得点券。
// 根因：旧代码把【账号名】（如 tianzi）直接传给 s5a3GetCurrencyTriple，
// 而它执行 `WHERE account_id = ?`，需要的是 dnf:10043 这种 account_id —— 查不到 → 0。
//
// 这里用假实现精确区分两种口径：
//   - getCera("tianzi")    → (0, true)   ← 旧代码命中这条，得 0
//   - getCera("dnf:10043") → (60, true)  ← 正确：先解析再查
//
// 修复后 result["tianzi"] 必须是 60；若退回旧行为（拿 name 直接查）立刻变红。
func TestGetCeraMapS5A3ResolvesAccountIDBeforeLookup(t *testing.T) {
	resolve := func(name string) (string, error) {
		switch name {
		case "tianzi":
			return "dnf:10043", nil
		case "no_account":
			return "", nil // 库里查不到账号行
		case "broken":
			return "", errors.New("db down")
		default:
			return "", nil
		}
	}
	// ★ 区分力核心：只有传入 account_id 才查得到钱，传账号名恒 0。
	getCera := func(key string) (int64, bool) {
		if key == "dnf:10043" {
			return 60, true
		}
		return 0, true // 老行为：拿登录名去查，查不到但 ok=true
	}

	got := getCeraMapS5A3([]string{"tianzi", "no_account", "broken", "", "tianzi"}, resolve, getCera)

	if got["tianzi"] != 60 {
		t.Fatalf("tianzi 点券应为 60（先 name→account_id 再查），实得 %d；若这里恒 0 说明又退回把账号名当 account_id 的旧 bug", got["tianzi"])
	}
	for _, name := range []string{"no_account", "broken", ""} {
		if v, ok := got[name]; !ok || v != 0 {
			t.Fatalf("%q 应返回 0 且不 panic，实得 v=%d ok=%v", name, v, ok)
		}
	}
	if len(got) != 4 {
		t.Fatalf("应恰好 4 个 key（去重+含空串），实得 %d: %v", len(got), got)
	}
}

// TestGetCeraMapS5A3LookupFailureKeepsZero 覆盖 getCera 返回 ok=false（库未配置/查询失败）
// 时的降级：余额记 0，不 panic、不误报。
func TestGetCeraMapS5A3LookupFailureKeepsZero(t *testing.T) {
	resolve := func(name string) (string, error) { return "dnf:10001", nil }
	getCera := func(key string) (int64, bool) { return 0, false }

	got := getCeraMapS5A3([]string{"someone"}, resolve, getCera)
	if v, ok := got["someone"]; !ok || v != 0 {
		t.Fatalf("查询失败应记 0，实得 v=%d ok=%v", v, ok)
	}
}
