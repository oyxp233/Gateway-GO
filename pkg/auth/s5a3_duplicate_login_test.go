package auth

import (
	"testing"
)

// TestS5A3DuplicateLoginDecision 是审查报告 H2（2026-11-17）的区分力测试。
//
// 现场：S5A3 登录分支（handleLoginS5A3）直接 ReplaceAccountSessions(carryOver=false)，
// 既没有「账号已在线 1023」提示，静默踢掉第一个玩家，又把在线时长/泡点清零。
// S4A21 路径则完整走 FindSessionByAccount + ForceLogin + 掉线重连放行 + carryOver。
//
// 这里把判定抽成共享的 duplicateLoginDecision，两条路径都调用它。
// 本测试锁定三档行为：
//  1. 已在线 + 无 force + 非掉线重连 → 拒绝（1023，登录器弹窗）
//  2. 已在线 + 带 force，或掉线重连 → 放行，且 alreadyOnline=true（结转时长）
//  3. 未在线 → 放行，alreadyOnline=false
//
// 若 S5A3 仍走旧的"无条件放行 + carryOver=false"，本用例会红在 case 1/2。
func TestS5A3DuplicateLoginDecision(t *testing.T) {
	cases := []struct {
		name           string
		alreadyOnline  bool
		forceLogin     bool
		staleReconnect bool
		wantReject     bool
		wantCarryOver  bool
	}{
		{"异地二次登录无 force → 1023", true, false, false, true, true},
		{"异地二次登录带 force → 放行并结转", true, true, false, false, true},
		{"同端掉线重连 → 放行并结转", true, false, true, false, true},
		{"首次登录 → 放行不结转", false, false, false, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reject, carryOver := duplicateLoginDecision(tc.alreadyOnline, tc.forceLogin, tc.staleReconnect)
			if reject != tc.wantReject {
				t.Fatalf("拒绝判定 = %v，期望 %v（已在线=%v force=%v stale=%v）",
					reject, tc.wantReject, tc.alreadyOnline, tc.forceLogin, tc.staleReconnect)
			}
			if carryOver != tc.wantCarryOver {
				t.Fatalf("carryOver = %v，期望 %v —— S5A3 旧 bug 正是这里恒 false 导致时长清零",
					carryOver, tc.wantCarryOver)
			}
		})
	}
}
