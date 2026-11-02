package auth

// ============================================================================
// 邀请码"失败不消耗"（2026-11-01）
//
// 玩家反馈：注册没成功，邀请码却被用掉了 —— 撞上注册限额后，账号没建成，
// 码也变成"已使用"，只能找运营补发。
//
// 旧实现是"先原子消耗邀请码，再建号"，建号失败时码就废了。
// 现在改成"只读校验 → 建号 → 成功后绑定"，本文件锁死这个行为：
//   ① 注册失败（撞限额）时，邀请码必须仍是未使用状态
//   ② 同一个码换台机器/换个 IP 之后还能正常注册
//   ③ 注册成功时，码的 used_by 必须正好是这个账号（绑定，不是丢弃）
// ============================================================================

import (
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/utils"
)

// TestInviteNotConsumedWhenRegisterFails 锁死"建号失败不烧码"。
func TestInviteNotConsumedWhenRegisterFails(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	// 同 IP 每天只允许 1 个号：第二个必然撞限额
	cfg.RegisterLimit.Enabled = true
	cfg.RegisterLimit.PerIPPerDay = 1
	cfg.RegisterLimit.PerMachine = 0

	h, _, db := newLoginFixtureWithDB(t, cfg)

	codeA := testInviteCodeAt(1)
	codeB := testInviteCodeAt(2)

	// ① 第一个号正常注册，用掉 codeA
	if c, msg := registerViaHandlerFull(t, h, "invfail1", "7.7.7.1", "", "", codeA, ""); c != models.Err.Ok {
		t.Fatalf("第一个号应注册成功: code=%d msg=%s", c, msg)
	}

	// ② 同一个 IP 再注册：撞限额，必须失败
	c, _ := registerViaHandlerFull(t, h, "invfail2", "7.7.7.1", "", "", codeB, "")
	if c == models.Err.Ok {
		t.Fatal("同 IP 第二个号竟然注册成功 —— 限额没生效，本用例的前提不成立")
	}

	// ③ ★ 关键断言：注册失败后 codeB 必须还是"未使用"
	if st := db.ValidateInvite(codeB); st != database.InviteConsumeOK {
		t.Fatalf("注册失败却把邀请码消耗了（status=%d）—— 玩家会既没号也没码", st)
	}

	// ④ 换个 IP 用同一个码，应该还能注册成功
	if c, msg := registerViaHandlerFull(t, h, "invfail3", "7.7.7.2", "", "", codeB, ""); c != models.Err.Ok {
		t.Fatalf("注册失败后同一个码应该还能用，实得 code=%d msg=%s", c, msg)
	}

	// ⑤ 成功之后码才真正绑到这个账号上
	code, usedBy := inviteUsage(t, db, codeB)
	if code != database.InviteStatusUsed {
		t.Fatalf("注册成功后码应为 used，实得 %s", code)
	}
	if usedBy != "invfail3" {
		t.Fatalf("码应绑定到 invfail3，实得 %q", usedBy)
	}
}

// TestInviteStillRejectsInvalidCode 确保"不消耗"没有把校验一起放宽。
func TestInviteStillRejectsInvalidCode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.RegisterLimit.Enabled = false
	h, _, _ := newLoginFixtureWithDB(t, cfg)

	c, _ := registerViaHandlerFull(t, h, "invbad1", "7.7.8.1", "", "", "ZZZZ-ZZZZ", "")
	if c != models.Err.InviteInvalid {
		t.Fatalf("无效码应返回 InviteInvalid，实得 code=%d", c)
	}
}

// TestInviteUsedCodeRejected 一码一用：已被绑定的码不能再注册第二个号。
func TestInviteUsedCodeRejected(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.RegisterLimit.Enabled = false
	h, _, db := newLoginFixtureWithDB(t, cfg)

	code := testInviteCodeAt(3)
	if c, msg := registerViaHandlerFull(t, h, "invused1", "7.7.9.1", "", "", code, ""); c != models.Err.Ok {
		t.Fatalf("首个号应成功: code=%d msg=%s", c, msg)
	}
	if c, _ := registerViaHandlerFull(t, h, "invused2", "7.7.9.2", "", "", code, ""); c != models.Err.InviteInvalid {
		t.Fatalf("已用的码应被拒，实得 code=%d", c)
	}

	// 被拒的那次不该改动绑定关系
	_, usedBy := inviteUsage(t, db, code)
	if usedBy != "invused1" {
		t.Fatalf("码的绑定关系被覆盖了: %q", usedBy)
	}
}

// inviteUsage 读出某个码的状态与绑定账号。
//
// ★ 走 GetInviteByCode 而不是 ListInvites：列表单页上限 200 条、
// 且批量码的时间戳相同导致翻页顺序不稳定，测试里会"明明有却查不到"。
func inviteUsage(t *testing.T, db *database.Database, rawCode string) (database.InviteStatus, string) {
	t.Helper()
	it, err := db.GetInviteByCode(rawCode)
	if err != nil {
		t.Fatalf("查邀请码失败: %v", err)
	}
	if it == nil {
		t.Fatalf("库里找不到邀请码 %s", database.NormalizeInviteCode(rawCode))
	}
	return it.Status(utils.NowUnix()), it.UsedBy
}
