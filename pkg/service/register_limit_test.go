package service

import (
	"testing"

	"s4a21-gateway/pkg/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// 注册限额（2026-10-13）
//
// 判据成对写：放行路径绿 + 每条"本该拒绝"的路径必须红。
// 覆盖的核心语义（与 config.RegisterLimitSection 的注释一一对应）：
//   A. 同 IP 当日超限 → 1036；
//   B. 同机器累计超限 → 1037；
//   C. 机器码**缺失**时跳过机器维度（绝不能空值共用一个配额）；
//   D. 阈值 0 = 不限制该维度；
//   E. 总开关关 = 全放行；
//   F. 热改后**立即**生效（不是下次启动才生效）；
//   G. 成功注册会落流水，流水是后续计数的唯一依据；
//   H. 不同 IP / 不同机器互不影响。
// ─────────────────────────────────────────────────────────────────────────────

const regTestPwd = "e10adc3949ba59abbe56e057f20f883e" // "123456"

// setLimit 直接改内存里的限额（测试内部用；生产走后台 → runtime 后端）。
func setLimit(svc *AccountService, enabled bool, perIP, perMachine int) {
	svc.config.SetRegisterLimitRuntime(&enabled, &perIP, &perMachine)
}

// reg 用带限额的注册路径注册一个账号，返回错误码。
func reg(svc *AccountService, name, ip, machine string) int {
	code, _ := svc.RegisterWithLimit(name, regTestPwd, ip, machine)
	return code
}

// ── A. 同一 IP 当日超限 ─────────────────────────────────────────────────

func TestRegisterLimit_IPPerDay(t *testing.T) {
	svc, db := newAccountSvcFixture(t)
	setLimit(svc, true, 2, 0) // 只开 IP 维度

	ip := "113.15.1.1"
	if code := reg(svc, "ipuseraa", ip, "mach-x"); code != models.Err.Ok {
		t.Fatalf("第 1 个应放行: code=%d", code)
	}
	if code := reg(svc, "ipuserbb", ip, "mach-x"); code != models.Err.Ok {
		t.Fatalf("第 2 个应放行: code=%d", code)
	}
	// 第 3 个：同一 IP，当日已达 2 ⇒ 必须红。
	if code := reg(svc, "ipusercc", ip, "mach-x"); code != models.Err.RegisterIpLimit {
		t.Fatalf("第 3 个应被 IP 限额拦下(1036): code=%d", code)
	}

	// ★ 反向断言：账号**没有**被创建。
	// 否则就是"拒绝了但脏数据落库"，玩家重试会撞 1003，看起来像注册彻底坏了。
	acc, err := db.GetAccountByName("ipusercc")
	if err != nil {
		t.Fatalf("查账号失败: %v", err)
	}
	if acc != nil {
		t.Fatal("被限额拦下的注册不该在建号表里留下记录")
	}

	// 流水只该有 2 条。
	n, err := db.CountRegistrationsByIPSince(ip, 0)
	if err != nil {
		t.Fatalf("统计流水失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("流水应为 2 条，实际 %d", n)
	}

	// 换一个 IP 不受影响。
	if code := reg(svc, "ipuserdd", "113.15.9.9", "mach-y"); code != models.Err.Ok {
		t.Fatalf("不同 IP 应放行: code=%d", code)
	}
}

// ── B. 同一机器累计超限 ─────────────────────────────────────────────────

func TestRegisterLimit_PerMachineTotal(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)
	setLimit(svc, true, 0, 2) // 只开机器维度

	machine := "AA-BB-CC-DD-EE-FF"
	// 刻意每条都换 IP：证明拦的是机器，不是 IP（否则测试会因 IP 限额误绿）。
	if code := reg(svc, "macuseraa", "10.0.0.1", machine); code != models.Err.Ok {
		t.Fatalf("第 1 个应放行: code=%d", code)
	}
	if code := reg(svc, "macuserbb", "10.0.0.2", machine); code != models.Err.Ok {
		t.Fatalf("第 2 个应放行: code=%d", code)
	}
	if code := reg(svc, "macusercc", "10.0.0.3", machine); code != models.Err.RegisterMachineLimit {
		t.Fatalf("第 3 个应被机器限额拦下(1037): code=%d", code)
	}

	// 换机器放行。
	if code := reg(svc, "macuserdd", "10.0.0.4", "11-22-33-44-55-66"); code != models.Err.Ok {
		t.Fatalf("不同机器应放行: code=%d", code)
	}
}

// ── C. 机器码缺失 ⇒ 跳过机器维度 ────────────────────────────────────────

func TestRegisterLimit_EmptyMachineSkipsMachineDimension(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)
	// 机器维度设成 1：若实现把空串当成"同一台机器"，第 2 个就会被拦。
	setLimit(svc, true, 0, 1)

	for i, name := range []string{"nomacuser1", "nomacuser2", "nomacuser3"} {
		// IP 各不相同，排除 IP 维度的干扰（这里 IP 维度本来就是 0，双保险）。
		ip := "10.1.0." + string(rune('1'+i))
		if code := reg(svc, name, ip, ""); code != models.Err.Ok {
			t.Fatalf("机器码缺失时应跳过机器维度、照常放行（第 %d 个）: code=%d", i+1, code)
		}
	}
}

// ── D. 阈值 0 = 该维度不限制 ────────────────────────────────────────────

func TestRegisterLimit_ZeroThresholdIsUnlimited(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)
	setLimit(svc, true, 0, 0)

	ip := "10.2.0.1"
	for i, name := range []string{"zerouseraa", "zerouserbb", "zerousercc", "zerouserdd"} {
		if code := reg(svc, name, ip, "same-machine"); code != models.Err.Ok {
			t.Fatalf("阈值 0 应不限制（第 %d 个）: code=%d", i+1, code)
		}
	}
}

// ── E. 总开关关 = 全放行 ────────────────────────────────────────────────

func TestRegisterLimit_DisabledAllowsAll(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)
	setLimit(svc, false, 1, 1)

	ip := "10.3.0.1"
	for i, name := range []string{"offuseraa", "offuserbb", "offusercc"} {
		if code := reg(svc, name, ip, "one-machine"); code != models.Err.Ok {
			t.Fatalf("总开关关闭时应放行（第 %d 个）: code=%d", i+1, code)
		}
	}
}

// ── F. 热改立即生效 ─────────────────────────────────────────────────────

func TestRegisterLimit_HotReloadTakesEffectImmediately(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)
	setLimit(svc, true, 1, 0)

	ip := "10.4.0.1"
	if code := reg(svc, "hotuseraa", ip, ""); code != models.Err.Ok {
		t.Fatalf("第 1 个应放行: code=%d", code)
	}
	if code := reg(svc, "hotuserbb", ip, ""); code != models.Err.RegisterIpLimit {
		t.Fatalf("限 1 时第 2 个应被拦(1036): code=%d", code)
	}

	// 后台把上限提到 3 —— 不重启、不重载配置，下一次注册就该放行。
	setLimit(svc, true, 3, 0)
	if code := reg(svc, "hotuserbb", ip, ""); code != models.Err.Ok {
		t.Fatalf("热改到 3 后第 2 个应放行: code=%d", code)
	}
	if code := reg(svc, "hotusercc", ip, ""); code != models.Err.Ok {
		t.Fatalf("热改到 3 后第 3 个应放行: code=%d", code)
	}
	if code := reg(svc, "hotuserdd", ip, ""); code != models.Err.RegisterIpLimit {
		t.Fatalf("热改到 3 后第 4 个应被拦(1036): code=%d", code)
	}
}

// ── G. 成功注册落流水（含机器码），且流水是可查询的历史 ──────────────────

func TestRegisterLimit_LogRecordedWithIPAndMachine(t *testing.T) {
	svc, db := newAccountSvcFixture(t)
	setLimit(svc, true, 0, 0)

	if code := reg(svc, "loguseraa", "10.5.0.1", "MACHINE-LOG-1"); code != models.Err.Ok {
		t.Fatalf("注册应成功: code=%d", code)
	}

	byIP, err := db.ListRecentRegistrationLogsByIP("10.5.0.1", 10)
	if err != nil {
		t.Fatalf("按 IP 查流水失败: %v", err)
	}
	if len(byIP) != 1 {
		t.Fatalf("应有 1 条流水，实际 %d", len(byIP))
	}
	if byIP[0].Account != "loguseraa" || byIP[0].MachineID != "MACHINE-LOG-1" {
		t.Fatalf("流水内容不对: %+v", byIP[0])
	}
	if byIP[0].MID == "" {
		t.Fatal("流水应带上 m_id（后台排查时要能直接定位账号）")
	}

	byMachine, err := db.ListRecentRegistrationLogsByMachine("MACHINE-LOG-1", 10)
	if err != nil {
		t.Fatalf("按机器查流水失败: %v", err)
	}
	if len(byMachine) != 1 {
		t.Fatalf("按机器码应有 1 条交叉命中，实际 %d", len(byMachine))
	}
}

// ── I. 限额拦下时不影响**已有账号**的登录（限额只作用在建号口）────────────

func TestRegisterLimit_DoesNotBlockExistingAccountLogin(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)
	setLimit(svc, true, 1, 1)

	ip := "10.6.0.1"
	if code := reg(svc, "logincheck", ip, "mach-login"); code != models.Err.Ok {
		t.Fatalf("首个注册应放行: code=%d", code)
	}
	// 配额已满。
	if code := reg(svc, "logincheck2", ip, "mach-login"); code != models.Err.RegisterIpLimit {
		t.Fatalf("第 2 个应被拦(1036): code=%d", code)
	}

	// 已有账号照常登录：限额只挂在注册口，不该连坐登录。
	res := svc.Login("logincheck", regTestPwd, "", ip)
	if res.ErrorCode != models.Err.Ok {
		t.Fatalf("已有账号登录不该受注册限额影响: code=%d", res.ErrorCode)
	}
}
