package auth

import (
	"encoding/json"
	"testing"

	"s4a21-gateway/pkg/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// 注册限额的**接线**验证（2026-10-13）
//
// pkg/service 的单测证明了判定逻辑本身对；这里证明**真实调用点接对了**：
//   A. clientIP 真的传进了 handleRegister（否则 IP 维度形同虚设）；
//   B. machine_id 真的从请求里取出来用（否则机器维度形同虚设）。
//
// ★ 这两条都必须走 Handler.Handle（真实入口）：
// 本项目吃过"单测传的措辞和真实调用点不一致，测试全绿而功能坏着"的亏
// （见 stale_relogin_test.go 的文件头注释）。判据成对：该拦的必须红，
// 不该拦的必须绿。
// ─────────────────────────────────────────────────────────────────────────────

// registerViaHandler 走真实入口注册，返回错误码。
func registerViaHandler(t *testing.T, h *Handler, account, ip, machineID string) int {
	t.Helper()
	ver := testLauncherVer
	pwd := testPwdMd5
	req := &models.GatewayRequest{
		Cmd:             models.Cmd.Register,
		Account:         &account,
		PasswordMd5:     &pwd,
		LauncherVersion: &ver,
	}
	if machineID != "" {
		m := machineID
		req.MachineId = &m
	}
	resp, err := h.Handle(req, ip)
	if err != nil {
		t.Fatalf("注册请求出错: %v", err)
	}
	return codeOf(resp)
}

// ── A. clientIP 必须真的被用上 ──────────────────────────────────────────

func TestRegisterLimit_HandlerUsesClientIP(t *testing.T) {
	h, _ := newLoginFixture(t, 0)

	// 只开 IP 维度、每次只允许 1 个 —— 这样"IP 有没有传进来"会直接反映在结果上。
	on := true
	one, zero := 1, 0
	h.config.SetRegisterLimitRuntime(&on, &one, &zero)

	// 同一 IP 的第二个必须被拦住。若 clientIP 被丢掉（变成 ""），
	// 判定会跳过 IP 维度 ⇒ 这里会绿 ⇒ 测试红。
	if code := registerViaHandler(t, h, "wireuseraa", "1.1.1.1", ""); code != models.Err.Ok {
		t.Fatalf("同 IP 第 1 个应放行: code=%d", code)
	}
	if code := registerViaHandler(t, h, "wireuserbb", "1.1.1.1", ""); code != models.Err.RegisterIpLimit {
		t.Fatalf("同 IP 第 2 个应被拦(1036) ⇒ 说明 clientIP 没传到 handleRegister: code=%d", code)
	}
	// 换 IP 放行。
	if code := registerViaHandler(t, h, "wireusercc", "2.2.2.2", ""); code != models.Err.Ok {
		t.Fatalf("不同 IP 应放行: code=%d", code)
	}
}

// ── B. machine_id 必须真的被用上 ────────────────────────────────────────

func TestRegisterLimit_HandlerUsesMachineId(t *testing.T) {
	h, _ := newLoginFixture(t, 0)

	on := true
	zero, one := 0, 1
	h.config.SetRegisterLimitRuntime(&on, &zero, &one)

	// IP 各不相同，排除 IP 维度的干扰。
	if code := registerViaHandler(t, h, "wiremaca1", "3.3.0.1", "WIRE-MACHINE-A"); code != models.Err.Ok {
		t.Fatalf("同机器第 1 个应放行: code=%d", code)
	}
	if code := registerViaHandler(t, h, "wiremacb2", "3.3.0.2", "WIRE-MACHINE-A"); code != models.Err.RegisterMachineLimit {
		t.Fatalf("同机器第 2 个应被拦(1037) ⇒ 说明 machine_id 没接进 handleRegister: code=%d", code)
	}
	// 换机器放行。
	if code := registerViaHandler(t, h, "wiremacc3", "3.3.0.3", "WIRE-MACHINE-B"); code != models.Err.Ok {
		t.Fatalf("不同机器应放行: code=%d", code)
	}
}

// ── C. 老登录器（不带 machine_id）照样能注册 ────────────────────────────

func TestRegisterLimit_HandlerToleratesMissingMachineId(t *testing.T) {
	h, _ := newLoginFixture(t, 0)

	on := true
	zero, one := 0, 1
	// 机器维度限 1：若空机器码被当成"同一台"，第 2 个老客户端就会被拦。
	h.config.SetRegisterLimitRuntime(&on, &zero, &one)

	for i, name := range []string{"legacyla1", "legacybb2", "legacycc3"} {
		ip := "4.4.0." + string(rune('1'+i))
		if code := registerViaHandler(t, h, name, ip, ""); code != models.Err.Ok {
			t.Fatalf("老登录器（无 machine_id）应照常注册（第 %d 个）: code=%d", i+1, code)
		}
	}
}

// ── D. JSON 协议契约：请求里的 "machine_id" 必须解码进 MachineId ────────
//
// 这条是**跨语言**契约（C# 登录器发 camelCase JSON，Go 侧按 tag 解）。
// 光看 Go 结构体是查不出来的：tag 写错时编译一样过、单测用结构体传参也一样过，
// 只有真的走一遍 JSON 才会暴露。

func TestGatewayRequest_MachineIdJSONTag(t *testing.T) {
	var req models.GatewayRequest
	raw := []byte(`{"cmd":"CMD_REGISTER","account":"jsonuser1","machine_id":"AA-BB-CC-DD-EE-FF"}`)
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if req.MachineId == nil || *req.MachineId != "AA-BB-CC-DD-EE-FF" {
		t.Fatalf("machine_id 未按预期解码: %+v", req.MachineId)
	}

	// 反向：不出现在请求里时必须是 nil（而不是空串指针），
	// 否则"没上报"与"上报了空值"两种情形会被混为一谈。
	var bare models.GatewayRequest
	if err := json.Unmarshal([]byte(`{"cmd":"CMD_REGISTER"}`), &bare); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if bare.MachineId != nil {
		t.Fatalf("未携带 machine_id 时应为 nil，实际 %q", *bare.MachineId)
	}
}
