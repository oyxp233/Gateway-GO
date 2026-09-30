package utils

import (
	"errors"
	"strings"
	"testing"
)

// 真实的 `systemctl show --property=ActiveState,SubState,MainPID,ExecStart` 输出样本。
const showSample = `ExecStart={ path=/opt/gateway/s4a21-admin ; argv[]=/opt/gateway/s4a21-admin --config /opt/gateway/appsettings.json ; ignore_errors=no ; start_time=[Wed 2026-09-23 07:19:49 UTC] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
MainPID=10920
ActiveState=active
SubState=running
`

func TestParseShowOutputMainPID(t *testing.T) {
	st := parseShowOutput(showSample)
	if st.PID != 10920 {
		t.Fatalf("MainPID 应解析为 10920，实际 %d", st.PID)
	}
	if st.Active != "active" || st.SubState != "running" {
		t.Fatalf("状态解析错误: active=%q sub=%q", st.Active, st.SubState)
	}
	if !strings.Contains(st.ExecStart, "/opt/gateway/s4a21-admin") {
		t.Fatalf("ExecStart 解析错误: %q", st.ExecStart)
	}
}

// 老实现用 `-p PID`（systemd 没有这个属性名）→ 整个属性都不返回，
// 结果管理页 PID 永远显示 0/-。这里固定住"没有 MainPID 时不许伪造数值"。
func TestParseShowOutputNoMainPID(t *testing.T) {
	st := parseShowOutput("ActiveState=inactive\nSubState=dead\n")
	if st.PID != 0 {
		t.Fatalf("无 MainPID 时应保持 0，实际 %d", st.PID)
	}
}

func TestParseShowOutputMainPIDZero(t *testing.T) {
	st := parseShowOutput("ActiveState=failed\nMainPID=0\n")
	if st.PID != 0 {
		t.Fatalf("MainPID=0（未运行）应保持 0，实际 %d", st.PID)
	}
}

func TestParseShowOutputGarbage(t *testing.T) {
	// ExecStart 里也含 `pid=0`，不能被误当成 MainPID；脏行不能 panic
	st := parseShowOutput("nonsense\nMainPID=abc\n=broken\nMainPID=42\n")
	if st.PID != 42 {
		t.Fatalf("应取到合法的那条 MainPID=42，实际 %d", st.PID)
	}
}

func TestIsAuthDenied(t *testing.T) {
	cases := map[string]bool{
		"Failed to restart cron.service: Interactive authentication required.": true,
		"Failed to restart x: Access denied":                                   true,
		"Failed to restart x: Unit x.service not found.":                       false,
		"": false,
	}
	for in, want := range cases {
		if got := isAuthDenied(in); got != want {
			t.Errorf("isAuthDenied(%q) = %v，期望 %v", in, got, want)
		}
	}
}

// 权限类错误必须带上可照抄的修复命令 —— 否则界面上只有一句
// "Interactive authentication required"，没法排查。
func TestSystemdErrorAddsHintOnAuthDenied(t *testing.T) {
	e := &SystemdError{
		Err:    errors.New("exit status 1"),
		Output: "Failed to restart gateway.service: Interactive authentication required.",
	}
	msg := e.Error()
	if !strings.Contains(msg, "Interactive authentication required") {
		t.Fatalf("应保留原始 systemd 输出: %q", msg)
	}
	if !strings.Contains(msg, "50-s4a21-gateway.rules") || !strings.Contains(msg, "restart polkit") {
		t.Fatalf("权限错误应附带修复指引: %q", msg)
	}
	if !e.IsAuthDenied() {
		t.Fatal("IsAuthDenied 应返回 true")
	}
}

func TestSystemdErrorNoHintOnOtherErrors(t *testing.T) {
	e := &SystemdError{
		Err:    errors.New("exit status 5"),
		Output: "Failed to restart nosuch.service: Unit nosuch.service not found.",
	}
	msg := e.Error()
	if strings.Contains(msg, "50-s4a21-gateway.rules") {
		t.Fatalf("非权限错误不该附权限指引: %q", msg)
	}
	if !strings.Contains(msg, "not found") {
		t.Fatalf("应返回原始错误: %q", msg)
	}
}

func TestSystemdErrorFallsBackToErr(t *testing.T) {
	e := &SystemdError{Err: errors.New("boom")}
	if e.Error() != "boom" {
		t.Fatalf("无输出时应回落到 Err，实际 %q", e.Error())
	}
	if !errors.Is(e, e.Err) {
		t.Fatal("Unwrap 应能取回原始错误")
	}
}

// 非 Linux（开发机）不应真的去调 systemctl，也不该把自己判成"没权限"。
func TestCheckControlPermissionNonLinux(t *testing.T) {
	if IsLinux() {
		t.Skip("仅在非 Linux 开发机上验证短路逻辑")
	}
	ok, note := NewSystemdControl().CheckControlPermission("gateway.service")
	if !ok {
		t.Fatalf("非 Linux 应跳过自检并返回放行，实际 %v（%s）", ok, note)
	}
}
