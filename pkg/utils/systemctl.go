package utils

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// systemctlTimeout systemctl 的最长等待时间。
//
// start/stop/restart 默认会**阻塞到任务结束**，慢单元（尤其是游戏服务端）可能要
// 十几秒。给一个上限是为了避免 HTTP 请求被无限挂住：超时就明确报错，而不是
// 让浏览器一直转圈。
const systemctlTimeout = 120 * time.Second

// AuthDeniedHint polkit 未放行时的排障指引。
//
// 这段会拼进接口返回的 error 字段，管理页弹窗里能直接看到 —— 否则用户在后台
// 只会看到一句干巴巴的 "Interactive authentication required"，无从下手。
//
// ★ 必须按 polkit 版本分支给指引（2026-09-27 的教训）：
//   0.105（Ubuntu 22.04）**不读** /etc/polkit-1/rules.d —— 那里的 JS 规则
//   （polkit.addRule）是 0.106+ 才有的能力。当年只写"装 rules 文件"，
//   在 22.04 上照做完全无效，按钮照样报 Interactive authentication required，
//   白白多排查一轮。0.105 要走 localauthority 下的 .pkla。
const AuthDeniedHint = "原因：服务账号没有 systemd 管理权限（polkit 未放行该单元）。\n" +
	"修复：先 `pkcheck --version` 看 polkit 版本，再按版本装对应授权文件（都用 root）：\n" +
	"  · polkit 0.106+（Ubuntu 24.04 及以后）→ JS 规则\n" +
	"      install -m 0644 50-s4a21-gateway.rules /etc/polkit-1/rules.d/50-s4a21-gateway.rules\n" +
	"  · polkit 0.105（Ubuntu 22.04）→ pkla（**该版本不读 rules.d**，装 JS 规则无效）\n" +
	"      install -m 0644 50-s4a21-control.pkla /etc/polkit-1/localauthority/50-local.d/50-s4a21-control.pkla\n" +
	"  最后 systemctl restart polkit\n" +
	"（授权文件在部署包 _cloud161/ 下；白名单里要有本单元名）"

// SystemdControl 封装 systemctl 命令调用。
//
// ⚠️ 这里**不带 sudo**：能否启停由宿主机的 polkit 规则决定（见 AuthDeniedHint）。
// 部署脚本会把规则装到 /etc/polkit-1/rules.d/ —— 换机器重装时漏装，按钮就会
// 报 Interactive authentication required，因此启动时会做一次自检
// （见 pkg/service 的 PreflightSystemdControl）。
type SystemdControl struct{}

// NewSystemdControl 创建 systemd 控制器。
func NewSystemdControl() *SystemdControl {
	return &SystemdControl{}
}

// IsLinux 检查当前系统是否为 Linux。
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// Status 获取 systemd 单元状态。
//
// 取的是 **MainPID**：老代码写的 `-p PID` 在 systemd 里根本不是合法属性名，
// systemctl 会静默返回空 —— 结果管理页的"进程 PID"永远是 0（显示成 "-"）。
func (sc *SystemdControl) Status(unit string) (*SystemdStatus, error) {
	if !IsLinux() {
		return nil, nil
	}

	out, err := sc.output("show", unit, "--property=ActiveState,SubState,MainPID,ExecStart")
	if err != nil {
		return nil, err
	}
	return parseShowOutput(string(out)), nil
}

// parseShowOutput 解析 `systemctl show --property=...` 的输出。
//
// 抽出来是为了能单测（Status 依赖真实 systemctl，没法在开发机上跑）。
func parseShowOutput(out string) *SystemdStatus {
	status := &SystemdStatus{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], strings.TrimSpace(parts[1])
		switch key {
		case "ActiveState":
			status.Active = val
		case "SubState":
			status.SubState = val
		case "MainPID":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				status.PID = n
			}
		case "ExecStart":
			status.ExecStart = val
		}
	}
	return status
}

// Start 启动 systemd 单元。
func (sc *SystemdControl) Start(unit string) error {
	return sc.execute("start", unit)
}

// Stop 停止 systemd 单元。
func (sc *SystemdControl) Stop(unit string) error {
	return sc.execute("stop", unit)
}

// Restart 重启 systemd 单元。
func (sc *SystemdControl) Restart(unit string) error {
	return sc.execute("restart", unit)
}

func (sc *SystemdControl) execute(action, unit string) error {
	if !IsLinux() {
		return nil // 非 Linux 系统不执行
	}
	out, err := sc.output(action, unit)
	if err != nil {
		return &SystemdError{Err: err, Output: string(out)}
	}
	return nil
}

// output 执行一条 systemctl 命令并返回合并后的输出。
//
// --no-ask-password：服务进程没有终端，万一 polkit 要求交互式认证，
// 这个参数能让它立刻失败，而不是卡在等密码上。
func (sc *SystemdControl) output(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()

	full := append([]string{"--no-ask-password"}, args...)
	cmd := exec.CommandContext(ctx, "systemctl", full...)
	// 进程被 kill 后，等一会儿让 IO 收尾，避免 CombinedOutput 永久阻塞在管道上
	cmd.WaitDelay = 5 * time.Second

	out, err := cmd.CombinedOutput()
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, errors.New("systemctl 执行超时（" + systemctlTimeout.String() + "），服务可能卡在启停过程中")
	}
	return out, err
}

// CheckControlPermission 在**不产生任何副作用**的前提下自检能否启停该单元。
//
// 原理：对**已经 active** 的单元执行 `systemctl start` 是幂等的 —— systemd 直接
// 返回"已经在运行"，不会真的再启动一次；但 polkit 的授权检查照样会执行。
// 于是这条命令既能探到权限，又不会动到服务。
//
// 实测（systemd 255 / Ubuntu 24.04）：
//   - 白名单单元 -> 成功（RC=0）
//   - 非白名单单元 -> Failed to start ...: Interactive authentication required.
//
// 单元当前不是 active 时**不探测** —— 对没运行的单元执行 start 会真的把它拉起来。
// 返回 (放行?, 说明)；无法判定时一律返回放行（true），避免误报吓人。
func (sc *SystemdControl) CheckControlPermission(unit string) (bool, string) {
	if !IsLinux() {
		return true, "非 Linux 系统，跳过权限自检"
	}

	status, err := sc.Status(unit)
	if err != nil || status == nil {
		return true, "无法读取单元状态，跳过权限自检：" + errText(err)
	}
	if status.Active != "active" {
		return true, "单元当前为 " + status.Active + "，跳过权限自检（避免误启动）"
	}

	out, err := sc.output("start", unit)
	if err == nil {
		return true, "已放行"
	}
	if isAuthDenied(string(out)) {
		return false, strings.TrimSpace(string(out))
	}
	// 其它错误（单元不存在等）不算权限问题，交给按钮自己去报错
	return true, "探测命令返回其它错误（未判定为权限问题）：" + firstLine(string(out))
}

// IsAuthDenied 判断 error 是否为 polkit 拒绝（供上层决定是否附加排障指引）。
func (e *SystemdError) IsAuthDenied() bool {
	return isAuthDenied(e.Output)
}

func isAuthDenied(out string) bool {
	return strings.Contains(out, "Interactive authentication required") ||
		strings.Contains(out, "Access denied") ||
		strings.Contains(out, "authentication is required")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func errText(err error) string {
	if err == nil {
		return "未知错误"
	}
	return err.Error()
}

// SystemdStatus systemd 单元状态。
type SystemdStatus struct {
	Active    string
	SubState  string
	PID       int
	ExecStart string
}

// SystemdError systemd 操作错误。
type SystemdError struct {
	Err    error
	Output string
}

// Error 返回给管理页展示的错误文案。
//
// 权限类错误会自动附上排障指引 —— 这是最常见的失败原因（宿主机没装 polkit 规则）。
func (e *SystemdError) Error() string {
	msg := strings.TrimSpace(e.Output)
	if msg == "" {
		msg = errText(e.Err)
	}
	if isAuthDenied(e.Output) {
		return msg + "\n\n" + AuthDeniedHint
	}
	return msg
}

// Unwrap 保留原始错误，便于 errors.Is/As。
func (e *SystemdError) Unwrap() error {
	return e.Err
}

// ==================== journald（2026-11-01） ====================

// journalctlTimeout journalctl 的最长等待时间。
//
// 只读最近 N 行，正常是毫秒级；给 15 秒是为了兜住"journal 很大 + 磁盘慢"，
// 又不至于把后台请求挂死。
const journalctlTimeout = 15 * time.Second

// JournalTail 读取某个 systemd 单元的最近 N 行日志（走 journalctl）。
//
// 为什么需要：S5A3 服务端由 systemd 托管，**不写日志文件** —— 标准输出直接进
// journald。后台「服务端日志」原来只按文件 tail，于是永远返回「未配置的日志键」。
//
// 返回 journalctl 的原样输出行（`short-iso` 格式，自带时间戳），观感与文件 tail 一致。
func JournalTail(unit string, lines int) ([]string, error) {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return nil, errors.New("未配置服务单元名（Server.Unit），无法从 journald 读取")
	}
	// 单元名来自配置文件，但仍然做一次白名单校验：配置写错时宁可明确报错，
	// 也不要把奇怪的值当参数塞给 journalctl。
	if !validUnitName(unit) {
		return nil, fmt.Errorf("服务单元名不合法: %q", unit)
	}
	if lines <= 0 {
		lines = 300
	}
	if lines > 5000 {
		lines = 5000
	}

	ctx, cancel := context.WithTimeout(context.Background(), journalctlTimeout)
	defer cancel()

	// --no-pager 必须带：否则 journalctl 会尝试调 less，在非交互环境下直接挂住。
	cmd := exec.CommandContext(ctx, "journalctl",
		"-u", unit,
		"-n", strconv.Itoa(lines),
		"--no-pager",
		"--output=short-iso")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("journalctl 超时（%s）", journalctlTimeout)
		}
		// 把 stderr 带出来：最常见的是权限不足（服务账号不在 systemd-journal 组）。
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("journalctl 读取失败: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("journalctl 读取失败: %w", err)
	}

	text := strings.TrimRight(string(out), "\n")
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

// validUnitName 校验 systemd 单元名：只允许字母数字与 @ . _ -，长度有上限。
func validUnitName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '@' || r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}
