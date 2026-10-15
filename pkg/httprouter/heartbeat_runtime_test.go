package httprouter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/service"
)

// ─────────────────────────────────────────────────────────────────────────────
// 心跳超时的运行时热改（2026-10-14）
//
// 事故背景：TimeoutSeconds=60 对 30s 心跳只留 1 拍冗余，会话被误清的表现是
// "玩家在游戏里被踢"。而改这个值原先**必须重启网关**（= 全体掉线）——
// 于是"为修掉线而重启"本身就制造掉线。
//
// 本批把它做成运行时可变：写内存（cfg.Heartbeat，锁内） + 落盘 override。
// 下面三条断言分别锁：
//   1. 写进去的值立刻能被读到（内存热改）；
//   2. 值同时落了盘（重启不丢）；
//   3. 真正读它的清理协程确实走的是**同一个快照**（不然热改是假的）。
// ─────────────────────────────────────────────────────────────────────────────

func newHeartbeatRuntimeFixture(t *testing.T) (*config.GatewayConfig, RuntimeConfigBackend, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	editor := service.NewAppSettingsEditor(dir, cfg)
	return cfg, NewLocalRuntimeConfigBackend(cfg, editor, nil), dir
}

// 默认值 + 热改 + 落盘。
func TestHeartbeatRuntime_SetUpdatesMemoryAndDisk(t *testing.T) {
	cfg, be, dir := newHeartbeatRuntimeFixture(t)

	hv, err := be.Heartbeat()
	if err != nil {
		t.Fatalf("读心跳配置失败: %v", err)
	}
	if hv.TimeoutSeconds != 60 {
		t.Fatalf("默认超时应为 60（与登录器 30s 心跳配套），实得 %d", hv.TimeoutSeconds)
	}

	// 传 nil = 该项不动（与 SetLauncher / SetRegisterLimit 同一约定）。
	if changed, err := be.SetHeartbeat(nil); err != nil || changed {
		t.Fatalf("传 nil 应无变更：changed=%v err=%v", changed, err)
	}

	v := 120
	changed, err := be.SetHeartbeat(&v)
	if err != nil {
		t.Fatalf("热改到 120 失败: %v", err)
	}
	if !changed {
		t.Fatalf("热改到 120 应报告有变更")
	}

	// ① 内存立即生效：这就是清理协程每 tick 读的那份值。
	hv2, err := be.Heartbeat()
	if err != nil {
		t.Fatalf("读心跳配置失败: %v", err)
	}
	if hv2.TimeoutSeconds != 120 {
		t.Fatalf("内存未热改：期望 120，实得 %d", hv2.TimeoutSeconds)
	}
	if got := cfg.HeartbeatSnapshot().TimeoutSeconds; got != 120 {
		t.Fatalf("cfg 快照未更新：期望 120，实得 %d", got)
	}

	// ② 落盘（重启后不还原）。
	raw, err := os.ReadFile(filepath.Join(dir, config.OverrideFileName))
	if err != nil {
		t.Fatalf("override 文件未写出: %v", err)
	}
	var parsed struct {
		Heartbeat struct {
			TimeoutSeconds int `json:"TimeoutSeconds"`
		} `json:"Heartbeat"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("override 不是合法 JSON: %v（原文 %s）", err, string(raw))
	}
	if parsed.Heartbeat.TimeoutSeconds != 120 {
		t.Fatalf("override 未写入 Heartbeat.TimeoutSeconds=120，实得 %d（重启会还原成 60）",
			parsed.Heartbeat.TimeoutSeconds)
	}
}

// 值域校验：必须大于心跳周期，且拒绝荒谬大数；被拒时**不许写盘**。
func TestHeartbeatRuntime_RejectsOutOfRangeAndDoesNotPersist(t *testing.T) {
	_, be, dir := newHeartbeatRuntimeFixture(t)

	for _, v := range []int{-5, 0, 10, 29, 3601, 99999} {
		vv := v
		_, err := be.SetHeartbeat(&vv)
		if err == nil {
			t.Fatalf("TimeoutSeconds=%d 应被拒（下限 30 = 心跳周期）", v)
		}
		// 后台按错误文本里的「取值必须在」回 400，所以这条文案是契约的一部分。
		if !strings.Contains(err.Error(), "取值必须在") {
			t.Fatalf("错误信息应含『取值必须在』，实得: %v", err)
		}
	}

	// 关键：越界值**不能被写进 override** —— 写进去下次启动会被原样读回，
	// 重启也修不好，只能手改文件（同 SetRegisterLimit 的理由）。
	if _, err := os.Stat(filepath.Join(dir, config.OverrideFileName)); !os.IsNotExist(err) {
		t.Fatalf("被拒的值不该产生 override 文件")
	}
}

// ★★ 源码级断言：清理协程必须走运行时快照读。
//
//	SetHeartbeat 把新值写进 cfg.Heartbeat 段，而**真正读它的地方在
//	cmd/gateway/main.go 的巡检协程** —— 那里必须写成
//	cfg.HeartbeatSnapshot().TimeoutSeconds（锁内快照），不能裸读字段。
//
//	两者只差一个函数调用：编译过、单测过，但"后台改完不生效"（而且裸读与
//	锁内写构成数据竞争）。这类"改了写入、漏改读取"的静默失效无法靠行为测试
//	发现（清理协程在 main 里，测试起不了），只能读源码文本钉死。
//
//	判据是**去掉注释后的代码文本**：注释里提到旧写法不该让用例变红。
func TestHeartbeatCleanupReadsRuntimeSnapshot(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cmd", "gateway", "main.go"))
	if err != nil {
		t.Fatalf("读 cmd/gateway/main.go 失败: %v", err)
	}

	var code strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	text := code.String()

	if !strings.Contains(text, "HeartbeatSnapshot().TimeoutSeconds") {
		t.Fatalf("清理协程没有走运行时快照：后台热改心跳超时不会生效")
	}
	if strings.Contains(text, "cfg.Heartbeat.TimeoutSeconds") {
		t.Fatalf("main.go 仍有对 Heartbeat.TimeoutSeconds 的裸读：" +
			"与 SetHeartbeat 的锁内写构成数据竞争，且可能读到旧值")
	}
}
