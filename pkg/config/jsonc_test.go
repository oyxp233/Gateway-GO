package config

import (
	"encoding/json"
	"testing"
)

// TestStripJsoncCommentsRealProductionShapes 钉住真实生产文件的两个形状。
//
// 背景（2026-09-28）：生产 8.138.9.216 的 appsettings.json 与 bonus.json 都是
// .NET 侧 System.Text.Json 体系的产物 —— 既有 `//` / `/* */` 注释，又有**尾随逗号**。
// 网关读它们时只去注释不去逗号，就会解析失败；bonus.json 那条症状很隐蔽：
// 解析失败 → 返回 nil → 泡点整轮跳过 + 每轮刷一条「泡点配置解析失败」。
func TestStripJsoncCommentsRealProductionShapes(t *testing.T) {
	// ① 216 的 bonus.json 原样（去掉注释后必须是合法 JSON）
	bonus := "// ============================================================\n" +
		"// 泡点配置（在线挂机奖励）\n" +
		"// 后台每隔 interval_seconds 秒，对最近 active_threshold_minutes\n" +
		"// 分钟内活跃的账号发放 amount_per_interval 点券（cera）。\n" +
		"// 修改保存后下一轮生效，无需重启网关。\n" +
		"// ============================================================\n" +
		"{\n" +
		"  // 是否启用泡点功能\n" +
		"  \"enabled\": true,\n" +
		"  // 发放间隔（秒）：后台每隔该时长对活跃账号发放一次点券\n" +
		"  \"interval_seconds\": 60,\n" +
		"  // 每轮每账号发放点券数量（cera）\n" +
		"  \"amount_per_interval\": 100,\n" +
		"  // 活跃判定阈值（分钟）\n" +
		"  \"active_threshold_minutes\": 2\n" +
		"}\n"

	var got struct {
		Enabled                bool
		IntervalSeconds        int
		AmountPerInterval      int
		ActiveThresholdMinutes int
	}
	// 用带 tag 的结构体名对不上，这里直接解到 map 再取，避免受 tag 影响
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(StripJsoncComments(bonus)), &m); err != nil {
		t.Fatalf("216 的 bonus.json 去注释后仍不能解析: %v", err)
	}
	if m["enabled"] != true || m["interval_seconds"].(float64) != 60 ||
		m["amount_per_interval"].(float64) != 100 ||
		m["active_threshold_minutes"].(float64) != 2 {
		t.Fatalf("解析出来的值不对: %#v", m)
	}
	_ = got

	// ② 块注释 + 尾随逗号（216 appsettings.json 的形状）
	app := "{\n" +
		"  /* 网关端口 */\n" +
		"  \"TcpPort\": 8000,\n" +
		"  \"Ports\": [8000, 8080,],\n" +
		"  \"Nested\": {\"a\": 1,},\n" +
		"}\n"
	var m2 map[string]interface{}
	if err := json.Unmarshal([]byte(StripJsoncComments(app)), &m2); err != nil {
		t.Fatalf("块注释 + 尾随逗号应能解析: %v", err)
	}
	if len(m2["Ports"].([]interface{})) != 2 {
		t.Fatalf("数组尾随逗号处理不对: %#v", m2["Ports"])
	}

	// ③ 字符串内部的 // 与 /* 不能被当注释吃掉；字符串里的逗号不能被当尾随逗号
	s := "{\n  \"Url\": \"https://example.com/a//b\",\n  \"Pat\": \"x/*y*/\",\n}\n"
	var m3 map[string]string
	if err := json.Unmarshal([]byte(StripJsoncComments(s)), &m3); err != nil {
		t.Fatalf("字符串内的注释序列被误删: %v", err)
	}
	if m3["Url"] != "https://example.com/a//b" || m3["Pat"] != "x/*y*/" {
		t.Fatalf("字符串内容被改坏: %#v", m3)
	}

	// ④ 不能因为"放宽"把合法内容改坏：普通 JSON 必须原样可解
	plain := `{"a":1,"b":[1,2,3],"c":{"d":"e,f"}}`
	var m4 map[string]interface{}
	if err := json.Unmarshal([]byte(StripJsoncComments(plain)), &m4); err != nil {
		t.Fatalf("普通 JSON 被改坏: %v", err)
	}
}
