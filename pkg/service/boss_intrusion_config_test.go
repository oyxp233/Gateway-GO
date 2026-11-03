package service

import (
	"encoding/json"
	"strings"
	"testing"
)

// BOSS 乱入配置的校验（2026-11-03）
//
// 网关不解释字段，只保证存进去的是**合法 JSON 对象**。这里锁住三条：
// 合法对象通过、非对象（数组/标量/null）拒绝、坏 JSON 拒绝。
// 字段语义归游戏服务端，网关不参与 —— 所以这里刻意不测任何业务字段。

func TestNormalizeBossIntrusionConfigJSONAcceptsObject(t *testing.T) {
	raw := `{"开关":true,"出现概率":20,"Boss黑名单":[56030,56055],"深渊模式":true}`
	normalized, err := normalizeBossIntrusionConfigJSON(raw)
	if err != nil {
		t.Fatalf("合法对象被拒绝: %v", err)
	}
	// 归一化后必须仍是等价对象（键顺序无关）。
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(normalized), &got); err != nil {
		t.Fatalf("归一化结果不是合法 JSON: %v", err)
	}
	for _, key := range []string{"开关", "出现概率", "Boss黑名单", "深渊模式"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("归一化后丢了字段 %q", key)
		}
	}
}

// TestNormalizeBossIntrusionConfigJSONKeepsLargeIDs 锁住大整数不丢精度。
//
// 黑名单里是装备 item id（如 612511545），一旦被当成 float64 往返就会变成
// 612511545.0000001 之类，服务端解析直接报「必须为正整数」。
func TestNormalizeBossIntrusionConfigJSONKeepsLargeIDs(t *testing.T) {
	raw := `{"装备黑名单":[612511545,100322294,490009858]}`
	normalized, err := normalizeBossIntrusionConfigJSON(raw)
	if err != nil {
		t.Fatalf("归一化失败: %v", err)
	}
	if !strings.Contains(normalized, "612511545") || !strings.Contains(normalized, "100322294") {
		t.Fatalf("大整数被改写：%s", normalized)
	}
}

func TestNormalizeBossIntrusionConfigJSONRejectsNonObject(t *testing.T) {
	cases := map[string]string{
		"数组":    `[1,2,3]`,
		"标量":    `123`,
		"字符串":   `"hello"`,
		"null":  `null`,
		"空串":    `   `,
		"坏JSON": `{"开关":}`,
	}
	for name, raw := range cases {
		if _, err := normalizeBossIntrusionConfigJSON(raw); err == nil {
			t.Fatalf("%s 必须被拒绝：%s", name, raw)
		}
	}
}
