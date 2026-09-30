package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestBonusGetConfigMissingFile 文件不存在时必须报错，而不是回退默认值。
//
// 这条口径很重要：后台读不到配置却收到一份"看起来正常"的默认值时，
// 玩家一保存就把线上真正在跑的值覆盖掉了 —— 静默改配置比报错危险得多。
func TestBonusGetConfigMissingFile(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	if _, err := os.Stat(svc.ConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("前置条件不成立：bonus.json 不该存在（path=%s）", svc.ConfigPath())
	}
	if _, err := svc.GetConfig(); err == nil {
		t.Fatal("文件不存在时 GetConfig 应返回错误")
	}
}

// TestBonusSaveAndGetConfig 保存后能原样读回，且不残留临时文件。
func TestBonusSaveAndGetConfig(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	in := &BonusConfig{Enabled: true, IntervalSeconds: 120, AmountPerInterval: 250}
	if err := svc.SaveConfig(in); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	out, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if !out.Enabled || out.IntervalSeconds != 120 || out.AmountPerInterval != 250 {
		t.Fatalf("读回的配置与写入不一致: %+v", out)
	}

	// 原子写用临时文件 + rename，跑完不能把 .tmp 留在 Data 目录里。
	if _, err := os.Stat(svc.ConfigPath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("不该残留临时文件: %s.tmp", svc.ConfigPath())
	}

	// 落盘内容必须是合法 JSON（主循环每轮读它，半截 JSON 会让整轮不发放）。
	raw, err := os.ReadFile(svc.ConfigPath())
	if err != nil {
		t.Fatalf("读文件失败: %v", err)
	}
	var parsed BonusConfig
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("落盘内容不是合法 JSON: %v\n%s", err, raw)
	}
}

// TestBonusSaveConfigRejectsInvalid 非法区间必须被拒，且**不覆盖**原有好配置。
func TestBonusSaveConfigRejectsInvalid(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	good := &BonusConfig{Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100}
	if err := svc.SaveConfig(good); err != nil {
		t.Fatalf("保存基准配置失败: %v", err)
	}

	bad := []*BonusConfig{
		{IntervalSeconds: 0, AmountPerInterval: 100},       // 周期为 0
		{IntervalSeconds: 86401, AmountPerInterval: 100},   // 周期超上限
		{IntervalSeconds: 60, AmountPerInterval: -1},       // 负数点券
		{IntervalSeconds: 60, AmountPerInterval: 10000001}, // 点券超上限
		{IntervalSeconds: 60, AmountPerInterval: 100, ActiveThresholdMinutes: 1441},
	}
	for i, c := range bad {
		if err := svc.SaveConfig(c); err == nil {
			t.Errorf("第 %d 条非法配置应被拒绝: %+v", i, c)
		}
	}

	// 拒绝之后文件必须还是原来那份好配置。
	out, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if out.IntervalSeconds != 60 || out.AmountPerInterval != 100 {
		t.Fatalf("非法保存不该动到已有配置，实得 %+v", out)
	}

	if err := svc.SaveConfig(nil); err == nil {
		t.Error("nil 配置应被拒绝")
	}
}

// TestBonusSaveConfigKeepsLegacyThreshold 后台不展示的废弃字段要保留，不能被悄悄抹掉。
func TestBonusSaveConfigKeepsLegacyThreshold(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	// 模拟部署脚本仍在写的老配置：带 active_threshold_minutes。
	if err := svc.SaveConfig(&BonusConfig{
		Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100, ActiveThresholdMinutes: 5,
	}); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 后台表单不带这个字段（值为 0）提交时，老值要留着。
	if err := svc.SaveConfig(&BonusConfig{
		Enabled: false, IntervalSeconds: 30, AmountPerInterval: 50,
	}); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	out, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if out.ActiveThresholdMinutes != 5 {
		t.Errorf("废弃字段应保留为 5，实得 %d", out.ActiveThresholdMinutes)
	}
	if out.Enabled || out.IntervalSeconds != 30 || out.AmountPerInterval != 50 {
		t.Errorf("本次提交的字段应生效，实得 %+v", out)
	}
}

// TestBonusMainLoopReReadsFile 主循环每轮重读盘 —— 保存后无需重启网关。
//
// 这里锁的是"能读到新值"这件事本身：loadConfig 每次调用都重新走路由。
func TestBonusMainLoopReReadsFile(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	if err := svc.SaveConfig(&BonusConfig{Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100}); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	first := svc.loadConfig()
	if first == nil || first.AmountPerInterval != 100 {
		t.Fatalf("首轮读取失败: %+v", first)
	}

	// 直接改盘（模拟另一个进程/运维手工改），下一轮必须看到新值。
	if err := os.WriteFile(svc.ConfigPath(),
		[]byte(`{"enabled":true,"interval_seconds":60,"amount_per_interval":777}`), 0644); err != nil {
		t.Fatalf("改盘失败: %v", err)
	}
	second := svc.loadConfig()
	if second == nil || second.AmountPerInterval != 777 {
		t.Fatalf("第二轮应读到新值 777，实得 %+v", second)
	}

	// ConfigPath 必须落在游戏库同级的 Data 目录（与网关既有约定一致）。
	if filepath.Base(svc.ConfigPath()) != "bonus.json" {
		t.Errorf("配置文件名应为 bonus.json，实得 %s", filepath.Base(svc.ConfigPath()))
	}
}
