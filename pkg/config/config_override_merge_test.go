package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// readOverride 读回 override 文件成 map，供断言用。
func readOverride(t *testing.T, dir string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, OverrideFileName))
	if err != nil {
		t.Fatalf("读 override 失败: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("override 不是合法 JSON: %v", err)
	}
	return m
}

// writeOverride 预置一份 override 文件（模拟线上既有的 override）。
func writeOverride(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, OverrideFileName), []byte(body), 0644); err != nil {
		t.Fatalf("写 override 失败: %v", err)
	}
}

// ★★★ 2026-10-19 193 线上事故的回归测试。
//
// 背景：后台「多开限制」只提交 max_instances，旧实现把整个 Launcher 段替换成
// {"MaxInstances":0}，同一段里的 MinVersion / DownloadUrl / UpdateNotice 被静默抹掉。
// 网关下次重启读回 override 时 min_version 从 2.5.8 掉回主配置值 —— 强制更新门槛
// 被无声放松，这正是"改一个字段，坏另一个功能"的典型。
func TestSaveOverrideKeepsLauncherSiblings(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, `{
  "Heartbeat": {"TimeoutSeconds": 120},
  "Launcher": {
    "DownloadUrl": "",
    "MinVersion": "2.5.8",
    "UpdateNotice": "1、修复勋章合成、强化。\n2、上架减速药剂。"
  }
}`)

	// 只提交 max_instances —— 与后台「多开限制」保存时的真实调用完全一致
	if err := SaveOverride(dir, map[string]interface{}{
		"Launcher": map[string]interface{}{"MaxInstances": 0},
	}); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}

	m := readOverride(t, dir)
	launcher, ok := m["Launcher"].(map[string]interface{})
	if !ok {
		t.Fatalf("Launcher 段丢失: %#v", m["Launcher"])
	}
	if got := launcher["MinVersion"]; got != "2.5.8" {
		t.Errorf("MinVersion 必须保留 2.5.8，实际 %#v（旧实现会丢成 nil）", got)
	}
	if got, _ := launcher["DownloadUrl"].(string); got != "" {
		t.Errorf("DownloadUrl 必须保留（空串也算保留），实际 %#v", launcher["DownloadUrl"])
	}
	if got, _ := launcher["UpdateNotice"].(string); got == "" {
		t.Errorf("UpdateNotice 必须保留原文，实际 %#v", launcher["UpdateNotice"])
	}
	// 本次提交的键要生效，且是数字 0
	if got, _ := launcher["MaxInstances"].(float64); got != 0 {
		t.Errorf("MaxInstances 应为 0，实际 %#v", launcher["MaxInstances"])
	}
	// 其它段不受影响
	if _, ok := m["Heartbeat"]; !ok {
		t.Errorf("Heartbeat 段被误删")
	}
}

// 同类接口：RegisterLimit 的字段也各自可选，只改一个维度不能抹掉另外两个。
func TestSaveOverrideKeepsRegisterLimitSiblings(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, `{
  "RegisterLimit": {"Enabled": true, "PerIPPerDay": 2, "PerMachine": 5}
}`)

	if err := SaveOverride(dir, map[string]interface{}{
		"RegisterLimit": map[string]interface{}{"PerMachine": 8},
	}); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}

	m := readOverride(t, dir)
	rl := m["RegisterLimit"].(map[string]interface{})
	if rl["Enabled"] != true {
		t.Errorf("Enabled 应保留 true，实际 %#v", rl["Enabled"])
	}
	if got, _ := rl["PerIPPerDay"].(float64); got != 2 {
		t.Errorf("PerIPPerDay 应保留 2，实际 %#v", rl["PerIPPerDay"])
	}
	if got, _ := rl["PerMachine"].(float64); got != 8 {
		t.Errorf("PerMachine 应为 8，实际 %#v", rl["PerMachine"])
	}
}

// 新增段/键要能落地（深度合并不能变成"只认已存在的键"）。
func TestSaveOverrideAddsNewSection(t *testing.T) {
	dir := t.TempDir()
	if err := SaveOverride(dir, map[string]interface{}{
		"Launcher":    map[string]interface{}{"MaxInstances": 3},
		"Maintenance": map[string]interface{}{"Enabled": true},
	}); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}
	m := readOverride(t, dir)
	if got, _ := m["Launcher"].(map[string]interface{})["MaxInstances"].(float64); got != 3 {
		t.Errorf("Launcher.MaxInstances 应为 3，实际 %#v", got)
	}
	if got := m["Maintenance"].(map[string]interface{})["Enabled"]; got != true {
		t.Errorf("Maintenance.Enabled 应为 true，实际 %#v", got)
	}
}

// 标量与数组保持整体替换语义（数组不做元素级合并，调用方传完整数组）。
func TestSaveOverrideReplacesScalarAndArray(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, `{
  "Maintenance": {"Enabled": false, "AdminAccounts": ["msp", "msp2"]}
}`)
	if err := SaveOverride(dir, map[string]interface{}{
		"Maintenance": map[string]interface{}{"AdminAccounts": []interface{}{"msp"}},
	}); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}
	m := readOverride(t, dir)
	mt := m["Maintenance"].(map[string]interface{})
	if mt["Enabled"] != false {
		t.Errorf("同级 Enabled 应保留 false，实际 %#v", mt["Enabled"])
	}
	arr, _ := mt["AdminAccounts"].([]interface{})
	if len(arr) != 1 || arr[0] != "msp" {
		t.Errorf("数组应整体替换为 [msp]，实际 %#v", mt["AdminAccounts"])
	}
}

// 空 override / 文件不存在时也要能正常创建。
func TestSaveOverrideOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	if err := SaveOverride(dir, map[string]interface{}{
		"Launcher": map[string]interface{}{"MaxInstances": 0},
	}); err != nil {
		t.Fatalf("SaveOverride: %v", err)
	}
	m := readOverride(t, dir)
	if _, ok := m["Launcher"]; !ok {
		t.Errorf("缺失文件时应新建并写入 Launcher 段")
	}
}
