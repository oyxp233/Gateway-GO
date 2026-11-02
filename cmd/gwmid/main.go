// Command gwmid 把历史遗留的非数字 m_id 迁移为纯数字 m_id。
//
// 背景：DNF 客户端把启动参数第 4 段（{m_id}）按数字解析，非数字会回落成字面量
// "invalid_id" 上报游戏服务端，服务端据此在游戏库建幽灵行 → 网关侧按真 m_id
// 关联的泡点 / 点券 / 查角色全部落空。详见 pkg/database 里 AllocateNumericMId 的
// 证据链注释。
//
// 用法（默认 dry-run，一个字节都不改）：
//
//	s4a21-gwmid --config ./appsettings.json                       # 只看计划
//	s4a21-gwmid --config ./appsettings.json --game-invalid-owner msp
//	s4a21-gwmid --config ./appsettings.json --game-invalid-owner msp --apply
//
// 建议在网关停止后再执行 --apply：迁移会改 accounts / device_history / 游戏库
// accounts，运行中执行虽不会写坏（SQLite WAL + 主键保护），但并发注册拿到的号
// 可能与本次计划重叠。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
)

func main() {
	configPath := flag.String("config", "./appsettings.json", "appsettings.json 路径")
	apply := flag.Bool("apply", false, "真正落库（默认 dry-run，只打印计划）")
	gameInvalidOwner := flag.String("game-invalid-owner", "",
		"游戏库幽灵行（m_id='invalid_id'）的归属账号名；改挂到该账号的新数字 m_id 下")
	asJSON := flag.Bool("json", false, "以 JSON 输出（便于脚本消费）")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 配置加载失败: %v\n", err)
		os.Exit(1)
	}

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               cfg.Database.Path,
		GamePath:           cfg.Database.GamePath,
		WalMode:            cfg.Database.WalMode,
		BusyTimeoutSeconds: cfg.Database.BusyTimeoutSeconds,
		// S5A3 的 MariaDB 游戏库（全服邮件/泡点/注册奖励/角色查询用）。
		// 留空 = 该部署没有 S5A3 后端，相关功能会明确报"未配置"。
		GameDSN:         cfg.S5A3GameDSN(),
		GameTablePrefix: cfg.S5A3TablePrefix(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 数据库打开失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if !db.GameConfigured() {
		fmt.Fprintln(os.Stderr, "[Warn] 游戏库未配置（Database.GamePath 为空）：不会做幽灵行归位，且号段查重只覆盖网关库。")
	}

	plan, err := db.MigrateLegacyNumericMIds(!*apply, *gameInvalidOwner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Fatal] 迁移失败: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		out, _ := json.MarshalIndent(plan, "", "  ")
		fmt.Println(string(out))
		return
	}

	mode := "DRY-RUN（未改动任何数据）"
	if *apply {
		mode = "已落库"
	}
	fmt.Printf("=== m_id 数字化迁移 [%s] ===\n", mode)
	if len(plan.Migrations) == 0 {
		fmt.Println("无需迁移：网关库所有真账号的 m_id 已是纯数字。")
	}
	for _, m := range plan.Migrations {
		fmt.Printf("  %-20s %s  ->  %s\n", m.Account, truncate(m.OldMId, 24), m.NewMId)
	}
	if plan.GameInvalidOwner != "" {
		verb := "将改挂到"
		if *apply {
			verb = "已改挂到"
		}
		fmt.Printf("\n游戏库幽灵行：m_id='invalid_id' %s 账号 %s 的新 m_id=%s，涉及 %d 行\n",
			verb, plan.GameInvalidOwner, plan.GameInvalidNew, plan.GameInvalidRows)
	} else if len(plan.Migrations) > 0 {
		fmt.Println("\n提示：未指定 --game-invalid-owner，游戏库 m_id='invalid_id' 的幽灵行未处理。")
	}
	if len(plan.ShadowAccounts) > 0 {
		fmt.Printf("\n影子账号（SyncGameAccounts 按游戏库 m_id 同步进来的行，本次跳过、未删除）：\n")
		for _, s := range plan.ShadowAccounts {
			fmt.Printf("  %s\n", s)
		}
	}
	if !*apply && len(plan.Migrations) > 0 {
		fmt.Println("\n加 --apply 才会真正写入。")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
