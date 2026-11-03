package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
)

// ============================================================================
// BOSS 乱入配置（2026-11-03）
//
// 职责边界：网关只负责**存和发**，不解释字段含义。
//
// 为什么不解析字段：这份 JSON 的消费方是游戏服务端（Server-S5A3 的
// `random_boss_intrusion_config.go`），字段会跟着玩法演进（2026-11-03 就新增了
// `深渊模式`）。网关要是也建一套结构体，每次加字段都得同时发两个二进制，
// 而且漏改一边就是「静默丢字段」——正好是这个项目踩过的坑。
//
// 所以这里只做两件事：
//   1. 保证存进去的是**合法 JSON 对象**（不是数组、不是标量、不是坏 JSON）；
//   2. 每次保存把 revision 推进 1，给服务端一个「要不要重建」的判据。
// ============================================================================

// bossIntrusionConfigMaxBytes 上限 1 MiB。真实配置（含 3000+ 装备黑名单）
// 约 60 KB，1 MiB 是防手滑贴了个二进制进去。
const bossIntrusionConfigMaxBytes = 1 << 20

// BossIntrusionConfigService 读写乱入配置。
//
// ★ **不做内存缓存**（对比 announce）：这份配置由 gateway 和 admin 两个进程
// 各自读写同一个 gateway.db。只要有一边缓存，就会出现「后台保存成功、网关还
// 在下发旧配置」的错位，而且不报错。读的是单行表，内部 API 每 10 秒才被拉
// 一次，直连 SQLite 的开销可以忽略 —— 一致性比这点 IO 重要得多。
type BossIntrusionConfigService struct {
	db  *database.Database
	log *logger.ConsoleLogger
}

func NewBossIntrusionConfigService(db *database.Database, log *logger.ConsoleLogger) *BossIntrusionConfigService {
	return &BossIntrusionConfigService{db: db, log: log}
}

// Config 返回当前配置。表空时返回零值（ConfigJSON == ""）。
func (s *BossIntrusionConfigService) Config() (database.BossIntrusionConfig, error) {
	if s == nil {
		return database.BossIntrusionConfig{}, errors.New("boss intrusion config service unavailable")
	}
	return s.db.LoadBossIntrusionConfig()
}

// Update 校验并保存配置，revision 自增 1。
//
// 校验失败**不落库**：后台贴了半截 JSON 就保存，会让所有游戏服在下一轮
// 轮询里拿到坏配置（服务端那边会拒绝并保留旧快照，但日志会一直刷错误）。
func (s *BossIntrusionConfigService) Update(raw string) (database.BossIntrusionConfig, error) {
	if s == nil {
		return database.BossIntrusionConfig{}, errors.New("boss intrusion config service unavailable")
	}
	normalized, err := normalizeBossIntrusionConfigJSON(raw)
	if err != nil {
		return database.BossIntrusionConfig{}, err
	}
	saved, err := s.db.SaveBossIntrusionConfig(normalized)
	if err != nil {
		return database.BossIntrusionConfig{}, err
	}
	if s.log != nil {
		s.log.Info(fmt.Sprintf("boss intrusion config saved: revision=%d bytes=%d",
			saved.Revision, len(saved.ConfigJSON)))
	}
	return saved, nil
}

// normalizeBossIntrusionConfigJSON 校验并归一化（缩进 2 空格）。
//
// 归一化不是为了好看：同一份语义的配置若每次缩进不同，revision 虽然会变，
// 但 diff 对比（后台历史、日志排查）会完全没法看。
func normalizeBossIntrusionConfigJSON(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("配置不能为空")
	}
	if len(trimmed) > bossIntrusionConfigMaxBytes {
		return "", fmt.Errorf("配置过大：%d 字节（上限 %d）", len(trimmed), bossIntrusionConfigMaxBytes)
	}
	// 解到 map 才能拒绝「[]」「123」「"x"」「null」这些合法 JSON 但不是配置的输入。
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return "", fmt.Errorf("不是合法的 JSON 对象: %v", err)
	}
	if probe == nil {
		return "", errors.New("配置不能是 null")
	}
	normalized, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化配置失败: %v", err)
	}
	return string(normalized), nil
}
