package database

import (
	"database/sql"
	"time"
)

// ============================================================================
// BOSS 乱入配置（2026-11-03）
//
// 单行表存整份配置 JSON。**网关不解析字段**，只保证是合法 JSON 对象 ——
// 字段增删（比如后来加的 `深渊模式`）由游戏服务端负责，网关跟着演进会把
// 两边版本绑死，一改就要同时发两个二进制。
//
// revision 每次保存 +1；游戏服务端只在它变化时重建装备池。
// ============================================================================

// BossIntrusionConfig 是 boss_intrusion_config 表的单行投影。
//
// 空表（从未保存过）返回零值：ConfigJSON == "" 表示「网关没配过」，
// 此时下发 `config: null`，游戏服务端会保持自己的启动期配置不动。
type BossIntrusionConfig struct {
	ConfigJSON string
	Revision   int64
	UpdatedAt  int64
}

// LoadBossIntrusionConfig 读当前配置。表空返回零值 + nil error。
func (db *Database) LoadBossIntrusionConfig() (BossIntrusionConfig, error) {
	var row BossIntrusionConfig
	err := db.gatewayDB.QueryRow(
		"SELECT config_json, revision, updated_at FROM boss_intrusion_config WHERE id = 1",
	).Scan(&row.ConfigJSON, &row.Revision, &row.UpdatedAt)
	if err == sql.ErrNoRows {
		return BossIntrusionConfig{}, nil
	}
	if err != nil {
		return BossIntrusionConfig{}, err
	}
	return row, nil
}

// SaveBossIntrusionConfig 覆盖写入并把 revision 推进 1。
//
// 与 `SaveAnnounceConfig` 同一原则：revision 由写入方自增，不接受调用方指定
// （否则两个并发的后台标签页能把版本号写回去，服务端就永远收不到变更）。
func (db *Database) SaveBossIntrusionConfig(configJSON string) (BossIntrusionConfig, error) {
	now := time.Now().Unix()
	var saved BossIntrusionConfig
	err := db.ExecTx(func(tx *sql.Tx) error {
		var current int64
		err := tx.QueryRow("SELECT revision FROM boss_intrusion_config WHERE id = 1").Scan(&current)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		saved = BossIntrusionConfig{
			ConfigJSON: configJSON,
			Revision:   current + 1,
			UpdatedAt:  now,
		}
		_, err = tx.Exec(
			"INSERT INTO boss_intrusion_config(id, config_json, revision, updated_at) VALUES(1, ?, ?, ?) "+
				"ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json, "+
				"revision = excluded.revision, updated_at = excluded.updated_at",
			saved.ConfigJSON, saved.Revision, saved.UpdatedAt)
		return err
	})
	if err != nil {
		return BossIntrusionConfig{}, err
	}
	return saved, nil
}
