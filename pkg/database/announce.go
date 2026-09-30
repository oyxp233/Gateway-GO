package database

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"s4a21-gateway/pkg/models"
)

// ============================================================================
// 全服公告：配置 / 事件 / 弹窗
//
// 这三块数据都落在**网关库**（gateway.db），由网关进程独占写入。
// admin 进程只读 announce_events / announce_popups（它有自己的 db 句柄，
// 但只做 SELECT）；配置与弹窗队列的写入一律经网关内部 API 转发 ——
// 因为网关内存里还有一份配置快照与弹窗投递状态，绕过它必然出现"库改了、内存没改"。
// ============================================================================

// announceConfigColumns 是配置的 KV 键名清单。
//
// ⚠️ 改键名等于改数据格式：旧行会变成孤儿（LoadAnnounceConfig 读不到 → 回退默认值），
// 而且不会报错。加新键只能追加。
const (
	announceKeyEnabled            = "enabled"
	announceKeyReport             = "report"
	announceKeyCleared            = "cleared"
	announceKeyIncomplete         = "incomplete"
	announceKeyPickup             = "pickup"
	announceKeyPickupHellEpic     = "pickup_hell_epic"
	announceKeyPickupLegend       = "pickup_legend"
	announceKeyPickupUnique       = "pickup_unique"
	announceKeyPickupStats        = "pickup_stats"
	announceKeyPickupItemLink     = "pickup_item_link"
	announceKeyHellDifficultyName = "hell_difficulty_name"
	announceKeyDifficultyNames    = "difficulty_names"
	announceKeyAnnounceDuration   = "announce_duration_ms"
	announceKeyPopupMode          = "popup_mode"
	announceKeyTemplateCleared    = "template_cleared"
	announceKeyTemplateIncomplete = "template_incomplete"
	announceKeyTemplatePickup     = "template_pickup"
	announceKeyEventRetentionDays = "event_retention_days"
	announceKeyRevision           = "revision"
)

// LoadAnnounceConfig 读公告配置。
//
// 缺失的键回退到 DefaultAnnounceConfig 的对应值，所以：
//   - 全新库第一次读 = 拿到出厂默认，不会出现全 false 的"公告静默停用"；
//   - 以后加了新键，老库也能平滑升级。
func (db *Database) LoadAnnounceConfig() (models.AnnounceConfig, error) {
	cfg := models.DefaultAnnounceConfig()

	rows, err := db.gatewayDB.Query("SELECT cfg_key, cfg_value FROM announce_config")
	if err != nil {
		return cfg, err
	}
	defer rows.Close()

	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return cfg, err
		}
		applyAnnounceConfigValue(&cfg, key, value)
	}
	return cfg, rows.Err()
}

// applyAnnounceConfigValue 把一条 KV 写进配置结构。
//
// 解析失败的键**保持默认值**（不是保持零值）：一个手改坏的 boolean
// 不该把整份公告配置打成"全关"。
func applyAnnounceConfigValue(cfg *models.AnnounceConfig, key, value string) {
	switch key {
	case announceKeyEnabled:
		cfg.Enabled = parseBoolDefault(value, cfg.Enabled)
	case announceKeyReport:
		cfg.Report = parseBoolDefault(value, cfg.Report)
	case announceKeyCleared:
		cfg.Cleared = parseBoolDefault(value, cfg.Cleared)
	case announceKeyIncomplete:
		cfg.Incomplete = parseBoolDefault(value, cfg.Incomplete)
	case announceKeyPickup:
		cfg.Pickup = parseBoolDefault(value, cfg.Pickup)
	case announceKeyPickupHellEpic:
		cfg.PickupHellEpic = parseBoolDefault(value, cfg.PickupHellEpic)
	case announceKeyPickupLegend:
		cfg.PickupLegend = parseBoolDefault(value, cfg.PickupLegend)
	case announceKeyPickupUnique:
		cfg.PickupUnique = parseBoolDefault(value, cfg.PickupUnique)
	case announceKeyPickupStats:
		cfg.PickupStats = parseBoolDefault(value, cfg.PickupStats)
	case announceKeyPickupItemLink:
		cfg.PickupItemLink = parseBoolDefault(value, cfg.PickupItemLink)
	case announceKeyHellDifficultyName:
		if strings.TrimSpace(value) != "" {
			cfg.HellDifficultyName = value
		}
	case announceKeyDifficultyNames:
		if names := splitList(value); len(names) > 0 {
			cfg.DifficultyNames = names
		}
	case announceKeyAnnounceDuration:
		if n, ok := parseClampedInt(value, 1000, 60000); ok {
			cfg.AnnounceDurationMs = n
		}
	case announceKeyPopupMode:
		if n, ok := parseClampedInt(value, 0, 255); ok {
			cfg.PopupMode = n
		}
	case announceKeyTemplateCleared:
		cfg.TemplateCleared = value
	case announceKeyTemplateIncomplete:
		cfg.TemplateIncomplete = value
	case announceKeyTemplatePickup:
		cfg.TemplatePickup = value
	case announceKeyEventRetentionDays:
		if n, ok := parseClampedInt(value, 0, 3650); ok {
			cfg.EventRetentionDays = n
		}
	case announceKeyRevision:
		if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			cfg.Revision = n
		}
	}
}

// SaveAnnounceConfig 覆盖写入公告配置，并把 Revision 推进 1。
//
// 入参的 Revision 被忽略（以库里的当前值为基准 +1）：Revision 是"服务端看到的是第几版"，
// 由写入方自增才有意义，若允许调用方指定，两个并发的后台标签页就能把版本号写回去。
func (db *Database) SaveAnnounceConfig(cfg models.AnnounceConfig) (models.AnnounceConfig, error) {
	now := time.Now().Unix()
	cfg.UpdatedAt = now

	err := db.ExecTx(func(tx *sql.Tx) error {
		var current int64
		err := tx.QueryRow("SELECT cfg_value FROM announce_config WHERE cfg_key = ?", announceKeyRevision).Scan(&current)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		cfg.Revision = current + 1

		pairs := map[string]string{
			announceKeyEnabled:            boolToKV(cfg.Enabled),
			announceKeyReport:             boolToKV(cfg.Report),
			announceKeyCleared:            boolToKV(cfg.Cleared),
			announceKeyIncomplete:         boolToKV(cfg.Incomplete),
			announceKeyPickup:             boolToKV(cfg.Pickup),
			announceKeyPickupHellEpic:     boolToKV(cfg.PickupHellEpic),
			announceKeyPickupLegend:       boolToKV(cfg.PickupLegend),
			announceKeyPickupUnique:       boolToKV(cfg.PickupUnique),
			announceKeyPickupStats:        boolToKV(cfg.PickupStats),
			announceKeyPickupItemLink:     boolToKV(cfg.PickupItemLink),
			announceKeyHellDifficultyName: cfg.HellDifficultyName,
			announceKeyDifficultyNames:    strings.Join(cfg.DifficultyNames, ","),
			announceKeyAnnounceDuration:   strconv.Itoa(cfg.AnnounceDurationMs),
			announceKeyPopupMode:          strconv.Itoa(cfg.PopupMode),
			announceKeyTemplateCleared:    cfg.TemplateCleared,
			announceKeyTemplateIncomplete: cfg.TemplateIncomplete,
			announceKeyTemplatePickup:     cfg.TemplatePickup,
			announceKeyEventRetentionDays: strconv.Itoa(cfg.EventRetentionDays),
			announceKeyRevision:           strconv.FormatInt(cfg.Revision, 10),
		}

		stmt, err := tx.Prepare("INSERT INTO announce_config(cfg_key, cfg_value, updated_at) VALUES(?, ?, ?) " +
			"ON CONFLICT(cfg_key) DO UPDATE SET cfg_value = excluded.cfg_value, updated_at = excluded.updated_at")
		if err != nil {
			return err
		}
		defer stmt.Close()

		for key, value := range pairs {
			if _, err := stmt.Exec(key, value, now); err != nil {
				return fmt.Errorf("写入配置项 %s 失败: %w", key, err)
			}
		}
		return nil
	})
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

// ============================================================================
// 事件流水
// ============================================================================

// InsertAnnounceEvents 批量写入事件。整批一个事务：要么全进，要么全不进。
//
// 调用方（内部 API）已负责字段范围校验，这里只做 kind 白名单校验 ——
// 一个畸形的 kind 进了库，后台的分类查询就永远有一类查不出来。
func (db *Database) InsertAnnounceEvents(events []models.AnnounceEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}

	now := time.Now().Unix()
	inserted := 0

	err := db.ExecTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`INSERT INTO announce_events(
			kind, account, character_id, character_name, dungeon_id, dungeon_name,
			difficulty, hell_mode, elapsed_ms, item_id, item_name, item_rarity,
			is_equipment, item_level, equipment_type, physical_attack, magical_attack,
			physical_defense, magical_defense, broadcast, created_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for i := range events {
			e := events[i]
			if !models.IsValidAnnounceKind(e.Kind) {
				continue
			}
			createdAt := e.CreatedAt
			if createdAt <= 0 {
				createdAt = now
			}
			// is_equipment 以显式字段为准；老客户端/老插件没发这个字段时按 item_id 兜底，
			// 否则排行榜会因为一个缺失字段而全空。
			isEquipment := e.IsEquipment || e.ItemID > 0
			if _, err := stmt.Exec(
				e.Kind, e.Account, e.CharacterID, e.CharacterName, e.DungeonID, e.DungeonName,
				e.Difficulty, boolToInt(e.HellMode), e.ElapsedMs, e.ItemID, e.ItemName, e.ItemRarity,
				boolToInt(isEquipment), e.ItemLevel, e.EquipmentType, e.PhysicalAtk, e.MagicalAtk,
				e.PhysicalDef, e.MagicalDef, boolToInt(e.Broadcast), createdAt,
			); err != nil {
				return err
			}
			inserted++
		}
		return nil
	})
	return inserted, err
}

// AnnounceEventFilter 是分类查询的过滤条件。
type AnnounceEventFilter struct {
	// Kind 为空表示不限；否则必须是 cleared / incomplete / pickup。
	Kind string
	// Account / Keyword / DungeonName 均为模糊匹配（空 = 不限）。
	Account     string
	Keyword     string
	DungeonName string
	// MinRarity ≥2 时才生效（拾取查询用）。
	MinRarity int
	// From / To 是 Unix 秒，0 = 不限。
	From int64
	To   int64
	// BroadcastOnly 只查广播过的（拾取事件才有意义）。
	BroadcastOnly bool
	Page          int
	PageSize      int
}

// QueryAnnounceEvents 分页查询事件流水（按时间倒序）。
func (db *Database) QueryAnnounceEvents(f AnnounceEventFilter) (int, []models.AnnounceEvent, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 500 {
		f.PageSize = 50
	}

	where := []string{"1=1"}
	args := []interface{}{}

	if k := strings.TrimSpace(f.Kind); k != "" {
		if !models.IsValidAnnounceKind(k) {
			return 0, nil, fmt.Errorf("未知的事件类型: %s", k)
		}
		where = append(where, "kind = ?")
		args = append(args, k)
	}
	if v := strings.TrimSpace(f.Account); v != "" {
		where = append(where, "account LIKE ?")
		args = append(args, "%"+v+"%")
	}
	if v := strings.TrimSpace(f.Keyword); v != "" {
		where = append(where, "(character_name LIKE ? OR item_name LIKE ? OR dungeon_name LIKE ?)")
		like := "%" + v + "%"
		args = append(args, like, like, like)
	}
	if v := strings.TrimSpace(f.DungeonName); v != "" {
		where = append(where, "dungeon_name LIKE ?")
		args = append(args, "%"+v+"%")
	}
	if f.MinRarity >= 2 {
		where = append(where, "item_rarity >= ?")
		args = append(args, f.MinRarity)
	}
	if f.From > 0 {
		where = append(where, "created_at >= ?")
		args = append(args, f.From)
	}
	if f.To > 0 {
		where = append(where, "created_at <= ?")
		args = append(args, f.To)
	}
	if f.BroadcastOnly {
		where = append(where, "broadcast = 1")
	}

	clause := " WHERE " + strings.Join(where, " AND ")

	var total int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM announce_events"+clause, args...).Scan(&total); err != nil {
		return 0, nil, err
	}

	listArgs := append(append([]interface{}{}, args...), f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := db.gatewayDB.Query(`SELECT id, kind, account, character_id, character_name,
		dungeon_id, dungeon_name, difficulty, hell_mode, elapsed_ms,
		item_id, item_name, item_rarity, item_level, equipment_type,
		physical_attack, magical_attack, physical_defense, magical_defense,
		broadcast, created_at FROM announce_events`+clause+
		" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	events := make([]models.AnnounceEvent, 0, f.PageSize)
	for rows.Next() {
		var e models.AnnounceEvent
		var hellMode, broadcast int
		if err := rows.Scan(&e.ID, &e.Kind, &e.Account, &e.CharacterID, &e.CharacterName,
			&e.DungeonID, &e.DungeonName, &e.Difficulty, &hellMode, &e.ElapsedMs,
			&e.ItemID, &e.ItemName, &e.ItemRarity, &e.ItemLevel, &e.EquipmentType,
			&e.PhysicalAtk, &e.MagicalAtk, &e.PhysicalDef, &e.MagicalDef,
			&broadcast, &e.CreatedAt); err != nil {
			return 0, nil, err
		}
		e.HellMode = hellMode != 0
		e.Broadcast = broadcast != 0
		events = append(events, e)
	}
	return total, events, rows.Err()
}

// AnnounceEventStats 返回各类事件的累计条数（后台概览用）。
func (db *Database) AnnounceEventStats() (map[string]int64, error) {
	out := map[string]int64{}
	rows, err := db.gatewayDB.Query("SELECT kind, COUNT(*) FROM announce_events GROUP BY kind")
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var n int64
		if err := rows.Scan(&kind, &n); err != nil {
			return out, err
		}
		out[kind] = n
	}
	return out, rows.Err()
}

// PurgeAnnounceEvents 删除 beforeUnix 之前的事件，返回删除条数。
func (db *Database) PurgeAnnounceEvents(beforeUnix int64) (int64, error) {
	res, err := db.gatewayDB.Exec("DELETE FROM announce_events WHERE created_at < ?", beforeUnix)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ============================================================================
// 弹窗队列
// ============================================================================

// EnqueueAnnouncePopup 把一个弹窗公告放进待投递队列。
func (db *Database) EnqueueAnnouncePopup(message string, mode int, createdBy string) (int64, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return 0, fmt.Errorf("弹窗内容不能为空")
	}
	if len([]rune(message)) > 500 {
		return 0, fmt.Errorf("弹窗内容过长（上限 500 字，当前 %d 字）", len([]rune(message)))
	}
	if mode < 0 || mode > 255 {
		return 0, fmt.Errorf("mode 必须是 0-255")
	}

	res, err := db.gatewayDB.Exec(
		"INSERT INTO announce_popups(message, mode, status, created_by, created_at) VALUES(?,?,?,?,?)",
		message, mode, models.AnnouncePopupPending, createdBy, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// TakePendingAnnouncePopups 取出待投递的弹窗并标记为已发送。
//
// 取与标记必须同一个事务，否则同一个弹窗会被两次拉取各投一次（玩家看到两遍弹窗）。
// 顺带把超过 ttlSeconds 仍未送达的 pending 标记为 expired：插件长时间不在线时，
// 队列不该无限堆积 —— 一条「10 分钟后维护」的弹窗晚一小时才弹出来是有害的。
func (db *Database) TakePendingAnnouncePopups(limit int, ttlSeconds int) ([]models.AnnouncePopup, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	now := time.Now().Unix()
	out := []models.AnnouncePopup{}

	err := db.ExecTx(func(tx *sql.Tx) error {
		expireBefore := now - int64(ttlSeconds)
		if _, err := tx.Exec(
			"UPDATE announce_popups SET status = ? WHERE status = ? AND deleted_at = 0 AND created_at < ?",
			models.AnnouncePopupExpired, models.AnnouncePopupPending, expireBefore); err != nil {
			return err
		}

		// deleted_at = 0 必须有：后台刚删掉的 pending 弹窗绝不能再被插件拉走投出去，
		// 否则「删了还在飘」——那正是运维最不能接受的一种不一致。
		rows, err := tx.Query(
			"SELECT id, message, mode, status, created_by, created_at, sent_at, delivered_at "+
				"FROM announce_popups WHERE status = ? AND deleted_at = 0 ORDER BY id ASC LIMIT ?",
			models.AnnouncePopupPending, limit)
		if err != nil {
			return err
		}
		ids := []int64{}
		for rows.Next() {
			p := models.AnnouncePopup{}
			if err := rows.Scan(&p.ID, &p.Message, &p.Mode, &p.Status, &p.CreatedBy,
				&p.CreatedAt, &p.SentAt, &p.DeliveredAt); err != nil {
				rows.Close()
				return err
			}
			out = append(out, p)
			ids = append(ids, p.ID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for i, id := range ids {
			if _, err := tx.Exec("UPDATE announce_popups SET status = ?, sent_at = ? WHERE id = ?",
				models.AnnouncePopupSent, now, id); err != nil {
				return err
			}
			out[i].Status = models.AnnouncePopupSent
			out[i].SentAt = now
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryAnnouncePopups 分页查询弹窗历史（按创建时间倒序）。
func (db *Database) QueryAnnouncePopups(status string, page, pageSize int) (int, []models.AnnouncePopup, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 20
	}

	// 后台「删除」是软删除：deleted_at != 0 的记录一律不再出现在列表里，
	// 但行还在库里，随时能回答"这条公告发出去没有"。
	where := "deleted_at = 0"
	args := []interface{}{}
	if s := strings.TrimSpace(status); s != "" {
		where += " AND status = ?"
		args = append(args, s)
	}

	var total int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM announce_popups WHERE "+where, args...).Scan(&total); err != nil {
		return 0, nil, err
	}

	listArgs := append(append([]interface{}{}, args...), pageSize, (page-1)*pageSize)
	rows, err := db.gatewayDB.Query(
		"SELECT id, message, mode, status, created_by, created_at, sent_at, delivered_at "+
			"FROM announce_popups WHERE "+where+" ORDER BY id DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	items := make([]models.AnnouncePopup, 0, pageSize)
	for rows.Next() {
		var p models.AnnouncePopup
		if err := rows.Scan(&p.ID, &p.Message, &p.Mode, &p.Status, &p.CreatedBy,
			&p.CreatedAt, &p.SentAt, &p.DeliveredAt); err != nil {
			return 0, nil, err
		}
		items = append(items, p)
	}
	return total, items, rows.Err()
}

// DeleteAnnouncePopup 从后台列表里删除一条弹窗记录（**不限状态**）。
//
// 语义是"软删除"：置 deleted_at，列表不再显示，行本身留在库里。
//
// 历史口径是"只能删 pending"（已投递的删了会丢审计痕迹），但实际用下来
// 玩家最常想删的恰恰是**已经发出去的那几条**——旧口径下按钮点了没反应
// （后端返回 409），后台表现为"撤销无效"。现在任何状态都能删，审计靠
// deleted_at 与行本身保留，不再牺牲可用性。
//
// 返回 false 表示 id 不存在或已经删过（幂等：重复点不报错）。
func (db *Database) DeleteAnnouncePopup(id int64) (bool, error) {
	res, err := db.gatewayDB.Exec(
		"UPDATE announce_popups SET deleted_at = ? WHERE id = ? AND deleted_at = 0",
		time.Now().Unix(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ============================================================================
// 排行榜
// ============================================================================

// announceTier 是"一档品级"的定义。
//
// 品级编号来自服务端注释实证：稀有=2、神器=3、史诗=4（5 也按史诗处理）、传说=6。
// 用户口径是"史诗/传说/神器分开为三个榜单"，所以这里就是三个 tier，
// 而不是"一张榜按品级排序"。
type announceTier struct {
	Tier     string
	Label    string
	Rarities []int
}

var announceTiers = []announceTier{
	{Tier: "epic", Label: "史诗", Rarities: []int{4, 5}},
	{Tier: "legend", Label: "传说", Rarities: []int{6}},
	{Tier: "unique", Label: "神器", Rarities: []int{3}},
}

// AnnounceTierKeys 返回三个档位的机器名，供接口校验查询参数。
func AnnounceTierKeys() []string {
	out := make([]string, 0, len(announceTiers))
	for _, t := range announceTiers {
		out = append(out, t.Tier)
	}
	return out
}

// BuildAnnounceRankings 生成三个品级榜单。
//
// limit 是每榜的玩家条数与物品条数上限。
// sinceUnix > 0 时只统计该时间之后的拾取；SinceDays 由调用方换算。
//
// 只统计 is_equipment=1 的拾取：非装备（材料/消耗品）没有品级意义，
// 混进来会把三个榜变成"谁刷得多"。
func (db *Database) BuildAnnounceRankings(limit int, sinceUnix int64) ([]models.AnnounceRanking, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}

	result := make([]models.AnnounceRanking, 0, len(announceTiers))
	for _, tier := range announceTiers {
		ranking, err := db.buildAnnounceRanking(tier, limit, sinceUnix)
		if err != nil {
			return nil, err
		}
		result = append(result, ranking)
	}
	return result, nil
}

func (db *Database) buildAnnounceRanking(tier announceTier, limit int, sinceUnix int64) (models.AnnounceRanking, error) {
	ranking := models.AnnounceRanking{
		Tier:     tier.Tier,
		Label:    tier.Label,
		Rarities: tier.Rarities,
		Players:  []models.AnnounceRankingEntry{},
		Items:    []models.AnnounceRankingEntry{},
		Owners:   map[int]string{},
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(tier.Rarities)), ",")
	args := make([]interface{}, 0, len(tier.Rarities)+2)
	for _, r := range tier.Rarities {
		args = append(args, r)
	}

	base := " FROM announce_events WHERE kind = ? AND is_equipment = 1 AND item_rarity IN (" +
		placeholders + ")"
	whereArgs := append([]interface{}{models.AnnounceKindPickup}, args...)
	if sinceUnix > 0 {
		base += " AND created_at >= ?"
		whereArgs = append(whereArgs, sinceUnix)
	}

	if err := db.gatewayDB.QueryRow("SELECT COUNT(*)"+base, whereArgs...).Scan(&ranking.Total); err != nil {
		return ranking, err
	}

	// ---- 玩家榜：按件数 ----
	playerArgs := append(append([]interface{}{}, whereArgs...), limit)
	rows, err := db.gatewayDB.Query(
		"SELECT character_name, COUNT(*) AS cnt, MAX(created_at)"+base+
			" AND character_name <> '' GROUP BY character_name ORDER BY cnt DESC, MAX(created_at) DESC LIMIT ?",
		playerArgs...)
	if err != nil {
		return ranking, err
	}
	rank := 0
	for rows.Next() {
		var name string
		var count, lastSeen int64
		if err := rows.Scan(&name, &count, &lastSeen); err != nil {
			rows.Close()
			return ranking, err
		}
		rank++
		ranking.Players = append(ranking.Players, models.AnnounceRankingEntry{
			Rank: rank, Key: name, Count: count, LastSeen: lastSeen,
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ranking, err
	}

	// ---- 物品清单：按件数 ----
	itemArgs := append(append([]interface{}{}, whereArgs...), limit)
	itemRows, err := db.gatewayDB.Query(
		"SELECT item_name, item_id, MAX(item_rarity), COUNT(*) AS cnt, MAX(created_at)"+base+
			" AND item_name <> '' GROUP BY item_name ORDER BY cnt DESC, MAX(created_at) DESC LIMIT ?",
		itemArgs...)
	if err != nil {
		return ranking, err
	}
	itemIDs := []int{}
	rank = 0
	for itemRows.Next() {
		var name string
		var itemID, rarity, count, lastSeen int64
		if err := itemRows.Scan(&name, &itemID, &rarity, &count, &lastSeen); err != nil {
			itemRows.Close()
			return ranking, err
		}
		rank++
		ranking.Items = append(ranking.Items, models.AnnounceRankingEntry{
			Rank: rank, Key: name, ItemID: int(itemID), Rarity: int(rarity),
			Count: count, LastSeen: lastSeen,
		})
		if itemID > 0 {
			itemIDs = append(itemIDs, int(itemID))
		}
	}
	itemRows.Close()
	if err := itemRows.Err(); err != nil {
		return ranking, err
	}

	// ---- 每个物品的最近获得者 ----
	// 只对已经进入清单的那几个 item_id 查，避免全表扫。
	// 用窗口函数一次查出（SQLite ≥3.25，modernc 驱动内置 3.4x，可用）。
	if len(itemIDs) > 0 {
		ownerWhere := strings.TrimRight(strings.Repeat("?,", len(itemIDs)), ",")
		ownerArgs := make([]interface{}, 0, len(itemIDs))
		for _, id := range itemIDs {
			ownerArgs = append(ownerArgs, id)
		}
		ownerRows, err := db.gatewayDB.Query(
			`SELECT item_id, character_name FROM (
				SELECT item_id, character_name,
				       ROW_NUMBER() OVER (PARTITION BY item_id ORDER BY created_at DESC, id DESC) AS rn
				FROM announce_events
				WHERE kind = ? AND is_equipment = 1 AND character_name <> '' AND item_id IN (`+ownerWhere+`)
			) WHERE rn = 1`,
			append([]interface{}{models.AnnounceKindPickup}, ownerArgs...)...)
		if err != nil {
			// 排行榜主体已经拿到，所有者信息是锦上添花 —— 失败就留空，不上抛。
			return ranking, nil
		}
		for ownerRows.Next() {
			var itemID int
			var name string
			if err := ownerRows.Scan(&itemID, &name); err != nil {
				continue
			}
			ranking.Owners[itemID] = name
		}
		ownerRows.Close()
	}

	return ranking, nil
}

// ============================================================================
// 小工具
// ============================================================================

func parseBoolDefault(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func parseClampedInt(raw string, min, max int) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	if n < min {
		n = min
	}
	if n > max {
		n = max
	}
	return n, true
}

func splitList(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '|' || r == ';' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func boolToKV(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
