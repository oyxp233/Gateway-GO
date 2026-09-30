package database

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
)

// ============================================================================
// GM 模块：管理后台直接读写游戏库
//
// 设计边界（与 DfoGmTool 的差异，务必先读）：
//
//	本文件只做**不需要服务端业务内核**的读写 —— 角色详情、改名、SP/TP、
//	背包读取与单件删除。这些都只是普通列或固定长度 BLOB，语义自洽。
//
//	**刻意不做**：改等级、转职/觉醒。它们要跑
//	CharacterStatComputer.BuildAdditionalInfo()（等级→战斗属性表）与
//	SkillStateService.LoadAndSync()（技能状态机），属服务端业务内核；
//	在 Go 里复刻等于重写半个服务端，失败形态是「等级升了属性没跟上」的
//	静默数据损坏。这类操作走管理后台的「GM 工具」应急入口（临时启动 DfoGmTool）。
//
// 并发约束（这是本项目踩过的坑，别放松）：
//
//	网关（本进程）与 DfoServer 是两个进程写同一个 SQLite 文件。
//	所有写操作必须**短事务**并依赖连接上的 busy_timeout；绝不允许长事务或
//	「先读一大段再写」（时间跨度越大，撞上 SQLITE_BUSY_SNAPSHOT 的概率越高）。
//	写操作还必须在 handler 层做在线保护 —— 角色在线时改库会被服务端内存覆盖。
// ============================================================================

// GmCharacterDetail 角色详情（管理后台「GM 工具」页展示用）。
type GmCharacterDetail struct {
	CharacterId int64  `json:"character_id"`
	AccountId   int64  `json:"account_id"`
	MId         string `json:"m_id"`
	Name        string `json:"name"`
	Job         int    `json:"job"`
	JobName     string `json:"job_name"`
	GrowType    int    `json:"grow_type"`
	Level       int    `json:"level"`
	Exp         int64  `json:"exp"`
	PvpGrade    int    `json:"pvp_grade"`
	// PvpRatingGrade 与 PvpGrade 相互独立（GM 工具 README 明确过），别合并展示。
	PvpRatingGrade  int    `json:"pvp_rating_grade"`
	BonusSp         int    `json:"bonus_sp"`
	BonusTp         int    `json:"bonus_tp"`
	ExEquipSlotStat int    `json:"ex_equip_slot_stat"`
	DeleteFlag      int    `json:"delete_flag"`
	Cera            int64  `json:"cera"`
	TokenCera       int64  `json:"token_cera"`
	HappyTokenCera  int64  `json:"happy_token_cera"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// GetGmCharacterDetail 按角色 ID 查询详情。
//
// 只读，不做任何写入。找不到（含已软删除）返回 nil, nil —— 让调用方自己决定
// 报「角色不存在」还是「角色已删除」，本层不替它编错误码。
func (db *Database) GetGmCharacterDetail(characterId int64) (*GmCharacterDetail, error) {
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}
	if characterId <= 0 {
		return nil, fmt.Errorf("角色 ID 无效")
	}

	// name 多带一个 typeof()：该列存 GBK 裸字节，必须按列类型解码（见 charset.go）。
	// accounts 的三列点券用 COALESCE 兜 NULL —— 老账号可能为 NULL。
	row := db.gameDB.QueryRow(`
		SELECT c.character_id, c.account_id, COALESCE(a.m_id, ''), c.name, typeof(c.name),
		       c.job, c.grow_type, c.level, c.exp, c.pvp_grade, c.pvp_rating_grade,
		       c.bonus_sp, c.bonus_tp, c.ex_equip_slot_stat, c.delete_flag,
		       COALESCE(a.cera, 0), COALESCE(a.token_cera, 0), COALESCE(a.happy_token_cera, 0),
		       COALESCE(c.created_at, ''), COALESCE(c.updated_at, '')
		FROM characters c
		LEFT JOIN accounts a ON a.account_id = c.account_id
		WHERE c.character_id = ?`, characterId)

	var d GmCharacterDetail
	var rawName []byte
	var nameType string
	err := row.Scan(&d.CharacterId, &d.AccountId, &d.MId, &rawName, &nameType,
		&d.Job, &d.GrowType, &d.Level, &d.Exp, &d.PvpGrade, &d.PvpRatingGrade,
		&d.BonusSp, &d.BonusTp, &d.ExEquipSlotStat, &d.DeleteFlag,
		&d.Cera, &d.TokenCera, &d.HappyTokenCera, &d.CreatedAt, &d.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询角色失败: %w", err)
	}
	d.Name = DecodeGameText(rawName, nameType)
	d.JobName = JobDisplayName(d.Job, d.GrowType)
	return &d, nil
}

// ValidateCharacterName 校验角色名是否符合游戏客户端规则。
//
// 规则与客户端 / DfoGmTool 的 validateCharacterNameInput 对齐：
// GBK(936) 可表示、按 **GBK 字节数** 2–12、禁控制字符与 NUL。
// 注意是字节数不是字符数 —— 一个汉字 2 字节，所以中文最长为 6 字。
func ValidateCharacterName(name string) error {
	if name == "" {
		return fmt.Errorf("角色名不能为空")
	}
	for _, r := range name {
		if r == 0 || unicode.IsControl(r) {
			return fmt.Errorf("角色名不能包含控制字符")
		}
	}
	encoded, err := EncodeGBK(name)
	if err != nil {
		return err
	}
	if n := len(encoded); n < 2 || n > 12 {
		return fmt.Errorf("角色名长度必须是 2–12 字节（一个汉字算 2 字节），当前 %d", n)
	}
	return nil
}

// RenameCharacter 修改角色名。
//
// 同时写 name 与 name_bytes 两列 —— schema 里它们是同一份 GBK 字节的两个落点，
// 只写一列会让客户端与某些查询看到不一致的名字（DfoGmTool 的改名实现同样两列同写）。
//
// 重名判定在**字节层**做：列里存的是 GBK blob，用 SQL 的 `name = ?` 直接比字节，
// 不做任何文本层比较（GBK 与 UTF-8 存在「不同字符串字节撞车」的情况，见项目记忆）。
// 另外 characters 上有 UNIQUE INDEX idx_characters_name_unique，
// 这里主动查一次是为了给出可读提示，真正的兜底仍是数据库的唯一约束。
func (db *Database) RenameCharacter(characterId int64, newName string) error {
	if !db.GameConfigured() {
		return fmt.Errorf("游戏库未配置")
	}
	if characterId <= 0 {
		return fmt.Errorf("角色 ID 无效")
	}
	if err := ValidateCharacterName(newName); err != nil {
		return err
	}
	encoded, err := EncodeGBK(newName)
	if err != nil {
		return err
	}

	// 角色必须存在且未删除
	var curName []byte
	var curType string
	var deleted int
	err = db.gameDB.QueryRow(
		"SELECT name, typeof(name), delete_flag FROM characters WHERE character_id = ?",
		characterId).Scan(&curName, &curType, &deleted)
	if err == sql.ErrNoRows {
		return fmt.Errorf("角色不存在")
	}
	if err != nil {
		return fmt.Errorf("查询角色失败: %w", err)
	}
	if deleted != 0 {
		return fmt.Errorf("角色已删除，无法改名")
	}
	if DecodeGameText(curName, curType) == newName {
		return fmt.Errorf("新名字与当前名字相同")
	}

	// 重名检查（字节层），排除自己
	var dup int
	if err := db.gameDB.QueryRow(
		"SELECT COUNT(*) FROM characters WHERE name = ? AND character_id <> ?",
		encoded, characterId).Scan(&dup); err != nil {
		return fmt.Errorf("重名检查失败: %w", err)
	}
	if dup > 0 {
		return fmt.Errorf("该角色名已被占用")
	}

	res, err := db.gameDB.Exec(
		"UPDATE characters SET name = ?, name_bytes = ?, updated_at = CURRENT_TIMESTAMP WHERE character_id = ? AND delete_flag = 0",
		encoded, encoded, characterId)
	if err != nil {
		// 唯一索引冲突也走这里（并发下上面那次检查可能过时）
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("该角色名已被占用")
		}
		return fmt.Errorf("改名失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("角色不存在或已删除")
	}
	return nil
}

// AdjustCharacterSpTp 增减角色的 SP / TP。
//
// 只改 characters 表的 bonus_sp / bonus_tp 两个「奖励加成」列，
// 与 DfoGmTool 的 AdjustSpTp 语义一致：真实的剩余/总量由服务端按
// 职业/等级/加成重算，GM 侧只负责调这个加成项。
//
// 用 SQL 的 MAX(0, ...) 保证不会减成负数 —— 前端传入的负数不该把点数变成负值，
// 否则服务端重算时会得出比 0 还小的剩余点。
// 返回调整后的值。
func (db *Database) AdjustCharacterSpTp(characterId int64, spDelta, tpDelta int) (sp, tp int, err error) {
	if !db.GameConfigured() {
		return 0, 0, fmt.Errorf("游戏库未配置")
	}
	if characterId <= 0 {
		return 0, 0, fmt.Errorf("角色 ID 无效")
	}
	if spDelta == 0 && tpDelta == 0 {
		return 0, 0, fmt.Errorf("SP 与 TP 至少要改一项")
	}
	// 单次调整幅度上限：不是业务规则，是防手抖输错数量级（比如把 100 敲成 100000）。
	const maxDelta = 1000000
	if spDelta > maxDelta || spDelta < -maxDelta || tpDelta > maxDelta || tpDelta < -maxDelta {
		return 0, 0, fmt.Errorf("单次调整幅度不能超过 %d", maxDelta)
	}

	res, err := db.gameDB.Exec(`
		UPDATE characters
		SET bonus_sp = MAX(0, bonus_sp + ?),
		    bonus_tp = MAX(0, bonus_tp + ?),
		    updated_at = CURRENT_TIMESTAMP
		WHERE character_id = ? AND delete_flag = 0`, spDelta, tpDelta, characterId)
	if err != nil {
		return 0, 0, fmt.Errorf("SP/TP 写入失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, 0, fmt.Errorf("角色不存在或已删除")
	}

	if err := db.gameDB.QueryRow(
		"SELECT bonus_sp, bonus_tp FROM characters WHERE character_id = ?",
		characterId).Scan(&sp, &tp); err != nil {
		return 0, 0, fmt.Errorf("回读 SP/TP 失败: %w", err)
	}
	return sp, tp, nil
}

// GmInventoryItem 一件背包物品（从 99 字节 item_core 解出的展示字段）。
//
// 只解出「人看得懂」的那几个字段，不做完整解码 ——
// 完整解码（强化/增幅/随机词条…）属服务端业务逻辑，本模块不做也不宣称。
type GmInventoryItem struct {
	Uid       int64 `json:"uid"`
	ListType  int   `json:"list_type"`
	SlotIndex int   `json:"slot_index"`
	Kind      int   `json:"kind"`
	ItemId    int   `json:"item_id"`
	Count     int   `json:"count"`
}

// item_core 的固定布局（与 DfoGmTool ServerCore/Game/Inventory/ItemCore.cs 对齐）。
//
// 这三种偏移是**契约**，不是猜的：ItemCore.Size = 99，列上有 CHECK(length=99)。
const (
	itemCoreSize      = 99
	itemKindOffset    = 0 // 1 字节 物品大类（1=装备 2=消耗 3=材料 …）
	itemIdOffset      = 1 // 4 字节 物品模板 ID（小端 int32）
	itemCountOffset   = 5 // 4 字节 数量/价值（小端 int32）
	itemDurabilityOff = 10
)

// ListCharacterInventory 读取角色的背包物品（只读）。
//
// 空 item_core、长度不为 99 的行会被跳过而不是报错 ——
// 库里若有历史遗留的畸形行，不该让整个页面打不开。
func (db *Database) ListCharacterInventory(characterId int64) ([]GmInventoryItem, error) {
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}
	if characterId <= 0 {
		return nil, fmt.Errorf("角色 ID 无效")
	}

	rows, err := db.gameDB.Query(
		"SELECT item_uid, list_type, slot_index, item_core FROM character_inventory_items WHERE character_id = ? ORDER BY list_type, slot_index",
		characterId)
	if err != nil {
		return nil, fmt.Errorf("查询背包失败: %w", err)
	}
	defer rows.Close()

	items := make([]GmInventoryItem, 0, 64)
	for rows.Next() {
		var it GmInventoryItem
		var core []byte
		if err := rows.Scan(&it.Uid, &it.ListType, &it.SlotIndex, &core); err != nil {
			continue
		}
		if len(core) != itemCoreSize {
			continue
		}
		it.Kind = int(core[itemKindOffset])
		it.ItemId = int(int32(binary.LittleEndian.Uint32(core[itemIdOffset : itemIdOffset+4])))
		it.Count = int(int32(binary.LittleEndian.Uint32(core[itemCountOffset : itemCountOffset+4])))
		items = append(items, it)
	}
	return items, rows.Err()
}

// DeleteCharacterInventoryItem 删除角色背包里的一件物品（按 item_uid）。
//
// 带 character_id 条件：防止拿到别人的 uid 越权删除。
// 返回是否真的删掉一行 —— 调用方据此区分「删成功」与「uid 不存在」。
func (db *Database) DeleteCharacterInventoryItem(characterId, uid int64) (bool, error) {
	if !db.GameConfigured() {
		return false, fmt.Errorf("游戏库未配置")
	}
	if characterId <= 0 || uid <= 0 {
		return false, fmt.Errorf("参数无效")
	}
	res, err := db.gameDB.Exec(
		"DELETE FROM character_inventory_items WHERE item_uid = ? AND character_id = ?",
		uid, characterId)
	if err != nil {
		return false, fmt.Errorf("删除物品失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SearchCharactersByName 按角色名模糊搜索（GBK 安全的做法）。
//
// 不能用 SQL LIKE：characters.name 是 GBK blob，用 UTF-8 模式去比永远比不中
// （项目已定的铁律）。这里退化成「取回候选行 + Go 侧 Contains」，
// 因此必须有 limit 兜底，避免整表拉回内存。
//
// 只返回存活角色；按 level 倒序（大号优先，GM 查人时更常找的就是大号）。
func (db *Database) SearchCharactersByName(keyword string, limit int) ([]*GmCharacterDetail, error) {
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return nil, fmt.Errorf("关键词不能为空")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := db.gameDB.Query(`
		SELECT c.character_id, c.account_id, COALESCE(a.m_id, ''), c.name, typeof(c.name),
		       c.job, c.grow_type, c.level, c.exp, c.pvp_grade, c.pvp_rating_grade,
		       c.bonus_sp, c.bonus_tp, c.ex_equip_slot_stat, c.delete_flag,
		       COALESCE(a.cera, 0), COALESCE(a.token_cera, 0), COALESCE(a.happy_token_cera, 0),
		       COALESCE(c.created_at, ''), COALESCE(c.updated_at, '')
		FROM characters c
		LEFT JOIN accounts a ON a.account_id = c.account_id
		WHERE c.delete_flag = 0
		ORDER BY c.level DESC, c.character_id ASC
		LIMIT 20000`)
	if err != nil {
		return nil, fmt.Errorf("查询角色失败: %w", err)
	}
	defer rows.Close()

	// 纯数字关键词按角色 ID 精确匹配（数字 ID 不能走包含匹配，
	// 否则查 38 会把 10038 也带出来 —— 项目已定的口径）。
	exactId := int64(0)
	if isAllDigits(keyword) {
		exactId = parseInt64(keyword)
	}

	out := make([]*GmCharacterDetail, 0, limit)
	for rows.Next() {
		var d GmCharacterDetail
		var rawName []byte
		var nameType string
		if err := rows.Scan(&d.CharacterId, &d.AccountId, &d.MId, &rawName, &nameType,
			&d.Job, &d.GrowType, &d.Level, &d.Exp, &d.PvpGrade, &d.PvpRatingGrade,
			&d.BonusSp, &d.BonusTp, &d.ExEquipSlotStat, &d.DeleteFlag,
			&d.Cera, &d.TokenCera, &d.HappyTokenCera, &d.CreatedAt, &d.UpdatedAt); err != nil {
			continue
		}
		d.Name = DecodeGameText(rawName, nameType)
		hit := strings.Contains(d.Name, keyword) || strings.Contains(d.MId, keyword)
		if !hit && exactId > 0 {
			hit = d.CharacterId == exactId
		}
		if !hit {
			continue
		}
		d.JobName = JobDisplayName(d.Job, d.GrowType)
		out = append(out, &d)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

// isAllDigits 判断是否全为 ASCII 数字（角色 ID 精确匹配用）。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseInt64 解析十进制整数，溢出或非法时返回 0（调用方用它做「不是 ID」的判据）。
func parseInt64(s string) int64 {
	var n int64
	for i := 0; i < len(s); i++ {
		d := int64(s[i] - '0')
		if n > (1<<62)/10 {
			return 0
		}
		n = n*10 + d
	}
	return n
}
