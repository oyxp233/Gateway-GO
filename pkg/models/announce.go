package models

// AnnounceConfig 是全服公告的**业务配置**（区别于 plugin.ini 里的接入参数）。
//
// 唯一真源是网关进程内存 + `announce_config` 表；管理后台通过网关写它，
// 游戏服务端的公告插件每「轮询秒」从 `/internal/announce/pull` 拉一次从而实现热重载。
//
// 字段分三类：
//  1. 总开关与分类开关 —— 决定"广播什么"；
//  2. 文案模板与难度名 —— 决定"长什么样"；
//  3. 保留期 —— 决定事件表怎么清理。
//
// JSON tag 同时是**下发契约**：插件侧 RuntimeConfig.Parse 按同一批名字读取，改名字要两边一起改。
type AnnounceConfig struct {
	// Enabled 公告服务总开关。false 时插件既不上报也不广播、不收弹窗（完全停用）。
	Enabled bool `json:"enabled"`
	// Report 是否把通关/未通关/拾取事件写入网关库。
	// 与上面的广播开关**解耦**：关掉广播仍要留数据，后台才能查历史与出榜单。
	Report bool `json:"report"`

	Cleared    bool `json:"cleared"`
	Incomplete bool `json:"incomplete"`
	// Pickup 拾取播报总开关。
	Pickup bool `json:"pickup"`
	// PickupHellEpic 拾取播报深渊史诗（品级 4/5，仅深渊）。
	PickupHellEpic bool `json:"pickup_hell_epic"`
	// PickupLegend 拾取播报传说（品级 6，任意地图）。
	PickupLegend bool `json:"pickup_legend"`
	// PickupUnique 拾取播报神器（品级 3，任意地图）。默认关，避免普通图刷屏。
	PickupUnique bool `json:"pickup_unique"`
	// PickupStats 播报是否附加装备属性摘要（Lv./物攻/魔攻/物防/魔防）。
	PickupStats bool `json:"pickup_stats"`
	// PickupItemLink 拾取播报是否附带装备数据块（公告里的物品变成客户端可点的链接）。
	//
	// ⚠️ 这是唯一"结构上有风险"的开关：带块的公告仍是同一条滚动公告封包
	// （SERVER_BROADCAST_TIME_MESSAGE），但包体尾部多了 141B 数据块。客户端是否按
	// "dstr 之后剩余字节"解析该块**无先例可循**，一旦有玩家反馈公告异常或客户端崩，
	// 后台关掉此开关即可立刻回退为纯文本公告 —— 不需要重启服务端、不需要重编译。
	PickupItemLink bool `json:"pickup_item_link"`

	// HellDifficultyName 深渊模式下展示的难度名。
	HellDifficultyName string `json:"hell_difficulty_name"`
	// DifficultyNames 按 difficulty 索引的难度名（下标 0..N）。
	DifficultyNames []string `json:"difficulty_names"`

	// AnnounceDurationMs 单条滚动公告的显示时长（毫秒）。
	AnnounceDurationMs int `json:"announce_duration_ms"`
	// PopupMode 弹窗包体的 mode 字段（服务端 SERVER_NOTICE_MESSAGE 首字节）。
	PopupMode int `json:"popup_mode"`

	// TemplateCleared 可用占位符：{player} {dungeon} {difficulty} {elapsed}
	TemplateCleared string `json:"template_cleared"`
	// TemplateIncomplete 同上。
	TemplateIncomplete string `json:"template_incomplete"`
	// TemplatePickup 可用占位符：{player} {dungeon} {difficulty} {item} {rarity} {level}
	TemplatePickup string `json:"template_pickup"`

	// EventRetentionDays announce_events 的保留天数，超期记录由网关定期清理。0 = 不清理。
	EventRetentionDays int `json:"event_retention_days"`

	// Revision 每次保存 +1。插件可用于判断"配置是否变过"，也便于排查"改没改到"。
	Revision int64 `json:"revision"`
	// UpdatedAt Unix 秒。
	UpdatedAt int64 `json:"updated_at"`
}

// DefaultAnnounceConfig 返回出厂默认配置。
//
// 默认值刻意与旧版 plugin.ini `[副本播报]` 模板保持一致（除「拾取播报神器」，
// 旧版代码默认就是关），这样从旧版升级上来的服务器行为不变。
func DefaultAnnounceConfig() AnnounceConfig {
	return AnnounceConfig{
		Enabled:        true,
		Report:         true,
		Cleared:        true,
		Incomplete:     true,
		Pickup:         true,
		PickupHellEpic: true,
		PickupLegend:   true,
		PickupUnique:   false,
		PickupStats:    true,
		// 默认开启：新掉落装备无强化/附魔，数据块头部之外全 0，风险面最小。
		PickupItemLink:     true,
		HellDifficultyName: "深渊",
		DifficultyNames:    []string{"普通", "冒险", "王者", "地狱", "深渊"},
		AnnounceDurationMs: 5000,
		PopupMode:          0,
		TemplateCleared:    "恭喜玩家 {player} 通关副本 [{dungeon}·{difficulty}]，用时 {elapsed}",
		TemplateIncomplete: "玩家 {player} 未能通关副本 [{dungeon}·{difficulty}]，用时 {elapsed}",
		TemplatePickup:     "恭喜玩家 {player} 在副本 [{dungeon}·{difficulty}] 中获得 [{item}]",
		EventRetentionDays: 90,
	}
}

// AnnounceEvent 是一条公告事件流水（通关 / 未通关 / 拾取）。
//
// 由游戏服务端插件批量上报，网关落 `announce_events` 表。
// 一个宽表装三种 kind 是有意为之：后台要"分类查询"和"跨类对比"，
// 拆三张表后聚合查询立刻变成三表 join。
type AnnounceEvent struct {
	ID            int64  `json:"id"`
	Kind          string `json:"kind"`
	Account       string `json:"account"`
	CharacterID   int64  `json:"character_id"`
	CharacterName string `json:"character_name"`
	DungeonID     int    `json:"dungeon_id"`
	DungeonName   string `json:"dungeon_name"`
	Difficulty    int    `json:"difficulty"`
	HellMode      bool   `json:"hell_mode"`
	ElapsedMs     int    `json:"elapsed_ms"`
	ItemID        int    `json:"item_id"`
	ItemName      string `json:"item_name"`
	ItemRarity    int    `json:"item_rarity"`
	// IsEquipment 是否装备类。只有装备才进排行榜（材料/消耗品没有品级意义）。
	// 插件恒发这个字段；缺省时网关按 item_id > 0 兜底推导。
	IsEquipment   bool   `json:"is_equipment"`
	ItemLevel     int    `json:"item_level"`
	EquipmentType string `json:"equipment_type"`
	PhysicalAtk   int    `json:"physical_attack"`
	MagicalAtk    int    `json:"magical_attack"`
	PhysicalDef   int    `json:"physical_defense"`
	MagicalDef    int    `json:"magical_defense"`
	Broadcast     bool   `json:"broadcast"`
	CreatedAt     int64  `json:"created_at"`
}

// AnnounceEventKind 是 kind 的合法取值。
const (
	AnnounceKindCleared    = "cleared"
	AnnounceKindIncomplete = "incomplete"
	AnnounceKindPickup     = "pickup"
)

// IsValidAnnounceKind 判断上报的 kind 是否合法（网关入库前必须校验，否则脏数据会污染分类查询）。
func IsValidAnnounceKind(kind string) bool {
	switch kind {
	case AnnounceKindCleared, AnnounceKindIncomplete, AnnounceKindPickup:
		return true
	default:
		return false
	}
}

// AnnouncePopup 是管理后台发起的弹窗公告。
//
// 生命周期：pending（排队）→ sent（已被插件拉走）→ 或 expired（插件长时间不在线，超期未送达）。
// 网关不做"在线判定"，因为插件的拉取节奏本身就是在线信号。
type AnnouncePopup struct {
	ID          int64  `json:"id"`
	Message     string `json:"message"`
	Mode        int    `json:"mode"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	SentAt      int64  `json:"sent_at"`
	DeliveredAt int64  `json:"delivered_at"`
	// CreatedBy 记录是哪条管理密钥发的，便于事后追溯（只存后 6 位）。
	CreatedBy string `json:"created_by"`
}

// 弹窗状态。
const (
	AnnouncePopupPending = "pending"
	AnnouncePopupSent    = "sent"
	AnnouncePopupExpired = "expired"
)

// AnnounceRankingEntry 是排行榜里的一行（玩家榜或物品榜共用）。
type AnnounceRankingEntry struct {
	Rank     int    `json:"rank"`
	Key      string `json:"key"`
	Count    int64  `json:"count"`
	ItemID   int    `json:"item_id,omitempty"`
	Rarity   int    `json:"rarity,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"`
}

// AnnounceRanking 是某一个品级的榜单。
type AnnounceRanking struct {
	// Tier 机器可读的档位名：epic / legend / unique。
	Tier string `json:"tier"`
	// Label 中文档位名：史诗 / 传说 / 神器。
	Label string `json:"label"`
	// Rarities 该档位对应的品级编号集合。
	Rarities []int `json:"rarities"`
	// Total 该档位累计拾取件数（全服）。
	Total int64 `json:"total"`
	// Players 按件数排行的玩家列表。
	Players []AnnounceRankingEntry `json:"players"`
	// Items 该档位的物品清单（按件数排序）。
	Items []AnnounceRankingEntry `json:"items"`
	// Owners 每个物品的最近获得者（item_id → 角色名），用于清单里显示"谁拿的"。
	Owners map[int]string `json:"owners,omitempty"`
}
