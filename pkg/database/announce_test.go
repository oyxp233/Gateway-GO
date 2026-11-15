package database

import (
	"path/filepath"
	"testing"
	"time"

	"s4a21-gateway/pkg/models"
)

// newAnnounceTestDB 建一套「网关库 + 最小游戏库」的临时环境。
//
// 游戏库只需 accounts(m_id) + characters(account_id,name)：
// 事件上报补全账号走的就是 ResolveMIdByCharacterID 这条 join。
func newAnnounceTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	gamePath := filepath.Join(dir, "inventory.db")

	game, err := openSQLite(gamePath, 5)
	if err != nil {
		t.Fatalf("打开测试游戏库失败: %v", err)
	}
	if _, err := game.Exec(`
		CREATE TABLE accounts (
			account_id    INTEGER PRIMARY KEY AUTOINCREMENT,
			m_id          TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE characters (
			character_id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id   INTEGER NOT NULL,
			name         TEXT NOT NULL,
			delete_flag  INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO accounts(account_id, m_id) VALUES (1, '10038');
		INSERT INTO characters(character_id, account_id, name) VALUES (500, 1, 'msp');`); err != nil {
		game.Close()
		t.Fatalf("建测试游戏库 schema 失败: %v", err)
	}
	game.Close()

	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           gamePath,
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("初始化网关库 schema 失败: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// TestAnnounceConfigDefaultsOnFreshDB 全新库必须读出**出厂默认**，而不是零值。
//
// 这是一个真实的坑：若缺失的键回退到 Go 零值，全新部署第一次启动就会
// Config.Enabled=false —— 公告静默全停，后台却显示"服务正常"。
func TestAnnounceConfigDefaultsOnFreshDB(t *testing.T) {
	db := newAnnounceTestDB(t)

	cfg, err := db.LoadAnnounceConfig()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	want := models.DefaultAnnounceConfig()
	if cfg.Enabled != want.Enabled || cfg.Report != want.Report {
		t.Fatalf("全新库应回退出厂默认（Enabled/Report 均为 true），实得 enabled=%v report=%v",
			cfg.Enabled, cfg.Report)
	}
	if !cfg.Cleared || !cfg.Incomplete || !cfg.Pickup {
		t.Fatalf("全新库的播报开关应为出厂默认（全开），实得 cleared=%v incomplete=%v pickup=%v",
			cfg.Cleared, cfg.Incomplete, cfg.Pickup)
	}
	if cfg.TemplatePickup != want.TemplatePickup {
		t.Fatalf("拾取文案模板不符: %q", cfg.TemplatePickup)
	}
	if len(cfg.DifficultyNames) != len(want.DifficultyNames) {
		t.Fatalf("难度名数量不符: %v", cfg.DifficultyNames)
	}
}

// TestAnnounceConfigRoundTrip 保存后再读，字段与 Revision 必须一致。
func TestAnnounceConfigRoundTrip(t *testing.T) {
	db := newAnnounceTestDB(t)

	cfg := models.DefaultAnnounceConfig()
	cfg.Cleared = false
	cfg.PickupUnique = true
	cfg.AnnounceDurationMs = 8000
	cfg.EventRetentionDays = 7
	cfg.TemplateCleared = "【通关】{player} -> {dungeon} ({difficulty}) {elapsed}"
	cfg.DifficultyNames = []string{"简单", "普通", "困难"}

	saved, err := db.SaveAnnounceConfig(cfg)
	if err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}
	if saved.Revision != 1 {
		t.Fatalf("首次保存 Revision 应为 1，实得 %d", saved.Revision)
	}

	got, err := db.LoadAnnounceConfig()
	if err != nil {
		t.Fatalf("重读配置失败: %v", err)
	}
	if got.Cleared {
		t.Fatal("Cleared 应为 false")
	}
	if !got.PickupUnique {
		t.Fatal("PickupUnique 应为 true")
	}
	if got.AnnounceDurationMs != 8000 {
		t.Fatalf("AnnounceDurationMs 应为 8000，实得 %d", got.AnnounceDurationMs)
	}
	if got.EventRetentionDays != 7 {
		t.Fatalf("EventRetentionDays 应为 7，实得 %d", got.EventRetentionDays)
	}
	if got.TemplateCleared != cfg.TemplateCleared {
		t.Fatalf("TemplateCleared 不符: %q", got.TemplateCleared)
	}
	if len(got.DifficultyNames) != 3 || got.DifficultyNames[0] != "简单" {
		t.Fatalf("DifficultyNames 不符: %v", got.DifficultyNames)
	}

	// 第二次保存 Revision 必须递增 —— 插件/后台靠它判断"配置变了没有"。
	saved2, err := db.SaveAnnounceConfig(got)
	if err != nil {
		t.Fatalf("二次保存失败: %v", err)
	}
	if saved2.Revision != 2 {
		t.Fatalf("二次保存 Revision 应为 2，实得 %d", saved2.Revision)
	}
}

// TestAnnounceConfigIgnoresCallerRevision 调用方传进来的 Revision 必须被忽略。
//
// 两个后台标签页并发保存时，若允许调用方指定版本号，版本会往回退，
// "配置有没有变" 这个判断随之失效。
func TestAnnounceConfigIgnoresCallerRevision(t *testing.T) {
	db := newAnnounceTestDB(t)

	cfg := models.DefaultAnnounceConfig()
	cfg.Revision = 9999
	saved, err := db.SaveAnnounceConfig(cfg)
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if saved.Revision != 1 {
		t.Fatalf("Revision 应被忽略并从 1 开始，实得 %d", saved.Revision)
	}
}

// TestAnnounceEventInsertQueryAndStats 事件落库、按类查询、计数。
func TestAnnounceEventInsertQueryAndStats(t *testing.T) {
	db := newAnnounceTestDB(t)
	now := time.Now().Unix()

	events := []models.AnnounceEvent{
		{Kind: models.AnnounceKindCleared, CharacterID: 500, CharacterName: "msp",
			DungeonID: 12, DungeonName: "幽暗密林", Difficulty: 2, ElapsedMs: 91000},
		{Kind: models.AnnounceKindIncomplete, CharacterID: 500, CharacterName: "msp",
			DungeonID: 12, DungeonName: "幽暗密林", Difficulty: 2, ElapsedMs: 30000},
		{Kind: models.AnnounceKindPickup, CharacterID: 500, CharacterName: "msp",
			DungeonID: 12, DungeonName: "幽暗密林", HellMode: true, Difficulty: 4,
			ItemID: 1001, ItemName: "魔剑·阿波菲斯", ItemRarity: 6, IsEquipment: true,
			ItemLevel: 55, EquipmentType: "weapon", PhysicalAtk: 700, Broadcast: true},
		{Kind: "bogus", CharacterName: "谁"},
	}

	inserted, err := db.InsertAnnounceEvents(events)
	if err != nil {
		t.Fatalf("写入事件失败: %v", err)
	}
	if inserted != 3 {
		t.Fatalf("非法 kind 应被丢弃，期望写入 3 条，实得 %d", inserted)
	}

	total, _, err := db.QueryAnnounceEvents(AnnounceEventFilter{Kind: models.AnnounceKindCleared, Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("按 kind 查询失败: %v", err)
	}
	if total != 1 {
		t.Fatalf("cleared 应有 1 条，实得 %d", total)
	}

	// 按关键词跨字段匹配（角色名 / 物品名 / 副本名）
	total, rows, err := db.QueryAnnounceEvents(AnnounceEventFilter{Keyword: "阿波菲斯", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("按关键词查询失败: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("关键词应命中 1 条，实得 %d", total)
	}
	if !rows[0].HellMode || !rows[0].Broadcast || rows[0].ItemRarity != 6 {
		t.Fatalf("命中行的布尔/数值字段解码错误: %+v", rows[0])
	}

	// 非法 kind 直接报错，而不是静默返回空列表
	if _, _, err := db.QueryAnnounceEvents(AnnounceEventFilter{Kind: "bogus"}); err == nil {
		t.Fatal("非法 kind 应报错")
	}

	stats, err := db.AnnounceEventStats()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if stats[models.AnnounceKindCleared] != 1 || stats[models.AnnounceKindPickup] != 1 {
		t.Fatalf("分类计数不符: %v", stats)
	}

	// 保留期清理：把窗口设在现在之后 → 全部删掉
	removed, err := db.PurgeAnnounceEvents(now + 3600)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if removed != 3 {
		t.Fatalf("应删除 3 条，实得 %d", removed)
	}
	if n, _, _ := db.QueryAnnounceEvents(AnnounceEventFilter{Page: 1, PageSize: 10}); n != 0 {
		t.Fatalf("清理后应为 0 条，实得 %d", n)
	}
}

// TestQueryAnnounceEventsIndependentFilters 四个文本筛选彼此独立 + 品级多选 + 只看广播过。
//
// 区分力设计：故意放一条「角色名叫阿波菲斯、物品却叫史诗戒指」的记录。
// item=阿波菲斯 只能命中真正的魔剑，character=阿波菲斯 只能命中那条角色 ——
// 旧版三合一 keyword 会把两条都捞出来，正是这次要修的串列问题。
func TestQueryAnnounceEventsIndependentFilters(t *testing.T) {
	db := newAnnounceTestDB(t)
	events := []models.AnnounceEvent{
		{Kind: models.AnnounceKindPickup, Account: "acc-a", CharacterName: "剑魂甲",
			DungeonName: "悲鸣洞穴", ItemName: "魔剑·阿波菲斯", ItemRarity: 6, IsEquipment: true, Broadcast: true},
		{Kind: models.AnnounceKindPickup, Account: "acc-b", CharacterName: "剑魂乙",
			DungeonName: "悲鸣洞穴", ItemName: "异界手镯", ItemRarity: 5, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, Account: "acc-a", CharacterName: "阿波菲斯",
			DungeonName: "幽暗密林", ItemName: "史诗戒指", ItemRarity: 4, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, Account: "acc-c", CharacterName: "奶妈",
			DungeonName: "天空之城", ItemName: "神器项链", ItemRarity: 3, IsEquipment: true, Broadcast: true},
		{Kind: models.AnnounceKindCleared, Account: "acc-a", CharacterName: "剑魂甲", DungeonName: "悲鸣洞穴"},
	}
	if n, err := db.InsertAnnounceEvents(events); err != nil || n != len(events) {
		t.Fatalf("写入失败: n=%d err=%v", n, err)
	}

	cases := []struct {
		name   string
		filter AnnounceEventFilter
		want   int
	}{
		{"账号独立", AnnounceEventFilter{Account: "acc-a"}, 3},
		{"角色名独立", AnnounceEventFilter{CharacterName: "剑魂"}, 3},
		{"副本名独立", AnnounceEventFilter{DungeonName: "悲鸣"}, 3},
		{"物品名独立", AnnounceEventFilter{ItemName: "阿波菲斯"}, 1},
		{"角色名与物品名不串", AnnounceEventFilter{CharacterName: "阿波菲斯"}, 1},
		{"四条件组合 AND", AnnounceEventFilter{Account: "acc-a", CharacterName: "剑魂甲", DungeonName: "悲鸣", ItemName: "魔剑"}, 1},
		{"品级多选 传说+异界", AnnounceEventFilter{Rarities: []int{5, 6}}, 2},
		{"品级多选 神器+史诗", AnnounceEventFilter{Rarities: []int{3, 4}}, 2},
		{"品级去重", AnnounceEventFilter{Rarities: []int{6, 6, 6}}, 1},
		{"只看广播过", AnnounceEventFilter{BroadcastOnly: true}, 2},
		{"品级+广播组合", AnnounceEventFilter{Rarities: []int{3}, BroadcastOnly: true}, 1},
		{"旧 min_rarity 兼容", AnnounceEventFilter{MinRarity: 6}, 1},
		{"旧 keyword 兼容", AnnounceEventFilter{Keyword: "阿波菲斯"}, 2},
	}
	for _, tc := range cases {
		tc.filter.Page, tc.filter.PageSize = 1, 50
		total, rows, err := db.QueryAnnounceEvents(tc.filter)
		if err != nil {
			t.Fatalf("%s: 查询失败: %v", tc.name, err)
		}
		if total != tc.want || len(rows) != tc.want {
			t.Errorf("%s: 期望 %d 条，实得 total=%d rows=%d", tc.name, tc.want, total, len(rows))
		}
	}

	if _, _, err := db.QueryAnnounceEvents(AnnounceEventFilter{Rarities: []int{99}}); err == nil {
		t.Error("非法品级应报错，不能静默变成「不限」返回全表")
	}
}

// TestResolveMIdByCharacterID 角色 → m_id 反查；查不到的路径必须是 (\"\", nil) 而不是错误。
func TestResolveMIdByCharacterID(t *testing.T) {
	db := newAnnounceTestDB(t)

	mid, err := db.ResolveMIdByCharacterID(500)
	if err != nil {
		t.Fatalf("反查失败: %v", err)
	}
	if mid != "10038" {
		t.Fatalf("期望 m_id=10038，实得 %q", mid)
	}

	// 不存在的角色不是错误：事件本身比账号字段重要，不能因为关联失败丢事件。
	mid, err = db.ResolveMIdByCharacterID(999999)
	if err != nil {
		t.Fatalf("查不到角色不应报错，实得 %v", err)
	}
	if mid != "" {
		t.Fatalf("查不到角色应返回空串，实得 %q", mid)
	}
}

// TestAnnouncePopupQueue 弹窗的入队 → 取走 → 不重复投递。
func TestAnnouncePopupQueue(t *testing.T) {
	db := newAnnounceTestDB(t)

	if _, err := db.EnqueueAnnouncePopup("  ", 0, "tester"); err == nil {
		t.Fatal("空白内容应被拒绝")
	}
	if _, err := db.EnqueueAnnouncePopup("维护公告", 300, "tester"); err == nil {
		t.Fatal("mode 越界应被拒绝")
	}

	id, err := db.EnqueueAnnouncePopup("服务器将于 10 分钟后维护，请及时下线", 1, "tester")
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if id <= 0 {
		t.Fatalf("返回的 id 非法: %d", id)
	}

	got, err := db.TakePendingAnnouncePopups(10, 900)
	if err != nil {
		t.Fatalf("取弹窗失败: %v", err)
	}
	if len(got) != 1 || got[0].Message != "服务器将于 10 分钟后维护，请及时下线" || got[0].Mode != 1 {
		t.Fatalf("取到的弹窗不符: %+v", got)
	}
	if got[0].Status != models.AnnouncePopupSent {
		t.Fatalf("取出后状态应为 sent，实得 %s", got[0].Status)
	}

	// 关键：同一条不允许被两次投递（否则玩家会看到两遍弹窗）
	again, err := db.TakePendingAnnouncePopups(10, 900)
	if err != nil {
		t.Fatalf("二次取弹窗失败: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("已投递的弹窗不应再被取出，实得 %d 条", len(again))
	}
}

// TestAnnouncePopupExpiry 超期未送达的 pending 必须转为 expired 且不再投递。
func TestAnnouncePopupExpiry(t *testing.T) {
	db := newAnnounceTestDB(t)

	id, err := db.EnqueueAnnouncePopup("一小时前的旧公告", 0, "tester")
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	// 手工把创建时间改到 1 小时前 —— 这一行是真实的"服务端离线期间积压"状态。
	if _, err := db.gatewayDB.Exec(
		"UPDATE announce_popups SET created_at = ? WHERE id = ?", time.Now().Unix()-3600, id); err != nil {
		t.Fatalf("回填创建时间失败: %v", err)
	}

	got, err := db.TakePendingAnnouncePopups(10, 900)
	if err != nil {
		t.Fatalf("取弹窗失败: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("超期弹窗不应被投递，实得 %d 条", len(got))
	}

	total, list, err := db.QueryAnnouncePopups(models.AnnouncePopupExpired, 1, 10)
	if err != nil {
		t.Fatalf("查超期弹窗失败: %v", err)
	}
	if total != 1 || list[0].ID != id {
		t.Fatalf("应有一条 expired 记录，实得 total=%d list=%+v", total, list)
	}

	// 2026-09-24 口径变更：任何状态都能从后台列表里删掉（软删除）。
	// 旧口径是"已超时/已投递的不给删"，结果玩家最想删的那几条刚好删不动，
	// 后台表现为"撤销按钮点了没反应"。
	if ok, err := db.DeleteAnnouncePopup(id); err != nil || !ok {
		t.Fatalf("expired 弹窗应可删（软删除），ok=%v err=%v", ok, err)
	}
	// 删掉之后不能还挂在列表里，但行本身还在库里（软删除，审计留痕）。
	if n, _, _ := db.QueryAnnouncePopups(models.AnnouncePopupExpired, 1, 10); n != 0 {
		t.Fatalf("软删除后 expired 列表应为空，实得 %d 条", n)
	}
	var remain int
	if err := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM announce_popups WHERE id = ?", id).Scan(&remain); err != nil {
		t.Fatalf("查残留行失败: %v", err)
	}
	if remain != 1 {
		t.Fatalf("软删除必须保留行本身，实得 %d 行", remain)
	}
}

// TestAnnouncePopupDeletePending 待投递的弹窗允许撤销。
func TestAnnouncePopupDeletePending(t *testing.T) {
	db := newAnnounceTestDB(t)
	id, err := db.EnqueueAnnouncePopup("误发的内容", 0, "tester")
	if err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	ok, err := db.DeleteAnnouncePopup(id)
	if err != nil || !ok {
		t.Fatalf("pending 弹窗应可删，ok=%v err=%v", ok, err)
	}
	if n, _, _ := db.QueryAnnouncePopups("", 1, 10); n != 0 {
		t.Fatalf("删除后应为 0 条，实得 %d", n)
	}
}

// TestBuildAnnounceRankings 三个品级榜单必须分开聚合，且各自只吃自己的品级。
func TestBuildAnnounceRankings(t *testing.T) {
	db := newAnnounceTestDB(t)

	// 品级：3=神器、4=史诗、5=异界、6=传说。异界(5) 不进三榜（登录器只认三个 tier），
	// 白装(0) 与材料同样不进任何榜。
	rows := []models.AnnounceEvent{
		{Kind: models.AnnounceKindPickup, CharacterName: "msp", ItemID: 1, ItemName: "魔剑", ItemRarity: 6, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, CharacterName: "msp", ItemID: 1, ItemName: "魔剑", ItemRarity: 6, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, CharacterName: "pp", ItemID: 2, ItemName: "太刀", ItemRarity: 6, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, CharacterName: "msp", ItemID: 3, ItemName: "史诗戒指", ItemRarity: 4, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, CharacterName: "ss", ItemID: 4, ItemName: "异界腰带", ItemRarity: 5, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, CharacterName: "pp", ItemID: 5, ItemName: "神器项链", ItemRarity: 3, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, CharacterName: "pp", ItemID: 6, ItemName: "白装布甲", ItemRarity: 0, IsEquipment: true},
		{Kind: models.AnnounceKindPickup, CharacterName: "pp", ItemID: 7, ItemName: "无色小晶块", ItemRarity: 0, IsEquipment: false},
		{Kind: models.AnnounceKindCleared, CharacterName: "pp", DungeonName: "幽暗密林"},
	}
	if _, err := db.InsertAnnounceEvents(rows); err != nil {
		t.Fatalf("写入事件失败: %v", err)
	}

	rankings, err := db.BuildAnnounceRankings(20, 0)
	if err != nil {
		t.Fatalf("生成榜单失败: %v", err)
	}
	if len(rankings) != 3 {
		t.Fatalf("应有 3 个榜单，实得 %d", len(rankings))
	}

	byTier := map[string]models.AnnounceRanking{}
	for _, r := range rankings {
		byTier[r.Tier] = r
	}

	legend := byTier["legend"]
	if legend.Label != "传说" || legend.Total != 3 {
		t.Fatalf("传说榜 total 应为 3（魔剑×2 + 太刀×1），实得 %+v", legend)
	}
	if len(legend.Players) != 2 || legend.Players[0].Key != "msp" || legend.Players[0].Count != 2 {
		t.Fatalf("传说榜玩家排序不符: %+v", legend.Players)
	}
	if len(legend.Items) != 2 || legend.Items[0].Key != "魔剑" || legend.Items[0].Count != 2 {
		t.Fatalf("传说榜物品排序不符: %+v", legend.Items)
	}
	if legend.Owners[1] != "msp" {
		t.Fatalf("传说榜最近获得者不符: %v", legend.Owners)
	}

	epic := byTier["epic"]
	if epic.Total != 1 {
		t.Fatalf("史诗榜 total 应为 1（只认品级 4，异界 5 不再并入），实得 %d", epic.Total)
	}
	if len(epic.Players) != 1 {
		t.Fatalf("史诗榜应有 1 个玩家，实得 %+v", epic.Players)
	}

	unique := byTier["unique"]
	if unique.Label != "神器" || unique.Total != 1 {
		t.Fatalf("神器榜不符: %+v", unique)
	}

	// 白装与材料一条都不该进榜
	var sum int64
	for _, r := range rankings {
		sum += r.Total
	}
	if sum != 5 {
		t.Fatalf("三榜合计应为 5 条（不含异界/白装/材料），实得 %d", sum)
	}

	// since 过滤：把窗口抬到未来 → 全部落空
	future, err := db.BuildAnnounceRankings(20, time.Now().Unix()+3600)
	if err != nil {
		t.Fatalf("带时间窗生成榜单失败: %v", err)
	}
	for _, r := range future {
		if r.Total != 0 {
			t.Fatalf("时间窗过滤失效: %s total=%d", r.Tier, r.Total)
		}
	}
}
