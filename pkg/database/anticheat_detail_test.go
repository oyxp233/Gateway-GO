package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// seedAntiCheatRows 造一批带「账号 / 角色 / 房间 / 地图」维度的记录，供筛选用例共用。
func seedAntiCheatRows(t *testing.T, db *Database) {
	t.Helper()
	rows := []AntiCheatDetection{
		{RuleName: "KillTooFast", Account: "msp", PlayerName: "剑魂A", RoomNumber: 3, MapID: 101,
			ActualValue: 94, ThresholdValue: 300, EventTimestamp: 1000, ReportedAt: 100,
			Evidence: "击杀间隔=94ms", ClientIP: "1.1.1.1"},
		{RuleName: "KillTooFast", Account: "msp", PlayerName: "剑魂A", RoomNumber: 5, MapID: 101,
			ActualValue: 88, ThresholdValue: 300, EventTimestamp: 1100, ReportedAt: 200,
			Evidence: "击杀间隔=88ms", ClientIP: "1.1.1.1"},
		{RuleName: "CodeByteTampered", Account: "msp", PlayerName: "鬼泣B", RoomNumber: 0, MapID: 0,
			ActualValue: 1, ThresholdValue: 0, EventTimestamp: 1200, ReportedAt: 300,
			Evidence: "点位=模拟秒杀,期望=0F 85 70 02,实际=90 90 90 90", ClientIP: "1.1.1.1"},
		{RuleName: "AttributeDrift", Account: "other", PlayerName: "", RoomNumber: 0, MapID: 0,
			ActualValue: 2544, ThresholdValue: 2500, EventTimestamp: 1300, ReportedAt: 400,
			Evidence: "命中字段=intellect", ClientIP: "2.2.2.2", Exempt: 1},
	}
	if err := db.InsertAntiCheatDetections(rows); err != nil {
		t.Fatalf("造数据失败: %v", err)
	}
}

// TestAntiCheatRoomPlayerRoundTrip：房间号 / 地图ID / 角色名必须能存能取。
//
// 这三个字段是「按账号、角色区分 + 还原现场」的落地保证。房间里最容易出的错是
// 插入了但 SELECT 没带列（或列序错位），表现为读到 0/空串而不是报错 —— 所以
// 必须逐字段断言值，不能只看 total。
func TestAntiCheatRoomPlayerRoundTrip(t *testing.T) {
	db := newAntiCheatTestDB(t)

	if err := db.InsertAntiCheatDetection(&AntiCheatDetection{
		RuleName: "KillTooFast", Description: "击杀间隔过短", ActualValue: 94, ThresholdValue: 300,
		EventTimestamp: 1000, Evidence: "击杀间隔=94ms", ClientIP: "1.2.3.4", Account: "msp",
		ReportedAt: 2000, RoomNumber: 17, MapID: 330, PlayerName: "测试角色",
	}); err != nil {
		t.Fatalf("单条插入失败: %v", err)
	}

	list, total, err := db.GetAntiCheatDetections(10, 0)
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("查询失败: total=%d len=%d err=%v", total, len(list), err)
	}
	d := list[0]
	if d.RoomNumber != 17 || d.MapID != 330 {
		t.Errorf("房间/地图未正确往返: room=%d map=%d", d.RoomNumber, d.MapID)
	}
	if d.PlayerName != "测试角色" {
		t.Errorf("角色名未正确往返: got %q", d.PlayerName)
	}

	// 按账号查那条路径也要带上（两条路径各自 Scan，容易只改一处）
	byAcct, n, err := db.GetAntiCheatDetectionsByAccount("msp", 10, 0)
	if err != nil || n != 1 {
		t.Fatalf("按账号查失败: n=%d err=%v", n, err)
	}
	if byAcct[0].PlayerName != "测试角色" || byAcct[0].RoomNumber != 17 {
		t.Errorf("按账号查丢了房间/角色: %+v", byAcct[0])
	}
}

// TestAntiCheatRoomPlayerMigration 老库（有 exempt/dedup_id、没有 room_number/map_id/player_name，
// 正是线上 161 现在的形态）打开后必须自动补列，且存量行不受影响。
//
// ★ 关键路径：线上表已存在 ⇒ CREATE TABLE IF NOT EXISTS 整段跳过，只能靠
// migrateSchema 补列。不补的话新版插件一上报就是「列数不匹配」整批写失败。
func TestAntiCheatRoomPlayerMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.db")

	raw, err := openSQLite(path, 5)
	if err != nil {
		t.Fatalf("建旧库失败: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE anticheat_detections (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_name TEXT NOT NULL,
			description TEXT DEFAULT '',
			actual_value REAL DEFAULT 0,
			threshold_value REAL DEFAULT 0,
			event_timestamp INTEGER NOT NULL,
			evidence TEXT DEFAULT '',
			client_ip TEXT DEFAULT '',
			account TEXT DEFAULT '',
			reported_at INTEGER NOT NULL,
			exempt INTEGER DEFAULT 0,
			dedup_id INTEGER DEFAULT 0
		);
		INSERT INTO anticheat_detections (rule_name, account, event_timestamp, reported_at)
			VALUES ('KillTooFast', 'olduser', 1, 2);`); err != nil {
		raw.Close()
		t.Fatalf("建旧 schema 失败: %v", err)
	}
	raw.Close()

	db, err := NewDatabase(DatabaseConfig{
		Path:               path,
		GamePath:           filepath.Join(dir, "inventory.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer db.Close()
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	// 1) 三列都补上了
	cols := map[string]bool{}
	rows, err := db.gatewayDB.Query("PRAGMA table_info(anticheat_detections)")
	if err != nil {
		t.Fatalf("PRAGMA 失败: %v", err)
	}
	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			t.Fatalf("scan 失败: %v", err)
		}
		cols[name] = true
	}
	rows.Close()
	if !cols["room_number"] || !cols["map_id"] || !cols["player_name"] {
		t.Fatalf("迁移后仍缺列: %v", cols)
	}

	// 2) 存量行必须是缺省值（迁移不能改既有数据）
	list, total, err := db.GetAntiCheatDetections(10, 0)
	if err != nil || total != 1 {
		t.Fatalf("查询存量失败: total=%d err=%v", total, err)
	}
	if list[0].RoomNumber != 0 || list[0].MapID != 0 || list[0].PlayerName != "" {
		t.Errorf("存量行应为缺省值，实际 room=%d map=%d name=%q",
			list[0].RoomNumber, list[0].MapID, list[0].PlayerName)
	}

	// 3) 迁移幂等：重复跑不能报错
	if err := db.migrateSchema(); err != nil {
		t.Errorf("二次迁移应幂等，却报错: %v", err)
	}

	// 4) 迁移后新数据要能正常写入（列已就位）
	if err := db.InsertAntiCheatDetection(&AntiCheatDetection{
		RuleName: "KillTooFast", EventTimestamp: 3, ReportedAt: 4, Account: "newuser",
		RoomNumber: 9, MapID: 77, PlayerName: "新角色",
	}); err != nil {
		t.Fatalf("迁移后插入失败: %v", err)
	}
}

// TestAntiCheatFilter 覆盖明细查询的每个筛选条件。
//
// 重点不在"能筛"，而在**不该筛的时候不能筛**：
// 零值 AntiCheatFilter 必须返回全部（ExemptFilter 用指针正是为了防止
// 「零值 0 静默变成只看非豁免」）。
func TestAntiCheatFilter(t *testing.T) {
	db := newAntiCheatTestDB(t)
	seedAntiCheatRows(t, db)

	exemptYes, exemptNo := 1, 0

	cases := []struct {
		name string
		f    AntiCheatFilter
		want int
	}{
		{"零值条件→全部（不能被误过滤）", AntiCheatFilter{}, 4},
		{"按账号", AntiCheatFilter{Account: "msp"}, 3},
		{"按角色", AntiCheatFilter{PlayerName: "剑魂A"}, 2},
		{"账号+角色", AntiCheatFilter{Account: "msp", PlayerName: "鬼泣B"}, 1},
		{"按规则", AntiCheatFilter{RuleName: "KillTooFast"}, 2},
		{"只看豁免", AntiCheatFilter{ExemptFilter: &exemptYes}, 1},
		{"只看非豁免", AntiCheatFilter{ExemptFilter: &exemptNo}, 3},
		{"关键字命中证据", AntiCheatFilter{Keyword: "90 90 90 90"}, 1},
		{"关键字命中角色", AntiCheatFilter{Keyword: "剑魂"}, 2},
		{"关键字命中账号", AntiCheatFilter{Keyword: "other"}, 1},
		{"时间下界", AntiCheatFilter{Since: 300}, 2},
		{"时间区间（闭区间）", AntiCheatFilter{Since: 200, Until: 300}, 2},
		{"组合：账号+规则+关键字", AntiCheatFilter{Account: "msp", RuleName: "KillTooFast", Keyword: "94ms"}, 1},
		{"无命中", AntiCheatFilter{Account: "nobody"}, 0},
	}
	for _, c := range cases {
		_, total, err := db.QueryAntiCheatDetections(c.f, 10, 0)
		if err != nil {
			t.Fatalf("%s: 查询失败 %v", c.name, err)
		}
		if total != c.want {
			t.Errorf("%s: 期望 %d 条，实际 %d 条", c.name, c.want, total)
		}
	}
}

// TestAntiCheatPagingStable 同一秒内上报的多条记录，翻页不能重复或漏行。
//
// reported_at 只到秒，同一批上报必然撞车；必须补 id 作次序键
// （ORDER BY reported_at DESC, id DESC），否则 SQLite 的返回顺序不保证稳定。
func TestAntiCheatPagingStable(t *testing.T) {
	db := newAntiCheatTestDB(t)
	for i := 0; i < 6; i++ {
		if err := db.InsertAntiCheatDetection(&AntiCheatDetection{
			RuleName: "KillTooFast", EventTimestamp: int64(i), ReportedAt: 500,
			Account: "msp", Evidence: "e",
		}); err != nil {
			t.Fatalf("插入失败: %v", err)
		}
	}

	p1, _, err := db.QueryAntiCheatDetections(AntiCheatFilter{}, 3, 0)
	if err != nil {
		t.Fatalf("第 1 页失败: %v", err)
	}
	p2, _, err := db.QueryAntiCheatDetections(AntiCheatFilter{}, 3, 3)
	if err != nil {
		t.Fatalf("第 2 页失败: %v", err)
	}

	seen := map[int64]bool{}
	for _, d := range append(append([]AntiCheatDetection{}, p1...), p2...) {
		if seen[d.ID] {
			t.Errorf("分页出现重复行 id=%d", d.ID)
		}
		seen[d.ID] = true
	}
	if len(seen) != 6 {
		t.Errorf("两页应覆盖 6 条，实际 %d", len(seen))
	}
}

// TestAntiCheatPlayerSummary 汇总里要能看到账号下出现过的角色。
//
// 空角色名必须被滤掉：同一账号混着老客户端（player_name=''）的行时，
// 汇总不该显示成「有一个没名字的角色」。
func TestAntiCheatPlayerSummary(t *testing.T) {
	db := newAntiCheatTestDB(t)
	seedAntiCheatRows(t, db)

	summaries, total, err := db.GetAntiCheatPlayerSummary(10, 0)
	if err != nil {
		t.Fatalf("汇总失败: %v", err)
	}
	if total != 2 {
		t.Fatalf("应有 2 个账号，实际 %d", total)
	}
	byAcct := map[string]map[string]interface{}{}
	for _, s := range summaries {
		byAcct[s["account"].(string)] = s
	}

	msp := byAcct["msp"]
	if msp == nil {
		t.Fatalf("缺 msp 汇总: %v", summaries)
	}
	players, _ := msp["playerNames"].([]string)
	got := map[string]bool{}
	for _, p := range players {
		got[p] = true
	}
	if !got["剑魂A"] || !got["鬼泣B"] || len(players) != 2 {
		t.Errorf("msp 角色集合不对: %v", players)
	}

	// other 只有一条 player_name='' 的记录 ⇒ 角色列表应为空
	other := byAcct["other"]
	if other == nil {
		t.Fatalf("缺 other 汇总")
	}
	if op, _ := other["playerNames"].([]string); len(op) != 0 {
		t.Errorf("空角色名不该进汇总: %v", op)
	}
}
