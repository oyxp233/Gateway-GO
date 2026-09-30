package database

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ─────────────────────────────────────────────────────────────────────────────
// 活动管理（game_event_state / game_event_info_details）
//
// 这两张表由服务端建（SqliteMigrations.cs ApplyGameEventsAndJoust），
// 后台只读写数据。测试 schema 与 161 真库逐列对齐，连 CHECK 约束都照抄 ——
// 少一个约束就会漏掉"后台写进去、服务端读出来才炸"的那类值。
// ─────────────────────────────────────────────────────────────────────────────

func newEventTestDB(t *testing.T) *Database {
	t.Helper()
	gamePath := filepath.Join(t.TempDir(), "inventory.db")

	game, err := openSQLite(gamePath, 5)
	if err != nil {
		t.Fatalf("打开测试游戏库失败: %v", err)
	}
	if _, err := game.Exec(`
		CREATE TABLE game_event_state (
			event_id INTEGER PRIMARY KEY,
			state INTEGER NOT NULL DEFAULT 0 CHECK(state IN (0, 1))
		);
		CREATE TABLE game_event_info_details (
			event_id INTEGER PRIMARY KEY,
			unknown0 INTEGER NOT NULL DEFAULT 0,
			start_notice TEXT NOT NULL DEFAULT '',
			end_notice TEXT NOT NULL DEFAULT '',
			detail_flag INTEGER NOT NULL DEFAULT 0 CHECK(detail_flag IN (0, 1)),
			flag_a INTEGER NOT NULL DEFAULT 0 CHECK(flag_a >= 0 AND flag_a <= 255),
			flag_b INTEGER NOT NULL DEFAULT 0 CHECK(flag_b >= 0 AND flag_b <= 255),
			title TEXT NOT NULL DEFAULT '',
			short_name TEXT NOT NULL DEFAULT '',
			reserved_or_icon TEXT NOT NULL DEFAULT '',
			start_unix_time INTEGER NOT NULL DEFAULT 0,
			end_unix_time INTEGER NOT NULL DEFAULT 0,
			link_key TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			detail_enabled INTEGER NOT NULL DEFAULT 0 CHECK(detail_enabled IN (0, 1)),
			sort_order INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		game.Close()
		t.Fatalf("建测试游戏库 schema 失败: %v", err)
	}

	db := &Database{gameDB: game}
	t.Cleanup(db.Close)
	return db
}

// seedReal161Events 复刻 161 真库里这四行的状态（2026-09-27 实测）：
// 只有 2365 是开着的，另外三个的标题/描述还是服务端写的英文占位串。
func seedReal161Events(t *testing.T, db *Database) {
	t.Helper()
	if _, err := db.gameDB.Exec(`
		INSERT INTO game_event_state(event_id, state) VALUES
			(228, 0), (2208, 0), (2365, 1), (2370, 0);`); err != nil {
		t.Fatalf("插入 game_event_state 失败: %v", err)
	}
	if _, err := db.gameDB.Exec(`
		INSERT INTO game_event_info_details
			(event_id, start_notice, end_notice, detail_flag, flag_a, flag_b,
			 title, short_name, description, detail_enabled, sort_order)
		VALUES
			(228,  'PC room time point event started.', 'PC room time point event ended.',
			 1, 0, 5, 'pcroomtimepoint', 'pcroomtimepoint', 'Online time point rewards.', 1, 20),
			(2208, 'Total attendance event started.', 'Total attendance event ended.',
			 1, 0, 5, 'totalattendanceevent', 'totalattendanceevent', 'Weekly attendance rewards.', 1, 22),
			(2365, '活动 - 正在进行[骑士马战大竞猜]活动！', '活动 - [骑士马战大竞猜]活动已结束！',
			 1, 0, 5, '骑士马战大竞猜', '骑士马战大竞猜', '参与骑士马战竞猜，赢取丰厚奖励', 1, 10),
			(2370, 'Daily attendance event started.', 'Daily attendance event ended.',
			 1, 0, 5, 'dailyattendanceanytimeevent', 'dailyattendanceanytimeevent',
			 'Daily attendance rewards.', 1, 21);`); err != nil {
		t.Fatalf("插入 game_event_info_details 失败: %v", err)
	}
}

func TestListGameEventsMergesStateAndDetails(t *testing.T) {
	db := newEventTestDB(t)
	seedReal161Events(t, db)

	events, err := db.ListGameEvents()
	if err != nil {
		t.Fatalf("ListGameEvents 失败: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("应有 4 个活动，实际 %d 个: %+v", len(events), events)
	}

	// 必须按 event_id 升序 —— 表格顺序不稳会让"刚才改的那行"到处跑。
	for i := 1; i < len(events); i++ {
		if events[i-1].EventID >= events[i].EventID {
			t.Fatalf("未按 event_id 升序: %d 在 %d 前面",
				events[i-1].EventID, events[i].EventID)
		}
	}

	byID := map[int]GameEvent{}
	for _, e := range events {
		byID[e.EventID] = e
	}

	// 开关来自 game_event_state：只有骑士马战是开的
	if !byID[2365].Enabled {
		t.Error("2365 应为开启状态")
	}
	for _, id := range []int{228, 2208, 2370} {
		if byID[id].Enabled {
			t.Errorf("%d 应为关闭状态", id)
		}
	}

	// 文案来自 game_event_info_details：字段不能串行
	joust := byID[2365]
	if joust.Title != "骑士马战大竞猜" ||
		joust.StartNotice != "活动 - 正在进行[骑士马战大竞猜]活动！" ||
		joust.EndNotice != "活动 - [骑士马战大竞猜]活动已结束！" ||
		joust.Description != "参与骑士马战竞猜，赢取丰厚奖励" {
		t.Errorf("2365 文案串行: %+v", joust)
	}
	if joust.SortOrder != 10 {
		t.Errorf("2365 sort_order 应为 10，实际 %d", joust.SortOrder)
	}
	if byID[228].SortOrder != 20 || byID[2370].SortOrder != 21 || byID[2208].SortOrder != 22 {
		t.Errorf("sort_order 串行: 228=%d 2370=%d 2208=%d",
			byID[228].SortOrder, byID[2370].SortOrder, byID[2208].SortOrder)
	}
	for _, e := range events {
		if !e.HasState || !e.HasDetails {
			t.Errorf("活动 %d 应同时有开关与文案: %+v", e.EventID, e)
		}
	}
}

// TestListGameEventsKeepsHalfRows 覆盖两张表只有一边有行的情形。
//
// 服务端只在**启动时**为自己认识的活动补行，所以库里完全可能出现
// "只有开关"（服务端刚INSERT了state就崩）或"只有文案"（手工加过 details）的行 ——
// 这类行必须照样显示出来，否则操作者会遇到"库里明明有、后台看不到"。
func TestListGameEventsKeepsHalfRows(t *testing.T) {
	db := newEventTestDB(t)

	if _, err := db.gameDB.Exec(`
		INSERT INTO game_event_state(event_id, state) VALUES (900, 1);
		INSERT INTO game_event_info_details(event_id, title, short_name, description)
			VALUES (901, '只有文案', '只有文案', '');`); err != nil {
		t.Fatalf("造半行数据失败: %v", err)
	}

	events, err := db.ListGameEvents()
	if err != nil {
		t.Fatalf("ListGameEvents 失败: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("应有 2 行，实际 %d", len(events))
	}

	onlyState, onlyDetails := events[0], events[1]
	if onlyState.EventID != 900 || !onlyState.HasState || onlyState.HasDetails {
		t.Errorf("900 应只有开关: %+v", onlyState)
	}
	if !onlyState.Enabled {
		t.Error("900 的开关值应为开启")
	}
	if onlyDetails.EventID != 901 || onlyDetails.HasState || !onlyDetails.HasDetails {
		t.Errorf("901 应只有文案: %+v", onlyDetails)
	}
	if onlyDetails.Title != "只有文案" {
		t.Errorf("901 标题读错: %q", onlyDetails.Title)
	}
}

// TestSetGameEventEnabledUpserts 是"用 UPSERT 而不是裸 UPDATE"的理由。
//
// 库里还没有该 ID 的 state 行时，裸 UPDATE 会静默改 0 行 ——
// 后台报"保存成功"，游戏里什么都没变。这条断言就是防它。
func TestSetGameEventEnabledUpserts(t *testing.T) {
	db := newEventTestDB(t)
	// 只为 228 造好 state 行，229 故意不建
	if err := db.SetGameEventEnabled(228, true); err != nil {
		t.Fatalf("开启 228 失败: %v", err)
	}
	if err := db.SetGameEventEnabled(229, true); err != nil {
		t.Fatalf("开启 229（库里原本没有该行）失败: %v", err)
	}
	if err := db.SetGameEventEnabled(228, false); err != nil {
		t.Fatalf("关闭 228 失败: %v", err)
	}

	got := map[int]int{}
	rows, err := db.gameDB.Query("SELECT event_id, state FROM game_event_state")
	if err != nil {
		t.Fatalf("回读 game_event_state 失败: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, st int
		if err := rows.Scan(&id, &st); err != nil {
			t.Fatalf("扫描失败: %v", err)
		}
		got[id] = st
	}
	if got[228] != 0 {
		t.Errorf("228 应被关成 0，实际 %d", got[228])
	}
	if got[229] != 1 {
		t.Errorf("229 应被 UPSERT 成 1（裸 UPDATE 会静默失败），实际 %d", got[229])
	}
	if len(got) != 2 {
		t.Errorf("不该多出别的行: %v", got)
	}
}

// TestUpdateGameEventTextWritesUtf8NotGbk 是这批改动里最值钱的一条断言。
//
// game_event_* 的文本列是 **UTF-8 TEXT**：服务端用 Microsoft.Data.Sqlite 按 UTF-8
// 读进 .NET string，再经 Infrastructure/ClientTextEncoding（GBK/936）上线。
// 这与 characters.name 那种「客户端协议字符串 = BLOB + GBK 裸字节」是两回事。
// 后台若按 GBK 写进去，游戏里中文全是乱码 —— 而库里还"看起来"存着一份中文，
// 排查时极易被误导。
func TestUpdateGameEventTextWritesUtf8NotGbk(t *testing.T) {
	db := newEventTestDB(t)
	seedReal161Events(t, db)

	title := "PC端在线累计计时"
	desc := "PC端挂机累计在线时长，领取在线奖励"
	if err := db.UpdateGameEventText(228, title, title, "开始", "结束", desc, 20); err != nil {
		t.Fatalf("更新文案失败: %v", err)
	}

	var rawTitle, rawDesc []byte
	if err := db.gameDB.QueryRow(
		"SELECT title, description FROM game_event_info_details WHERE event_id = 228").
		Scan(&rawTitle, &rawDesc); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if !utf8.Valid(rawTitle) || !utf8.Valid(rawDesc) {
		t.Fatalf("库里存的不是合法 UTF-8：title=% x desc=% x", rawTitle, rawDesc)
	}
	if string(rawTitle) != title || string(rawDesc) != desc {
		t.Fatalf("UTF-8 回读不一致: %q / %q", string(rawTitle), string(rawDesc))
	}

	gbk, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(title))
	if err != nil {
		t.Fatalf("构造 GBK 对照失败: %v", err)
	}
	if string(rawTitle) == string(gbk) {
		t.Fatal("库里存的是 GBK 字节：这两列必须是 UTF-8，否则游戏里中文乱码")
	}

	// updated_at 必须被刷新（后台要能看到"最后改动时间"）
	after, _ := db.GetGameEvent(228)
	if strings.TrimSpace(after.UpdatedAt) == "" {
		t.Error("updated_at 未被刷新")
	}
}

// TestUpdateGameEventTextRefusesMissingRow：库里没有该行时必须报错，
// 而不是 INSERT 出一条缺 detail_flag / 起止时间的半残记录 ——
// 那种行会被服务端读进 EVENT_INFO 包，让客户端活动列表错位。
func TestUpdateGameEventTextRefusesMissingRow(t *testing.T) {
	db := newEventTestDB(t)
	seedReal161Events(t, db)

	err := db.UpdateGameEventText(4242, "x", "x", "s", "e", "d", 0)
	if err == nil {
		t.Fatal("活动不存在时应报错，实际返回 nil")
	}
	if !strings.Contains(err.Error(), "没有活动 4242") {
		t.Errorf("错误信息应说清是『没有这一行』，实际: %v", err)
	}

	var n int
	if err := db.gameDB.QueryRow(
		"SELECT COUNT(*) FROM game_event_info_details WHERE event_id = 4242").Scan(&n); err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("不该代建出 %d 行", n)
	}
}

func TestSetGameEventEnabledRejectsBadID(t *testing.T) {
	db := newEventTestDB(t)
	if err := db.SetGameEventEnabled(0, true); err == nil {
		t.Fatal("event_id=0 应被拒绝")
	}
	if err := db.UpdateGameEventText(-1, "a", "b", "c", "d", "e", 0); err == nil {
		t.Fatal("event_id=-1 应被拒绝")
	}
}

func TestListGameEventsWithoutGameDB(t *testing.T) {
	db := &Database{}
	if _, err := db.ListGameEvents(); err == nil {
		t.Fatal("游戏库未配置时应报错，而不是返回空列表（会被误读成『没有活动』）")
	}
}

// TestNormalizeGameEventTextKeepsDescriptionLayout 保护 description 的排版。
//
// 现网 2365 的描述用大段空格做居中与缩进。统一 TrimSpace 会把排版吃掉，
// 而这类"少几个空格"的回归在界面上几乎看不出来。
//
// ⚠️ 这条测试上一版是**假绿**：它断言的是 NormalizeGameEventText("description", …)
// 而处理器实际传的是中文「描述」→ 函数内部按字段名判断恒为 false，描述照样被
// TrimSpace。测试的措辞和调用点不一致，等于没测（161 实机验收才把它咬出来：
// 209 字符的描述复原后只剩 150）。
// 现在按显式布尔参数断言，并另有一条走 HTTP 处理器的回归
// （httprouter.TestAdminGameEventUpdateKeepsDescriptionLayout）堵这条路。
func TestNormalizeGameEventTextKeepsDescriptionLayout(t *testing.T) {
	padded := "        [骑士马战大竞猜]        "
	if got := NormalizeGameEventText(padded, true); got != padded {
		t.Errorf("keepLayout=true 不该被 TrimSpace: %q", got)
	}
	if got := NormalizeGameEventText("  骑士马战大竞猜  ", false); got != "骑士马战大竞猜" {
		t.Errorf("keepLayout=false 应被去首尾空白: %q", got)
	}
}

// TestGameEventTextLockedOnlyJoust 把"服务端重启会覆盖谁的文案"钉成断言。
//
// 依据：JoustRepository 的 details 用 ON CONFLICT DO UPDATE（覆盖），
// 另外三个用 DO NOTHING（保留）。若将来服务端改了策略，这条会先红，
// 提醒同步改后台的告警文案 —— 而不是留一个骗人的提示。
func TestGameEventTextLockedOnlyJoust(t *testing.T) {
	for _, id := range []int{228, 2208, 2370} {
		if GameEventTextLocked(id) {
			t.Errorf("活动 %d 的文案是持久的，不该标成会被覆盖", id)
		}
	}
	if !GameEventTextLocked(2365) {
		t.Error("2365（骑士马战）的文案会被服务端重启覆盖，必须标出来")
	}
	if GameEventTextLocked(9999) {
		t.Error("未登记的活动不该谎报风险")
	}
}
