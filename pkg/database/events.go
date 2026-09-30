package database

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// ==================== 活动（game_event_*）读写 ====================
//
// 涉及两张**服务端建的表**（DfoServer/Sqlite/SqliteMigrations.cs 的
// ApplyGameEventsAndJoust）：
//
//	game_event_state(event_id, state)              state 0=关 1=开
//	game_event_info_details(event_id, title, short_name,
//	                       start_notice, end_notice, description, sort_order, ...)
//
// 网关/后台侧**只读写数据，绝不改 schema**：建表与迁移是服务端的事。
//
// ⚠️ 编码：这两张表的文本列是 **UTF-8 TEXT**，不是 GBK 裸字节。
// 与 characters.name 那类「客户端协议字符串」（BLOB + GBK）是两回事 ——
// 服务端用 Microsoft.Data.Sqlite 按 UTF-8 读进来，再经
// Infrastructure/ClientTextEncoding（GBK/936）编码后上线给客户端。
// 所以后台写 UTF-8 是对的；写 GBK 会让游戏里显示成乱码。

// GameEvent 管理后台「活动管理」看到的一行：开关 + 文案的合并视图。
//
// HasState / HasDetails 分开给，是因为两张表可能只有一边有行：
// 服务端只在**启动时**为自己认识的活动补行（EnsureStaticConfigRows），
// 所以手工往库里加过的未知 ID，可能只有文案没有开关。
type GameEvent struct {
	EventID int `json:"event_id"`

	Enabled  bool `json:"enabled"`
	HasState bool `json:"has_state"`

	HasDetails  bool   `json:"has_details"`
	Title       string `json:"title"`
	ShortName   string `json:"short_name"`
	StartNotice string `json:"start_notice"`
	EndNotice   string `json:"end_notice"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`

	DetailFlag    bool `json:"detail_flag"`
	DetailEnabled bool `json:"detail_enabled"`

	// UpdatedAt 是 game_event_info_details.updated_at，UTC 文本
	// （"2006-01-02 15:04:05"，**不带时区后缀**）—— 前端要自己补 'Z'，
	// 否则浏览器会当本地时间显示，差 8 小时。
	UpdatedAt string `json:"updated_at"`
}

// GameEventDefaults 一个活动的**推荐文案**（运营给的《活动中文指令》）。
//
// TextLocked / Note 是本功能最反直觉的一点，必须让操作者看到：
//
// 服务端启动时执行 EnsureStaticConfigRows()，四个活动对 details 表的
// 冲突策略**并不一致**：
//
//	PcRoomTimePoint(228) / TotalAttendance(2208) / DailyAttendanceAnytime(2370)
//	    → ON CONFLICT(event_id) DO NOTHING  ⇒ 后台改的文案**能持久**
//	Joust(2365)
//	    → ON CONFLICT(event_id) DO UPDATE，把 title / short_name /
//	      start_notice / end_notice / description / sort_order 六列
//	      按硬编码常量**覆盖回去** ⇒ 后台改完，下次重启服务端就还原
//
// （game_event_state 四张表都是 INSERT OR IGNORE ⇒ **开关改动全部持久**。）
//
// 这里刻意不"补偿"（例如重启后检测并回写）：那会让"服务端配置"和
// "后台配置"两个真源打架，出了问题无从判断谁对。正确做法是**告诉操作者**。
type GameEventDefaults struct {
	EventID     int    `json:"event_id"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	ShortName   string `json:"short_name"`
	StartNotice string `json:"start_notice"`
	EndNotice   string `json:"end_notice"`
	Description string `json:"description"`
	TextLocked  bool   `json:"text_locked"`
	Note        string `json:"note"`
}

// GameEventDefaultsList 是四个已知活动的推荐文案。
//
// 来源：`活动中文指令.txt`（运营给的 UPDATE 语句）。数据库始终是唯一真源 ——
// 这张表只用于后台的「填入推荐文案」按钮，不会自动写库。
var GameEventDefaultsList = []GameEventDefaults{
	{
		EventID:     228,
		Name:        "PC端在线累计计时",
		Title:       "PC端在线累计计时",
		ShortName:   "PC端在线累计计时",
		StartNotice: "活动 - 正在进行[PC端在线累计计时]活动！",
		EndNotice:   "活动 - [PC端在线累计计时]活动已结束！",
		Description: "PC端挂机累计在线时长，领取在线奖励",
	},
	{
		EventID:     2208,
		Name:        "勇者之梦签到",
		Title:       "勇者之梦签到",
		ShortName:   "勇者之梦签到",
		StartNotice: "活动 - 正在进行[勇者之梦签到]活动！",
		EndNotice:   "活动 - [勇者之梦签到]活动已结束！",
		Description: "每周通关推荐地下城完成签到，获取活动奖励，活动不定期开放",
	},
	{
		EventID:     2365,
		Name:        "骑士马战大竞猜",
		Title:       "骑士马战大竞猜",
		ShortName:   "骑士马战大竞猜",
		StartNotice: "活动 - 正在进行[骑士马战大竞猜]活动！",
		EndNotice:   "活动 - [骑士马战大竞猜]活动已结束！",
		Description: "参与骑士马战竞猜，赢取丰厚奖励",
		TextLocked:  true,
		Note: "标题/简称/开始公告/结束公告/描述/客户端顺序由服务端硬编码" +
			"（JoustRepository 的 ON CONFLICT DO UPDATE），每次重启服务端都会被覆盖回原值；" +
			"开关不受影响，是持久的",
	},
	{
		EventID:     2370,
		Name:        "每日签到",
		Title:       "每日签到",
		ShortName:   "每日签到",
		StartNotice: "活动 - 正在进行[每日签到]活动！",
		EndNotice:   "活动 - [每日签到]活动已结束！",
		Description: "每日登录游戏完成签到，领取签到福利奖励",
	},
}

// ListGameEvents 合并读取活动开关与文案，按 event_id 升序返回。
//
// 用两条查询在 Go 里合并，而不是写一条 FULL OUTER JOIN：
// 表只有几行，两次查询的成本可以忽略，但代码一眼能看懂哪一列来自哪张表。
func (db *Database) ListGameEvents() ([]GameEvent, error) {
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置（appsettings.json 的 Database.GamePath 为空）")
	}

	byID := make(map[int]*GameEvent)

	stateRows, err := db.gameDB.Query(
		"SELECT event_id, state FROM game_event_state")
	if err != nil {
		return nil, fmt.Errorf("读取 game_event_state 失败: %w", err)
	}
	for stateRows.Next() {
		var id, state int
		if err := stateRows.Scan(&id, &state); err != nil {
			stateRows.Close()
			return nil, fmt.Errorf("扫描 game_event_state 失败: %w", err)
		}
		byID[id] = &GameEvent{
			EventID:  id,
			Enabled:  state != 0,
			HasState: true,
		}
	}
	stateRows.Close()
	if err := stateRows.Err(); err != nil {
		return nil, fmt.Errorf("遍历 game_event_state 失败: %w", err)
	}

	detailRows, err := db.gameDB.Query(`
		SELECT event_id, title, short_name, start_notice, end_notice,
		       description, detail_flag, detail_enabled, sort_order,
		       IFNULL(updated_at, '')
		  FROM game_event_info_details`)
	if err != nil {
		return nil, fmt.Errorf("读取 game_event_info_details 失败: %w", err)
	}
	for detailRows.Next() {
		var (
			id          int
			title       string
			shortName   string
			startNotice string
			endNotice   string
			description string
			detailFlag  int
			detailOn    int
			sortOrder   int
			updatedAt   string
		)
		if err := detailRows.Scan(&id, &title, &shortName, &startNotice,
			&endNotice, &description, &detailFlag, &detailOn,
			&sortOrder, &updatedAt); err != nil {
			detailRows.Close()
			return nil, fmt.Errorf("扫描 game_event_info_details 失败: %w", err)
		}
		e := byID[id]
		if e == nil {
			e = &GameEvent{EventID: id}
			byID[id] = e
		}
		e.HasDetails = true
		e.Title = title
		e.ShortName = shortName
		e.StartNotice = startNotice
		e.EndNotice = endNotice
		e.Description = description
		e.DetailFlag = detailFlag != 0
		e.DetailEnabled = detailOn != 0
		e.SortOrder = sortOrder
		e.UpdatedAt = updatedAt
	}
	detailRows.Close()
	if err := detailRows.Err(); err != nil {
		return nil, fmt.Errorf("遍历 game_event_info_details 失败: %w", err)
	}

	out := make([]GameEvent, 0, len(byID))
	for _, e := range byID {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	return out, nil
}

// SetGameEventEnabled 打开/关闭活动，写 game_event_state.state。
//
// 用 UPSERT 而不是裸 UPDATE：服务端只在启动时为自己认识的活动补行，
// 若某个 ID 还没有 state 行，裸 UPDATE 会**静默改 0 行** ——
// 后台看起来"保存成功"，游戏里却什么都没变。UPSERT 保证结果符合预期。
func (db *Database) SetGameEventEnabled(eventID int, enabled bool) error {
	if !db.GameConfigured() {
		return fmt.Errorf("游戏库未配置（appsettings.json 的 Database.GamePath 为空）")
	}
	if eventID <= 0 {
		return fmt.Errorf("活动 ID 非法: %d", eventID)
	}

	state := 0
	if enabled {
		state = 1
	}
	if _, err := db.gameDB.Exec(`
		INSERT INTO game_event_state(event_id, state) VALUES(?, ?)
		ON CONFLICT(event_id) DO UPDATE SET state = excluded.state`,
		eventID, state); err != nil {
		return fmt.Errorf("写 game_event_state 失败: %w", err)
	}
	return nil
}

// UpdateGameEventText 覆盖活动文案，写 game_event_info_details。
//
// **只 UPDATE，不 INSERT**：库里没有这一行时应当明确报错，而不是凭空造一条
// 只有文案、缺少 detail_flag / 起止时间等结构字段的半残记录 ——
// 那种行被服务端读出去会让客户端活动列表错位，且很难排查。
// 需要新增活动时，正确做法是改服务端配置（EnsureStaticConfigRows 会补行）。
func (db *Database) UpdateGameEventText(eventID int, title, shortName,
	startNotice, endNotice, description string, sortOrder int) error {
	if !db.GameConfigured() {
		return fmt.Errorf("游戏库未配置（appsettings.json 的 Database.GamePath 为空）")
	}
	if eventID <= 0 {
		return fmt.Errorf("活动 ID 非法: %d", eventID)
	}

	res, err := db.gameDB.Exec(`
		UPDATE game_event_info_details
		   SET title = ?, short_name = ?, start_notice = ?, end_notice = ?,
		       description = ?, sort_order = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE event_id = ?`,
		title, shortName, startNotice, endNotice, description, sortOrder, eventID)
	if err != nil {
		return fmt.Errorf("更新活动文案失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("游戏库里没有活动 %d 的文案行"+
			"（game_event_info_details 无此 event_id；新增活动要改服务端配置，后台不代建）", eventID)
	}
	return nil
}

// GetGameEvent 读取单个活动（供处理器在写前做存在性判断与回显）。
func (db *Database) GetGameEvent(eventID int) (*GameEvent, error) {
	if !db.GameConfigured() {
		return nil, fmt.Errorf("游戏库未配置")
	}
	var e GameEvent
	e.EventID = eventID

	var state sql.NullInt64
	if err := db.gameDB.QueryRow(
		"SELECT state FROM game_event_state WHERE event_id = ?", eventID).
		Scan(&state); err == nil {
		e.HasState = true
		e.Enabled = state.Int64 != 0
	} else if err != sql.ErrNoRows {
		return nil, fmt.Errorf("读取活动开关失败: %w", err)
	}

	var detailFlag, detailOn sql.NullInt64
	var title, shortName, startNotice, endNotice, description, updatedAt sql.NullString
	var sortOrder sql.NullInt64
	err := db.gameDB.QueryRow(`
		SELECT title, short_name, start_notice, end_notice, description,
		       detail_flag, detail_enabled, sort_order, IFNULL(updated_at, '')
		  FROM game_event_info_details WHERE event_id = ?`, eventID).
		Scan(&title, &shortName, &startNotice, &endNotice, &description,
			&detailFlag, &detailOn, &sortOrder, &updatedAt)
	if err == nil {
		e.HasDetails = true
		e.Title = title.String
		e.ShortName = shortName.String
		e.StartNotice = startNotice.String
		e.EndNotice = endNotice.String
		e.Description = description.String
		e.DetailFlag = detailFlag.Int64 != 0
		e.DetailEnabled = detailOn.Int64 != 0
		e.SortOrder = int(sortOrder.Int64)
		e.UpdatedAt = updatedAt.String
	} else if err != sql.ErrNoRows {
		return nil, fmt.Errorf("读取活动文案失败: %w", err)
	}

	if !e.HasState && !e.HasDetails {
		return nil, nil
	}
	return &e, nil
}

// FindGameEventDefault 按 ID 取推荐文案。
func FindGameEventDefault(eventID int) *GameEventDefaults {
	for i := range GameEventDefaultsList {
		if GameEventDefaultsList[i].EventID == eventID {
			return &GameEventDefaultsList[i]
		}
	}
	return nil
}

// GameEventTextLocked 判断该活动的文案是否会被服务端重启覆盖。
//
// 依据是服务端各 Repository 的冲突策略（见 GameEventDefaults 的注释）。
// 未登记在 GameEventDefaultsList 里的 ID 一律按"不锁定"处理：没有证据说它会
// 被覆盖，就不该对操作者谎报风险。
func GameEventTextLocked(eventID int) bool {
	d := FindGameEventDefault(eventID)
	return d != nil && d.TextLocked
}

// NormalizeGameEventText 按 keepLayout 决定去不去首尾空白。
//
//	keepLayout=true  描述：排版文本（现网 2365 的描述用大段空格做居中与缩进），原样返回
//	keepLayout=false 标题 / 简称 / 公告：单行短文本，首尾空白无意义，去干净
//
// ⚠️ 这里原来是按**字段名**判断的（strings.EqualFold(field, "description")），
// 而处理器传进来的字段名是中文「描述」→ 判定恒为 false → 描述落进 TrimSpace 分支，
// 2365 描述的 15 个前导空格 + 44 个尾随空格被吃掉（209 字符 → 150 字符）。
// 界面上只是"少几个空格"，几乎看不出来；而当时的单测传的是英文名 "description"，
// 所以一路绿灯 —— 测试和真实调用点措辞不一致，等于没测。
//
// 教训：别拿自然语言的名字做逻辑分支（等于把正确性绑在调用方的措辞上）。
// 现在改成显式布尔参数，调用点一眼能看出"这个字段要不要保排版"。
func NormalizeGameEventText(value string, keepLayout bool) string {
	if keepLayout {
		return value
	}
	return strings.TrimSpace(value)
}
