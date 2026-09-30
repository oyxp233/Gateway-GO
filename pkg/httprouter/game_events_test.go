package httprouter

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────────────────────────────────────
// 活动管理 HTTP 层（/api/admin/game-events*）
//
// 这一层要挡住的东西比读写层更"人为"：漏鉴权、ID 写反、把游戏渲染不出来的
// 字符存进库。所以测试重点是**拒绝路径**，不是 happy path。
// ─────────────────────────────────────────────────────────────────────────────

const testAdminKey = "test-admin-key"

func newGameEventTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	gwPath := filepath.Join(dir, "gateway.db")
	gamePath := filepath.Join(dir, "inventory.db")

	game, err := sql.Open("sqlite", gamePath)
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
			start_notice TEXT NOT NULL DEFAULT '',
			end_notice TEXT NOT NULL DEFAULT '',
			detail_flag INTEGER NOT NULL DEFAULT 0,
			flag_a INTEGER NOT NULL DEFAULT 0,
			flag_b INTEGER NOT NULL DEFAULT 0,
			title TEXT NOT NULL DEFAULT '',
			short_name TEXT NOT NULL DEFAULT '',
			reserved_or_icon TEXT NOT NULL DEFAULT '',
			start_unix_time INTEGER NOT NULL DEFAULT 0,
			end_unix_time INTEGER NOT NULL DEFAULT 0,
			link_key TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			detail_enabled INTEGER NOT NULL DEFAULT 0,
			sort_order INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			unknown0 INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO game_event_state(event_id, state) VALUES (228, 0), (2365, 1);
		INSERT INTO game_event_info_details
			(event_id, start_notice, end_notice, detail_flag, flag_a, flag_b,
			 title, short_name, description, detail_enabled, sort_order)
		VALUES
			(228, 's', 'e', 1, 0, 5, 'pcroomtimepoint', 'pcroomtimepoint', 'd', 1, 20),
			(2365, '活动 - 正在进行[骑士马战大竞猜]活动！', '活动 - [骑士马战大竞猜]活动已结束！',
			 1, 0, 5, '骑士马战大竞猜', '骑士马战大竞猜', '规则', 1, 10);`); err != nil {
		game.Close()
		t.Fatalf("建测试游戏库失败: %v", err)
	}
	game.Close()

	db, err := database.NewDatabase(database.DatabaseConfig{
		Path: gwPath, GamePath: gamePath, BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(db.Close)

	lg, err := logger.NewConsoleLogger(filepath.Join(dir, "logs"), logger.Info)
	if err != nil {
		t.Fatalf("建测试日志失败: %v", err)
	}
	t.Cleanup(lg.Close)

	cfg := &config.GatewayConfig{}
	cfg.Admin.AuthKey = testAdminKey

	return &Server{config: cfg, logger: lg, db: db}
}

// callHandler 直接调处理器，不起 HTTP 服务 —— 测的是参数校验与写库，
// 中间件（限流/端口分流）另有 drain_test.go / 真机验收覆盖。
func callHandler(t *testing.T, s *Server, handler http.HandlerFunc,
	method, body string, withKey bool) (int, map[string]interface{}) {
	t.Helper()

	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "/api/admin/game-events", nil)
	} else {
		req = httptest.NewRequest(method, "/api/admin/game-events", bytes.NewBufferString(body))
	}
	req.RemoteAddr = "127.0.0.1:45678"
	if withKey {
		req.Header.Set("X-Auth-Key", testAdminKey)
	}

	rec := httptest.NewRecorder()
	handler(rec, req)

	var payload map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	return rec.Code, payload
}

// TestAdminGameEventsRequiresAuth：三个接口都不能漏鉴权。
// 这些接口能改线上活动的开关与文案，未鉴权等于把运营后台开门。
func TestAdminGameEventsRequiresAuth(t *testing.T) {
	s := newGameEventTestServer(t)

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
	}{
		{"列表", s.handleAdminGameEvents, "GET", ""},
		{"开关", s.handleAdminGameEventToggle, "POST", `{"event_id":228,"enabled":true}`},
		{"文案", s.handleAdminGameEventUpdate, "POST",
			`{"event_id":228,"title":"t","short_name":"t","start_notice":"s","end_notice":"e","description":"d"}`},
	}
	for _, c := range cases {
		code, _ := callHandler(t, s, c.handler, c.method, c.body, false)
		if code != http.StatusUnauthorized {
			t.Errorf("%s：无密钥应回 401，实际 %d", c.name, code)
		}
	}
}

func TestAdminGameEventsListsWithDefaults(t *testing.T) {
	s := newGameEventTestServer(t)

	code, body := callHandler(t, s, s.handleAdminGameEvents, "GET", "", true)
	if code != http.StatusOK {
		t.Fatalf("应回 200，实际 %d（%v）", code, body)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("ok 应为 true: %v", body)
	}
	events, _ := body["events"].([]interface{})
	if len(events) != 2 {
		t.Fatalf("应有 2 个活动，实际 %d", len(events))
	}
	defaults, _ := body["defaults"].([]interface{})
	if len(defaults) != 4 {
		t.Errorf("推荐文案应有 4 条（228/2208/2365/2370），实际 %d", len(defaults))
	}
	if strings.TrimSpace(body["apply_hint"].(string)) == "" {
		t.Error("apply_hint 不能为空：生效时机必须明确告诉操作者")
	}
	if body["game_configured"] != true {
		t.Error("game_configured 应为 true")
	}
}

func TestAdminGameEventToggleWritesState(t *testing.T) {
	s := newGameEventTestServer(t)

	code, body := callHandler(t, s, s.handleAdminGameEventToggle, "POST",
		`{"event_id":228,"enabled":true}`, true)
	if code != http.StatusOK {
		t.Fatalf("应回 200，实际 %d（%v）", code, body)
	}

	ev, err := s.db.GetGameEvent(228)
	if err != nil || ev == nil {
		t.Fatalf("回读活动失败: %v / %v", ev, err)
	}
	if !ev.Enabled {
		t.Fatal("228 应已被开启")
	}

	// 关回去
	if code, body = callHandler(t, s, s.handleAdminGameEventToggle, "POST",
		`{"event_id":228,"enabled":false}`, true); code != http.StatusOK {
		t.Fatalf("关闭应回 200，实际 %d（%v）", code, body)
	}
	if ev, _ = s.db.GetGameEvent(228); ev.Enabled {
		t.Fatal("228 应已被关闭")
	}
}

func TestAdminGameEventToggleRejectsBadID(t *testing.T) {
	s := newGameEventTestServer(t)

	for _, body := range []string{`{"event_id":0,"enabled":true}`, `{"event_id":-3,"enabled":true}`} {
		code, payload := callHandler(t, s, s.handleAdminGameEventToggle, "POST", body, true)
		if code != http.StatusBadRequest {
			t.Errorf("%s 应回 400，实际 %d（%v）", body, code, payload)
		}
	}

	// 请求体不是 JSON 也必须 400，不能把零值当"ID=0"往下走
	if code, _ := callHandler(t, s, s.handleAdminGameEventToggle, "POST", `not-json`, true); code != http.StatusBadRequest {
		t.Errorf("坏 JSON 应回 400，实际 %d", code)
	}
}

func TestAdminGameEventUpdateSavesText(t *testing.T) {
	s := newGameEventTestServer(t)

	payload := `{"event_id":228,"title":"PC端在线累计计时","short_name":"在线计时",` +
		`"start_notice":"活动 - 正在进行[PC端在线累计计时]活动！",` +
		`"end_notice":"活动 - [PC端在线累计计时]活动已结束！",` +
		`"description":"PC端挂机累计在线时长，领取在线奖励","sort_order":25}`
	code, body := callHandler(t, s, s.handleAdminGameEventUpdate, "POST", payload, true)
	if code != http.StatusOK {
		t.Fatalf("应回 200，实际 %d（%v）", code, body)
	}
	if w, _ := body["warning"].(string); w != "" {
		t.Errorf("228 的文案是持久的，不该带覆盖告警：%q", w)
	}

	ev, err := s.db.GetGameEvent(228)
	if err != nil || ev == nil {
		t.Fatalf("回读失败: %v / %v", ev, err)
	}
	if ev.Title != "PC端在线累计计时" || ev.ShortName != "在线计时" ||
		ev.SortOrder != 25 || ev.Description != "PC端挂机累计在线时长，领取在线奖励" {
		t.Fatalf("文案未按预期落库: %+v", ev)
	}
}

// TestAdminGameEventUpdateKeepsDescriptionLayout：描述里的空格是排版，不能被吞。
//
// 这条是 161 实机验收咬出来的回归。上一版 httprouter 把字段名「描述」交给
// database.NormalizeGameEventText，而那个函数按**英文字段名**判断该不该 TrimSpace →
// 判定恒为 false → 带排版的描述（现网 2365：15 个前导空格 + 44 个尾随空格，
// 共 209 字符）存回库只剩 150 字符。
//
// 单测当时是绿的，因为它传的是英文 "description" —— 测试的措辞和真实调用点
// 不一致。所以这条**故意走 HTTP 处理器**（真实调用点），并用首尾带空格的
// 值做输入，凡"按名字猜字段类型"的写法都会被它逮住。
func TestAdminGameEventUpdateKeepsDescriptionLayout(t *testing.T) {
	s := newGameEventTestServer(t)

	padded := "     [骑士马战大竞猜]     *规则：    -倍率随动。    "
	payload, err := json.Marshal(map[string]interface{}{
		"event_id": 2365, "title": "骑士马战大竞猜", "short_name": "骑士马战大竞猜",
		"start_notice": "a", "end_notice": "b",
		"description": padded, "sort_order": 10,
	})
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	code, body := callHandler(t, s, s.handleAdminGameEventUpdate, "POST", string(payload), true)
	if code != http.StatusOK {
		t.Fatalf("应回 200，实际 %d（%v）", code, body)
	}

	ev, err := s.db.GetGameEvent(2365)
	if err != nil || ev == nil {
		t.Fatalf("回读失败: %v / %v", ev, err)
	}
	if ev.Description != padded {
		t.Fatalf("描述的排版空格被改动了：\n  存入 %d 字符 %q\n  读回 %d 字符 %q",
			len(padded), padded, len(ev.Description), ev.Description)
	}

	// 标题这类单行短文本反过来：首尾空白要去掉（免得列表里出现带空格的怪名字）。
	payload, _ = json.Marshal(map[string]interface{}{
		"event_id": 2365, "title": "  骑士马战大竞猜  ", "short_name": "骑士马战大竞猜",
		"start_notice": "a", "end_notice": "b", "description": "", "sort_order": 10,
	})
	if code, body := callHandler(t, s, s.handleAdminGameEventUpdate, "POST", string(payload), true); code != http.StatusOK {
		t.Fatalf("应回 200，实际 %d（%v）", code, body)
	}
	ev, _ = s.db.GetGameEvent(2365)
	if ev.Title != "骑士马战大竞猜" {
		t.Fatalf("标题该被去首尾空白，实际 %q", ev.Title)
	}
}

// TestAdminGameEventUpdateWarnsJoustLocked：2365 的文案会被服务端重启覆盖，
// 保存必须**当场**告诉操作者 —— 否则这就是一个"改了没报错、过几天自己变回去"的坑。
func TestAdminGameEventUpdateWarnsJoustLocked(t *testing.T) {
	s := newGameEventTestServer(t)

	payload := `{"event_id":2365,"title":"骑士马战大竞猜","short_name":"骑士马战大竞猜",` +
		`"start_notice":"a","end_notice":"b","description":"参与骑士马战竞猜，赢取丰厚奖励","sort_order":10}`
	code, body := callHandler(t, s, s.handleAdminGameEventUpdate, "POST", payload, true)
	if code != http.StatusOK {
		t.Fatalf("应回 200，实际 %d（%v）", code, body)
	}
	w, _ := body["warning"].(string)
	if !strings.Contains(w, "重启") {
		t.Fatalf("2365 保存后必须带『重启会还原』的告警，实际: %q", w)
	}
}

// TestAdminGameEventUpdateValidatesInput 把闸门逐条钉住。
//
// 这些边界都是"存进去不报错、游戏里才出问题"的类型：
// 空标题 → 客户端一行没名字；换行 → 单行区域错位；
// emoji/日文 → 服务端 ClientTextEncoding 用 GBK 编，上线变成 '?'。
func TestAdminGameEventUpdateValidatesInput(t *testing.T) {
	longTitle := strings.Repeat("字", 70) // 70 汉字 = 140 GBK 字节 > 128

	cases := []struct {
		name     string
		body     string
		wantCode int
		wantMsg  string
	}{
		{
			name: "标题为空",
			body: `{"event_id":228,"title":"  ","short_name":"s",` +
				`"start_notice":"a","end_notice":"b","description":"d"}`,
			wantCode: http.StatusBadRequest, wantMsg: "标题不能为空",
		},
		{
			name: "描述含换行",
			body: `{"event_id":228,"title":"t","short_name":"s",` +
				`"start_notice":"a","end_notice":"b","description":"第一行\n第二行"}`,
			wantCode: http.StatusBadRequest, wantMsg: "不能含换行",
		},
		{
			name: "标题含 emoji",
			body: `{"event_id":228,"title":"在线计时😀","short_name":"s",` +
				`"start_notice":"a","end_notice":"b","description":"d"}`,
			wantCode: http.StatusBadRequest, wantMsg: "编不出的字符",
		},
		{
			name: "标题超长（按 GBK 字节算）",
			body: `{"event_id":228,"title":"` + longTitle + `","short_name":"s",` +
				`"start_notice":"a","end_notice":"b","description":"d"}`,
			wantCode: http.StatusBadRequest, wantMsg: "标题过长",
		},
		{
			name: "客户端顺序越界",
			body: `{"event_id":228,"title":"t","short_name":"s",` +
				`"start_notice":"a","end_notice":"b","description":"d","sort_order":10000}`,
			wantCode: http.StatusBadRequest, wantMsg: "客户端顺序",
		},
		{
			name: "活动不存在（不代建行）",
			body: `{"event_id":777,"title":"t","short_name":"s",` +
				`"start_notice":"a","end_notice":"b","description":"d"}`,
			wantCode: http.StatusInternalServerError, wantMsg: "没有活动 777",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newGameEventTestServer(t)
			code, body := callHandler(t, s, s.handleAdminGameEventUpdate, "POST", c.body, true)
			if code != c.wantCode {
				t.Fatalf("应回 %d，实际 %d（%v）", c.wantCode, code, body)
			}
			msg, _ := body["message"].(string)
			if !strings.Contains(msg, c.wantMsg) {
				t.Fatalf("错误信息应含 %q，实际 %q", c.wantMsg, msg)
			}
		})
	}
}

// TestAdminGameEventUpdateUsesGbkByteBudget 钉住长度单位：**GBK 字节**，不是 UTF-8 字节。
//
// 标题上限 128 字节下：64 个汉字 = 128 GBK 字节（刚好过关），
// 但同一串在 UTF-8 下是 192 字节。谁把口径写成 len([]byte(v))，
// 这条就会红 —— 而症状是"运营明明没超长，后台就是不让存"，很难反查。
func TestAdminGameEventUpdateUsesGbkByteBudget(t *testing.T) {
	build := func(title string) string {
		return `{"event_id":228,"title":"` + title + `","short_name":"s",` +
			`"start_notice":"a","end_notice":"b","description":"d"}`
	}
	if len([]byte(strings.Repeat("字", 64))) <= 128 {
		t.Fatal("测试前提不成立：64 个汉字的 UTF-8 字节数应大于 128，否则这条断言没有区分力")
	}

	s := newGameEventTestServer(t)
	if code, body := callHandler(t, s, s.handleAdminGameEventUpdate, "POST",
		build(strings.Repeat("字", 64)), true); code != http.StatusOK {
		t.Fatalf("64 个汉字 = 128 GBK 字节，刚好在上限内，应回 200，实际 %d（%v）", code, body)
	}

	s2 := newGameEventTestServer(t)
	code, body := callHandler(t, s2, s2.handleAdminGameEventUpdate, "POST",
		build(strings.Repeat("字", 65)), true)
	if code != http.StatusBadRequest {
		t.Fatalf("65 个汉字 = 130 GBK 字节，超出 128，应回 400，实际 %d（%v）", code, body)
	}
}

// TestAdminGameEventUpdateAcceptsFullWidthText 是上面闸门的**对照组**：
// 全是中文的正常文案必须放得进去，否则闸门就成了"谁都过不了"的摆设。
func TestAdminGameEventUpdateAcceptsFullWidthText(t *testing.T) {
	s := newGameEventTestServer(t)

	body := `{"event_id":228,"title":"PC端在线累计计时","short_name":"PC端在线累计计时",` +
		`"start_notice":"活动 - 正在进行[PC端在线累计计时]活动！",` +
		`"end_notice":"活动 - [PC端在线累计计时]活动已结束！",` +
		`"description":"PC端挂机累计在线时长，领取在线奖励","sort_order":20}`
	code, payload := callHandler(t, s, s.handleAdminGameEventUpdate, "POST", body, true)
	if code != http.StatusOK {
		t.Fatalf("正常中文文案应回 200，实际 %d（%v）", code, payload)
	}
	if msg, _ := payload["message"].(string); !strings.Contains(msg, "已保存") {
		t.Errorf("成功信息异常: %q", msg)
	}
}
