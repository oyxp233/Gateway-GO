package httprouter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"s4a21-gateway/pkg/database"
)

// ==================== 活动管理（服务端管理页） ====================
//
// 读写游戏库的 game_event_state / game_event_info_details（见
// pkg/database/events.go）。两条约束贯穿本文件：
//
//  1. **文案按 GBK 字节口径校验**。这两列在库里是 UTF-8，但上线给客户端前
//     会被 Infrastructure/ClientTextEncoding 转成 GBK(936) —— 所以：
//     · 长度要按 GBK 字节数算（一个汉字 2 字节，不是 UTF-8 的 3 字节）；
//     · GBK 编不出来的字符（emoji、日文假名、韩文）必须在这里拒掉，
//     否则客户端收到的是 '?'，而库里却存着一份"看起来正常"的文本。
//  2. **文案进的是单行渲染区域**。现网 2365 的描述用大段空格做居中，
//     没有换行 —— 所以换行符一律拒绝，而不是存进去让客户端自己错位。
//
// 长度上限的取法：没有客户端侧的权威文档，取"比现网最长文案再宽松一截"的值
// （现网最长 = 2365 的描述 ≈ 220 GBK 字节）。宁可在后台明确拒绝，
// 也不要让操作者存进一个"显示成功、游戏里不全"的值。
const (
	maxEventTitleGBK       = 128  // 标题
	maxEventShortNameGBK   = 128  // 简称
	maxEventNoticeGBK      = 256  // 开始/结束公告
	maxEventDescriptionGBK = 2000 // 描述正文
	maxEventSortOrder      = 9999
)

type gameEventToggleRequest struct {
	EventID int  `json:"event_id"`
	Enabled bool `json:"enabled"`
}

type gameEventUpdateRequest struct {
	EventID     int    `json:"event_id"`
	Title       string `json:"title"`
	ShortName   string `json:"short_name"`
	StartNotice string `json:"start_notice"`
	EndNotice   string `json:"end_notice"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`
}

// gbkLength 返回文本在客户端协议上的字节数。
//
// 第二个返回值 false 表示有字符 GBK(936) 编不出来 —— 调用方必须拒绝，
// 因为服务端 ClientTextEncoding 用的是 GBK 编码器，编不出的字符会变成 '?'。
func gbkLength(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	out, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(s))
	if err != nil {
		return 0, false
	}
	return len(out), true
}

// validateEventText 校验单个文案字段，返回规范化后的值。
//
// required 为 true 时不允许为空：标题 / 简称 / 公告为空会让客户端活动列表
// 出现一行没有名字的条目，属于必须挡住的输入错误。描述可以留空
// （detail_flag 仍是 1，客户端会显示一个空详情区）。
//
// keepLayout 必须由调用方显式给出（描述 = true，其余 = false），**不要按
// field 的名字去猜** —— 见 database.NormalizeGameEventText 上的注释，
// 上一版就是"猜名字"猜错了，把描述的排版空格 TrimSpace 掉。
func validateEventText(field, value string, limit int, required, keepLayout bool) (string, error) {
	v := database.NormalizeGameEventText(value, keepLayout)
	if v == "" {
		if required {
			return "", fmt.Errorf("%s不能为空", field)
		}
		return "", nil
	}
	if strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("%s不能含换行：游戏里是单行渲染，需要换行请用空格填充", field)
	}
	n, ok := gbkLength(v)
	if !ok {
		return "", fmt.Errorf("%s含游戏字体编不出的字符（emoji、日文假名等），请改用中文/英文/数字", field)
	}
	if n > limit {
		return "", fmt.Errorf("%s过长：%d 字节，上限 %d 字节（一个汉字算 2 字节）", field, n, limit)
	}
	return v, nil
}

// handleAdminGameEvents 列出活动（开关 + 文案）。
func (s *Server) handleAdminGameEvents(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if !s.db.GameConfigured() {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":              false,
			"game_configured": false,
			"message":         "游戏库未配置（appsettings.json 的 Database.GamePath 为空），活动管理不可用",
		})
		return
	}

	events, err := s.db.ListGameEvents()
	if err != nil {
		s.logger.Error(fmt.Sprintf("[EVENT] 读取活动列表失败: %v", err))
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":              true,
		"game_configured": true,
		"events":          events,
		"defaults":        database.GameEventDefaultsList,
		// 生效时机必须写清楚：开关是服务端每次判定时读库，即时生效；
		// 客户端的活动列表只在**选角进游戏**时下发（CharacterSelectHandler
		// → EventInfoBodyBuilder），所以文案/新增活动要玩家重登才看得到。
		"apply_hint": "开关对服务端判定（计时/领奖判断）即时生效；" +
			"客户端活动列表在玩家选角进游戏时下发，文案改动要玩家重新登录才可见。",
	})
}

// handleAdminGameEventToggle 打开/关闭活动。
func (s *Server) handleAdminGameEventToggle(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req gameEventToggleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "请求格式错误",
		})
		return
	}
	if req.EventID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "活动 ID 非法",
		})
		return
	}

	if err := s.db.SetGameEventEnabled(req.EventID, req.Enabled); err != nil {
		s.logger.Error(fmt.Sprintf("[EVENT] 活动 %d 开关写入失败: %v", req.EventID, err))
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}

	action := "关闭"
	if req.Enabled {
		action = "开启"
	}
	s.logger.Info(fmt.Sprintf("[EVENT] 活动 %d 已%s（操作者 %s）", req.EventID, action, getClientIP(r)))

	event, _ := s.db.GetGameEvent(req.EventID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"message": fmt.Sprintf("活动 %d 已%s", req.EventID, action),
		"event":   event,
	})
}

// handleAdminGameEventUpdate 覆盖活动文案（标题/简称/公告/描述/客户端顺序）。
func (s *Server) handleAdminGameEventUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var req gameEventUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "请求格式错误",
		})
		return
	}
	if req.EventID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "活动 ID 非法",
		})
		return
	}

	title, err := validateEventText("标题", req.Title, maxEventTitleGBK, true, false)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	shortName, err := validateEventText("简称", req.ShortName, maxEventShortNameGBK, true, false)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	startNotice, err := validateEventText("开始公告", req.StartNotice, maxEventNoticeGBK, true, false)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	endNotice, err := validateEventText("结束公告", req.EndNotice, maxEventNoticeGBK, true, false)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	// 描述 keepLayout=true：大段空格是排版，不能 TrimSpace
	description, err := validateEventText("描述", req.Description, maxEventDescriptionGBK, false, true)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	if req.SortOrder < 0 || req.SortOrder > maxEventSortOrder {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false,
			"message": fmt.Sprintf("客户端顺序取值 0~%d（小的排前面；同值时按活动 ID）",
				maxEventSortOrder),
		})
		return
	}

	if err := s.db.UpdateGameEventText(req.EventID, title, shortName,
		startNotice, endNotice, description, req.SortOrder); err != nil {
		s.logger.Error(fmt.Sprintf("[EVENT] 活动 %d 文案更新失败: %v", req.EventID, err))
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}

	s.logger.Info(fmt.Sprintf("[EVENT] 活动 %d 文案已更新（操作者 %s）：title=%q sort=%d",
		req.EventID, getClientIP(r), title, req.SortOrder))

	event, _ := s.db.GetGameEvent(req.EventID)
	// 文案会被服务端重启覆盖的活动，在响应里带一句话 —— 前端据此提示，
	// 不让操作者以为"存住了"。
	warning := ""
	if database.GameEventTextLocked(req.EventID) {
		warning = "该活动的文案由服务端硬编码，重启服务端后会还原（开关不受影响）"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"message": fmt.Sprintf("活动 %d 文案已保存", req.EventID),
		"warning": warning,
		"event":   event,
	})
}
