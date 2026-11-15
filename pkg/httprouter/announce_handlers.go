package httprouter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/models"
)

// ============================================================================
// 全服公告 —— 传输契约
//
// 三方在这里交汇，任何一个字段名都不许单方面改：
//
//	管理后台(8443)  --/api/admin/announce/*-->  网关 / admin 进程
//	                --/internal/announce/*-->  网关（18080，Admin.InternalKey）
//	游戏服务端插件  --/internal/announce/pull-->  拿配置 + 弹窗队列（热重载）
//	                --/internal/announce/events-> 批量上报通关/未通关/拾取
//	登录器          --/api/launcher/item-ranking--> 三榜（公开只读）
// ============================================================================

// announceMaxEventsPerReport 单次上报的条数上限。
//
// 与服务端插件 plugin.ini 的「上报批量」上限（5000）保持一致：
// 网关这里如果更小，插件按上限发过来就会被整批拒绝并无限重试。
const announceMaxEventsPerReport = 5000

// announceMaxReportBytes 单次上报请求体上限（5 MB）。
// 5000 条拾取事件带装备属性摘要，实际约 1 MB 量级，5 MB 是防御性上界。
const announceMaxReportBytes = 5 << 20

// announcePullPopupLimit 单次 pull 最多取走的弹窗数。
const announcePullPopupLimit = 50

// announcePendingPopupTTLSeconds 弹窗在队列里最多等多久。
//
// 超时未送达即标记 expired：插件（游戏服务端）长时间离线时，
// 一条「10 分钟后维护」的弹窗晚一小时才弹出来是有害的，不如不发。
// 后台的弹窗历史页会把这些显示为「超时未送达」。
const announcePendingPopupTTLSeconds = 900

// announcePullResponse 是给服务端插件的 pull 响应。
type announcePullResponse struct {
	OK         bool                  `json:"ok"`
	ServerTime string                `json:"server_time"`
	Config     models.AnnounceConfig `json:"config"`
	Popups     []announcePullPopup   `json:"popups"`
}

type announcePullPopup struct {
	ID      int64  `json:"id"`
	Message string `json:"message"`
	Mode    int    `json:"mode"`
}

// announceEventsRequest 是插件批量上报的请求体。
type announceEventsRequest struct {
	Events []models.AnnounceEvent `json:"events"`
}

// ============================================================================
// 内部 API（18080，仅网关进程监听）
// ============================================================================

// handleInternalAnnouncePull 供游戏服务端插件拉取"配置 + 弹窗队列"。
//
// 这一次请求同时承担两件事：热重载（换配置快照）与弹窗投递（取走队列）。
// 合成一个接口是有意的：插件的轮询周期就是热重载延迟的上界，
// 拆两条接口会让"配置生效了但弹窗还没拉"这类中间态变成常态。
func (s *Server) handleInternalAnnouncePull(w http.ResponseWriter, r *http.Request) {
	if s.announceSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]interface{}{"ok": false, "message": "公告服务未初始化"})
		return
	}

	cfg := s.announceSvc.Config()

	// ★ popups=0：服务端没有在线玩家时会带这个参数，**不要取走队列**。
	//
	// 网关的 PullPopups 是"拉走即标记 sent"（同事务改状态），一旦取走就再也发不出去。
	// 没有在线玩家时取走 = 运营点了「全服弹窗」、玩家一条都没看到、后台却显示已投递。
	// 带 popups=0 时弹窗留在 pending，等有人上线再取（2026-11-01）。
	var popups []models.AnnouncePopup
	if r.URL.Query().Get("popups") != "0" {
		var err error
		popups, err = s.announceSvc.PullPopups(announcePullPopupLimit, announcePendingPopupTTLSeconds)
		if err != nil {
			// 弹窗取不出来不该拖垮配置下发：公告开关仍然要热重载。
			s.logger.Error(fmt.Sprintf("[Announce] 取弹窗队列失败: %v", err))
			popups = nil
		}
	}

	out := announcePullResponse{
		OK:         true,
		ServerTime: time.Now().UTC().Format(time.RFC3339),
		Config:     cfg,
		Popups:     make([]announcePullPopup, 0, len(popups)),
	}
	for _, p := range popups {
		out.Popups = append(out.Popups, announcePullPopup{ID: p.ID, Message: p.Message, Mode: p.Mode})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleInternalAnnounceEvents 接收插件批量上报的通关/未通关/拾取事件。
//
// 整批一个事务落库；部分成功不返回 200，避免"返回 200 但丢了一半"
// 让插件把没入库的事件当已送达丢弃。
func (s *Server) handleInternalAnnounceEvents(w http.ResponseWriter, r *http.Request) {
	if s.announceSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]interface{}{"ok": false, "message": "公告服务未初始化"})
		return
	}

	var req announceEventsRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, announceMaxReportBytes))
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}
	if len(req.Events) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "accepted": 0})
		return
	}
	if len(req.Events) > announceMaxEventsPerReport {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": fmt.Sprintf("单次上报最多 %d 条，收到 %d 条", announceMaxEventsPerReport, len(req.Events)),
		})
		return
	}

	// 有非法 kind 就整批拒绝：静默丢弃会让后台的分类查询凭空少数据，且无从发现。
	for i := range req.Events {
		if !models.IsValidAnnounceKind(strings.TrimSpace(req.Events[i].Kind)) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"ok":      false,
				"message": fmt.Sprintf("第 %d 条事件的 kind 非法: %q", i+1, req.Events[i].Kind),
			})
			return
		}
	}

	accepted, err := s.announceSvc.IngestEvents(req.Events)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "accepted": accepted})
}

// handleInternalAnnounceConfigGet 供 admin 进程读取网关内存里的配置快照。
func (s *Server) handleInternalAnnounceConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.announce.Config()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "config": cfg})
}

// handleInternalAnnounceConfigSet 供 admin 进程保存并热重载配置。
func (s *Server) handleInternalAnnounceConfigSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config *models.AnnounceConfig `json:"config"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Config == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}
	saved, err := s.announce.UpdateConfig(*body.Config)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "config": saved})
}

// handleInternalAnnouncePopup 供 admin 进程入队一条弹窗公告。
func (s *Server) handleInternalAnnouncePopup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Message   string `json:"message"`
		Mode      *int   `json:"mode"`
		CreatedBy string `json:"created_by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}
	mode := 0
	if body.Mode != nil {
		mode = *body.Mode
	}
	id, err := s.announce.SendPopup(body.Message, mode, body.CreatedBy)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "id": id})
}

// ============================================================================
// 管理后台 API（8443）
// ============================================================================

// handleAdminAnnounceConfigGet 返回当前公告配置（含待投递弹窗数，便于前端提示）。
func (s *Server) handleAdminAnnounceConfigGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	cfg, err := s.announce.Config()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	resp := map[string]interface{}{"ok": true, "config": cfg}
	// pending 数只是页面提示，本地库读得到就带上，读不到不算错。
	if total, err := s.countPendingPopups(); err == nil {
		resp["pending_popups"] = total
	}
	writeJSON(w, http.StatusOK, resp)
}

// countPendingPopups 统计待投递弹窗数。
func (s *Server) countPendingPopups() (int, error) {
	total, _, err := s.db.QueryAnnouncePopups(models.AnnouncePopupPending, 1, 1)
	return total, err
}

// handleAdminAnnounceConfigPost 保存公告配置并热重载（不重启服务端）。
func (s *Server) handleAdminAnnounceConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Config *models.AnnounceConfig `json:"config"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Config == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "请求体缺少 config"})
		return
	}

	saved, err := s.announce.UpdateConfig(*body.Config)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "config": saved,
		// 说清楚"多快生效"，避免运营改完立刻去游戏里看不到变化就以为坏了。
		"message": "已保存并热重载；游戏服务端插件将在其轮询周期内（默认 3 秒）生效，无需重启服务端。",
	})
}

// handleAdminAnnounceEvents 分类查询通关/未通关/拾取事件。
//
// 直读本地库：这是纯历史数据（只追加），两个进程各持句柄读都安全，
// 反而经网关转一圈会让 8443 的可用性依赖 18080。
func (s *Server) handleAdminAnnounceEvents(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	q := r.URL.Query()
	broadcastRaw := strings.TrimSpace(q.Get("broadcast_only"))
	filter := database.AnnounceEventFilter{
		Kind:          strings.TrimSpace(q.Get("kind")),
		Account:       strings.TrimSpace(q.Get("account")),
		CharacterName: strings.TrimSpace(q.Get("character")),
		DungeonName:   strings.TrimSpace(q.Get("dungeon")),
		ItemName:      strings.TrimSpace(q.Get("item")),
		// 旧版三合一关键词 / 最低品级只留兼容，新页面四个框与品级勾选框走独立参数。
		Keyword:       strings.TrimSpace(q.Get("keyword")),
		Rarities:      parseAnnounceRarities(q.Get("rarities")),
		MinRarity:     atoiDefault(q.Get("min_rarity"), 0),
		From:          int64(atoiDefault(q.Get("from"), 0)),
		To:            int64(atoiDefault(q.Get("to"), 0)),
		BroadcastOnly: broadcastRaw == "1" || strings.EqualFold(broadcastRaw, "true"),
		Page:          atoiDefault(q.Get("page"), 1),
		PageSize:      atoiDefault(q.Get("page_size"), 50),
	}

	total, events, err := s.db.QueryAnnounceEvents(filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "total": total, "page": filter.Page, "page_size": filter.PageSize, "events": events,
	})
}

// handleAdminAnnounceStats 返回各类事件的累计条数（页面顶部的概览数字）。
func (s *Server) handleAdminAnnounceStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	stats, err := s.db.AnnounceEventStats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	var pending int
	if total, err := s.countPendingPopups(); err == nil {
		pending = total
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":             true,
		"cleared":        stats[models.AnnounceKindCleared],
		"incomplete":     stats[models.AnnounceKindIncomplete],
		"pickup":         stats[models.AnnounceKindPickup],
		"pending_popups": pending,
	})
}

// handleAdminAnnouncePopups 分页查询弹窗历史。
func (s *Server) handleAdminAnnouncePopups(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	if status != "" && status != models.AnnouncePopupPending &&
		status != models.AnnouncePopupSent && status != models.AnnouncePopupExpired {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "未知的 status"})
		return
	}

	page := atoiDefault(q.Get("page"), 1)
	pageSize := atoiDefault(q.Get("page_size"), 20)
	total, popups, err := s.db.QueryAnnouncePopups(status, page, pageSize)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "total": total, "page": page, "page_size": pageSize, "popups": popups,
	})
}

// handleAdminAnnouncePopupSend 发一条全服弹窗公告。
//
// 弹窗与第 2 条的"滚动公告"是两种封包：这条走 SERVER_NOTICE_MESSAGE（需要玩家点确认），
// 用于「通知玩家更新下线 / 开启活动」这类必须被看见的消息。
func (s *Server) handleAdminAnnouncePopupSend(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Message string `json:"message"`
		Mode    *int   `json:"mode"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "bad json"})
		return
	}
	message := strings.TrimSpace(body.Message)
	if message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "弹窗内容不能为空"})
		return
	}

	mode := 0
	if body.Mode != nil {
		mode = *body.Mode
	}

	id, err := s.announce.SendPopup(message, mode, s.createdByTag(r))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "id": id,
		"message": "已入队。游戏服务端插件下一次轮询（默认 3 秒内）会把弹窗推送给全部在线玩家。",
	})
}

// handleAdminAnnouncePopupDelete 删除一条尚未投递的弹窗。
func (s *Server) handleAdminAnnouncePopupDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "缺少合法的 id"})
		return
	}

	ok, err := s.db.DeleteAnnouncePopup(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	if !ok {
		// 只有两种情况：id 不存在，或者这条早就删过了。
		// 都返回 404 让前端能区分"没删成"和"删掉了"，不再有"状态不对不给删"的 409。
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"ok": false, "message": "记录不存在或已删除",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// createdByTag 记录本次操作来自哪条管理密钥（只留后 6 位，不落全量密钥）。
func (s *Server) createdByTag(r *http.Request) string {
	key := r.Header.Get("X-Auth-Key")
	if key == "" {
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			key = auth[7:]
		}
	}
	if key == "" {
		return "unknown"
	}
	if len(key) <= 6 {
		return "***"
	}
	return "***" + key[len(key)-6:]
}

// ============================================================================
// 登录器公开接口（8080）
// ============================================================================

// handleLauncherItemRanking 返回三个品级榜单（史诗 / 传说 / 神器）。
//
// 公开只读，与 /api/launcher/policy 同级（登录器在登录前就要展示榜单，
// 此时没有 auth_key 可用）。因此这里**只暴露聚合结果**：
// 角色名 + 件数 + 物品名 + 件数，不含账号、IP、时间戳之外的任何账号级信息。
func (s *Server) handleLauncherItemRanking(w http.ResponseWriter, r *http.Request) {
	if s.announceSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]interface{}{"ok": false, "message": "榜单服务未初始化"})
		return
	}

	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 20)
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	// since_days 默认 30 天：榜单要体现"近期活跃"，全量历史会让榜单永远凝固。
	sinceDays := atoiDefault(q.Get("since_days"), 30)
	if sinceDays < 0 || sinceDays > 3650 {
		sinceDays = 30
	}

	rankings, err := s.announceSvc.Rankings(limit, sinceDays)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	// 三个榜单的键直接给出（epic/legend/unique），前端不必再按数组下标猜；
	// 同时保留 rankings 数组，便于以后加档位。
	out := map[string]interface{}{
		"ok":         true,
		"generated":  time.Now().UTC().Format(time.RFC3339),
		"limit":      limit,
		"since_days": sinceDays,
		"rankings":   rankings,
	}
	for _, rk := range rankings {
		out[rk.Tier] = rk
	}
	writeJSON(w, http.StatusOK, out)
}

// parseAnnounceRarities 解析 rarities=3,4,5,6（后台品级勾选框）。
//
// 只接受 database.AnnounceRarityValues 白名单里的四个编号；非法值直接丢弃而不是
// 整页报错 —— 运营手改 URL / 浏览器插件塞了脏参数时，页面仍要能出结果。
// 去重是必要的：重复编号会让 IN(...) 多几个占位符，虽不影响结果但会污染慢查询日志。
func parseAnnounceRarities(raw string) []int {
	out := []int{}
	seen := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || !database.IsValidAnnounceRarity(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// atoiDefault 解析整数查询参数，失败或为空时返回默认值。
func atoiDefault(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}
