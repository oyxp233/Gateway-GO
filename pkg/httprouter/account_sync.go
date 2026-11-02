package httprouter

// ============================================================================
// 账号事件同步（三服合一，2026-10-24）
//
// 见评估-三服合一登录器-20261023.md 第五章：
//
// 主网关是账号主权方（accounts 表 + account_events 流水），
// 从网关按 id 增量拉取事件，应用到本地副本。
//
// 内部 API（只绑 loopback，X-Internal-Key 鉴权）：
//
//	GET /internal/account/events?since=<id>&limit=<n>   拉取事件流
//
// ★ 只同步"身份 + 封禁"，不同步密码哈希（S4A21 是 MD5、S5A3 是 bcrypt，
//   两种凭据不可互换 —— 这是评估文档第五章的硬约束）。
// ============================================================================

import (
	"net/http"
	"strconv"
	"strings"

	"s4a21-gateway/pkg/database"
)

// AccountEventsResponse 是 GET /internal/account/events 的响应体。
type AccountEventsResponse struct {
	OK     bool                   `json:"ok"`
	Events []database.AccountEvent `json:"events"`
	// MaxID 是本批事件里最大的 id，调用方下次用 since=MaxID 继续拉。
	// 没有事件时 = since 原值。
	MaxID int64 `json:"max_id"`
}

// handleInternalAccountEvents 返回 id > since 的账号事件（增量同步用）。
//
// 从网关定时调用（默认 60 秒），拉到的全局封禁/解封事件应用到本地。
func (s *Server) handleInternalAccountEvents(w http.ResponseWriter, r *http.Request) {
	sinceStr := r.URL.Query().Get("since")
	since, _ := strconv.ParseInt(sinceStr, 10, 64)

	limitStr := r.URL.Query().Get("limit")
	limit, _ := strconv.Atoi(limitStr)

	events, err := s.db.AccountEventsSince(since, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}

	maxID := since
	for _, e := range events {
		if e.ID > maxID {
			maxID = e.ID
		}
	}

	writeJSON(w, http.StatusOK, AccountEventsResponse{
		OK:     true,
		Events: events,
		MaxID:  maxID,
	})
}

// AccountCredentialResponse 是 GET /internal/account/credential 的响应体。
//
// ★ 这是"注册一次、三服都能登"的关键一环（评估文档 5.4）：
//   从网关本地查不到账号时，向主网关反查**凭据本身**（pwd_hash + salt + m_id），
//   本地用同一套算法验密 → 验过就懒建本地副本，后续登录走本地路径。
//
// 只反查凭据而不只是"确认存在"：确认存在没用 —— 本地没有 pwd_hash 仍然验不了密，
// 玩家照样登不进。必须拿到哈希才能验。
//
// 安全边界：这个接口只在内部端口（默认只绑 loopback）且要 X-Internal-Key。
// 网关之间是同一运营方的可信内网，所以可以传哈希（不是明文密码）。
type AccountCredentialResponse struct {
	OK bool `json:"ok"`
	// Exists 账号在主网关是否存在。
	Exists bool `json:"exists"`
	// PwdHash / Salt / MId 只在 Exists=true 时有值。
	PwdHash string `json:"pwd_hash,omitempty"`
	Salt    string `json:"salt,omitempty"`
	MId     string `json:"m_id,omitempty"`
}

// handleInternalAccountCredential 供从网关反查账号凭据。
//
// 只返回 pwd_hash / salt / m_id，**不返回**点券、设备绑定等其它字段 ——
// 从网关懒建时只需要"能验密 + 能对上游戏库角色"这三样。
func (s *Server) handleInternalAccountCredential(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "name 不能为空"})
		return
	}

	acc, err := s.db.GetAccountByName(name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	if acc == nil {
		// 不存在是**正常结果**，不是错误 —— 用 200 + exists=false，
		// 让从网关的判定逻辑只有一条分支。
		writeJSON(w, http.StatusOK, AccountCredentialResponse{OK: true, Exists: false})
		return
	}

	writeJSON(w, http.StatusOK, AccountCredentialResponse{
		OK:      true,
		Exists:  true,
		PwdHash: acc.PwdHash,
		Salt:    acc.Salt,
		MId:     acc.MId,
	})
}
