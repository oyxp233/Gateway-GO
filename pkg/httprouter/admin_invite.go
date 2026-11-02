package httprouter

// ============================================================================
// 邀请码管理 API（2026-10-24）
//
// 后台接口（8443，checkAdmin 鉴权）：
//
//	POST /api/admin/invite/generate  批量生成
//	GET  /api/admin/invite/list      分页列表（状态筛选 + 关键词）
//	POST /api/admin/invite/revoke    作废未使用的码
//	GET  /api/admin/invite/export    导出全部可用码（纯文本，一行一个）
//
// 生成参数：
//
//	{"count":10,"note":"十月批","expires_in_hours":720}
//
// expires_in_hours = 0 表示永不过期。
//
// ★ 导出返回 text/plain 而不是 JSON：运营的用法是"复制一大段粘到群里"，
//   JSON 还要额外解析。一行一个码，带连字符便于人工核对。
// ============================================================================

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/utils"
)

// inviteGenerateMaxCount 是一次生成的上限。
//
// 与 database.GenerateInvites 内部的 500 上限一致 —— 这里先拦，
// 是为了给后台一个明确的报错而不是"静默只生成 500 个"。
const inviteGenerateMaxCount = 500

// handleAdminInviteGenerate 批量生成邀请码。
func (s *Server) handleAdminInviteGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Count int    `json:"count"`
		Note  string `json:"note"`
		// ExpiresInHours 有效期（小时）。0 / 缺省 = 永不过期。
		ExpiresInHours int `json:"expires_in_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "请求格式不正确",
		})
		return
	}

	if body.Count <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "生成数量必须大于 0",
		})
		return
	}
	if body.Count > inviteGenerateMaxCount {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false,
			"message": "一次最多生成 " + strconv.Itoa(inviteGenerateMaxCount) +
				" 个，请分批生成",
		})
		return
	}
	if body.ExpiresInHours < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "有效期不能为负数",
		})
		return
	}

	var expiresAt int64
	if body.ExpiresInHours > 0 {
		expiresAt = utils.NowUnix() + int64(body.ExpiresInHours)*3600
	}

	// created_by 取管理员标识（AuthKey 的短哈希）—— 不记明文密钥。
	createdBy := adminActor(r)

	codes, err := s.db.GenerateInvites(body.Count, body.Note, createdBy, expiresAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}

	// 返回展示形式（带连字符），方便运营直接复制
	display := make([]string, len(codes))
	for i, c := range codes {
		display[i] = database.FormatInviteCode(c)
	}

	s.logger.Info("[Invite] 生成邀请码 " + strconv.Itoa(len(codes)) +
		" 个，备注=" + strings.TrimSpace(body.Note))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"codes":      display,
		"count":      len(codes),
		"expires_at": expiresAt,
	})
}

// handleAdminInviteList 分页查询邀请码。
func (s *Server) handleAdminInviteList(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	q := r.URL.Query()
	status := strings.TrimSpace(q.Get("status"))
	keyword := strings.TrimSpace(q.Get("keyword"))
	page := parseIntParam(q.Get("page"), 1)
	pageSize := parseIntParam(q.Get("page_size"), 50)

	total, entries, err := s.db.ListInvites(status, keyword, page, pageSize)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}

	now := utils.NowUnix()
	rows := make([]map[string]interface{}, len(entries))
	for i, e := range entries {
		rows[i] = map[string]interface{}{
			"code":       database.FormatInviteCode(e.Code),
			"note":       e.Note,
			"created_by": e.CreatedBy,
			"created_at": e.CreatedAt,
			"expires_at": e.ExpiresAt,
			"used_by":    e.UsedBy,
			"used_at":    e.UsedAt,
			"status":     string(e.Status(now)),
		}
	}

	// 未用数量：后台首页/标签页用它提示"快用完了"
	unused, _ := s.db.CountUnusedInvites()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "total": total, "page": page, "page_size": pageSize,
		"rows": rows, "unused": unused,
	})
}

// handleAdminInviteRevoke 作废一个未使用的邀请码。
func (s *Server) handleAdminInviteRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "请求格式不正确",
		})
		return
	}

	changed, err := s.db.RevokeInvite(body.Code)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}
	if !changed {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":      false,
			"message": "邀请码不存在、已被使用或已作废",
		})
		return
	}

	s.logger.Info("[Invite] 作废邀请码 " + database.FormatInviteCode(database.NormalizeInviteCode(body.Code)))
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// handleAdminInviteExport 导出全部可用邀请码（纯文本，一行一个）。
func (s *Server) handleAdminInviteExport(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}

	codes, err := s.db.ExportUnusedInvites(0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": err.Error(),
		})
		return
	}

	var b strings.Builder
	for _, c := range codes {
		b.WriteString(database.FormatInviteCode(c))
		b.WriteByte('\n')
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="invite-codes-`+time.Now().Format("20060102-150405")+`.txt"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.String()))
}

// adminActor 返回管理员标识（用于 created_by 字段）。
//
// ★ 刻意**不记** AuthKey 明文：那个值等于后台密码，
//   写进库里/日志里等于把密钥落盘。这里取它的短哈希，够用来区分"谁生成的"。
func adminActor(r *http.Request) string {
	key := strings.TrimSpace(r.Header.Get("X-Auth-Key"))
	if key == "" {
		key = strings.TrimSpace(r.URL.Query().Get("auth_key"))
	}
	if len(key) <= 8 {
		return "admin"
	}
	// SHA-256 前 8 位（不可逆推原文，只用于区分不同管理员）
	full := security.HashSHA256Upper([]byte(key))
	if len(full) > 8 {
		full = full[:8]
	}
	return "admin:" + full
}
