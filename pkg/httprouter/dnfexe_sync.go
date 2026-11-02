package httprouter

// ============================================================================
// DNF.EXE 包同步（三服合一，2026-10-25）
//
// 与登录器包同步（launcher_sync.go）同构，区别只在内/公开 API 路径前缀。
// 主网关做权威，其余从网关拉取。登录器检测到 DNF.EXE 新版后下载并替换。
//
// 内部 API（只绑 loopback，X-Internal-Key 鉴权）：
//
//	GET  /internal/dnfexe/sync?since=<revision>   拉取比 since 更新的版本元数据
//	POST /internal/dnfexe/push                    主网关推送"有新版本"通知
//
// 降级策略（与登录器同步同底线）：
//   - 主网关不可达时从网关**保持现有版本继续服务**
//   - 绝不能因为同步失败让玩家没法更新
//   - 同步失败只记日志，不返回错误给玩家
// ============================================================================

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"s4a21-gateway/pkg/models"
)

// DnfExeSyncResponse 是 GET /internal/dnfexe/sync 的响应体。
type DnfExeSyncResponse struct {
	OK      bool                        `json:"ok"`
	Current *models.DnfExeBuildEntry    `json:"current"`
	History []models.DnfExeBuildEntry    `json:"history,omitempty"`
}

// handleInternalDnfExeSync 从网关拉取 DNF.EXE 版本信息（只返回元数据，不含 exe 字节）。
func (s *Server) handleInternalDnfExeSync(w http.ResponseWriter, r *http.Request) {
	if s.dnfExeUpdate == nil {
		writeJSON(w, http.StatusOK, DnfExeSyncResponse{OK: false})
		return
	}

	sinceStr := r.URL.Query().Get("since")
	since, _ := strconv.ParseInt(sinceStr, 10, 64)

	current := s.dnfExeUpdate.Current()

	var history []models.DnfExeBuildEntry
	allHistory := s.dnfExeUpdate.History()
	for i := range allHistory {
		if allHistory[i].AuthorityRevision > since {
			history = append(history, allHistory[i])
		}
	}

	writeJSON(w, http.StatusOK, DnfExeSyncResponse{
		OK:      true,
		Current: current,
		History: history,
	})
}

// DnfExePushRequest 是 POST /internal/dnfexe/push 的请求体。
type DnfExePushRequest struct {
	Hash     string `json:"hash"`
	Version  string `json:"version"`
	Size     int64  `json:"size"`
	Revision int64  `json:"revision"`
}

// handleInternalDnfExePush 接收主网关的"有新版本"通知。
func (s *Server) handleInternalDnfExePush(w http.ResponseWriter, r *http.Request) {
	if s.dnfExeUpdate == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "message": "dnfexe update not configured"})
		return
	}

	peerBase := strings.TrimSpace(s.config.Signing.PeerBaseUrl)
	if peerBase == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]interface{}{
			"ok":      false,
			"message": "本机未配置 Signing.PeerBaseUrl，无法作为从网关拉取（主网关无需配置此项）",
		})
		return
	}

	var req DnfExePushRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "invalid body"})
		return
	}

	if req.Hash == "" || req.Revision <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "missing hash or revision"})
		return
	}

	if current := s.dnfExeUpdate.Current(); current != nil && strings.EqualFold(current.Hash, req.Hash) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "skipped": true, "reason": "already current"})
		return
	}

	go s.pullDnfExeFromPeer(peerBase, req)

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "skipped": false, "message": "pulling async"})
}

// pullDnfExeFromPeer 从主网关（peer）拉取 DNF.EXE 并替换本地版本。
func (s *Server) pullDnfExeFromPeer(peerBase string, req DnfExePushRequest) {
	shortHash := req.Hash
	if len(shortHash) > 8 {
		shortHash = shortHash[:8]
	}

	err := s.dnfExeUpdate.PullFromPeer(peerBase, req.Hash, req.Version, req.Revision)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("[DnfExeSync] peer 拉取失败（hash=%s rev=%d，保持现有版本）: %v",
			shortHash, req.Revision, err))
		return
	}
	s.logger.Info(fmt.Sprintf("[DnfExeSync] peer 推送已应用 hash=%s rev=%d", shortHash, req.Revision))
}
