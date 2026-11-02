package httprouter

// ============================================================================
// 登录器包同步（三服合一，2026-10-24）
//
// 见评估-三服合一登录器-20261023.md 第四章：
// 主网关做权威，其余从网关拉取。登录器仍只调就近那台的 /api/launcher/update，
// 三台内容已一致 → 玩家就近拉，主网关挂了也不影响。
//
// 内部 API（只绑 loopback，X-Internal-Key 鉴权）：
//
//	GET  /internal/launcher/sync?since=<revision>   拉取比 since 更新的版本元数据
//	POST /internal/launcher/push                    主网关推送"有新版本"通知
//
// 从网关侧的配置：Signing.PeerBaseUrl（公开 HTTP 基址，用于拉 exe）
//
// 降级策略（★ 最重要的约束）：
//   - 主网关不可达时从网关**保持现有版本继续服务**
//   - 绝不能因为同步失败让玩家没法更新
//   - 同步失败只记日志，不返回错误给玩家（玩家链路根本不经过这里）
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

// LauncherSyncResponse 是 GET /internal/launcher/sync 的响应体。
//
// since=0 时返回当前版 + 全部历史；
// since=N 时只返回 AuthorityRevision > N 的条目。
type LauncherSyncResponse struct {
	OK      bool                       `json:"ok"`
	Current *models.LauncherBuildEntry `json:"current"`
	History []models.LauncherBuildEntry `json:"history,omitempty"`
}

// handleInternalLauncherSync 从网关拉取登录器版本信息（只返回元数据，不含 exe 字节）。
//
// 调用方按返回的 hash 判断是否需要拉 exe：
//   - 需要 → GET {PeerBaseUrl}/api/launcher/update/exe 拉全量
//   - 已有 → 跳过（幂等）
func (s *Server) handleInternalLauncherSync(w http.ResponseWriter, r *http.Request) {
	if s.launcherUpdate == nil {
		writeJSON(w, http.StatusOK, LauncherSyncResponse{OK: false})
		return
	}

	sinceStr := r.URL.Query().Get("since")
	since, _ := strconv.ParseInt(sinceStr, 10, 64)

	current := s.launcherUpdate.Current()

	// 从历史里筛出 AuthorityRevision > since 的条目
	var history []models.LauncherBuildEntry
	allHistory := s.launcherUpdate.History()
	for i := range allHistory {
		if allHistory[i].AuthorityRevision > since {
			history = append(history, allHistory[i])
		}
	}

	writeJSON(w, http.StatusOK, LauncherSyncResponse{
		OK:      true,
		Current: current,
		History: history,
	})
}

// LauncherPushRequest 是 POST /internal/launcher/push 的请求体。
//
// 主网关上传新版本后推送通知到从网关。从网关收到后按 hash 判断：
//   - 已有该版本 → 幂等跳过
//   - 没有 → 异步从 PeerBaseUrl 拉全量 exe
type LauncherPushRequest struct {
	Hash     string `json:"hash"`
	Version  string `json:"version"`
	Size     int64  `json:"size"`
	Revision int64  `json:"revision"`
}

// handleInternalLauncherPush 接收主网关的"有新版本"通知。
//
// 响应语义：
//   - 501：本机未配 Signing.PeerBaseUrl（主网关自己，或未启用同步）
//   - 200 + skipped=true：已有该版本（幂等）
//   - 200 + skipped=false：已受理，异步拉取中
//
// ★ 不在这里直接接收 exe 字节：128 MiB 会吃满 internal API 带宽。
//   推送请求本身只有几百字节，真正的字节走公开的 /api/launcher/update/exe。
func (s *Server) handleInternalLauncherPush(w http.ResponseWriter, r *http.Request) {
	if s.launcherUpdate == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": false, "message": "launcher update not configured"})
		return
	}

	// 没配 peer = 本机就是主网关（或未启用同步）→ 明确告知，不假装成功
	peerBase := strings.TrimSpace(s.config.Signing.PeerBaseUrl)
	if peerBase == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]interface{}{
			"ok":      false,
			"message": "本机未配置 Signing.PeerBaseUrl，无法作为从网关拉取（主网关无需配置此项）",
		})
		return
	}

	var req LauncherPushRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "invalid body"})
		return
	}

	if req.Hash == "" || req.Revision <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "missing hash or revision"})
		return
	}

	// 幂等：已有同 hash 的当前版就跳过
	if current := s.launcherUpdate.Current(); current != nil && strings.EqualFold(current.Hash, req.Hash) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "skipped": true, "reason": "already current"})
		return
	}

	// 异步拉取（128 MiB 可能要几分钟，不阻塞推送响应）
	go s.pullLauncherFromPeer(peerBase, req)

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "skipped": false, "message": "pulling async"})
}

// pullLauncherFromPeer 从主网关（peer）拉取登录器 exe 并替换本地版本。
//
// 真正的拉取逻辑在 service.LauncherUpdateService.PullFromPeer（与定时轮询共用一份），
// 这里只负责异步调度 + 失败日志。
//
// 失败只记日志：同步是增强能力，绝不能影响任何在线服务。
func (s *Server) pullLauncherFromPeer(peerBase string, req LauncherPushRequest) {
	shortHash := req.Hash
	if len(shortHash) > 8 {
		shortHash = shortHash[:8]
	}

	err := s.launcherUpdate.PullFromPeer(peerBase, req.Hash, req.Version, req.Revision)
	if err != nil {
		s.logger.Warn(fmt.Sprintf("[LauncherSync] peer 拉取失败（hash=%s rev=%d，保持现有版本）: %v",
			shortHash, req.Revision, err))
		return
	}
	s.logger.Info(fmt.Sprintf("[LauncherSync] peer 推送已应用 hash=%s rev=%d", shortHash, req.Revision))
}
