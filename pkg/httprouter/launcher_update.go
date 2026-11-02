package httprouter

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/service"
	"s4a21-gateway/pkg/utils"
)

// ============================================================================
// 登录器自更新路由（2026-10-01）
//
// 公开（网关 8080，/api 前缀）：
//
//	GET /api/launcher/update          更新清单（版本/hash/体积/min_version）
//	GET /api/launcher/update/exe      当前版全量 exe（首装与 delta 失败的回退路径）
//	GET /api/launcher/update/delta?from=<hash>  按需增量（历史现场生成 + 缓存）
//
// 管理（admin 8443，X-Auth-Key）：
//
//	GET  /api/admin/launcher/versions 当前版 + 历史表
//	POST /api/admin/launcher/upload   上传新 exe（multipart: file + version + name）
//	POST /api/admin/launcher/rollback 回退到历史版本
//
// ★ 走 /api 路由而不是静态目录：与插件/PVF delta 同因 —— 双进程形态下
//   玩家端口的非 /api 路径一律 404（usePublicOnlyMiddleware）。
//
// ★ 兼容性：2.3.8 及更早的登录器不认识这些端点，永远不会请求 ——
//   上线后第一个自更新版本必须靠手动下载铺开，之后才是全自动。
// ============================================================================

// handleLauncherUpdateManifest 下发更新清单。
//
// 永远 200（除非服务出错）：enabled=false / 无版本信息都是**有效状态**，
// 登录器按清单里的字段决定跳过还是更新 —— 404 会被登录器当成
// 「网关没升级」（Unsupported）处理，两种状态不可混。
func (s *Server) handleLauncherUpdateManifest(w http.ResponseWriter, r *http.Request) {
	if s.launcherUpdate == nil {
		http.NotFound(w, r)
		return
	}

	lz := s.config.LauncherSnapshot() // G-5：运行时可变段走快照
	m := models.LauncherUpdateManifest{
		OK:         true,
		Enabled:    s.launcherUpdate.Enabled(),
		MinVersion: strings.TrimSpace(lz.MinVersion),
		FullURL:    "/api/launcher/update/exe",
		DeltaURL:   "/api/launcher/update/delta",
	}
	if cur := s.launcherUpdate.Current(); cur != nil && cur.Hash != "" {
		m.Version = cur.Version
		m.Hash = cur.Hash
		m.Size = cur.Size
		m.StoredUtc = cur.StoredUtc
	}
	writeJSON(w, http.StatusOK, m)
}

// handleLauncherUpdateExe 下发当前版全量 exe。
// ServeFile 自带 Range/If-Modified-Since 支持，134 MiB 走流式不占内存。
func (s *Server) handleLauncherUpdateExe(w http.ResponseWriter, r *http.Request) {
	if s.launcherUpdate == nil || !s.launcherUpdate.Enabled() {
		http.NotFound(w, r)
		return
	}
	path := s.launcherUpdate.CurrentPath()
	if !utils.FileExists(path) {
		http.NotFound(w, r)
		return
	}
	// 与 delta 同口径：no-store（中间层留旧字节只会造成「更新完还提示更新」）。
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	if cur := s.launcherUpdate.Current(); cur != nil && cur.Hash != "" {
		w.Header().Set("ETag", `"`+cur.Hash+`"`)
		w.Header().Set("X-Launcher-Version", cur.Version)
	}
	http.ServeFile(w, r, path)
}

// handleLauncherUpdateDelta 按需增量。与 PVF delta 同语义：
// 404 = 「本次没有增量」（登录器回退全量），绝不 200 空体。
func (s *Server) handleLauncherUpdateDelta(w http.ResponseWriter, r *http.Request) {
	if s.launcherUpdate == nil || !s.launcherUpdate.Enabled() {
		http.NotFound(w, r)
		return
	}
	from := r.URL.Query().Get("from")
	if from == "" {
		// 登录器增量必须带 from（本地 exe hash）；不带 = 调用方口径错。
		http.NotFound(w, r)
		return
	}
	d := s.launcherUpdate.GetOnDemandDelta(from)
	if d == nil {
		// 没有增量：历史无此版（客户端 exe 被改过/太老）或生成失败。
		http.NotFound(w, r)
		return
	}
	if !utils.FileExists(d.Path) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+d.ToHash+`"`)
	w.Header().Set("X-Delta-From", d.FromHash)
	w.Header().Set("X-Delta-To", d.ToHash)
	w.Header().Set("X-Delta-To-Size", strconv.FormatInt(d.ToSize, 10))
	http.ServeFile(w, r, d.Path)
}

// handleAdminLauncherVersions 当前版 + 历史表（后台「登录器版本」区）。
func (s *Server) handleAdminLauncherVersions(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	entries := s.launcherUpdate.GetHistory()
	currentHash := ""
	if cur := s.launcherUpdate.Current(); cur != nil {
		currentHash = cur.Hash
	}
	out := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]interface{}{
			"hash":       e.Hash,
			"version":    e.Version,
			"size":       e.Size,
			"name":       e.Name,
			"filename":   e.Filename,
			"stored_utc": e.StoredUtc,
			"is_current": strings.EqualFold(e.Hash, currentHash),
		})
	}
	curMap := map[string]interface{}{}
	if cur := s.launcherUpdate.Current(); cur != nil {
		curMap = map[string]interface{}{
			"version": cur.Version, "hash": cur.Hash, "size": cur.Size,
			"name": cur.Name, "stored_utc": cur.StoredUtc,
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "enabled": s.launcherUpdate.Enabled(),
		"dir": s.launcherUpdate.UpdateDir(), "current": curMap, "entries": out,
	})
}

// SetPeerSync 注入网关间同步服务（主网关上传播录器版本用）。
//
// 传 nil 或本机没配 Signing.Peers 时，上传/回退完成后**不推送** ——
// 只靠从网关自己的 300s 轮询追平（旧行为）。
func (s *Server) SetPeerSync(ps *service.PeerSyncService) {
	s.peerSync = ps
}

// notifyPeersLauncherChanged 把新版本推送给所有从网关（异步、失败不影响调用方）。
//
// ★ 只在**主网关**（配了 Signing.Peers）有意义。
//   从网关不配 Peers，PushLauncherToPeers 内部会直接返回。
//
// ★ 异步：从网关可能在内网慢链路上，同步等会把后台 HTTP 请求挂住。
//
// ★ 推送失败不影响上传结果：轮询兜底还在（默认 300s），
//   这只是把生效时间从"最多 5 分钟"降到"秒级"。
func (s *Server) notifyPeersLauncherChanged(cur *models.LauncherBuildEntry) {
	if s.peerSync == nil || cur == nil {
		return
	}
	rev := s.launcherUpdate.MaxAuthorityRevision()
	go s.peerSync.PushLauncherToPeers(cur.Hash, cur.Version, rev)
}

// handleAdminLauncherUpload 上传新版本登录器 exe。
//
// multipart 字段：file（必填，exe 本体）、version（必填，x.y.z）、name（可选备注）。
// 上传 134 MiB 走 admin 端口（bodylimit 白名单放行 512 MiB）。
//
// 成功后除写响应外，还会**异步通知从网关**有新版本（见 notifyPeersLauncherChanged）。
func (s *Server) handleAdminLauncherUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if err := r.ParseMultipartForm(2 << 30); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}

	version := strings.TrimSpace(r.FormValue("version"))
	name := strings.TrimSpace(r.FormValue("name"))

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "no exe file"})
		return
	}
	defer file.Close()

	filename := ""
	if header != nil {
		filename = filepath.Base(filepath.Clean(header.Filename))
	}

	cur, err := s.launcherUpdate.ReplaceLauncher(file, version, name, filename)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	// 上传成功 → 通知从网关有新版本（异步，失败不影响本次上传）
	s.notifyPeersLauncherChanged(cur)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "version": cur.Version, "hash": cur.Hash, "size": cur.Size,
	})
}

// handleAdminLauncherRollback 回退到历史版本（走完整替换链路）。
func (s *Server) handleAdminLauncherRollback(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	var body struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "请求体不是合法 JSON"})
		return
	}
	cur, err := s.launcherUpdate.RollbackLauncher(body.Hash)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	// 回退也是"版本变了"，同样要通知从网关（否则它们还停在新版上）
	s.notifyPeersLauncherChanged(cur)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "version": cur.Version, "hash": cur.Hash, "size": cur.Size,
	})
}
