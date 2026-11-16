package httprouter

// ============================================================================
// DNF.EXE 增量更新路由（2026-10-25）
//
// 公开（网关 8080，/api 前缀）：
//
//	GET /api/dnfexe/update          更新清单（版本/hash/体积/min_version）
//	GET /api/dnfexe/update/exe      当前版全量 exe（首装与 delta 失败的回退路径）
//	GET /api/dnfexe/update/delta?from=<hash>  按需增量（历史现场生成 + 缓存）
//
// 管理（admin 8443，X-Auth-Key）：
//
//	GET  /api/admin/dnfexe/versions 当前版 + 历史表
//	POST /api/admin/dnfexe/upload   上传新 exe（multipart: file + version + name）
//	POST /api/admin/dnfexe/rollback 回退到历史版本
//
// 与登录器自更新（launcher_update.go）同构，区别仅在目录与路由前缀。
// ============================================================================

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/utils"
)

// handleDnfExeUpdateManifest 下发 DNF.EXE 更新清单。
//
// 永远 200（除非服务出错）：enabled=false / 无版本信息都是**有效状态**，
// 登录器按清单里的字段决定跳过还是更新 —— 404 会被登录器当成
// 「网关没升级」（Unsupported）处理，两种状态不可混。
func (s *Server) handleDnfExeUpdateManifest(w http.ResponseWriter, r *http.Request) {
	if s.dnfExeUpdate == nil {
		http.NotFound(w, r)
		return
	}

	dz := s.config.DnfExeSnapshot()
	m := models.DnfExeUpdateManifest{
		OK:         true,
		Enabled:    s.dnfExeUpdate.Enabled(),
		MinVersion: strings.TrimSpace(dz.MinVersion),
		FullURL:    "/api/dnfexe/update/exe",
		DeltaURL:   "/api/dnfexe/update/delta",
	}
	if cur := s.dnfExeUpdate.Current(); cur != nil && cur.Hash != "" {
		m.Version = cur.Version
		// ★ 版本号在上传时是**选填**的（ReplaceDnfExe 明确允许留空），但留空会让
		//   登录器把整个清单当成「无版本信息」静默跳过 —— 后台显示上传成功、
		//   玩家侧却永远不弹更新，且日志里连一条失败都没有，极难排查。
		//   所以这里用指纹短码兜底：version 只承担展示与 min_version 比较，
		//   更新判定永远看 hash，给个假名不会误判。
		if strings.TrimSpace(m.Version) == "" {
			m.Version = "build-" + strings.ToUpper(cur.Hash[:12])
		}
		m.Hash = cur.Hash
		m.Size = cur.Size
		m.StoredUtc = cur.StoredUtc

		// 全量包外部分发（2026-11-16）：与登录器同构 —— 只换 full_url，
		// delta_url 留在网关（按需增量现场生成，对象存储里没有现成文件）。
		if base := strings.TrimSpace(s.config.DnfExe.ExeBaseUrl); base != "" {
			m.FullURL = strings.TrimRight(base, "/") + "/dnfexe/" + cur.Hash + ".exe"
		}
	}
	writeJSON(w, http.StatusOK, m)
}

// handleDnfExeUpdateExe 下发当前版全量 DNF.EXE。
func (s *Server) handleDnfExeUpdateExe(w http.ResponseWriter, r *http.Request) {
	if s.dnfExeUpdate == nil || !s.dnfExeUpdate.Enabled() {
		http.NotFound(w, r)
		return
	}
	path := s.dnfExeUpdate.CurrentPath()
	if !utils.FileExists(path) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	if cur := s.dnfExeUpdate.Current(); cur != nil && cur.Hash != "" {
		w.Header().Set("ETag", `"`+cur.Hash+`"`)
		w.Header().Set("X-DnfExe-Version", cur.Version)
	}
	tw, release, ok := s.dl.Begin(w, r)
	if !ok {
		return
	}
	defer release()
	http.ServeFile(tw, r, path)
}

// handleDnfExeUpdateDelta 按需增量。与登录器 delta 同语义：
// 404 = 「本次没有增量」（登录器回退全量），绝不 200 空体。
func (s *Server) handleDnfExeUpdateDelta(w http.ResponseWriter, r *http.Request) {
	if s.dnfExeUpdate == nil || !s.dnfExeUpdate.Enabled() {
		http.NotFound(w, r)
		return
	}
	from := r.URL.Query().Get("from")
	if from == "" {
		http.NotFound(w, r)
		return
	}
	d := s.dnfExeUpdate.GetOnDemandDelta(from)
	if d == nil {
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
	tw, release, ok := s.dl.Begin(w, r)
	if !ok {
		return
	}
	defer release()
	http.ServeFile(tw, r, d.Path)
}

// handleAdminDnfExeVersions 当前版 + 历史表（后台「DNF.EXE 版本」区）。
func (s *Server) handleAdminDnfExeVersions(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	entries := s.dnfExeUpdate.GetHistory()
	currentHash := ""
	if cur := s.dnfExeUpdate.Current(); cur != nil {
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
	if cur := s.dnfExeUpdate.Current(); cur != nil {
		curMap = map[string]interface{}{
			"version": cur.Version, "hash": cur.Hash, "size": cur.Size,
			"name": cur.Name, "stored_utc": cur.StoredUtc,
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "enabled": s.dnfExeUpdate.Enabled(),
		"dir": s.dnfExeUpdate.UpdateDir(), "current": curMap, "entries": out,
	})
}

// notifyPeersDnfExeChanged 把新版本推送给所有从网关（异步、失败不影响调用方）。
func (s *Server) notifyPeersDnfExeChanged(cur *models.DnfExeBuildEntry) {
	if s.peerSync == nil || cur == nil {
		return
	}
	rev := s.dnfExeUpdate.MaxAuthorityRevision()
	go s.peerSync.PushDnfExeToPeers(cur.Hash, cur.Version, rev)
}

// handleAdminDnfExeUpload 上传新版本 DNF.EXE。
//
// multipart 字段：file（必填，exe 本体）、version（可选，用于展示）、name（可选备注）。
func (s *Server) handleAdminDnfExeUpload(w http.ResponseWriter, r *http.Request) {
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

	cur, err := s.dnfExeUpdate.ReplaceDnfExe(file, version, name, filename)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	s.notifyPeersDnfExeChanged(cur)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "version": cur.Version, "hash": cur.Hash, "size": cur.Size,
	})
}

// handleAdminDnfExeRollback 回退到历史版本（走完整替换链路）。
func (s *Server) handleAdminDnfExeRollback(w http.ResponseWriter, r *http.Request) {
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
	cur, err := s.dnfExeUpdate.RollbackDnfExe(body.Hash)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	s.notifyPeersDnfExeChanged(cur)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "version": cur.Version, "hash": cur.Hash, "size": cur.Size,
	})
}
