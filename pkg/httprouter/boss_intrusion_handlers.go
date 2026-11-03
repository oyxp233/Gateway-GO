package httprouter

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/service"
)

// ============================================================================
// BOSS 乱入配置（2026-11-03）
//
// 背景：这份配置原本冻结在游戏服务端的启动流程里（`warmUp` 读一次就锁死），
// 运营改一行 Boss黑名单 要重启服务端 + 等 60~90 秒 PVF 预热。改造后：
//
//	管理后台(8443)  --POST /api/admin/boss-intrusion/config-->  写 gateway.db
//	游戏服务端       --GET  /internal/boss-intrusion/config -->  每 10 秒轮询
//	                                                             revision 变了才重建
//
// ★ 网关**不解析字段**，只保证是合法 JSON 对象。字段语义归游戏服务端
//   （`Server-S5A3/.../random_boss_intrusion_config.go`），两边各自演进。
//
// ★ `config: null` 的语义是「网关从没配过」⇒ 服务端保持启动期那份配置不动。
//   绝不能把空对象下发成「全关」，那会让一次误保存直接关掉线上功能。
// ============================================================================

// bossIntrusionConfigMaxBodyBytes 与 service 层的上限一致，多留 1 字节用于判定超限。
const bossIntrusionConfigMaxBodyBytes = 1 << 20

// writeBossIntrusionConfig 统一输出形状。
//
// `includeMeta` 只影响是否带 updated_at：内部 API 是给服务端轮询用的，
// 少一个字段少一点噪声；后台页面要显示「上次保存时间」。
func writeBossIntrusionConfig(w http.ResponseWriter, cfg database.BossIntrusionConfig, includeMeta bool) {
	resp := map[string]interface{}{
		"ok":       true,
		"revision": cfg.Revision,
	}
	if strings.TrimSpace(cfg.ConfigJSON) == "" {
		// 从没配过 ⇒ null，服务端据此保持启动期配置。
		resp["config"] = nil
	} else {
		// RawMessage：原样透传，不经过一次 map 反序列化再序列化
		//（那会把数字变成 float64，大整数黑名单 ID 有精度风险）。
		resp["config"] = json.RawMessage(cfg.ConfigJSON)
	}
	if includeMeta {
		resp["updated_at"] = cfg.UpdatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleInternalBossIntrusionConfig 供游戏服务端轮询（内部端口 18080，明文）。
func (s *Server) handleInternalBossIntrusionConfig(w http.ResponseWriter, r *http.Request) {
	if s.bossIntrusionSvc == nil {
		// 老版本网关没装配这个服务 ⇒ 404，服务端会静默保持启动期配置。
		http.NotFound(w, r)
		return
	}
	cfg, err := s.bossIntrusionSvc.Config()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError,
			map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeBossIntrusionConfig(w, cfg, false)
}

// handleAdminBossIntrusionConfigGet 后台读取当前配置。
func (s *Server) handleAdminBossIntrusionConfigGet(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.bossIntrusionSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]interface{}{"ok": false, "message": "乱入配置服务未装配"})
		return
	}
	cfg, err := s.bossIntrusionSvc.Config()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError,
			map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeBossIntrusionConfig(w, cfg, true)
}

// handleAdminBossIntrusionConfigPost 后台保存配置。
//
// 请求体**就是配置对象本身**（不是 `{"config": {...}}` 包装）：后台是一个
// textarea 直接贴 JSON，多包一层只会让前端多写一次拆包。
func (s *Server) handleAdminBossIntrusionConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.bossIntrusionSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]interface{}{"ok": false, "message": "乱入配置服务未装配"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, bossIntrusionConfigMaxBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "读取请求体失败"})
		return
	}
	if len(raw) > bossIntrusionConfigMaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]interface{}{"ok": false, "message": "配置超过 1 MiB"})
		return
	}
	saved, err := s.bossIntrusionSvc.Update(string(raw))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": err.Error()})
		return
	}
	writeBossIntrusionConfig(w, saved, true)
}

// SetBossIntrusionConfig 注入乱入配置服务（gateway / admin 两个进程都要注入）。
//
// 用 Setter 而不是加进 NewServer 的位置参数：那个签名已经 20 个参数，
// 再加一个会逼着所有调用点（含测试）一起改。
func (s *Server) SetBossIntrusionConfig(svc *service.BossIntrusionConfigService) {
	if s == nil {
		return
	}
	s.bossIntrusionSvc = svc
}
