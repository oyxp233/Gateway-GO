package httprouter

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 金币寄售系统托底收购 —— 配置分发（2026-11-08）
//
// 与 BOSS 乱入（boss_intrusion_handlers.go）同一套形状，差别只有存储：
// 乱入写 gateway.db，这里**写文件**（data/gold_consign_buyback.json）。
//
//	管理后台(8443)  --POST /api/admin/gold-consign-buyback/config-->  写文件
//	游戏服务端       --GET  /internal/gold-consign-buyback/config  -->  每 10 秒轮询
//	                                                                  revision 变了才应用
//
// ★ 网关**不解析字段**，只保证是合法 JSON 对象。字段语义归游戏服务端
//   （Server-S5A3/.../gold_consign_buyback_config.go），两边各自演进。
//
// ★ `config: null` 的语义是「网关从没配过」⇒ 服务端保持「什么都不做」。
//   绝不能把空对象下发成一份「全关」配置，那会让一次误保存直接改掉线上状态。
// ============================================================================

// goldConsignBuybackConfigPath 是配置文件位置（相对网关运行目录）。
// 声明成变量而非常量，便于测试指向临时目录。
var goldConsignBuybackConfigPath = "data/gold_consign_buyback.json"

// goldConsignBuybackConfigMaxBodyBytes 是后台提交体上限（与乱入一致）。
const goldConsignBuybackConfigMaxBodyBytes = 1 << 20

// goldConsignBuybackConfigFile 是落盘形状。
type goldConsignBuybackConfigFile struct {
	Revision  int64           `json:"revision"`
	Config    json.RawMessage `json:"config,omitempty"`
	UpdatedAt string          `json:"updated_at,omitempty"`
}

// 进程内串行化读写：GET 高频、POST 低频，但两者都碰同一个文件。
var goldConsignBuybackConfigMu sync.Mutex

// loadGoldConsignBuybackConfig 读盘。文件不存在 / 内容坏掉一律返回
// 「revision 0 + config null」—— 服务端据此保持「什么都不做」，不会误开功能。
func loadGoldConsignBuybackConfig() goldConsignBuybackConfigFile {
	var out goldConsignBuybackConfigFile
	raw, err := os.ReadFile(goldConsignBuybackConfigPath)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return goldConsignBuybackConfigFile{}
	}
	return out
}

// writeGoldConsignBuybackConfig 原子落盘。
func writeGoldConsignBuybackConfig(cfg goldConsignBuybackConfigFile) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(goldConsignBuybackConfigPath), 0o755); err != nil {
		return err
	}
	return atomicWriteFile(goldConsignBuybackConfigPath, raw, 0o644)
}

// writeGoldConsignBuybackConfigResponse 统一输出形状。
//
// `includeMeta` 只影响是否带 updated_at：内部 API 给服务端轮询用，少一个字段
// 少一点噪声；后台页面要显示「上次保存时间」。
func writeGoldConsignBuybackConfigResponse(w http.ResponseWriter, cfg goldConsignBuybackConfigFile, includeMeta bool) {
	resp := map[string]interface{}{
		"ok":       true,
		"revision": cfg.Revision,
	}
	if len(cfg.Config) == 0 || string(cfg.Config) == "null" {
		// 从没配过 ⇒ null，服务端据此保持「什么都不做」。
		resp["config"] = nil
	} else {
		// RawMessage 原样透传：不经过 map 反序列化再序列化，
		// 那会把数字变成 float64，大整数（金币面额/点券价）有精度风险。
		resp["config"] = cfg.Config
	}
	if includeMeta {
		resp["updated_at"] = cfg.UpdatedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleInternalGoldConsignBuybackConfig 供游戏服务端轮询（内部端口，明文）。
func (s *Server) handleInternalGoldConsignBuybackConfig(w http.ResponseWriter, r *http.Request) {
	goldConsignBuybackConfigMu.Lock()
	cfg := loadGoldConsignBuybackConfig()
	goldConsignBuybackConfigMu.Unlock()
	writeGoldConsignBuybackConfigResponse(w, cfg, false)
}

// handleInternalGoldConsignBuybackConfigPost 供游戏服务端代 GM 后台写入配置。
//
// 为什么不直接让浏览器打 admin 端点：网关的 admin(8443) 只监听 127.0.0.1，
// GM 前端在公网侧根本连不上。链路是
//
//	浏览器 → GMService → PlayerGateway → 游戏服务端 admin API → 这里
//
// 所以需要一个用 InternalKey 认证的写入入口，语义与 admin 的 POST 完全一致。
func (s *Server) handleInternalGoldConsignBuybackConfigPost(w http.ResponseWriter, r *http.Request) {
	s.saveGoldConsignBuybackConfig(w, r)
}

// handleAdminGoldConsignBuybackConfigGet 供 GM 后台读当前配置。
func (s *Server) handleAdminGoldConsignBuybackConfigGet(w http.ResponseWriter, r *http.Request) {
	goldConsignBuybackConfigMu.Lock()
	cfg := loadGoldConsignBuybackConfig()
	goldConsignBuybackConfigMu.Unlock()
	writeGoldConsignBuybackConfigResponse(w, cfg, true)
}

// handleAdminGoldConsignBuybackConfigPost 供 GM 后台保存配置。
//
// 请求体既接受裸配置对象 `{...}`，也接受包了一层的 `{"config":{...}}`。
// 只校验「是合法 JSON 对象」——字段语义归服务端，网关不解释。
func (s *Server) handleAdminGoldConsignBuybackConfigPost(w http.ResponseWriter, r *http.Request) {
	s.saveGoldConsignBuybackConfig(w, r)
}

// saveGoldConsignBuybackConfig 是 admin(8443) 与 internal 两个入口共用的写入逻辑。
func (s *Server) saveGoldConsignBuybackConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, goldConsignBuybackConfigMaxBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "读取请求体失败"})
		return
	}
	if len(body) > goldConsignBuybackConfigMaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]interface{}{"ok": false, "message": "配置过大"})
		return
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "配置不能为空"})
		return
	}

	// 允许 {config: {...}} 包装，取出内层。
	var envelope struct {
		Config json.RawMessage `json:"config"`
	}
	payload := json.RawMessage(trimmed)
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Config) > 0 && string(envelope.Config) != "null" {
		payload = envelope.Config
	}

	// 必须是 JSON 对象（数组/标量一律拒绝）。
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(payload, &probe); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "message": "配置必须是 JSON 对象"})
		return
	}

	goldConsignBuybackConfigMu.Lock()
	defer goldConsignBuybackConfigMu.Unlock()

	prev := loadGoldConsignBuybackConfig()
	next := goldConsignBuybackConfigFile{
		Revision:  prev.Revision + 1,
		Config:    payload,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeGoldConsignBuybackConfig(next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "message": "写入失败: " + err.Error()})
		return
	}
	writeGoldConsignBuybackConfigResponse(w, next, true)
}
