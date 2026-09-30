package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/proxy"
	"s4a21-gateway/pkg/security"
)

// Server 管理后台 HTTP 服务器。
type Server struct {
	config     *config.GatewayConfig
	logger     *logger.ConsoleLogger
	db         *database.Database
	configDir  string
	portConfig *proxy.PortConfigStore
	httpServer *http.Server
}

// ErrStandaloneDisabled 独立管理后台已废弃。
//
// 历史背景：本项目曾计划让 cmd/admin 作为独立进程提供管理后台，
// 但主进程 cmd/gateway 已完整实现全部后台路由（48 条，含端口管理、
// 配置查询、账号管理、封禁、完整性策略、服务端控制等），
// 且作为唯一写入方持有 gateway.db 与 proxy_ports.json。
//
// 若放行独立进程会同时踩三个坑：
//  1. 抢占主进程的 AdminHttpPort（两者监听同一端口，必有一个启动失败）；
//  2. 两个进程同时 Watch proxy_ports.json，端口热加载互相打架；
//  3. 两个进程各自持有 gateway.db 连接，SQLite 单写者模型下极易 database is locked。
//
// 注意：build.sh 只构建 ./cmd/gateway/，本包从未进入部署产物。
var ErrStandaloneDisabled = fmt.Errorf(
	"独立管理后台已废弃：请直接使用主进程 cmd/gateway 的内置管理后台（同一 AdminHttpPort）")

// NewServer 创建管理后台服务器。
//
// Deprecated: 独立管理后台已废弃，调用方应直接使用 cmd/gateway 的内置后台。
// 保留本构造函数仅为兼容历史引用，实际不会建立任何监听或文件监听。
func NewServer(cfg *config.GatewayConfig, log *logger.ConsoleLogger, db *database.Database, configDir string) *Server {
	return &Server{
		config:    cfg,
		logger:    log,
		db:        db,
		configDir: configDir,
	}
}

// Start 启动 HTTP 服务。
//
// 独立管理后台已废弃，本方法**不再监听任何端口**，直接返回 ErrStandaloneDisabled。
// 返回错误而非 panic，便于 cmd/admin 优雅退出并打出可读提示。
func (s *Server) Start() error {
	return ErrStandaloneDisabled
}

// Stop 停止 HTTP 服务。
func (s *Server) Stop() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	if s.portConfig != nil {
		s.portConfig.StopWatching()
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetPorts(w, r)
	case http.MethodPost:
		s.handleSavePorts(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
	}
}

// handleGetPorts 返回当前端口配置。调用方 handlePorts 已完成鉴权。
func (s *Server) handleGetPorts(w http.ResponseWriter, r *http.Request) {
	if s.portConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "独立管理后台已废弃，未加载端口配置",
		})
		return
	}
	config := s.portConfig.GetConfig()
	if config == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "config not loaded"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config":       config,
		"active_ports": s.getActivePorts(),
	})
}

func (s *Server) handleSavePorts(w http.ResponseWriter, r *http.Request) {
	if s.portConfig == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "独立管理后台已废弃，拒绝写入端口配置",
		})
		return
	}

	var newConfig proxy.ProxyPortConfig
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}

	if _, err := s.portConfig.Save(&newConfig); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "message": "saved"})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"admin": map[string]interface{}{
			"auth_key":       "****",
			"listen_address": s.config.Gateway.AdminHttpListenAddress,
			"port":           s.config.Gateway.AdminHttpPort,
		},
		"gateway": map[string]interface{}{
			"tcp_port":   s.config.Gateway.TcpPort,
			"http_port":  s.config.Gateway.HttpPort,
			"proxy_port": s.config.Gateway.ProxyPort,
		},
		"game_server": map[string]interface{}{
			"backend_host": s.config.GameServer.BackendHost,
			"backend_port": s.config.GameServer.BackendChannelPort,
			"public_ip":    s.config.GameServer.PublicIP,
		},
	})
}

// getActivePorts 返回各监听端口上的当前连接数。
//
// 注意：这里**有意**返回空 map，不是未实现的占位。
// 本包（独立管理后台）已废弃，s.portConfig 恒为 nil，handleGetPorts 不会走到这里；
// 真实活跃端口统计由主进程 cmd/gateway 的 /api/admin/ports 提供。
// 保留本方法仅为兼容历史引用，避免留下“看着能跑、实际永远为空”的实现陷阱。
//
// Deprecated: 请使用主进程内置管理后台的端口统计接口。
func (s *Server) getActivePorts() map[int]int {
	if s.portConfig == nil {
		return map[int]int{}
	}
	// 防御性兜底：即便 portConfig 被外部注入，也只返回稳定的空快照，
	// 不做任何 I/O，避免独立进程读到半写状态的文件。
	return map[int]int{}
}

func (s *Server) checkAuth(r *http.Request) bool {
	key := r.Header.Get("X-Auth-Key")
	if key == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			key = auth[7:]
		}
	}
	// 恒定时间比较，与 httprouter.checkAdmin 保持一致
	return security.ConstantTimeEquals(key, s.config.Admin.AuthKey)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
