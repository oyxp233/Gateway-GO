package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ProxyPortConfig 代理端口配置。
type ProxyPortConfig struct {
	// Channel 代理端口
	ChannelPort int `json:"channel_port"`

	// Game 代理端口映射 (public -> backend)
	GamePorts []GamePortMapping `json:"game_ports"`

	// 后端地址
	BackendHost string `json:"backend_host"`
	BackendPort int    `json:"backend_port"`

	// 代理端口范围 (用于动态添加)
	PortRange PortRange `json:"port_range"`
}

// GamePortMapping 游戏端口映射。
type GamePortMapping struct {
	Public  int    `json:"public"`
	Backend int    `json:"backend"`
	Enabled bool   `json:"enabled"`
	Note    string `json:"note,omitempty"`
}

// PortRange 端口范围配置。
type PortRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// PortConfigStore 端口配置存储，支持热加载。
//
// 落盘即生效：Save 写文件的同时同步回调 onChange 完成监听的开/关，
// 免去"改配置要重启网关"。回调的返回值描述本次实际生效内容（开了哪些、
// 关了哪些、哪些端口启动失败），供管理后台原样回报给操作者。
type PortConfigStore struct {
	configPath string
	config     *ProxyPortConfig
	bootstrap  *ProxyPortConfig // 文件缺失/非法时使用的初始配置
	mu         sync.RWMutex
	onChange   func(newConfig *ProxyPortConfig) ReloadResult
	watcher    *fsWatcher
}

// fsWatcher 文件系统监听器。
type fsWatcher struct {
	path       string
	lastMod    time.Time
	lastSize   int64
	checkTimer *time.Ticker
	done       chan struct{}
}

// NewPortConfigStore 创建端口配置存储。
func NewPortConfigStore(configDir string, onChange func(*ProxyPortConfig) ReloadResult) *PortConfigStore {
	return newPortConfigStore(configDir, onChange, nil)
}

// NewPortConfigStoreBootstrap 创建端口配置存储，文件缺失时用 bootstrap 初始化
// （bootstrap 从 appsettings 的 GamePorts/GamePortMap 派生，保证新旧配置一致）。
func NewPortConfigStoreBootstrap(configDir string, onChange func(*ProxyPortConfig) ReloadResult, bootstrap *ProxyPortConfig) *PortConfigStore {
	return newPortConfigStore(configDir, onChange, bootstrap)
}

func newPortConfigStore(configDir string, onChange func(*ProxyPortConfig) ReloadResult, bootstrap *ProxyPortConfig) *PortConfigStore {
	store := &PortConfigStore{
		configPath: filepath.Join(configDir, "proxy_ports.json"),
		onChange:   onChange,
		bootstrap:  bootstrap,
	}
	store.load()
	return store
}

// StartWatching 开始监听配置文件变化。
func (s *PortConfigStore) StartWatching() {
	s.watcher = &fsWatcher{
		path:       s.configPath,
		checkTimer: time.NewTicker(2 * time.Second),
		done:       make(chan struct{}),
	}

	if info, err := os.Stat(s.configPath); err == nil {
		s.watcher.lastMod = info.ModTime()
		s.watcher.lastSize = info.Size()
	}

	go s.watcherLoop()
}

// StopWatching 停止监听。
func (s *PortConfigStore) StopWatching() {
	if s.watcher != nil {
		close(s.watcher.done)
		s.watcher.checkTimer.Stop()
	}
}

func (s *PortConfigStore) watcherLoop() {
	for {
		select {
		case <-s.watcher.done:
			return
		case <-s.watcher.checkTimer.C:
			if s.checkAndReload() {
				break
			}
		}
	}
}

func (s *PortConfigStore) checkAndReload() bool {
	info, err := os.Stat(s.configPath)
	if err != nil {
		return false
	}

	// 文件未变化
	if info.ModTime().Equal(s.watcher.lastMod) && info.Size() == s.watcher.lastSize {
		return false
	}

	// 文件已变化，重新加载
	if err := s.load(); err != nil {
		return false
	}

	s.watcher.lastMod = info.ModTime()
	s.watcher.lastSize = info.Size()

	if s.onChange != nil {
		s.mu.RLock()
		config := s.config
		s.mu.RUnlock()
		s.onChange(config)
	}

	return true
}

func (s *PortConfigStore) load() error {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		// 文件不存在，生成默认配置
		if os.IsNotExist(err) {
			return s.generateInitialFile()
		}
		return err
	}

	var config ProxyPortConfig
	if err := json.Unmarshal(data, &config); err != nil {
		// 解析失败：回退 bootstrap，不覆盖磁盘文件
		if s.bootstrap != nil {
			s.mu.Lock()
			s.config = s.bootstrap
			s.mu.Unlock()
			return nil
		}
		return fmt.Errorf("parse proxy_ports.json: %w", err)
	}

	s.mu.Lock()
	s.config = &config
	s.mu.Unlock()
	return nil
}

// generateInitialFile 生成本机初始端口配置文件：
// 提供 bootstrap（来自 appsettings）时以其为准，否则退回硬编码默认值。
func (s *PortConfigStore) generateInitialFile() error {
	var defaultConfig *ProxyPortConfig
	if s.bootstrap != nil {
		defaultConfig = s.bootstrap
	} else {
		defaultConfig = &ProxyPortConfig{
			ChannelPort: 8001,
			GamePorts: []GamePortMapping{
				{Public: 20001, Backend: 10001, Enabled: true},
				{Public: 20002, Backend: 10002, Enabled: true},
				{Public: 20003, Backend: 10003, Enabled: true},
			},
			BackendHost: "127.0.0.1",
			BackendPort: 10001,
			PortRange:   PortRange{Start: 20001, End: 20201},
		}
	}

	_, err := s.Save(defaultConfig)
	return err
}

// Save 保存配置到文件并立即应用，返回本次实际生效的结果。
func (s *PortConfigStore) Save(config *ProxyPortConfig) (ReloadResult, error) {
	if config == nil {
		return ReloadResult{}, fmt.Errorf("config is nil")
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return ReloadResult{}, err
	}

	dir := filepath.Dir(s.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ReloadResult{}, err
	}

	// 原子写入：临时文件 + 重命名，避免半截文件被 watcher 读到
	tmpPath := s.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return ReloadResult{}, err
	}
	if err := os.Rename(tmpPath, s.configPath); err != nil {
		return ReloadResult{}, err
	}

	s.mu.Lock()
	s.config = config
	s.mu.Unlock()

	// 立即应用（后台保存无须等文件轮询）
	if s.onChange != nil {
		return s.onChange(config), nil
	}
	return ReloadResult{}, nil
}

// ApplyNow 主动触发一次 apply（重建内部状态后调用）。
func (s *PortConfigStore) ApplyNow() ReloadResult {
	s.mu.RLock()
	config := s.config
	s.mu.RUnlock()
	if s.onChange != nil && config != nil {
		return s.onChange(config)
	}
	return ReloadResult{}
}

// GetConfig 获取当前配置。
func (s *PortConfigStore) GetConfig() *ProxyPortConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// Reload 从磁盘重新读一遍配置到内存，**不写文件、不触发 onChange**。
//
// 用途：进程分离后 admin 进程只读配置，真正落盘的是网关。
// 网关写完文件后，admin 调这里同步内存，避免管理页 GET 到旧数据。
func (s *PortConfigStore) Reload() error {
	return s.load()
}

// ConfigPath 返回配置文件路径。
func (s *PortConfigStore) ConfigPath() string {
	return s.configPath
}
