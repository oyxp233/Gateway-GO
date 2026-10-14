// Package backends 提供管理后台进程分离时、admin 进程侧的远程后端实现。
//
// 网关进程内存里的状态（会话表 / PVF 缓存 / 代理监听端口 / 运行时配置）
// 无法被另一个进程直接读到，admin 进程通过网关的**内部 API**（默认 127.0.0.1:18080）
// 取得它。这里是那 4 个 httprouter 接口的 HTTP 实现。
//
// 安全前提（三选一都缺一不可）：
//  1. 内部 API 只绑 loopback（网关侧强制校验，非回环直接拒绝启动）；
//  2. 独立密钥 Admin.InternalKey（与前台 Admin.AuthKey 分开）；
//  3. 请求头 X-Internal-Key 用常量时间比较。
package backends

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"s4a21-gateway/pkg/httprouter"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/proxy"
)

// Client 是访问网关内部 API 的客户端。
type Client struct {
	baseURL string
	key     string
	http    *http.Client
}

// NewClient 构造内部 API 客户端。host 通常是 127.0.0.1。
func NewClient(host string, port int, key string) *Client {
	return &Client{
		baseURL: "http://" + net.JoinHostPort(host, strconv.Itoa(port)),
		key:     key,
		// 管理操作里有"重载端口表""重算 PVF 缓存"这类可能稍慢的动作，超时给宽一点
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// BaseURL 返回内部 API 基址（用于日志）。
func (c *Client) BaseURL() string { return c.baseURL }

// Ping 探测网关内部 API 是否可达（启动时自检用）。
func (c *Client) Ping() error {
	var out map[string]interface{}
	return c.do(http.MethodGet, "/internal/online?count_only=1", nil, &out)
}

// ApplyPorts 请求网关应用端口表（写文件 + 开/关监听），返回实际生效明细。
//
// 之所以由网关执行而不是 admin 自己写文件：真正的监听在网关进程里。
// 让唯一持有监听器的一方落盘并 apply，才不会出现"文件改了但监听没变"。
func (c *Client) ApplyPorts(cfg *proxy.ProxyPortConfig) (proxy.ReloadResult, error) {
	var result proxy.ReloadResult
	if err := c.do(http.MethodPost, "/internal/apply-ports", cfg, &result); err != nil {
		return proxy.ReloadResult{}, err
	}
	return result, nil
}

// do 发一次内部 API 请求。
//
// 响应体限制 8MB：在线名单可能较大，但也不该无上限地读。
func (c *Client) do(method, path string, body, out interface{}) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("序列化请求失败: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("X-Internal-Key", c.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("调用网关内部 API %s 失败: %w", path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("网关内部 API %s 返回 %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("解析网关内部 API %s 响应失败: %w", path, err)
		}
	}
	return nil
}

// ============================================================================
// 会话后端
// ============================================================================

type RemoteSessionBackend struct{ c *Client }

// NewRemoteSessionBackend 构造走内部 API 的会话后端。
func NewRemoteSessionBackend(c *Client) httprouter.SessionBackend {
	return &RemoteSessionBackend{c: c}
}

func (b *RemoteSessionBackend) List() ([]httprouter.OnlinePlayer, error) {
	var resp struct {
		Count   int                       `json:"count"`
		Players []httprouter.OnlinePlayer `json:"players"`
	}
	if err := b.c.do(http.MethodGet, "/internal/online", nil, &resp); err != nil {
		return nil, err
	}
	if resp.Players == nil {
		resp.Players = []httprouter.OnlinePlayer{}
	}
	return resp.Players, nil
}

func (b *RemoteSessionBackend) Kick(account string) (int, error) {
	var resp struct {
		Kicked int `json:"kicked"`
	}
	payload := map[string]interface{}{"account": account}
	if err := b.c.do(http.MethodPost, "/internal/kick", payload, &resp); err != nil {
		return 0, err
	}
	return resp.Kicked, nil
}

func (b *RemoteSessionBackend) KickNonAdmin(admins []string) (int, error) {
	if admins == nil {
		admins = []string{}
	}
	var resp struct {
		Kicked int `json:"kicked"`
	}
	payload := map[string]interface{}{"non_admin": true, "admins": admins}
	if err := b.c.do(http.MethodPost, "/internal/kick", payload, &resp); err != nil {
		return 0, err
	}
	return resp.Kicked, nil
}

func (b *RemoteSessionBackend) Count() (int, error) {
	var resp struct {
		Count int `json:"count"`
	}
	// count_only 让网关不必序列化整份在线名单
	if err := b.c.do(http.MethodGet, "/internal/online?count_only=1", nil, &resp); err != nil {
		return 0, err
	}
	return resp.Count, nil
}

// ============================================================================
// PVF 后端
// ============================================================================

type RemotePvfBackend struct{ c *Client }

// NewRemotePvfBackend 构造走内部 API 的 PVF 后端。
func NewRemotePvfBackend(c *Client) httprouter.PvfBackend {
	return &RemotePvfBackend{c: c}
}

func (b *RemotePvfBackend) Info() (httprouter.PvfView, error) {
	var v httprouter.PvfView
	if err := b.c.do(http.MethodGet, "/internal/pvf-info", nil, &v); err != nil {
		return httprouter.PvfView{}, err
	}
	return v, nil
}

func (b *RemotePvfBackend) Refresh() error {
	return b.c.do(http.MethodPost, "/internal/refresh-pvf", map[string]interface{}{}, nil)
}

// ============================================================================
// 端口后端
// ============================================================================

// RemotePortsBackend 走内部 API 读"实际监听状态"，并把"保存并生效"整体委托给网关。
//
// ⚠️ 为什么 admin **不自己写** proxy_ports.json（曾踩过）：
// 网关的 PortConfigStore 每秒轮询同一个文件（StartWatching）。若 admin 先落盘，
// 网关的 watcher 会在 2 秒内抢先把这次变更 apply 掉，随后 admin 再调内部
// apply-ports 时"要开的端口已经开好了" —— 返回的 ReloadResult 明细是空的，
// 管理页于是显示"没有变化"，而端口其实已经变了。报告与事实不符。
//
// 正确做法：唯一持有监听器的一方（网关）落盘 + apply，admin 只做"读回来"。
// 这样返回的明细与单进程模式下完全一致；网关不可达时 admin 也不会留下
// "文件改了但没生效"的半成品状态。
type RemotePortsBackend struct {
	c     *Client
	store *proxy.PortConfigStore
}

// NewRemotePortsBackend 构造走内部 API 的端口后端。
//
// store 是 admin 侧那个 onChange 为 nil 的实例：它只负责**读**配置
// （管理页 GET 用），不负责写。
func NewRemotePortsBackend(c *Client, store *proxy.PortConfigStore) httprouter.PortsBackend {
	return &RemotePortsBackend{c: c, store: store}
}

func (b *RemotePortsBackend) Active() (map[int]int, error) {
	var resp struct {
		Active map[int]int `json:"active"`
	}
	if err := b.c.do(http.MethodGet, "/internal/active-ports", nil, &resp); err != nil {
		return map[int]int{}, err
	}
	if resp.Active == nil {
		resp.Active = map[int]int{}
	}
	return resp.Active, nil
}

func (b *RemotePortsBackend) Connections() (map[int]int, error) {
	var resp struct {
		Connections map[int]int `json:"connections"`
	}
	if err := b.c.do(http.MethodGet, "/internal/active-ports", nil, &resp); err != nil {
		return map[int]int{}, err
	}
	if resp.Connections == nil {
		resp.Connections = map[int]int{}
	}
	return resp.Connections, nil
}

func (b *RemotePortsBackend) Apply(cfg *proxy.ProxyPortConfig) (proxy.ReloadResult, error) {
	if cfg == nil {
		return proxy.ReloadResult{}, fmt.Errorf("端口配置为空")
	}

	// ① 让网关落盘并真正开/关监听，拿回真实的"新开/关闭/失败"明细。
	result, err := b.c.ApplyPorts(cfg)
	if err != nil {
		return proxy.ReloadResult{}, err
	}

	// ② 把网关刚写好的文件读回本进程内存，让管理页 GET 立刻看到新值。
	//    只是 load()，不写盘、不触发任何 apply。
	if b.store != nil {
		if err := b.store.Reload(); err != nil {
			// 读回失败不影响"已经生效"这个事实，降级为提示，不上抛。
			return result, nil
		}
	}
	return result, nil
}

// ============================================================================
// 运行时配置后端
// ============================================================================

type RemoteRuntimeConfigBackend struct{ c *Client }

// NewRemoteRuntimeConfigBackend 构造走内部 API 的运行时配置后端。
func NewRemoteRuntimeConfigBackend(c *Client) httprouter.RuntimeConfigBackend {
	return &RemoteRuntimeConfigBackend{c: c}
}

type runtimeConfigResponse struct {
	// Launcher 直接复用 httprouter.LauncherView：json tag 与内部 API 一致，
	// 后端加字段时只改一处，不会出现「内部 API 返回了、远端结构没接」的漏接。
	Launcher      httprouter.LauncherView      `json:"launcher"`
	Maintenance   httprouter.MaintenanceView   `json:"maintenance"`
	RegisterLimit httprouter.RegisterLimitView `json:"register_limit"`
	Online        int                          `json:"online"`
}

func (b *RemoteRuntimeConfigBackend) fetch() (*runtimeConfigResponse, error) {
	var resp runtimeConfigResponse
	if err := b.c.do(http.MethodGet, "/internal/runtime-config", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (b *RemoteRuntimeConfigBackend) Launcher() (httprouter.LauncherView, error) {
	resp, err := b.fetch()
	if err != nil {
		return httprouter.LauncherView{}, err
	}
	return resp.Launcher, nil
}

func (b *RemoteRuntimeConfigBackend) SetLauncher(minVersion, downloadURL, updateNotice *string) (bool, error) {
	if minVersion == nil && downloadURL == nil && updateNotice == nil {
		return false, nil
	}
	body := map[string]interface{}{
		"launcher": map[string]interface{}{
			"min_version":   minVersion,
			"download_url":  downloadURL,
			"update_notice": updateNotice,
		},
	}
	var resp struct {
		Changed bool `json:"changed"`
	}
	if err := b.c.do(http.MethodPost, "/internal/runtime-config", body, &resp); err != nil {
		return false, err
	}
	return resp.Changed, nil
}

func (b *RemoteRuntimeConfigBackend) Maintenance() (httprouter.MaintenanceView, error) {
	resp, err := b.fetch()
	if err != nil {
		return httprouter.MaintenanceView{}, err
	}
	return resp.Maintenance, nil
}

func (b *RemoteRuntimeConfigBackend) SetMaintenance(enabled *bool, message *string, admins []string) (int, error) {
	if enabled == nil && message == nil && admins == nil {
		return 0, nil
	}
	m := map[string]interface{}{}
	if enabled != nil {
		m["enabled"] = *enabled
	}
	if message != nil {
		m["message"] = *message
	}
	if admins != nil {
		m["admin_accounts"] = admins
	}

	var resp struct {
		Kicked int `json:"kicked"`
	}
	if err := b.c.do(http.MethodPost, "/internal/runtime-config",
		map[string]interface{}{"maintenance": m}, &resp); err != nil {
		return 0, err
	}
	return resp.Kicked, nil
}

func (b *RemoteRuntimeConfigBackend) RegisterLimit() (httprouter.RegisterLimitView, error) {
	resp, err := b.fetch()
	if err != nil {
		return httprouter.RegisterLimitView{}, err
	}
	return resp.RegisterLimit, nil
}

func (b *RemoteRuntimeConfigBackend) SetRegisterLimit(enabled *bool, perIPPerDay, perMachine *int) (bool, error) {
	if enabled == nil && perIPPerDay == nil && perMachine == nil {
		return false, nil
	}
	m := map[string]interface{}{}
	if enabled != nil {
		m["enabled"] = *enabled
	}
	if perIPPerDay != nil {
		m["per_ip_per_day"] = *perIPPerDay
	}
	if perMachine != nil {
		m["per_machine"] = *perMachine
	}

	var resp struct {
		Changed bool `json:"changed"`
	}
	if err := b.c.do(http.MethodPost, "/internal/runtime-config",
		map[string]interface{}{"register_limit": m}, &resp); err != nil {
		return false, err
	}
	return resp.Changed, nil
}

// OnlineCount 返回网关侧的在线会话数（维护页用；与 Sessions.Count 同源）。
func (b *RemoteRuntimeConfigBackend) OnlineCount() (int, error) {
	resp, err := b.fetch()
	if err != nil {
		return 0, err
	}
	return resp.Online, nil
}

// ============================================================================
// 公告后端
// ============================================================================

// RemoteAnnounceBackend 把公告配置的读写与弹窗入队转发给网关。
//
// 为什么这三件事必须走网关（而事件查询/弹窗历史不用）：
//   - 公告配置有**两份状态** —— 库里的行，和网关内存里的快照。插件拉的是快照。
//     admin 直接写库会得到「后台显示已改，插件拉的还是旧的」这一静默失效。
//   - 弹窗队列的投递状态由网关的 pull 路径推进，绕过它没意义。
//
// 而 announce_events / announce_popups 的**读**是纯历史数据（只追加、不依赖内存），
// admin 直读自己的 db 句柄即可，不必把 8443 的可用性绑到 18080 上。
type RemoteAnnounceBackend struct{ c *Client }

// NewRemoteAnnounceBackend 构造走内部 API 的公告后端。
func NewRemoteAnnounceBackend(c *Client) httprouter.AnnounceBackend {
	return &RemoteAnnounceBackend{c: c}
}

func (b *RemoteAnnounceBackend) Config() (models.AnnounceConfig, error) {
	var resp struct {
		Config models.AnnounceConfig `json:"config"`
	}
	if err := b.c.do(http.MethodGet, "/internal/announce/config", nil, &resp); err != nil {
		return models.DefaultAnnounceConfig(), err
	}
	return resp.Config, nil
}

func (b *RemoteAnnounceBackend) UpdateConfig(cfg models.AnnounceConfig) (models.AnnounceConfig, error) {
	var resp struct {
		Config models.AnnounceConfig `json:"config"`
	}
	body := map[string]interface{}{"config": cfg}
	if err := b.c.do(http.MethodPost, "/internal/announce/config", body, &resp); err != nil {
		return cfg, err
	}
	return resp.Config, nil
}

func (b *RemoteAnnounceBackend) SendPopup(message string, mode int, createdBy string) (int64, error) {
	var resp struct {
		ID int64 `json:"id"`
	}
	payload := map[string]interface{}{
		"message":    message,
		"mode":       mode,
		"created_by": createdBy,
	}
	if err := b.c.do(http.MethodPost, "/internal/announce/popup", payload, &resp); err != nil {
		return 0, err
	}
	return resp.ID, nil
}
