package httprouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// ============================================================================
// 登录器插件下发（2026-09-30）
//
// 背景：登录器是 127.7 MiB 的单文件自包含 exe，12 个插件 DLL（合计 2.79 MiB）
// 以 <EmbeddedResource> 嵌在 exe 里。于是「改一个 300 KB 的插件，全体玩家要重下
// 127.7 MiB」，带宽放大 450 倍。
//
// 解法：把**可变内容**从 exe 里挪出去。网关出**权威清单**（有哪些插件、每个文件的
// sha256），字节按内容寻址按需拉取 —— 改一个插件只下那一个。
//
// ★ 为什么走 API 路由，而不是 wwwroot 静态文件：
//   双进程模式下 usePublicOnlyMiddleware 把玩家端口(8080)上所有非 /api 路径一律 404
//   （刻意不暴露后台页面），wwwroot 只在管理端口(8443)可见。
//   所以插件下载**必须**是 /api 路由。评估文档里"wwwroot 可直接当下载承载"那句
//   在双进程生产形态下不成立，以本文件为准。
//
// ★ 清单的权威性：
//   元数据（哪个是核心插件、默认开关、显示名、顺序）来自插件目录里的 plugins.json。
//   它缺失或条目非法时 → degraded=true 并在 messages 里说明，登录器据此**拒绝启动**。
//   这是刻意的失败方向：宁可拦住，也不让客户端拿一份"猜出来的"清单去改玩家游戏目录。
//
// ★ 字节的权威性由 sha256 保证，与来源无关：
//   清单里每个文件都带 sha256，由本进程现算（不读配置、不接受上传方声明）。
//   PluginBaseUrl 可以把字节挪到 CDN/对象存储，但清单与 hash 仍由网关出。
// ============================================================================

// pluginMetaFileName 是插件目录里的元数据文件名。
const pluginMetaFileName = "plugins.json"

// PluginManifest 是 GET /api/launcher/plugins 的响应体。
//
// 字段名刻意用 snake_case：登录器侧用 System.Text.Json 直接反序列化，
// 与 /api/launcher/policy 的既有口径一致（policy 的字段如 white_digest 也是 snake_case）。
type PluginManifest struct {
	OK bool `json:"ok"`

	// Enabled=false 表示插件下发被 Launcher.PluginEnabled 关掉了，
	// 登录器退回内置插件、不做任何下载（一键回滚开关，不必回滚 exe）。
	Enabled bool `json:"enabled"`

	// Degraded=true 表示清单**不可信**：plugins.json 缺失/条目非法/引用的文件不存在。
	// 此时 Plugins 里仍会给出"按目录推导"的结果供人工核对，但登录器必须拒绝启动。
	Degraded bool `json:"degraded"`

	// Revision 是清单内容的 sha256（只覆盖 plugins 数组），登录器用来判断"变没变"。
	// 与 Degraded 无关：即使退化也会算，便于观察。
	Revision string `json:"revision"`

	GeneratedUTC string `json:"generated_utc"`

	// FileBaseURL 非空时是插件字节的基址（CDN / 对象存储），
	// 空串表示"用你自己连的网关地址"（登录器拼 HttpBaseUrl + 相对 url）。
	FileBaseURL string `json:"file_base_url"`

	Plugins []PluginManifestEntry `json:"plugins"`

	// Messages 是退化原因等人类可读说明（只在非空时出现）。
	Messages []string `json:"messages,omitempty"`
}

// PluginManifestEntry 一个受管插件的完整描述。
//
// 字段与登录器 Plugins/PluginCatalog.cs 的 PluginInfo 一一对应 ——
// 改造后**清单是权威源**，客户端那份只作为首次冷启动的初始内容。
type PluginManifestEntry struct {
	Key         string `json:"key"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`

	// IsCore=true 表示加载链核心：恒部署、界面上不可关闭。
	IsCore bool `json:"is_core"`

	// DefaultEnabled 只在 IsCore=false 时有意义：首次出现时的默认勾选态。
	DefaultEnabled bool `json:"default_enabled"`

	// ConfigKind: "None"（勾选即生效）| "Configured"（需打开配置界面填参数）。
	// 未知值由登录器按 None 处理 —— 新增配置类型时才需要动客户端代码。
	ConfigKind string `json:"config_kind"`

	// Order 决定 GameGaurd.ini 的加载顺序，越小越先加载。
	// ★ GameNative 必须在依赖它的扩展之前，顺序错了插件会加载失败。
	Order int `json:"order"`

	Files []PluginManifestFile `json:"files"`
}

// PluginManifestFile 清单里的一个文件。Role 决定客户端把它部署到哪。
type PluginManifestFile struct {
	// Role: "dll"（插件本体）| "ini"（伴随配置模板）| "xui"（界面布局）。
	Role   string `json:"role"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// URL 由 handler 按 PluginBaseUrl 拼：绝对地址（CDN）或相对路径（走网关）。
	URL string `json:"url"`
}

// ----------------------------------------------------------------------------
// plugins.json —— 运维在插件目录里维护的元数据
// ----------------------------------------------------------------------------

type pluginMetaDoc struct {
	Version int               `json:"version"`
	Plugins []pluginMetaEntry `json:"plugins"`
}

type pluginMetaEntry struct {
	Key            string `json:"key"`
	DisplayName    string `json:"display_name"`
	Description    string `json:"description"`
	IsCore         bool   `json:"is_core"`
	DefaultEnabled bool   `json:"default_enabled"`
	ConfigKind     string `json:"config_kind"`
	Order          int    `json:"order"`

	// DLL 必填；Ini / Xui 可选（缺省表示该插件没有对应文件）。
	DLL string `json:"dll"`
	Ini string `json:"ini,omitempty"`
	Xui string `json:"xui,omitempty"`
}

// ----------------------------------------------------------------------------
// pluginStore：目录扫描 + sha256 缓存
// ----------------------------------------------------------------------------

// pluginSnapshot 是一次目录扫描的不可变结果。
//
// 用「目录签名」做缓存键：签名只包含 (name,size,mtime)，O(目录项) 且不读文件内容。
// 签名没变就直接返回缓存 —— 否则每次 GET 清单都要重算 2.8 MB 的 sha256。
type pluginSnapshot struct {
	sig      string
	degraded bool
	messages []string
	plugins  []PluginManifestEntry // Files[].URL 留空，由 handler 拼
	byName   map[string]string     // 文件名 -> sha256（下载 handler 的准入表）
	size     map[string]int64
	revision string
	builtUTC string
}

type pluginStore struct {
	dir string

	mu   sync.Mutex
	snap *pluginSnapshot
}

func newPluginStore(dir string) *pluginStore {
	d := strings.TrimSpace(dir)
	if d == "" {
		d = "./plugins"
	}
	return &pluginStore{dir: filepath.Clean(d)}
}

// Snapshot 返回当前目录对应的清单快照（带签名缓存）。
func (st *pluginStore) Snapshot() *pluginSnapshot {
	st.mu.Lock()
	defer st.mu.Unlock()

	sig := st.dirSignature()
	if st.snap != nil && st.snap.sig == sig {
		return st.snap
	}
	st.snap = st.build(sig)
	return st.snap
}

// Dir 返回插件目录（绝对路径用于下载 handler 做越权校验）。
func (st *pluginStore) Dir() string { return st.dir }

// dirSignature 计算目录签名：每个目录项的 name|size|mtime 排序后拼接。
//
// 目录不存在时返回 "<missing>" —— 它同样是一个合法的缓存键，
// 所以"先请求、后建目录"的场景会在建目录后自动重建（签名变了）。
func (st *pluginStore) dirSignature() string {
	entries, err := os.ReadDir(st.dir)
	if err != nil {
		return "<unreadable>"
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			// 读不到就把它当作"每次都可能变"：拼一个随机值让缓存必然失效。
			// 宁可慢，也不要拿一份陈旧的 hash 下发出去（校验失败=玩家进不去）。
			parts = append(parts, e.Name()+"|?"+"|?")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s|%d|%d", e.Name(), info.Size(), info.ModTime().UnixNano()))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// build 真正扫描目录并组装清单。调用方必须已持有 st.mu。
func (st *pluginStore) build(sig string) *pluginSnapshot {
	snap := &pluginSnapshot{
		sig:      sig,
		byName:   map[string]string{},
		size:     map[string]int64{},
		builtUTC: time.Now().UTC().Format(time.RFC3339),
	}

	entries, err := os.ReadDir(st.dir)
	if err != nil {
		snap.degraded = true
		snap.messages = append(snap.messages, fmt.Sprintf(
			"插件目录不可读：%s（请看 Launcher.PluginDir 配置与实际目录权限）", st.dir))
		snap.revision = revisionOf(nil)
		return snap
	}

	// 目录里实际存在的文件名集合（含非 DLL，供引用校验）。
	present := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			present[e.Name()] = true
		}
	}

	metaPath := filepath.Join(st.dir, pluginMetaFileName)
	rawMeta, metaErr := os.ReadFile(metaPath)

	var metas []pluginMetaEntry
	switch {
	case metaErr != nil:
		// 没有 plugins.json → 退化模式：按 *.dll 文件名推导一份"仅供参考"的清单。
		// 登录器见到 degraded 会拒绝启动，所以这份推导结果只用于人工核对。
		snap.degraded = true
		snap.messages = append(snap.messages, fmt.Sprintf(
			"缺少 %s：无法确定哪些插件是核心、默认开关与加载顺序，清单标记为 degraded", pluginMetaFileName))
		metas = degradedMetas(entries)
	default:
		var doc pluginMetaDoc
		if err := json.Unmarshal(rawMeta, &doc); err != nil {
			snap.degraded = true
			snap.messages = append(snap.messages, fmt.Sprintf("%s 不是合法 JSON：%v", pluginMetaFileName, err))
			metas = degradedMetas(entries)
		} else {
			metas = doc.Plugins
		}
	}

	// 空清单同样"没法用"：客户端拿不到加载链核心，游戏起不来。
	// 这是"整份文档"层面的性质，所以放在这里判，不进 checkMetaDoc。
	if len(metas) == 0 {
		snap.degraded = true
		snap.messages = append(snap.messages, "插件清单为空：至少需要一个插件，否则客户端拿不到加载链核心")
	}

	// 校验全部条目。★ 规则与后台保存期**共用同一份**（见 checkMetaDoc）：
	// 两边各写一份必然漂移，症状是"后台提示保存成功、清单却立刻 degraded"。
	problems := checkMetaDoc(present, metas)

	// 有问题的条目整条跳过，其余照常组装 —— 后台仍能看到目录里其余插件长什么样。
	// 而 degraded 一旦置位，登录器会拒绝启动。
	for i := range metas {
		if len(problems[i]) > 0 {
			snap.degraded = true
			for _, p := range problems[i] {
				snap.messages = append(snap.messages, fmt.Sprintf("%s 第 %d 条：%s", pluginMetaFileName, i+1, p))
			}
			continue
		}

		m := metas[i]
		key := strings.TrimSpace(m.Key)

		// 先算 hash 再组装：Files 的顺序即下发数组里的顺序，客户端按 role 取用。
		// dll 必填（已由 checkMetaDoc 保证存在），ini / xui 可选。
		var files []PluginManifestFile
		for _, ref := range []struct{ role, name string }{
			{"dll", m.DLL}, {"ini", m.Ini}, {"xui", m.Xui},
		} {
			name := strings.TrimSpace(ref.name)
			if name == "" {
				continue
			}
			sum, size, err := fileSHA256(filepath.Join(st.dir, name))
			if err != nil {
				// 校验过了仍可能读失败（文件恰在这两次读取之间被删或改了权限）。
				// 不能静默跳过：少一个文件的清单下发出去 = 客户端校验失败、进不去游戏。
				snap.degraded = true
				snap.messages = append(snap.messages, fmt.Sprintf("读取 %s 失败：%v", name, err))
				files = nil
				break
			}
			files = append(files, PluginManifestFile{
				Role: ref.role, Name: name, SHA256: sum, Size: size,
			})
		}
		if len(files) == 0 {
			continue
		}

		for _, f := range files {
			snap.byName[f.Name] = f.SHA256
			snap.size[f.Name] = f.Size
		}

		entry := PluginManifestEntry{
			Key:            key,
			DisplayName:    firstNonEmpty(m.DisplayName, key),
			Description:    m.Description,
			IsCore:         m.IsCore,
			DefaultEnabled: m.DefaultEnabled,
			ConfigKind:     normalizeConfigKind(m.ConfigKind),
			Order:          m.Order,
			Files:          files,
		}
		// 核心插件必然部署，DefaultEnabled 只是界面上那个勾选态的初始值，
		// 让它在数据层就一致，免得客户端要为"核心却默认关闭"再造一条特例。
		if entry.IsCore {
			entry.DefaultEnabled = true
		}

		snap.plugins = append(snap.plugins, entry)
	}

	// 稳定排序：Order 升序，同 Order 按 Key。
	// 下发顺序 = GameGaurd.ini 的加载顺序（登录器直接沿用数组顺序），
	// 所以这里必须确定，不能依赖目录扫描的返回顺序。
	sort.SliceStable(snap.plugins, func(a, b int) bool {
		if snap.plugins[a].Order != snap.plugins[b].Order {
			return snap.plugins[a].Order < snap.plugins[b].Order
		}
		return snap.plugins[a].Key < snap.plugins[b].Key
	})

	// 一份**没有任何核心插件**的清单在实践中必然是错的：登录器的加载链
	// （az / GameGaurd / GameNative 那一串）必须恒部署，否则游戏起不来。
	//
	// 这里刻意**不硬编码插件名**（那会变成"客户端语义散落在网关"，两边一旦不同步
	// 就是静默错配），只判"一个都没有"这个纯结构性质。它同时让后台生成的草稿
	// （全部非核心）无法被误当成成品直接上线。
	if len(snap.plugins) > 0 {
		hasCore := false
		for _, p := range snap.plugins {
			if p.IsCore {
				hasCore = true
				break
			}
		}
		if !hasCore {
			snap.degraded = true
			snap.messages = append(snap.messages,
				"清单里没有任何核心插件（is_core=true）：客户端的加载链会不完整，游戏起不来")
		}
	}

	snap.revision = revisionOf(snap.plugins)
	return snap
}

// degradedMetas 在缺少 plugins.json 时按目录里的 *.dll 推导一份**仅供参考**的清单。
//
// 刻意全部标成"可选 + 默认关闭 + 非核心"：不能让一份推导结果意外地把某个插件
// 变成恒部署。它唯一的作用是让人在后台看到"目录里有哪些 DLL 还没登记"。
func degradedMetas(entries []os.DirEntry) []pluginMetaEntry {
	var out []pluginMetaEntry
	i := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".dll") {
			continue
		}
		i++
		out = append(out, pluginMetaEntry{
			Key:         strings.TrimSuffix(name, filepath.Ext(name)),
			DisplayName: name,
			Description: "（未登记：本条目由网关按目录文件名推导，请补 plugins.json）",
			Order:       900 + i,
			DLL:         name,
			ConfigKind:  "None",
		})
	}
	return out
}

// checkMetaDoc 校验一份元数据文档，返回「条目下标 -> 问题列表」。
// 返回空 map（或所有值都为空）表示整份文档合法。
//
// ★ 扫描期（build）与后台保存期共用这一份规则。
//   两边各写一份必然漂移，症状是「后台提示保存成功，但清单立刻变 degraded」——
//   运维会以为是缓存没刷新，实际是两套校验对同一份数据给了不同结论。
//
// present 是插件目录里实际存在的文件名集合。本函数**只读**它，不做任何 IO
//（hash 由调用方按需计算），因此保存期可以在落盘前先跑一遍。
func checkMetaDoc(present map[string]bool, metas []pluginMetaEntry) map[int][]string {
	problems := map[int][]string{}
	add := func(idx int, format string, args ...interface{}) {
		problems[idx] = append(problems[idx], fmt.Sprintf(format, args...))
	}

	seenKey := map[string]bool{}
	seenFile := map[string]bool{}

	for i, m := range metas {
		key := strings.TrimSpace(m.Key)
		dll := strings.TrimSpace(m.DLL)

		if key == "" || dll == "" {
			add(i, "缺少 key 或 dll")
			continue
		}
		if seenKey[strings.ToLower(key)] {
			add(i, "key 重复：%s", key)
			continue
		}
		seenKey[strings.ToLower(key)] = true

		for _, ref := range []struct{ role, name string }{
			{"dll", dll}, {"ini", m.Ini}, {"xui", m.Xui},
		} {
			name := strings.TrimSpace(ref.name)
			if name == "" {
				continue
			}
			if !validPluginFileName(name) {
				add(i, "%s 文件名非法：%q", ref.role, name)
				// 非法名不进 seenFile：让它继续被别处引用时报"不在目录里"，
				// 而不是被误判成"重复引用"。
				continue
			}
			if !present[name] {
				add(i, "%s 引用的文件不在插件目录里：%s", ref.role, name)
				continue
			}
			if seenFile[name] {
				add(i, "文件被重复引用：%s", name)
				continue
			}
			seenFile[name] = true
		}
	}
	return problems
}

// validPluginFileName 只接受"扁平文件名"：不含路径分隔符、不是 . / ..
//
// 这道校验在扫描期与下载期都要过。虽然下载 handler 是查表（天然没有穿越），
// 但扫描期放行一个 "..\\evil.dll" 会让它进 byName，从而被 http.ServeFile 读到目录外。
func validPluginFileName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	// Windows 保留字符，防御性拦截（网关跑 Linux，但清单会被 Windows 侧登录器消费）
	if strings.ContainsAny(name, `:*?"<>|`) {
		return false
	}
	for _, r := range name {
		if r < 0x20 {
			return false
		}
	}
	return true
}

func normalizeConfigKind(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "Configured") {
		return "Configured"
	}
	return "None"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// fileSHA256 流式算文件摘要，避免把小文件读进内存（虽然只有几百 KB，口径统一）。
func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// revisionOf 是清单内容的稳定摘要。
//
// 直接对 entries 做 json.Marshal：Go 的结构体字段顺序固定、切片顺序由上面 sort 保证，
// 所以同一份清单永远得到同一个 revision。登录器用它做"清单变没变"的判断。
func revisionOf(entries []PluginManifestEntry) string {
	if entries == nil {
		entries = []PluginManifestEntry{}
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pluginFileURL 拼单个文件的下载地址。
//
// base 为空 → 相对路径，登录器用自己配置的网关地址（含 TLS 开关）拼，
// 这样 scheme 由客户端决定，不会出现"网关以为自己是 http、实际跑在 TLS 后"的错配。
func pluginFileURL(base, name string) string {
	if strings.TrimSpace(base) == "" {
		return "/api/launcher/plugins/file/" + url.PathEscape(name)
	}
	return strings.TrimRight(base, "/") + "/" + url.PathEscape(name)
}

// ============================================================================
// handlers
// ============================================================================

// handleLauncherPlugins 下发权威插件清单（公开只读）。
func (s *Server) handleLauncherPlugins(w http.ResponseWriter, r *http.Request) {
	// 总开关关闭：仍然 200，但 enabled=false。
	// 登录器据此退回内置插件 —— 这是"插件下发坏了"时的一键回滚，不必回滚 exe。
	if !s.config.LauncherPluginEnabled() {
		writeJSON(w, http.StatusOK, PluginManifest{
			OK:      true,
			Enabled: false,
			Plugins: []PluginManifestEntry{},
			Messages: []string{
				"插件下发已由服务端关闭（Launcher.PluginEnabled=false），客户端使用内置插件",
			},
			GeneratedUTC: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	if s.plugins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok":      false,
			"message": "插件下发未初始化",
		})
		return
	}

	snap := s.plugins.Snapshot()
	base := strings.TrimSpace(s.config.Launcher.PluginBaseUrl)

	// 逐个补上 url。深拷贝 Files 切片，避免把带 url 的副本写回缓存快照。
	plugins := make([]PluginManifestEntry, 0, len(snap.plugins))
	for _, p := range snap.plugins {
		cp := p
		cp.Files = make([]PluginManifestFile, len(p.Files))
		for i, f := range p.Files {
			f.URL = pluginFileURL(base, f.Name)
			cp.Files[i] = f
		}
		plugins = append(plugins, cp)
	}

	writeJSON(w, http.StatusOK, PluginManifest{
		OK:           true,
		Enabled:      true,
		Degraded:     snap.degraded,
		Revision:     snap.revision,
		GeneratedUTC: snap.builtUTC,
		FileBaseURL:  base,
		Plugins:      plugins,
		Messages:     snap.messages,
	})
}

// handleLauncherPluginFile 下发单个插件文件。
//
// 准入表 = 当前清单里的文件名。不在表里一律 404 ——
// 这样目录里的"没登记的杂项文件"不会经这个接口外泄。
func (s *Server) handleLauncherPluginFile(w http.ResponseWriter, r *http.Request) {
	if s.plugins == nil {
		http.NotFound(w, r)
		return
	}

	name := mux.Vars(r)["name"]
	if !validPluginFileName(name) {
		http.NotFound(w, r)
		return
	}

	snap := s.plugins.Snapshot()
	sum, ok := snap.byName[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	absDir, err := filepath.Abs(s.plugins.Dir())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	absPath, err := filepath.Abs(filepath.Join(absDir, name))
	if err != nil || !strings.HasPrefix(absPath, absDir+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}

	// ★ 刻意 no-store：登录器自己有 sha256 内容寻址缓存（命中就根本不发请求），
	// 服务端再做 HTTP 缓存只会引入"中间层留着旧字节、客户端校验失败却一直重试"的风险。
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"`+sum+`"`)
	// 便于线上对拍"客户端下的到底是哪一份"
	w.Header().Set("X-Content-SHA256", sum)
	tw, release, ok := s.dl.Begin(w, r)
	if !ok {
		return
	}
	defer release()
	http.ServeFile(tw, r, absPath)
}
