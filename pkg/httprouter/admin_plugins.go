package httprouter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// 管理后台：插件管理（2026-09-30，配合登录器插件增量更新）
//
// 与 launcher_plugins.go 的分工：
//   launcher_plugins.go —— 面向**登录器**的只读下发（清单 + 文件字节）
//   本文件              —— 面向**运维**的读写（上传 / 删除 / 编辑元数据）
//
// ★ 为什么不需要 backends 抽象（不像端口表 / 维护模式那样必须走网关）：
//   这里打交道的全是**文件系统**，两个进程(网关 8080 / admin 8443)共用同一个目录。
//   admin 写完文件，网关进程下一次收到 /api/launcher/plugins 时按目录签名自动重扫
//   （见 pluginStore.Snapshot）。不存在"改了 admin 内存却不影响网关"那类错位。
//
// ★ 部署前提：两个进程的 WorkingDirectory 必须一致，否则 "./plugins" 会解析到
//   两个不同的目录（admin 传上去的文件，网关看不见）。与 Pvf.FilePath 是同一个前提。
// ============================================================================

// maxPluginFileBytes 单个插件文件的上传上限。
//
// 取 7 MiB 而不是 8 MiB：withBodyLimit 的全局上限是 8 MiB，而 multipart 还有
// boundary / header 的开销。留 1 MiB 余量，保证"文件本身合法"时不会因为信封开销
// 被 MaxBytesReader 拦掉（那种失败对运维来说极难理解）。
//
// 现状最大插件是 CombatPower.dll（753 KB），7 MiB 有 9 倍余量。
// 刻意**不进** uploadPaths 白名单：插件远小于全局上限，不需要放宽。
const maxPluginFileBytes = 7 << 20

// pluginFileRow 后台列表里的一行（一个目录内的文件）。
type pluginFileRow struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ModifiedUTC string `json:"modified_utc"`

	// Referenced=true 表示该文件被 plugins.json 引用（会下发给登录器）。
	// Referenced=false 的文件既不下发也不能经下载接口取走，只在后台可见。
	Referenced bool   `json:"referenced"`
	Role       string `json:"role,omitempty"` // dll | ini | xui
}

// pluginDirScan 扫描插件目录，算每个文件的 sha256 并标注引用情况。
func (s *Server) pluginDirScan(dir string, metas []pluginMetaEntry) ([]pluginFileRow, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{fmt.Sprintf("插件目录不可读：%s（%v）", dir, err)}
	}

	// 引用关系：文件名 -> role
	refs := map[string]string{}
	for _, m := range metas {
		for _, r := range []struct{ role, name string }{
			{"dll", m.DLL}, {"ini", m.Ini}, {"xui", m.Xui},
		} {
			n := strings.TrimSpace(r.name)
			if n != "" {
				refs[n] = r.role
			}
		}
	}

	var rows []pluginFileRow
	for _, e := range entries {
		if e.IsDir() || e.Name() == pluginMetaFileName {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(dir, e.Name())
		sum, size, err := fileSHA256(path)
		if err != nil {
			// 单个文件读不动不该让整个列表失败 —— 把它列出来、hash 留空，
			// 比"后台整页报错、运维看不到其它文件"有用得多。
			rows = append(rows, pluginFileRow{
				Name: e.Name(), Size: info.Size(), SHA256: "",
				ModifiedUTC: info.ModTime().UTC().Format(time.RFC3339),
			})
			continue
		}
		role, referenced := refs[e.Name()]
		rows = append(rows, pluginFileRow{
			Name:        e.Name(),
			Size:        size,
			SHA256:      sum,
			ModifiedUTC: info.ModTime().UTC().Format(time.RFC3339),
			Referenced:  referenced,
			Role:        role,
		})
	}

	sort.Slice(rows, func(a, b int) bool { return rows[a].Name < rows[b].Name })
	return rows, nil
}

// readMetaDoc 读 plugins.json；文件不存在时返回空文档 + exists=false。
//
// 读失败/解析失败**如实上报**（error 非空），不静默回退成空文档 ——
// 否则后台会把"看起来正常"的空清单保存回去，把线上真正在跑的清单覆盖掉。
func (s *Server) readMetaDoc(dir string) (pluginMetaDoc, bool, error) {
	path := filepath.Join(dir, pluginMetaFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return pluginMetaDoc{Version: 1}, false, nil
		}
		return pluginMetaDoc{}, false, err
	}
	var doc pluginMetaDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return pluginMetaDoc{}, true, fmt.Errorf("%s 不是合法 JSON：%w", pluginMetaFileName, err)
	}
	if doc.Version <= 0 {
		doc.Version = 1
	}
	return doc, true, nil
}

// handleAdminPluginsList 插件管理页的数据源：目录文件 + 当前元数据 + 下发状态。
func (s *Server) handleAdminPluginsList(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.plugins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok": false, "message": "插件下发未初始化",
		})
		return
	}

	dir := s.plugins.Dir()
	doc, metaExists, metaErr := s.readMetaDoc(dir)

	var messages []string
	if metaErr != nil {
		messages = append(messages, metaErr.Error())
	}

	metas := doc.Plugins
	if metaErr != nil {
		// 元数据坏了：不给前端一份"看起来能编辑"的清单，避免它被保存回去覆盖掉。
		metas = nil
	}

	rows, scanErrs := s.pluginDirScan(dir, metas)
	messages = append(messages, scanErrs...)

	// 未登记的文件：目录里有、但清单没引用。它们不会被下发。
	var unregistered []string
	for _, row := range rows {
		if !row.Referenced {
			unregistered = append(unregistered, row.Name)
		}
	}

	// 与登录器看到的一致：这里也算一遍 degraded，方便运维在后台直接看到
	// "登录器会因为什么拒绝启动"。
	snap := s.plugins.Snapshot()

	resp := map[string]interface{}{
		"ok":              true,
		"dir":             dir,
		"plugins_enabled": s.config.LauncherPluginEnabled(),
		"meta_exists":     metaExists,
		"meta":            doc,
		"files":           rows,
		"unregistered":    unregistered,
		"degraded":        snap.degraded,
		"revision":        snap.revision,
		"downstream_count": len(snap.plugins),
		"plugin_base_url": strings.TrimSpace(s.config.Launcher.PluginBaseUrl),
	}
	if len(messages) > 0 {
		resp["messages"] = messages
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAdminPluginUpload 上传一个插件文件（multipart，字段名 file）。
//
// 覆盖已存在文件是**正常操作**（更新插件就是覆盖）。用原子写：临时文件 + rename，
// 保证网关进程任何时刻读到的都是完整文件 —— 否则可能把半截 DLL 算进 sha256 下发出去。
func (s *Server) handleAdminPluginUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.plugins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok": false, "message": "插件下发未初始化",
		})
		return
	}

	// 内存阈值取 8 MiB：单文件上限 7 MiB，超出的部分由标准库落临时文件。
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "表单解析失败：" + err.Error(),
		})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "缺少文件字段 file",
		})
		return
	}
	defer file.Close()

	// 浏览器（尤其 IE）会把完整路径塞进 filename，且分隔符可能是任一平台的。
	// 先切掉路径部分，再过白名单 —— 只靠白名单不够（"evil.dll" 本身是合法名，
	// 不带路径的它本来就允许上传）。
	//
	// ★ 刻意**不用** filepath.Base：Linux 不把 `\` 当分隔符，于是 `..\evil.dll`
	//   在本机(Windows)测试里是 "evil.dll"、在线上(Linux)却是 "..\evil.dll" ——
	//   测试全绿而线上行为不同，正是这类差异最难排查。两种分隔符都切一刀，
	//   本机与线上行为就一致了。
	name := header.Filename
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if !validPluginFileName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": fmt.Sprintf("文件名不合法：%q（只允许扁平文件名）", header.Filename),
		})
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, maxPluginFileBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "读取上传内容失败：" + err.Error(),
		})
		return
	}
	if int64(len(data)) > maxPluginFileBytes {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": fmt.Sprintf("文件超过 %d MiB 上限", maxPluginFileBytes>>20),
		})
		return
	}
	if len(data) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "文件内容为空",
		})
		return
	}

	dir := s.plugins.Dir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "创建插件目录失败：" + err.Error(),
		})
		return
	}

	path := filepath.Join(dir, name)
	if err := atomicWriteFile(path, data, 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "写入失败：" + err.Error(),
		})
		return
	}

	sum := sha256.Sum256(data)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "message": fmt.Sprintf("已上传 %s", name),
		"name": name, "size": len(data), "sha256": hex.EncodeToString(sum[:]),
		"hint": "若要让登录器真正下发它，还需在下方元数据里引用该文件",
	})
}

// handleAdminPluginDelete 删除插件目录里的一个文件。
//
// 默认拒绝删除"仍被元数据引用"的文件：删了它，清单立刻 degraded，登录器全体拒绝启动。
// 想删就必须先改元数据（或显式 force）。
func (s *Server) handleAdminPluginDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.plugins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok": false, "message": "插件下发未初始化",
		})
		return
	}

	var body struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "参数不完整（需要 name）",
		})
		return
	}

	name := strings.TrimSpace(body.Name)
	if !validPluginFileName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "文件名不合法",
		})
		return
	}
	if name == pluginMetaFileName {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "元数据文件请用「保存清单」，不要直接删除",
		})
		return
	}

	dir := s.plugins.Dir()
	doc, _, metaErr := s.readMetaDoc(dir)
	if metaErr == nil && !body.Force {
		for _, m := range doc.Plugins {
			for _, n := range []string{m.DLL, m.Ini, m.Xui} {
				if strings.TrimSpace(n) == name {
					writeJSON(w, http.StatusBadRequest, map[string]interface{}{
						"ok": false,
						"message": fmt.Sprintf("%s 仍被清单引用（key=%s）。先把它从元数据里去掉，"+
							"否则清单会立刻 degraded、登录器全体拒绝启动。", name, m.Key),
					})
					return
				}
			}
		}
	}

	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"ok": false, "message": "文件不存在：" + name,
		})
		return
	}
	if err := os.Remove(path); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "删除失败：" + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "message": fmt.Sprintf("已删除 %s", name),
	})
}

// handleAdminPluginMetaSave 保存 plugins.json。
//
// ★ 保存前**必须**校验通过：这是"后台能保存、保存完却 degraded"的唯一防线，
//   而校验规则与扫描期共用 checkMetaDoc，两边不会给出不同结论。
func (s *Server) handleAdminPluginMetaSave(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdmin(w, r) {
		return
	}
	if s.plugins == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"ok": false, "message": "插件下发未初始化",
		})
		return
	}

	var doc pluginMetaDoc
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "清单格式错误：" + err.Error(),
		})
		return
	}
	if doc.Version <= 0 {
		doc.Version = 1
	}
	if len(doc.Plugins) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok":      false,
			"message": "清单不能为空：至少需要一个插件，否则客户端拿不到加载链核心",
		})
		return
	}

	dir := s.plugins.Dir()

	// 目录里实际存在的文件（校验引用的依据）
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "插件目录不可读：" + err.Error(),
		})
		return
	}
	present := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			present[e.Name()] = true
		}
	}

	problems := checkMetaDoc(present, doc.Plugins)
	if len(problems) > 0 {
		var list []string
		for i := range doc.Plugins {
			for _, p := range problems[i] {
				list = append(list, fmt.Sprintf("第 %d 条：%s", i+1, p))
			}
		}
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"ok": false, "message": "清单校验未通过，未保存", "problems": list,
		})
		return
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "创建插件目录失败：" + err.Error(),
		})
		return
	}

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "序列化失败：" + err.Error(),
		})
		return
	}
	raw = append(raw, '\n')

	if err := atomicWriteFile(filepath.Join(dir, pluginMetaFileName), raw, 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"ok": false, "message": "写入失败：" + err.Error(),
		})
		return
	}

	snap := s.plugins.Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "message": "已保存，登录器下次请求即生效（无需重启网关）",
		"revision": snap.revision, "degraded": snap.degraded,
		"downstream_count": len(snap.plugins),
	})
}

// ★ 2026-09-30 移除 handleAdminPluginMetaDraft（按目录生成清单草稿）。
//
// 移除原因（安南报的真实误操作）：它按目录里的 *.dll 重新推导一份清单并**整体覆盖**
// plugins.json，且每条都写成"非核心 + 默认关闭"。后台点错一次，就要手工把 12 条的
// 顺序与核心标记全部重排回来 —— 而顺序错了插件根本不加载，登录器加载链也会断。
//
// 首次部署的清单以仓库里的 plugins/plugins.json 为准（受版本控制、可 review、可回滚），
// 不再由后台从目录结构反推。
//
// ★ degradedMetas 本身**保留**：launcher_plugins.go 在"缺 plugins.json / 清单非法"时
//   仍用它给登录器推一份仅供参考的降级清单 —— 那是运行期兜底，与这个后台按钮无关。

// atomicWriteFile 原子写：同目录临时文件 → fsync → rename。
//
// 为什么必须原子：网关进程随时可能正在读这些文件（算 sha256 下发）。
// 直接 os.WriteFile 会让它在写入过程中读到**半截**内容，把错误的 sha256
// 下发给登录器 —— 表现是客户端校验失败、全体拒绝启动。
//
// 临时文件刻意放在同目录：rename 只有同文件系统内才是原子的，
// 放 /tmp 再 rename 会变成"复制 + 删除"，反而更长地暴露中间态。
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-plugin-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// 失败路径清掉临时文件。成功路径下 rename 之后这里已不存在，忽略报错即可。
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
