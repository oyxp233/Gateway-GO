package service

// ============================================================================
// DNF.EXE 增量更新分发（2026-10-25）
//
// 背景：DNF.EXE 是游戏客户端主程序（~20 MB），每次更新玩家要重下全量。
// 与登录器自更新（LauncherUpdateService）同构：复用 A21D（通用文件差分）
// 做 exe 级增量，玩家从「等几十秒」变成「约 1 秒」。
//
// 与登录器增量（LauncherUpdateService）同构但**独立实现**，不共用状态：
//   - 存储独立：dnfexe_update/ 目录（current.exe + history/ + delta/）；
//   - 无网关内存依赖：与插件目录同模式，gateway(8080) 下发、admin(8443) 上传
//     两个进程各持一份实例共用目录 —— 不需要 backends 抽象，重启不丢状态。
//     ★ 两进程缓存一致性靠 currentStamp（size+mtime 签名）解决：
//     admin 进程替换 current.exe 后，网关进程下一次请求 stat 发现签名变了
//     自动重算指纹 —— 不需要跨进程通知。
//
// 安全边界（与登录器/PVF delta 同一条底线）：
//   - delta 包只含「从旧 exe 拷贝哪些区间」+「原样字面量」；
//   - 登录器合成产物必须过整文件 SHA-256 == 清单 hash 才会替换本地 exe，
//     任何一步失败保留旧文件 —— 网关侧无论发什么，都改不了这条判据。
// ============================================================================

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/pvfdiff"
	"s4a21-gateway/pkg/security"
	"s4a21-gateway/pkg/utils"
)

// dnfExeCurrentName 是当前版本全量 exe 在 UpdateDir 里的固定文件名。
const dnfExeCurrentName = "current.exe"

// dnfExeCurrentCache 是当前版的进程内缓存（与 launcherCurrentCache 同构）。
//
// ★ 缓存必须带 stamp（current.exe 的 size+mtime 签名）而不是无脑信任：
// 双进程共用目录，admin 进程上传新 exe 不会通知到网关进程 —— 没有签名校验的话，
// 网关会拿着旧 hash 的清单继续下发，玩家「更新完发现还要更新」。
type dnfExeCurrentCache struct {
	entry models.DnfExeBuildEntry
	stamp string
}

// DnfExeUpdateService 是 DNF.EXE 增量更新分发服务。
//
// 与 LauncherUpdateService 同构：同样的缓存 + stamp + 按需增量 + 网关间同步能力。
type DnfExeUpdateService struct {
	config *config.GatewayConfig
	logger *logger.ConsoleLogger

	// mu 保护 cur（当前版缓存）。读路径：cachedCurrent / Current。
	mu sync.RWMutex
	// cur == nil 表示未加载；entry.Hash == "" 表示目录里还没有 current.exe。
	cur *dnfExeCurrentCache

	// histMu 只保护 history/index.json 的读-改-写（与 mu 互不嵌套）。
	histMu sync.Mutex

	// deltaGroup 合并「同一个 from 的并发按需增量生成」。
	deltaGroup keyedGroup
}

// NewDnfExeUpdateService 创建 DNF.EXE 更新分发服务。
func NewDnfExeUpdateService(cfg *config.GatewayConfig, lg *logger.ConsoleLogger) *DnfExeUpdateService {
	return &DnfExeUpdateService{config: cfg, logger: lg}
}

// Enabled 返回 DNF.EXE 自更新总开关的生效值。
func (s *DnfExeUpdateService) Enabled() bool {
	return s.config.DnfExeUpdateEnabled()
}

// UpdateDir 返回 DNF.EXE 更新分发根目录（相对路径按网关运行目录解析）。
func (s *DnfExeUpdateService) UpdateDir() string {
	dir := strings.TrimSpace(s.config.DnfExe.UpdateDir)
	if dir == "" {
		dir = "./dnfexe_update"
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// historyDir 历史版本目录。
func (s *DnfExeUpdateService) historyDir() string {
	return filepath.Join(s.UpdateDir(), "history")
}

// deltaDir 按需增量缓存目录。
func (s *DnfExeUpdateService) deltaDir() string {
	return filepath.Join(s.UpdateDir(), "delta")
}

// CurrentPath 返回当前版全量 exe 的绝对路径（供全量下载 handler 用）。
func (s *DnfExeUpdateService) CurrentPath() string {
	return filepath.Join(s.UpdateDir(), dnfExeCurrentName)
}

// updateKeep 历史保留版数上限。
func (s *DnfExeUpdateService) updateKeep() int {
	if s.config.DnfExe.UpdateKeep > 0 {
		return s.config.DnfExe.UpdateKeep
	}
	return 8
}

// currentStamp 拿 current.exe 的 size+mtime 签名。文件不存在返回空串。
func (s *DnfExeUpdateService) currentStamp() string {
	st, err := os.Stat(s.CurrentPath())
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d|%d", st.Size(), st.ModTime().UnixNano())
}

// cachedCurrent 只读缓存（不刷新、不触发 IO）。持 histMu 时唯一可用的读法。
func (s *DnfExeUpdateService) cachedCurrent() *models.DnfExeBuildEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return nil
	}
	cp := s.cur.entry
	return &cp
}

// refreshCurrent 重算当前版（current.exe 指纹 + 索引里的版本信息）并写缓存。
func (s *DnfExeUpdateService) refreshCurrent() {
	path := s.CurrentPath()
	var entry models.DnfExeBuildEntry
	if utils.FileExists(path) {
		if hash, err := security.ComputeFileFingerprintPath(path); err == nil {
			entry.Hash = hash
			if stats, _ := utils.GetFileStats(path); stats != nil {
				entry.Size = stats.Size
			}
			s.histMu.Lock()
			meta := s.versionOfLocked(hash)
			s.histMu.Unlock()
			entry.Version = meta.Version
			entry.Name = meta.Name
			entry.Filename = meta.Filename
			entry.StoredUtc = meta.StoredUtc
			entry.AuthorityRevision = meta.AuthorityRevision
		} else {
			s.logger.Warn("DNF.EXE 当前版指纹计算失败: " + err.Error())
		}
	}
	s.mu.Lock()
	s.cur = &dnfExeCurrentCache{entry: entry, stamp: s.currentStamp()}
	s.mu.Unlock()
}

// Current 返回当前版描述。缓存有效（签名一致）直接回；签名变了重算。
// 目录里没有 current.exe 时返回 Hash 为空的条目（清单据此下发「无版本信息」，
// 登录器跳过检查 —— fail-safe 方向：永远不因为缺数据拦玩家）。
func (s *DnfExeUpdateService) Current() *models.DnfExeBuildEntry {
	stamp := s.currentStamp()
	if stamp != "" {
		s.mu.RLock()
		cur := s.cur
		s.mu.RUnlock()
		if cur != nil && cur.entry.Hash != "" && cur.stamp == stamp {
			cp := cur.entry
			return &cp
		}
	}
	s.refreshCurrent()
	return s.cachedCurrent()
}

const dnfExeHistoryIndexName = "index.json"

// loadHistoryIndexLocked 读历史索引（文件不存在 → nil）。调用方须持有 histMu。
func (s *DnfExeUpdateService) loadHistoryIndexLocked() []models.DnfExeBuildEntry {
	raw, err := os.ReadFile(filepath.Join(s.historyDir(), dnfExeHistoryIndexName))
	if err != nil {
		return nil
	}
	var entries []models.DnfExeBuildEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		s.logger.Warn("DNF.EXE 历史索引不可读（按空处理）: " + err.Error())
		return nil
	}
	return entries
}

// saveHistoryIndexLocked 原子写历史索引。调用方须持有 histMu。
func (s *DnfExeUpdateService) saveHistoryIndexLocked(entries []models.DnfExeBuildEntry) error {
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	dir := s.historyDir()
	if err := utils.MkdirAll(dir); err != nil {
		return err
	}
	final := filepath.Join(dir, dnfExeHistoryIndexName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// versionOfLocked 从历史索引里查某个 hash 的记录。调用方须持有 histMu。
func (s *DnfExeUpdateService) versionOfLocked(hash string) models.DnfExeBuildEntry {
	for _, e := range s.loadHistoryIndexLocked() {
		if strings.EqualFold(e.Hash, hash) {
			return e
		}
	}
	return models.DnfExeBuildEntry{}
}

// dnfExeVersionLabel 给日志/展示用的版本号标签。
//
// DNF.EXE 的 version 选填，空串时不能打成「（v）」这种半截字符串 ——
// 运维看日志会以为版本号解析坏了。
func dnfExeVersionLabel(v string) string {
	if strings.TrimSpace(v) == "" {
		return "版本号未登记"
	}
	return "v" + v
}

// archiveHistory 把一份 DNF.EXE 存进历史（内容寻址）。
// 已有同 hash 记录则跳过（不覆盖既有备注），返回是否新增。
func (s *DnfExeUpdateService) archiveHistory(path, version, name, filename string) (bool, error) {
	hash, err := security.ComputeFileFingerprintPath(path)
	if err != nil {
		return false, err
	}
	stats, _ := utils.GetFileStats(path)

	dir := s.historyDir()
	if err := utils.MkdirAll(dir); err != nil {
		return false, err
	}
	dst := filepath.Join(dir, hash+".exe")
	if !utils.FileExists(dst) {
		tmp := dst + ".tmp"
		if err := utils.CopyFile(path, tmp); err != nil {
			os.Remove(tmp)
			return false, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return false, err
		}
	}

	s.histMu.Lock()
	defer s.histMu.Unlock()
	entries := s.loadHistoryIndexLocked()
	for _, e := range entries {
		if strings.EqualFold(e.Hash, hash) {
			return false, nil // 已在历史：文件与记录都不动
		}
	}
	entry := models.DnfExeBuildEntry{
		Hash:              hash,
		StoredUtc:         time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		Version:           strings.TrimSpace(version),
		Name:              strings.TrimSpace(name),
		Filename:          strings.TrimSpace(filename),
		AuthorityRevision: s.nextAuthorityRevisionLocked(),
	}
	if stats != nil {
		entry.Size = stats.Size
	}
	entries = append(entries, entry)
	entries = s.pruneHistoryLocked(entries)
	if err := s.saveHistoryIndexLocked(entries); err != nil {
		return false, err
	}
	s.logger.Info(fmt.Sprintf("DNF.EXE 版本已入历史: %s（%s）%d 字节",
		utils.ShortHash(hash), dnfExeVersionLabel(entry.Version), entry.Size))
	return true, nil
}

// pruneHistoryLocked 超限删最老。保留最新的 keep 条，当前版必须在内。
// 调用方须持有 histMu。★ 只准用 cachedCurrent。
func (s *DnfExeUpdateService) pruneHistoryLocked(entries []models.DnfExeBuildEntry) []models.DnfExeBuildEntry {
	keep := s.updateKeep()
	if len(entries) <= keep {
		return entries
	}
	curHash := ""
	if cur := s.cachedCurrent(); cur != nil && cur.Hash != "" {
		curHash = strings.ToUpper(cur.Hash)
	}

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StoredUtc > entries[j].StoredUtc })

	keepIdx := make([]int, 0, keep)
	for i := range entries {
		if len(keepIdx) < keep {
			keepIdx = append(keepIdx, i)
		}
	}
	if curHash != "" {
		inKeep := false
		for _, i := range keepIdx {
			if strings.ToUpper(entries[i].Hash) == curHash {
				inKeep = true
				break
			}
		}
		if !inKeep {
			for i := keep; i < len(entries); i++ {
				if strings.ToUpper(entries[i].Hash) == curHash {
					keepIdx[len(keepIdx)-1] = i
					break
				}
			}
		}
	}
	keepSet := make(map[int]bool, len(keepIdx))
	for _, i := range keepIdx {
		keepSet[i] = true
	}

	var kept []models.DnfExeBuildEntry
	for i, e := range entries {
		if keepSet[i] {
			kept = append(kept, e)
			continue
		}
		os.Remove(filepath.Join(s.historyDir(), e.Hash+".exe"))
		s.logger.Info(fmt.Sprintf("DNF.EXE 历史超限清理: %s（%s）",
			utils.ShortHash(e.Hash), dnfExeVersionLabel(e.Version)))
	}
	return kept
}

// GetHistory 返回历史列表（新→旧）。带惰性 seed：current.exe 不在历史时先入史。
func (s *DnfExeUpdateService) GetHistory() []models.DnfExeBuildEntry {
	if cur := s.Current(); cur != nil && cur.Hash != "" {
		if !utils.FileExists(filepath.Join(s.historyDir(), cur.Hash+".exe")) {
			if _, err := s.archiveHistory(s.CurrentPath(), "", "", ""); err != nil {
				s.logger.Warn("DNF.EXE 历史自动存档失败: " + err.Error())
			}
		}
	}

	s.histMu.Lock()
	entries := s.loadHistoryIndexLocked()
	s.histMu.Unlock()

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StoredUtc > entries[j].StoredUtc })
	return entries
}

// History 是 GetHistory 的别名（供 dnfexe_sync.go 的 handler 调用）。
func (s *DnfExeUpdateService) History() []models.DnfExeBuildEntry {
	return s.GetHistory()
}

// nextAuthorityRevision 返回下一个权威版本序号（单调递增）。
func (s *DnfExeUpdateService) nextAuthorityRevision() int64 {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	return s.nextAuthorityRevisionLocked()
}

func (s *DnfExeUpdateService) nextAuthorityRevisionLocked() int64 {
	entries := s.loadHistoryIndexLocked()
	var max int64
	for _, e := range entries {
		if e.AuthorityRevision > max {
			max = e.AuthorityRevision
		}
	}
	return max + 1
}

// SetAuthorityRevision 把某个 hash 的权威版本序号改成指定值（网关间同步用）。
func (s *DnfExeUpdateService) SetAuthorityRevision(hash string, revision int64) error {
	s.histMu.Lock()
	entries := s.loadHistoryIndexLocked()
	found := false
	for i := range entries {
		if strings.EqualFold(entries[i].Hash, hash) {
			entries[i].AuthorityRevision = revision
			found = true
			break
		}
	}
	if !found {
		s.histMu.Unlock()
		return fmt.Errorf("历史索引里没有 hash=%s 的记录", utils.ShortHash(hash))
	}
	err := s.saveHistoryIndexLocked(entries)
	s.histMu.Unlock()
	if err != nil {
		return err
	}

	s.refreshCurrent()
	return nil
}

// MaxAuthorityRevision 返回本地已知的最大权威版本序号（从网关的轮询水位）。
func (s *DnfExeUpdateService) MaxAuthorityRevision() int64 {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	entries := s.loadHistoryIndexLocked()
	var max int64
	for _, e := range entries {
		if e.AuthorityRevision > max {
			max = e.AuthorityRevision
		}
	}
	return max
}

// pullHTTP 是拉取 peer exe 用的 HTTP 客户端。20 MB 全量下载在慢链路上可能要几分钟。
var dnfExePullHTTP = &http.Client{Timeout: 10 * time.Minute}

// PullFromPeer 从主网关（peer）拉取指定版本的 DNF.EXE 并替换本地版本。
//
// 流程：
//  1. GET {peerBase}/api/dnfexe/update/exe（流式，不整读进内存）
//  2. 写入临时文件
//  3. ★ 校验 SHA-256 == 期望 hash（完整性硬约束，不匹配直接丢弃）
//  4. ReplaceDnfExe 完成"入史 + 替换 current.exe + 清 delta"
//  5. 序号对齐到 peer 的值
//
// ★ 任何失败都不影响本地现有版本 —— 降级策略是"保持能服务"。
func (s *DnfExeUpdateService) PullFromPeer(peerBase, wantHash, version string, revision int64) error {
	peerBase = strings.TrimRight(strings.TrimSpace(peerBase), "/")
	if peerBase == "" {
		return fmt.Errorf("peerBase 为空")
	}
	if wantHash == "" {
		return fmt.Errorf("期望 hash 为空")
	}

	url := peerBase + "/api/dnfexe/update/exe"
	resp, err := dnfExePullHTTP.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer 返回 %d", resp.StatusCode)
	}

	updateDir := s.UpdateDir()
	if err := utils.MkdirAll(updateDir); err != nil {
		return fmt.Errorf("建目录: %w", err)
	}
	shortHash := wantHash
	if len(shortHash) > 8 {
		shortHash = shortHash[:8]
	}
	tmpPath := filepath.Join(updateDir, ".sync-"+shortHash+".tmp")
	defer os.Remove(tmpPath)

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("建临时文件: %w", err)
	}
	written, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("下载中断: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("落盘: %w", closeErr)
	}

	// ★ 完整性校验：下载内容的 SHA-256 必须等于期望值
	actualHash, err := security.ComputeFileFingerprintPath(tmpPath)
	if err != nil {
		return fmt.Errorf("算指纹: %w", err)
	}
	if !strings.EqualFold(actualHash, wantHash) {
		return fmt.Errorf("指纹不匹配：期望 %s 实得 %s（%d 字节）",
			shortHash, utils.ShortHash(actualHash), written)
	}

	src, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("重开临时文件: %w", err)
	}
	entry, err := s.ReplaceDnfExe(src, version, "synced from peer", "")
	src.Close()
	if err != nil {
		return fmt.Errorf("ReplaceDnfExe: %w", err)
	}

	if err := s.SetAuthorityRevision(entry.Hash, revision); err != nil {
		s.logger.Warn(fmt.Sprintf("[DnfExeSync] 序号对齐失败（不影响版本生效）: %v", err))
	}

	s.logger.Info(fmt.Sprintf("[DnfExeSync] 已从 peer 同步到 %s（%s，%d 字节，rev=%d）",
		dnfExeVersionLabel(version), utils.ShortHash(entry.Hash), written, revision))
	return nil
}

// ReplaceDnfExe 上传新版本 DNF.EXE。
//
// 流程：版本号校验 → 流式落 tmp → PE 头校验（MZ + 体积下限，防传错文件）
// → 旧 current 入史 → rename 为新 current → 清按需 delta 缓存 → 新版入史。
// 失败在 rename 之前的任何一步都不动 current.exe。
//
// ★ 与 ReplaceLauncher 的唯一差别：version **选填**。
//   DNF.EXE 的版本号来自游戏客户端构建，运营未必知道（登录器强更判据只认 hash），
//   所以允许空串；但一旦填了就必须是 x.y.z —— 否则 DnfExe.MinVersion 的
//   语义化比较会失效（"abc" < "1.0.0" 是字符串比较，结论毫无意义）。
func (s *DnfExeUpdateService) ReplaceDnfExe(src io.Reader, version, name, filename string) (*models.DnfExeBuildEntry, error) {
	version = strings.TrimSpace(version)
	if version != "" && !ValidateLauncherVersion(version) {
		return nil, fmt.Errorf("版本号可留空，填写时必须是 x.y.z 格式（如 1.0.3），收到：%q", version)
	}

	path := s.CurrentPath()
	if err := utils.MkdirAll(filepath.Dir(path)); err != nil {
		return nil, err
	}

	// 流式写 tmp。
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, err
	}
	written, copyErr := io.Copy(f, src)
	closeErr := f.Close()
	if copyErr != nil {
		os.Remove(tmpPath)
		return nil, copyErr
	}
	if closeErr != nil {
		os.Remove(tmpPath)
		return nil, closeErr
	}

	// PE 校验：MZ 头 + 体积下限。上限由 bodylimit（512 MiB）挡。
	const minDnfExeSize = 1 << 20 // 1 MiB：真 DNF.EXE ~20 MiB，这里只防「传了个小文件/空文件」
	if written < minDnfExeSize {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("文件太小（%d 字节），不像 DNF.EXE（应约 20 MiB）", written)
	}
	head := make([]byte, 2)
	if hf, err := os.Open(tmpPath); err == nil {
		_, _ = io.ReadFull(hf, head)
		hf.Close()
	}
	if string(head) != "MZ" {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("不是有效的 Windows 可执行文件（缺 MZ 头）")
	}

	// 旧版入史（在动 current 之前，保证失败时历史无损）。
	if utils.FileExists(path) {
		if _, err := s.archiveHistory(path, "", "", ""); err != nil {
			s.logger.Warn("DNF.EXE 旧版入历史失败（不影响替换）: " + err.Error())
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return nil, err
	}

	// 先刷新当前版缓存再入史（pruneHistoryLocked 保护名单来自 cachedCurrent）。
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
	_ = s.Current()

	s.clearOnDemandDeltas()
	if _, err := s.archiveHistory(path, version, name, filename); err != nil {
		s.logger.Warn("DNF.EXE 新版入历史失败（不影响替换）: " + err.Error())
	}
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()

	cur := s.Current()
	s.logger.Info(fmt.Sprintf("DNF.EXE 当前版已更新: %s（%s）%d 字节",
		dnfExeVersionLabel(cur.Version), utils.ShortHash(cur.Hash), cur.Size))
	return cur, nil
}

// RollbackDnfExe 回退到某个历史版本。
func (s *DnfExeUpdateService) RollbackDnfExe(hash string) (*models.DnfExeBuildEntry, error) {
	normalized := NormalizeHashArg(hash)
	if normalized == "" {
		return nil, fmt.Errorf("hash 必须是 64 位十六进制 SHA-256")
	}
	src := filepath.Join(s.historyDir(), normalized+".exe")
	if !utils.FileExists(src) {
		return nil, fmt.Errorf("历史版本不存在：%s", utils.ShortHash(normalized))
	}
	if cur := s.Current(); cur != nil && strings.EqualFold(cur.Hash, normalized) {
		return nil, fmt.Errorf("该版本就是当前版本")
	}
	meta := func() models.DnfExeBuildEntry {
		s.histMu.Lock()
		defer s.histMu.Unlock()
		return s.versionOfLocked(normalized)
	}()
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return s.ReplaceDnfExe(f, meta.Version, meta.Name, meta.Filename)
}

// clearOnDemandDeltas 删除全部按需增量缓存（换版后 to_hash 全部过期）。
func (s *DnfExeUpdateService) clearOnDemandDeltas() {
	dir := s.deltaDir()
	items, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, it := range items {
		if !it.IsDir() && strings.HasPrefix(it.Name(), "from_") && strings.HasSuffix(it.Name(), ".delta") {
			os.Remove(filepath.Join(dir, it.Name()))
		}
	}
}

// GetOnDemandDelta 按 ?from=<hash> 返回「任意历史版 → 当前版」的增量包。
// 三层：缓存命中 → 历史现场生成 → nil（调用方回 404）。
// 任何产物都要过 Inspect 双校验（from == 请求值 && to == 当前版 hash）才下发。
func (s *DnfExeUpdateService) GetOnDemandDelta(fromRaw string) *models.DnfExeDeltaInfo {
	from := NormalizeHashArg(fromRaw)
	if from == "" {
		return nil
	}
	cur := s.Current()
	if cur == nil || cur.Hash == "" {
		return nil
	}
	if strings.EqualFold(from, cur.Hash) {
		return nil // 已是最新
	}

	dir := s.deltaDir()
	cache := filepath.Join(dir, "from_"+from+".delta")
	if d := s.inspectDeltaFile(cache, from, cur.Hash); d != nil {
		return d
	}

	v, _ := s.deltaGroup.do(from, onDemandBuildWait, func() any {
		if d := s.inspectDeltaFile(cache, from, cur.Hash); d != nil {
			return d
		}
		if utils.FileExists(cache) {
			os.Remove(cache)
		}

		histPath := filepath.Join(s.historyDir(), from+".exe")
		curPath := s.CurrentPath()
		if !utils.FileExists(histPath) || !utils.FileExists(curPath) {
			return nil
		}
		if err := utils.MkdirAll(dir); err != nil {
			return nil
		}

		t0 := time.Now()
		tmp := fmt.Sprintf("%s.tmp-%d-%d", cache, os.Getpid(), time.Now().UnixNano())
		st, err := pvfdiff.Build(histPath, curPath, tmp, pvfdiff.DefaultBlockSize)
		if err != nil {
			os.Remove(tmp)
			s.logger.Warn("DNF.EXE 按需增量生成失败: " + err.Error())
			return nil
		}
		if err := os.Rename(tmp, cache); err != nil {
			os.Remove(tmp)
			return nil
		}
		s.logger.Info(fmt.Sprintf(
			"DNF.EXE 按需增量已生成: %s → %s, %d 字节 (%.2f%%), 指令 %d 条, 耗时 %.2fs",
			utils.ShortHash(st.FromHash), utils.ShortHash(st.ToHash),
			st.DeltaSize, st.DeltaRatio()*100, st.InstrCount, time.Since(t0).Seconds()))

		return s.inspectDeltaFile(cache, from, cur.Hash)
	})
	if v == nil {
		return nil
	}
	d, _ := v.(*models.DnfExeDeltaInfo)
	return d
}

// inspectDeltaFile 读取 delta 文件并做 from/to 双校验；不通过返回 nil。
func (s *DnfExeUpdateService) inspectDeltaFile(path, wantFrom, wantTo string) *models.DnfExeDeltaInfo {
	if !utils.FileExists(path) {
		return nil
	}
	h, err := pvfdiff.Inspect(path)
	if err != nil {
		return nil
	}
	if !strings.EqualFold(h.FromHash, wantFrom) || !strings.EqualFold(h.ToHash, wantTo) {
		return nil
	}
	created := ""
	if stats, _ := utils.GetFileStats(path); stats != nil {
		created = stats.ModifiedUtc
	}
	return &models.DnfExeDeltaInfo{
		FromHash:   h.FromHash,
		ToHash:     h.ToHash,
		ToSize:     h.ToSize,
		Size:       h.TotalSize,
		Path:       path,
		CreatedUtc: created,
	}
}
