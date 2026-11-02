package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

// ============================================================================
// 登录器自更新分发（2026-10-01）
//
// 背景：登录器是 127.8 MiB 的自包含单文件 exe，每改一版全体玩家要重下全量。
// 实测相邻版本差分只有 0.21%~0.44%（288~587 KB），跨大版本也只有 1.09% ——
// 复用 A21D（通用文件差分）做 exe 级增量，玩家从「等 6 分钟」变成「约 1 秒」。
//
// 与 PVF 增量（PvfService）同构但**独立实现**，不共用状态：
//   - 存储独立：launcher_update/ 目录（current.exe + history/ + delta/）；
//   - 无网关内存依赖：与插件目录同模式，gateway(8080) 下发、admin(8443) 上传
//     两个进程各持一份实例共用目录 —— 不需要 backends 抽象，重启不丢状态。
//     ★ 两进程缓存一致性靠 currentStamp（size+mtime 签名）解决：
//     admin 进程替换 current.exe 后，网关进程下一次请求 stat 发现签名变了
//     自动重算指纹 —— 不需要跨进程通知（PVF 走 internal API 通知是因为它
//     还要重建固定 delta；这里历史/按需 delta 全在磁盘上，谁算都一样）。
//
// 安全边界（与 PVF delta 同一条底线）：
//   - delta 包只含「从旧 exe 拷贝哪些区间」+「原样字面量」；
//   - 登录器合成产物必须过整文件 SHA-256 == 清单 hash 才会替换本地 exe，
//     任何一步失败保留旧文件 —— 网关侧无论发什么，都改不了这条判据。
// ============================================================================

// currentExeName 是当前版本全量 exe 在 UpdateDir 里的固定文件名。
const currentExeName = "current.exe"

// launcherVersionPattern 登录器版本号格式（与登录器 csproj/MiniVersion 同口径）。
var launcherVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// ValidateLauncherVersion 校验登录器版本号格式（x.y.z，纯数字段）。
// 空串或格式错都返回 false —— 上传接口用它把「手滑写错版本号」拦在写盘之前。
func ValidateLauncherVersion(v string) bool {
	return launcherVersionPattern.MatchString(strings.TrimSpace(v))
}

// launcherCurrentCache 是当前版的进程内缓存。
//
// ★ 缓存必须带 stamp（current.exe 的 size+mtime 签名）而不是无脑信任：
// 双进程共用目录，admin 进程上传新 exe 不会通知到网关进程 —— 没有签名校验的话，
// 网关会拿着旧 hash 的清单继续下发，玩家「更新完发现还要更新」。
// stat 一次的开销是微秒级，每次请求都做完全可接受。
type launcherCurrentCache struct {
	entry models.LauncherBuildEntry
	stamp string
}

type LauncherUpdateService struct {
	config *config.GatewayConfig
	logger *logger.ConsoleLogger

	// mu 保护 cur（当前版缓存）。读路径：cachedCurrent / Current。
	mu sync.RWMutex
	// cur == nil 表示未加载；entry.Hash == "" 表示目录里还没有 current.exe。
	cur *launcherCurrentCache

	// histMu 只保护 history/index.json 的读-改-写（与 mu 互不嵌套：
	// 持 histMu 时只准用 cachedCurrent，不准调 Current —— 后者可能刷新，
	// refreshCurrent 内部要拿 histMu，会自锁）。
	histMu sync.Mutex

	// deltaGroup 合并「同一个 from 的并发按需增量生成」（G-4 / G-10）。
	deltaGroup keyedGroup
}

// NewLauncherUpdateService 创建登录器更新分发服务。
func NewLauncherUpdateService(cfg *config.GatewayConfig, lg *logger.ConsoleLogger) *LauncherUpdateService {
	return &LauncherUpdateService{config: cfg, logger: lg}
}

// Enabled 返回自更新总开关的生效值。
func (s *LauncherUpdateService) Enabled() bool {
	return s.config.LauncherUpdateEnabled()
}

// UpdateDir 返回登录器更新分发根目录（相对路径按网关运行目录解析）。
func (s *LauncherUpdateService) UpdateDir() string {
	dir := strings.TrimSpace(s.config.Launcher.UpdateDir)
	if dir == "" {
		dir = "./launcher_update"
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// historyDir 历史版本目录。
func (s *LauncherUpdateService) historyDir() string {
	return filepath.Join(s.UpdateDir(), "history")
}

// deltaDir 按需增量缓存目录。
func (s *LauncherUpdateService) deltaDir() string {
	return filepath.Join(s.UpdateDir(), "delta")
}

// CurrentPath 返回当前版全量 exe 的绝对路径（供全量下载 handler 用）。
func (s *LauncherUpdateService) CurrentPath() string {
	return filepath.Join(s.UpdateDir(), currentExeName)
}

// updateKeep 历史保留版数上限。
func (s *LauncherUpdateService) updateKeep() int {
	if s.config.Launcher.UpdateKeep > 0 {
		return s.config.Launcher.UpdateKeep
	}
	return 4
}

// currentStamp 拿 current.exe 的 size+mtime 签名。文件不存在返回空串。
func (s *LauncherUpdateService) currentStamp() string {
	st, err := os.Stat(s.CurrentPath())
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d|%d", st.Size(), st.ModTime().UnixNano())
}

// cachedCurrent 只读缓存（不刷新、不触发 IO）。持 histMu 时唯一可用的读法。
// 返回的是拷贝，调用方改不动缓存。
func (s *LauncherUpdateService) cachedCurrent() *models.LauncherBuildEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cur == nil {
		return nil
	}
	cp := s.cur.entry
	return &cp
}

// refreshCurrent 重算当前版（current.exe 指纹 + 索引里的版本信息）并写缓存。
// 调用方不得持有 mu 或 histMu。
func (s *LauncherUpdateService) refreshCurrent() {
	path := s.CurrentPath()
	var entry models.LauncherBuildEntry
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
			// ★ AuthorityRevision 必须一起拷贝（三服合一，2026-10-24）：
			// 漏了它会让 /internal/launcher/sync 下发的 current.revision 恒为 0，
			// 从网关按 since= 比较时永远认为"没有更新"（或每次都认为有更新）。
			// 单测 TestPullLauncherFromPeer 就是靠这条抓住的。
			entry.AuthorityRevision = meta.AuthorityRevision
		} else {
			s.logger.Warn("登录器当前版指纹计算失败: " + err.Error())
		}
	}
	s.mu.Lock()
	s.cur = &launcherCurrentCache{entry: entry, stamp: s.currentStamp()}
	s.mu.Unlock()
}

// Current 返回当前版描述。缓存有效（签名一致）直接回；签名变了重算 ——
// 覆盖「admin 进程在另一个进程眼皮底下换了 current.exe」的跨进程场景。
// 目录里没有 current.exe 时返回 Hash 为空的条目（清单据此下发「无版本信息」，
// 登录器跳过检查 —— fail-safe 方向：永远不因为缺数据拦玩家）。
func (s *LauncherUpdateService) Current() *models.LauncherBuildEntry {
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

const launcherHistoryIndexName = "index.json"

// loadHistoryIndexLocked 读历史索引（文件不存在 → nil）。调用方须持有 histMu。
func (s *LauncherUpdateService) loadHistoryIndexLocked() []models.LauncherBuildEntry {
	raw, err := os.ReadFile(filepath.Join(s.historyDir(), launcherHistoryIndexName))
	if err != nil {
		return nil
	}
	var entries []models.LauncherBuildEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		s.logger.Warn("登录器历史索引不可读（按空处理）: " + err.Error())
		return nil
	}
	return entries
}

// saveHistoryIndexLocked 原子写历史索引。调用方须持有 histMu。
func (s *LauncherUpdateService) saveHistoryIndexLocked(entries []models.LauncherBuildEntry) error {
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	dir := s.historyDir()
	if err := utils.MkdirAll(dir); err != nil {
		return err
	}
	final := filepath.Join(dir, launcherHistoryIndexName)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// versionOfLocked 从历史索引里查某个 hash 的记录。调用方须持有 histMu。
func (s *LauncherUpdateService) versionOfLocked(hash string) models.LauncherBuildEntry {
	for _, e := range s.loadHistoryIndexLocked() {
		if strings.EqualFold(e.Hash, hash) {
			return e
		}
	}
	return models.LauncherBuildEntry{}
}

// archiveHistory 把一份登录器 exe 存进历史（内容寻址）。
// 已有同 hash 记录则跳过（不覆盖既有备注），返回是否新增。
func (s *LauncherUpdateService) archiveHistory(path, version, name, filename string) (bool, error) {
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
	entry := models.LauncherBuildEntry{
		Hash: hash,
		// 毫秒精度：秒级会在「同一次操作连续入档两版」时撞值（PVF 那批踩过）。
		StoredUtc: time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		Version:   strings.TrimSpace(version),
		Name:      strings.TrimSpace(name),
		Filename:  strings.TrimSpace(filename),
		// 权威版本序号（三服合一同步用，单调递增）
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
	s.logger.Info(fmt.Sprintf("登录器版本已入历史: %s（v%s）%d 字节",
		utils.ShortHash(hash), entry.Version, entry.Size))
	return true, nil
}

// pruneHistoryLocked 超限删最老。语义：**保留最新的 keep 条，当前版必须在内**。
// 调用方须持有 histMu。★ 只准用 cachedCurrent（拿锁顺序见类型注释）。
//
// ★ 为什么不照抄 PVF 的「升序 + len(kept)<keep 无条件保留」：那个写法保留的是
//   **最老**的 keep 条（外加保护名单），keep=20 时永远碰不到边界所以没暴露；
//   登录器 UpdateKeep=2（磁盘所迫）时一跑单测就现形：删了新版、留了两个老版。
func (s *LauncherUpdateService) pruneHistoryLocked(entries []models.LauncherBuildEntry) []models.LauncherBuildEntry {
	keep := s.updateKeep()
	if len(entries) <= keep {
		return entries
	}
	curHash := ""
	if cur := s.cachedCurrent(); cur != nil && cur.Hash != "" {
		curHash = strings.ToUpper(cur.Hash)
	}

	// 新→旧稳定排序。
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StoredUtc > entries[j].StoredUtc })

	// 选保留集合：最新的 keep 条；当前版若被挤出（rollback 到旧版时其 StoredUtc 老），
	// 顶掉最老的一条。
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

	var kept []models.LauncherBuildEntry
	for i, e := range entries {
		if keepSet[i] {
			kept = append(kept, e)
			continue
		}
		// 删文件 + 跳过记录。文件删失败也照常跳过（残留文件无索引引用，无害）。
		os.Remove(filepath.Join(s.historyDir(), e.Hash+".exe"))
		s.logger.Info(fmt.Sprintf("登录器历史超限清理: %s（v%s）", utils.ShortHash(e.Hash), e.Version))
	}
	return kept
}

// GetHistory 返回历史列表（新→旧）。带惰性 seed：current.exe 不在历史时先入史
//（version 未知 → 空串），保证「从未走过上传流程」的部署也能回退到当前版。
func (s *LauncherUpdateService) GetHistory() []models.LauncherBuildEntry {
	if cur := s.Current(); cur != nil && cur.Hash != "" {
		if !utils.FileExists(filepath.Join(s.historyDir(), cur.Hash+".exe")) {
			if _, err := s.archiveHistory(s.CurrentPath(), "", "", ""); err != nil {
				s.logger.Warn("登录器历史自动存档失败: " + err.Error())
			}
		}
	}

	s.histMu.Lock()
	entries := s.loadHistoryIndexLocked()
	s.histMu.Unlock()

	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StoredUtc > entries[j].StoredUtc })
	return entries
}

// History 是 GetHistory 的别名（供 launcher_sync.go 的 handler 调用）。
func (s *LauncherUpdateService) History() []models.LauncherBuildEntry {
	return s.GetHistory()
}

// nextAuthorityRevision 返回下一个权威版本序号（单调递增）。
//
// 见评估-三服合一登录器-20261023.md 第四章：
// 同步按序号而非版本号判断新旧，防"回滚到旧版后从网关覆盖回新版"。
// 序号 = 历史索引中最大 AuthorityRevision + 1，0 起步。
func (s *LauncherUpdateService) nextAuthorityRevision() int64 {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	return s.nextAuthorityRevisionLocked()
}

// nextAuthorityRevisionLocked 是持锁版本，调用方须持有 histMu。
func (s *LauncherUpdateService) nextAuthorityRevisionLocked() int64 {
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
//
// 为什么需要它：从网关通过 ReplaceLauncher 拉取 peer 的包时，ReplaceLauncher
// 会按本地索引分配一个新序号 —— 那与 peer 的序号对不上，后续按 since= 比较
// 就会漏拉或重复拉。同步完成后调用本方法把序号对齐到 peer 的值。
//
// hash 不存在时返回错误（调用方应先 ReplaceLauncher 再调本方法）。
//
// ★ 写完索引必须主动 refreshCurrent：current.exe 本身没变（stamp 不变），
//   Current() 会直接返回缓存里的旧 entry（revision 还是 0）。
//   这里先释放 histMu 再刷新 —— refreshCurrent 内部要拿 histMu，持锁调用会自锁。
func (s *LauncherUpdateService) SetAuthorityRevision(hash string, revision int64) error {
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

	// 释放 histMu 后刷新缓存，让 Current() 看到新序号
	s.refreshCurrent()
	return nil
}

// MaxAuthorityRevision 返回本地已知的最大权威版本序号（从网关的轮询水位）。
//
// 0 = 本地从未同步过任何带序号的版本。
func (s *LauncherUpdateService) MaxAuthorityRevision() int64 {
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

// pullHTTP 是拉取 peer exe 用的 HTTP 客户端。
//
// 10 分钟超时：128 MiB 全量下载在慢链路上可能要几分钟。
// 与登录器侧 LauncherSelfUpdate.UpdateHttp 同口径。
var pullHTTP = &http.Client{Timeout: 10 * time.Minute}

// PullFromPeer 从主网关（peer）拉取指定版本的登录器 exe 并替换本地版本。
//
// 这是网关间同步的**唯一拉取实现**，两个调用方共用：
//   - httprouter 的 /internal/launcher/push handler（收到主网关推送时）
//   - PeerSyncService 的定时轮询（主网关没推、或推送丢了时的兜底）
//
// 流程：
//  1. GET {peerBase}/api/launcher/update/exe（流式，不整读进内存）
//  2. 写入临时文件
//  3. ★ 校验 SHA-256 == 期望 hash（完整性硬约束，不匹配直接丢弃）
//  4. ReplaceLauncher 完成"入史 + 替换 current.exe + 清 delta"
//  5. 序号对齐到 peer 的值
//
// 返回 error 由调用方决定记什么日志（推送侧记 WARN，轮询侧记 WARN 并下轮重试）。
// ★ 任何失败都不影响本地现有版本 —— 降级策略是"保持能服务"。
func (s *LauncherUpdateService) PullFromPeer(peerBase, wantHash, version string, revision int64) error {
	peerBase = strings.TrimRight(strings.TrimSpace(peerBase), "/")
	if peerBase == "" {
		return fmt.Errorf("peerBase 为空")
	}
	if wantHash == "" {
		return fmt.Errorf("期望 hash 为空")
	}
	if !ValidateLauncherVersion(version) {
		return fmt.Errorf("版本号非法: %q", version)
	}

	url := peerBase + "/api/launcher/update/exe"
	resp, err := pullHTTP.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer 返回 %d", resp.StatusCode)
	}

	// 落临时文件
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

	// 交给既有上传流程（PE 校验 / 入史 / 替换 / 清 delta）
	src, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("重开临时文件: %w", err)
	}
	entry, err := s.ReplaceLauncher(src, version, "synced from peer", "")
	src.Close()
	if err != nil {
		return fmt.Errorf("ReplaceLauncher: %w", err)
	}

	// 序号对齐到 peer（失败不影响版本生效，只影响下次轮询的 since 值）
	if err := s.SetAuthorityRevision(entry.Hash, revision); err != nil {
		s.logger.Warn(fmt.Sprintf("[LauncherSync] 序号对齐失败（不影响版本生效）: %v", err))
	}

	s.logger.Info(fmt.Sprintf("[LauncherSync] 已从 peer 同步到 v%s（%s，%d 字节，rev=%d）",
		version, utils.ShortHash(entry.Hash), written, revision))
	return nil
}

// ReplaceLauncher 上传新版本登录器 exe。
//
// 流程：版本号校验 → 流式落 tmp → PE 头校验（MZ + 体积下限，防传错文件）
// → 旧 current 入史 → rename 为新 current → 清按需 delta 缓存 → 新版入史。
// 失败在 rename 之前的任何一步都不动 current.exe。
func (s *LauncherUpdateService) ReplaceLauncher(src io.Reader, version, name, filename string) (*models.LauncherBuildEntry, error) {
	version = strings.TrimSpace(version)
	if !ValidateLauncherVersion(version) {
		return nil, fmt.Errorf("版本号必须是 x.y.z 格式（如 2.4.0），收到：%q", version)
	}

	path := s.CurrentPath()
	if err := utils.MkdirAll(filepath.Dir(path)); err != nil {
		return nil, err
	}

	// 流式写 tmp（登录器 exe 约 134 MiB，不能整读进内存）。
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
	const minLauncherSize = 1 << 20 // 1 MiB：真登录器 ~128 MiB，这里只防「传了个小文件/空文件」
	if written < minLauncherSize {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("文件太小（%d 字节），不像登录器 exe（应约 128 MiB）", written)
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
			// 旧版入史失败不阻断替换 —— 当前版永远可以再入史；
			// 代价只是这版不再可回退/可按需。
			s.logger.Warn("登录器旧版入历史失败（不影响替换）: " + err.Error())
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return nil, err
	}

	// ★ 先刷新当前版缓存再入史：archiveHistory → pruneHistoryLocked 的
	// 「绝删不得当前版」保护名单来自 cachedCurrent —— 不刷新的话它是 nil，
	// prune 会把**刚换上的当前版**当成最老历史删掉（单测 TestLauncherPruneKeep 抓到）。
	// 此时索引里还没有新版记录，version 暂为空 —— 无妨，保护只用 hash。
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
	_ = s.Current() // 强制重载（缓存已 nil，必走 refreshCurrent）

	// 换版即清：旧 from_*.delta 的 to_hash 全部过期。
	s.clearOnDemandDeltas()
	if _, err := s.archiveHistory(path, version, name, filename); err != nil {
		s.logger.Warn("登录器新版入历史失败（不影响替换）: " + err.Error())
	}
	// 入史完成（version 已进索引）后再失效一次，让 Current() 带上完整元数据。
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()

	cur := s.Current()
	s.logger.Info(fmt.Sprintf("登录器当前版已更新: v%s（%s）%d 字节",
		cur.Version, utils.ShortHash(cur.Hash), cur.Size))
	return cur, nil
}

// RollbackLauncher 回退到某个历史版本。
func (s *LauncherUpdateService) RollbackLauncher(hash string) (*models.LauncherBuildEntry, error) {
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
	// 走完整替换链路；版本号从历史索引取（seed 过的空 version 原样带过 ——
	// 显示为空总比编一个错值强）。
	meta := func() models.LauncherBuildEntry {
		s.histMu.Lock()
		defer s.histMu.Unlock()
		return s.versionOfLocked(normalized)
	}()
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return s.ReplaceLauncher(f, meta.Version, meta.Name, meta.Filename)
}

// clearOnDemandDeltas 删除全部按需增量缓存（换版后 to_hash 全部过期）。
func (s *LauncherUpdateService) clearOnDemandDeltas() {
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
func (s *LauncherUpdateService) GetOnDemandDelta(fromRaw string) *models.LauncherDeltaInfo {
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

	// G-4 / G-10：与 PVF 按需增量同样的并发问题（共写 tmp + N 次全量重算），
	// 用同一个 singleflight 原语合并同 from 的并发请求。
	v, _ := s.deltaGroup.do(from, onDemandBuildWait, func() any {
		if d := s.inspectDeltaFile(cache, from, cur.Hash); d != nil {
			return d // 等待期间已有别的调用生成好了
		}
		if utils.FileExists(cache) {
			os.Remove(cache) // 有文件但校验不过（过期/损坏）→ 作废重建
		}

		histPath := filepath.Join(s.historyDir(), from+".exe")
		curPath := s.CurrentPath()
		if !utils.FileExists(histPath) || !utils.FileExists(curPath) {
			return nil // 历史里没有这版 ⇒ 该客户端回退全量
		}
		if err := utils.MkdirAll(dir); err != nil {
			return nil
		}

		t0 := time.Now()
		// G-4：tmp 名带 pid + 纳秒后缀，避免并发 / 多进程共写同一临时文件。
		tmp := fmt.Sprintf("%s.tmp-%d-%d", cache, os.Getpid(), time.Now().UnixNano())
		st, err := pvfdiff.Build(histPath, curPath, tmp, pvfdiff.DefaultBlockSize)
		if err != nil {
			os.Remove(tmp)
			s.logger.Warn("登录器按需增量生成失败: " + err.Error())
			return nil
		}
		if err := os.Rename(tmp, cache); err != nil {
			os.Remove(tmp)
			return nil
		}
		s.logger.Info(fmt.Sprintf(
			"登录器按需增量已生成: %s → %s, %d 字节 (%.2f%%), 指令 %d 条, 耗时 %.2fs",
			shortHash(st.FromHash), shortHash(st.ToHash),
			st.DeltaSize, st.DeltaRatio()*100, st.InstrCount, time.Since(t0).Seconds()))

		return s.inspectDeltaFile(cache, from, cur.Hash)
	})
	if v == nil {
		return nil
	}
	d, _ := v.(*models.LauncherDeltaInfo)
	return d
}

// inspectDeltaFile 读取 delta 文件并做 from/to 双校验；不通过返回 nil。
func (s *LauncherUpdateService) inspectDeltaFile(path, wantFrom, wantTo string) *models.LauncherDeltaInfo {
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
	return &models.LauncherDeltaInfo{
		FromHash:   h.FromHash,
		ToHash:     h.ToHash,
		ToSize:     h.ToSize,
		Size:       h.TotalSize,
		Path:       path,
		CreatedUtc: created,
	}
}
