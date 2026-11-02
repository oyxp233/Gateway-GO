package service

// ============================================================================
// 从网关定时拉取（三服合一，2026-10-24）
//
// 见评估-三服合一登录器-20261023.md 第四/五章：
// 主网关做权威，从网关定时拉取。这是"推送丢了也能追平"的兜底，
// 也是"主网关没实现推送"时唯一的同步路径。
//
// 两个独立周期：
//
//	① 账号事件（默认 60s）
//	   GET {PeerInternalUrl}/internal/account/events?since=<水位>
//	   → database.ApplyRemoteAccountEvent（只落地全局封禁/解封）
//	   → database.SetSyncWatermark 推进水位
//
//	② 登录器版本（默认 300s）
//	   GET {PeerInternalUrl}/internal/launcher/sync?since=<本地最大 revision>
//	   → 有比本地新的版本 → LauncherUpdateService.PullFromPeer 拉 exe
//
// ★ 降级原则（最重要的一条）：
//   - 主网关不可达时**保持现有数据继续服务**，绝不因为同步失败影响玩家
//   - 所有失败只记日志，不 panic、不退出、不阻塞任何请求路径
//   - 水位只在"成功应用"后推进；失败下轮重试同一段
//
// ★ 只在配了 Signing.PeerInternalUrl 时启动：
//   主网关（自己就是权威）不需要拉任何人。
// ============================================================================

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/safego"
)

// launcherPushRequestBody 是主→从推送登录器版本的请求体。
//
// ★ 与 httprouter.LauncherPushRequest 字段一致（JSON 契约跨包）：
//   改任一侧必须同步另一侧，否则从网关解析不出 hash/revision。
//   这里刻意不复用那个类型（避免 service 依赖 httprouter）。
type launcherPushRequestBody struct {
	Hash     string `json:"hash"`
	Version  string `json:"version"`
	Revision int64  `json:"revision"`
	FromName string `json:"from,omitempty"`
}

// peerSyncHTTP 是拉取 peer 内部 API 的 HTTP 客户端。
//
// 10s 超时：内部 API 只返回 JSON 元数据（几百字节到几十 KB），
// 跨内网 10s 已经很宽松。慢到这个程度说明链路有问题，下轮重试更好。
// ★ 拉 exe 不用这个客户端 —— 那是 128 MiB，走 PullFromPeer 里的 pullHTTP（10 分钟）。
var peerSyncHTTP = &http.Client{Timeout: 10 * time.Second}

// peerName 是同步水位表里的 peer 标识。
//
// 用固定串而不是 URL：换了主网关地址不该丢掉已同步水位
// （否则会从 since=0 重拉全部历史事件，重复应用一遍全局封禁 —— 幂等，但白费流量）。
const peerName = "primary"

// 默认同步间隔（秒）。
const (
	defaultAccountSyncSeconds  = 60
	defaultLauncherSyncSeconds = 300
)

// PeerSyncService 从主网关定时拉取账号事件、登录器版本与 DNF.EXE 版本。
type PeerSyncService struct {
	cfg      *config.GatewayConfig
	log      *logger.ConsoleLogger
	db       *database.Database
	launcher *LauncherUpdateService
	dnfExe   *DnfExeUpdateService

	stop     chan struct{}
	wg       sync.WaitGroup
	stopOnce sync.Once
}

// NewPeerSyncService 创建同步服务。未配 PeerInternalUrl 时 Start 会直接返回。
func NewPeerSyncService(
	cfg *config.GatewayConfig,
	lg *logger.ConsoleLogger,
	db *database.Database,
	launcher *LauncherUpdateService,
	dnfExe *DnfExeUpdateService,
) *PeerSyncService {
	return &PeerSyncService{
		cfg:      cfg,
		log:      lg,
		db:       db,
		launcher: launcher,
		dnfExe:   dnfExe,
		stop:     make(chan struct{}),
	}
}

// SetDnfExeService 注入 DNF.EXE 更新服务（网关间同步用）。
//
// 与构造函数注入分离：admin 进程不需要 dnfExe 同步（它不上传），
// 但 main.go 统一创建 PeerSyncService 时可以注入 nil 再按需设置。
func (s *PeerSyncService) SetDnfExeService(dnfExe *DnfExeUpdateService) {
	if s != nil {
		s.dnfExe = dnfExe
	}
}

// Enabled 返回是否启用了从网关同步（配了 PeerInternalUrl 才算）。
func (s *PeerSyncService) Enabled() bool {
	return s != nil && s.cfg != nil && strings.TrimSpace(s.cfg.Signing.PeerInternalUrl) != ""
}

// HasPeers 返回本机是否配了从网关列表（= 是否可能向外推送）。
func (s *PeerSyncService) HasPeers() bool {
	return s != nil && s.cfg != nil && len(s.cfg.Signing.Peers) > 0
}

// PushLauncherToPeers 把新登录器版本推送给所有从网关。
//
// 由主网关在「上传新 exe / 回退版本」成功后调用，让发版从
// "等从网关 300s 轮询" 变成秒级生效。
//
// ★ 失败只记日志、不影响调用方：推送是**加速**手段，
//   轮询兜底还在。任何一台从网关连不上都不该让"上传成功"变成失败。
//
// ★ 异步调用：从网关可能在内网慢链路上，同步等会把后台 HTTP 请求挂住。
//   调用方应直接 `go PushLauncherToPeers(...)`。
func (s *PeerSyncService) PushLauncherToPeers(hash, version string, revision int64) {
	if !s.HasPeers() {
		return
	}
	body, err := json.Marshal(launcherPushRequestBody{
		Hash:     hash,
		Version:  version,
		Revision: revision,
		FromName: "primary",
	})
	if err != nil {
		s.log.Warn(fmt.Sprintf("[PeerSync] 序列化推送请求失败: %v", err))
		return
	}

	var okCount, failCount int
	for _, p := range s.cfg.Signing.Peers {
		base := strings.TrimRight(strings.TrimSpace(p.InternalUrl), "/")
		if base == "" {
			continue
		}
		key := strings.TrimSpace(p.InternalKey)
		if key == "" {
			s.log.Warn(fmt.Sprintf("[PeerSync] 从网关 %s 未配 InternalKey，跳过推送", p.Name))
			failCount++
			continue
		}

		url := base + "/internal/launcher/push"
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			s.log.Warn(fmt.Sprintf("[PeerSync] 构造推送请求失败（%s）: %v", p.Name, err))
			failCount++
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Key", key)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			s.log.Warn(fmt.Sprintf("[PeerSync] 推送登录器版本到 %s 失败（轮询兜底）: %v", p.Name, err))
			failCount++
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			s.log.Info(fmt.Sprintf("[PeerSync] 已推送登录器版本到 %s（v%s rev %d）: %s",
				p.Name, version, revision, string(respBody)))
			okCount++
			continue
		}
		s.log.Warn(fmt.Sprintf("[PeerSync] 推送登录器版本到 %s 返回 %d（轮询兜底）: %s",
			p.Name, resp.StatusCode, string(respBody)))
		failCount++
	}

	if okCount > 0 || failCount > 0 {
		s.log.Info(fmt.Sprintf("[PeerSync] 登录器版本推送完成：成功 %d，失败 %d", okCount, failCount))
	}
}

// PushDnfExeToPeers 把新 DNF.EXE 版本推送给所有从网关（2026-10-25）。
//
// 与 PushLauncherToPeers 同构，只是推送到 /internal/dnfexe/push。
// 失败只记日志、不影响调用方：轮询兜底还在。
func (s *PeerSyncService) PushDnfExeToPeers(hash, version string, revision int64) {
	if !s.HasPeers() {
		return
	}
	body, err := json.Marshal(launcherPushRequestBody{
		Hash:     hash,
		Version:  version,
		Revision: revision,
		FromName: "primary",
	})
	if err != nil {
		s.log.Warn(fmt.Sprintf("[PeerSync] 序列化 DNF.EXE 推送请求失败: %v", err))
		return
	}

	var okCount, failCount int
	for _, p := range s.cfg.Signing.Peers {
		base := strings.TrimRight(strings.TrimSpace(p.InternalUrl), "/")
		if base == "" {
			continue
		}
		key := strings.TrimSpace(p.InternalKey)
		if key == "" {
			s.log.Warn(fmt.Sprintf("[PeerSync] 从网关 %s 未配 InternalKey，跳过 DNF.EXE 推送", p.Name))
			failCount++
			continue
		}

		url := base + "/internal/dnfexe/push"
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			s.log.Warn(fmt.Sprintf("[PeerSync] 构造 DNF.EXE 推送请求失败（%s）: %v", p.Name, err))
			failCount++
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Key", key)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			s.log.Warn(fmt.Sprintf("[PeerSync] 推送 DNF.EXE 版本到 %s 失败（轮询兜底）: %v", p.Name, err))
			failCount++
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			s.log.Info(fmt.Sprintf("[PeerSync] 已推送 DNF.EXE 版本到 %s（%s rev %d）: %s",
				p.Name, dnfExeVersionLabel(version), revision, string(respBody)))
			okCount++
			continue
		}
		s.log.Warn(fmt.Sprintf("[PeerSync] 推送 DNF.EXE 版本到 %s 返回 %d（轮询兜底）: %s",
			p.Name, resp.StatusCode, string(respBody)))
		failCount++
	}

	if okCount > 0 || failCount > 0 {
		s.log.Info(fmt.Sprintf("[PeerSync] DNF.EXE 版本推送完成：成功 %d，失败 %d", okCount, failCount))
	}
}

// Start 启动两个定时协程。未启用时立即返回（不占用 goroutine）。
func (s *PeerSyncService) Start() {
	if !s.Enabled() {
		s.log.Info("[PeerSync] 未配置 Signing.PeerInternalUrl，本机不参与网关间同步（主网关的正常形态）")
		return
	}
	if strings.TrimSpace(s.cfg.Signing.PeerInternalKey) == "" {
		// 配了地址没配密钥 = 一定 401，提前喊出来比每轮刷 WARN 好
		s.log.Error("[PeerSync] 配了 PeerInternalUrl 但 PeerInternalKey 为空，" +
			"同步请求会全部 401。请填主网关的 Admin.InternalKey。")
	}

	accSec := s.cfg.Signing.PeerAccountSyncSeconds
	if accSec <= 0 {
		accSec = defaultAccountSyncSeconds
	}
	launcherSec := s.cfg.Signing.PeerLauncherSyncSeconds
	if launcherSec <= 0 {
		launcherSec = defaultLauncherSyncSeconds
	}

	s.log.Info(fmt.Sprintf("[PeerSync] 已启动：peer=%s 账号事件间隔=%ds 登录器版本间隔=%ds DNF.EXE版本间隔=%ds",
		s.cfg.Signing.PeerInternalUrl, accSec, launcherSec, launcherSec))

	// 首轮延迟 5 秒：让网关先把监听端口、数据库、会话表都起好。
	// 直接 0 延迟会在启动瞬间和 PVF 预热/账号迁移抢资源。
	const firstDelay = 5 * time.Second

	s.wg.Add(3)
	safego.Go(s.log, "peer-sync-account", func() {
		defer s.wg.Done()
		s.loop(firstDelay, time.Duration(accSec)*time.Second, s.syncAccountEventsOnce)
	})
	safego.Go(s.log, "peer-sync-launcher", func() {
		defer s.wg.Done()
		// 登录器同步错开 15s，避免两轮同时打主网关
		s.loop(firstDelay+15*time.Second, time.Duration(launcherSec)*time.Second, s.syncLauncherOnce)
	})
	safego.Go(s.log, "peer-sync-dnfexe", func() {
		defer s.wg.Done()
		// DNF.EXE 同步错开 30s，避免三轮同时打主网关
		s.loop(firstDelay+30*time.Second, time.Duration(launcherSec)*time.Second, s.syncDnfExeOnce)
	})
}

// Stop 停止定时协程并等待退出。
func (s *PeerSyncService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stop) })

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		s.log.Warn("[PeerSync] 停止超时（协程可能卡在网络请求上，会在超时后自行退出）")
	}
}

// loop 是通用定时循环：先等 firstDelay，之后按 interval 重复。
func (s *PeerSyncService) loop(firstDelay, interval time.Duration, job func()) {
	timer := time.NewTimer(firstDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-s.stop:
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	job() // 首轮
	for {
		select {
		case <-ticker.C:
			job()
		case <-s.stop:
			return
		}
	}
}

// ============================================================================
// ① 账号事件同步
// ============================================================================

// accountEventsResponse 对应 httprouter 的 AccountEventsResponse。
//
// ★ 单独定义而不是 import httprouter：httprouter 已 import service（反向依赖会成环）。
//   字段名必须与那边逐字一致 —— 两边都有测试锁着。
type accountEventsResponse struct {
	OK     bool                   `json:"ok"`
	Events []database.AccountEvent `json:"events"`
	MaxID  int64                  `json:"max_id"`
}

// syncAccountEventsOnce 拉一轮账号事件并应用。
func (s *PeerSyncService) syncAccountEventsOnce() {
	defer func() {
		// 定时协程里任何 panic 都不能把进程带走
		if r := recover(); r != nil {
			s.log.Error(fmt.Sprintf("[PeerSync] 账号事件同步 panic（已恢复）: %v", r))
		}
	}()

	watermark, err := s.db.SyncWatermark(peerName)
	if err != nil {
		s.log.Warn(fmt.Sprintf("[PeerSync] 读同步水位失败（本轮跳过）: %v", err))
		return
	}

	var resp accountEventsResponse
	if err := s.getPeerJSON("/internal/account/events?since="+itoa(watermark)+"&limit=200", &resp); err != nil {
		// 主网关不可达是常态（重启/网络抖动），用 Info 级别避免刷屏
		s.log.Info(fmt.Sprintf("[PeerSync] 拉账号事件失败（保持现有数据）: %v", err))
		return
	}
	if !resp.OK {
		s.log.Warn("[PeerSync] 主网关拒绝账号事件请求（检查 PeerInternalKey 是否正确）")
		return
	}
	if len(resp.Events) == 0 {
		return // 无变化，静默
	}

	applied, failed := 0, 0
	for _, e := range resp.Events {
		if err := s.db.ApplyRemoteAccountEvent(e); err != nil {
			failed++
			s.log.Warn(fmt.Sprintf("[PeerSync] 应用事件失败 id=%d type=%s account=%s: %v",
				e.ID, e.EventType, e.Account, err))
			continue
		}
		applied++
	}

	// ★ 水位推进策略：**有失败就不推进**。
	//
	// 若推进到 MaxID，失败那条会被永久跳过（下一轮 since 已越过它）。
	// 整批下轮重放是安全的 —— ApplyRemoteAccountEvent 是幂等的
	// （全局封禁 INSERT ON CONFLICT、解封 DELETE，重复应用无副作用）。
	newWatermark := watermark
	if failed == 0 {
		newWatermark = resp.MaxID
	}

	if newWatermark > watermark {
		if err := s.db.SetSyncWatermark(peerName, newWatermark); err != nil {
			s.log.Warn(fmt.Sprintf("[PeerSync] 写同步水位失败: %v", err))
		}
	}

	if applied > 0 || failed > 0 {
		s.log.Info(fmt.Sprintf("[PeerSync] 账号事件已应用 %d 条（失败 %d），水位 %d → %d",
			applied, failed, watermark, newWatermark))
	}
}

// ============================================================================
// ② 登录器版本同步
// ============================================================================

// launcherSyncResponse 对应 httprouter 的 LauncherSyncResponse。
type launcherSyncResponse struct {
	OK      bool                       `json:"ok"`
	Current *models.LauncherBuildEntry `json:"current"`
	History []models.LauncherBuildEntry `json:"history,omitempty"`
}

// syncLauncherOnce 拉一轮版本元数据，必要时拉 exe。
func (s *PeerSyncService) syncLauncherOnce() {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error(fmt.Sprintf("[PeerSync] 登录器版本同步 panic（已恢复）: %v", r))
		}
	}()

	if s.launcher == nil {
		return
	}

	localRev := s.launcher.MaxAuthorityRevision()

	var resp launcherSyncResponse
	if err := s.getPeerJSON("/internal/launcher/sync?since="+itoa(localRev), &resp); err != nil {
		s.log.Info(fmt.Sprintf("[PeerSync] 拉登录器版本失败（保持现有版本）: %v", err))
		return
	}
	if !resp.OK || resp.Current == nil || resp.Current.Hash == "" {
		return // 主网关也没有版本，或未启用自更新
	}

	// 已是最新（按 hash 判，不按版本号 —— 同 hash 才是同一份文件）
	local := s.launcher.Current()
	if local != nil && strings.EqualFold(local.Hash, resp.Current.Hash) {
		return // 静默：绝大多数轮次走这里
	}

	// 本地落后 → 拉 exe
	// ★ 用 Current（当前版）而不是 History 里最新的一条：
	//   主网关可能回滚过，Current 才是"该生效的那个"。
	cur := resp.Current
	if err := s.launcher.PullFromPeer(
		s.cfg.Signing.PeerBaseUrl, cur.Hash, cur.Version, cur.AuthorityRevision,
	); err != nil {
		s.log.Warn(fmt.Sprintf("[PeerSync] 拉取登录器 exe 失败（保持现有版本，下轮重试）: %v", err))
		return
	}
	s.log.Info(fmt.Sprintf("[PeerSync] 登录器已同步到 v%s（rev %d → %d）",
		cur.Version, localRev, cur.AuthorityRevision))
}

// ============================================================================
// ③ DNF.EXE 版本同步（2026-10-25）
// ============================================================================

// dnfExeSyncResponse 对应 httprouter 的 DnfExeSyncResponse。
// ★ 与 launcherSyncResponse 字段一致（JSON 契约跨包），刻意不复用那个类型。
type dnfExeSyncResponse struct {
	OK      bool                          `json:"ok"`
	Current *models.DnfExeBuildEntry      `json:"current"`
	History []models.DnfExeBuildEntry      `json:"history,omitempty"`
}

// syncDnfExeOnce 拉一轮 DNF.EXE 版本元数据，必要时拉 exe。
//
// 与 syncLauncherOnce 同构，区别只在内/公开 API 路径前缀。
func (s *PeerSyncService) syncDnfExeOnce() {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error(fmt.Sprintf("[PeerSync] DNF.EXE 版本同步 panic（已恢复）: %v", r))
		}
	}()

	if s.dnfExe == nil {
		return
	}

	localRev := s.dnfExe.MaxAuthorityRevision()

	var resp dnfExeSyncResponse
	if err := s.getPeerJSON("/internal/dnfexe/sync?since="+itoa(localRev), &resp); err != nil {
		s.log.Info(fmt.Sprintf("[PeerSync] 拉 DNF.EXE 版本失败（保持现有版本）: %v", err))
		return
	}
	if !resp.OK || resp.Current == nil || resp.Current.Hash == "" {
		return
	}

	local := s.dnfExe.Current()
	if local != nil && strings.EqualFold(local.Hash, resp.Current.Hash) {
		return
	}

	cur := resp.Current
	if err := s.dnfExe.PullFromPeer(
		s.cfg.Signing.PeerBaseUrl, cur.Hash, cur.Version, cur.AuthorityRevision,
	); err != nil {
		s.log.Warn(fmt.Sprintf("[PeerSync] 拉取 DNF.EXE 失败（保持现有版本，下轮重试）: %v", err))
		return
	}
	s.log.Info(fmt.Sprintf("[PeerSync] DNF.EXE 已同步到 %s（rev %d → %d）",
		dnfExeVersionLabel(cur.Version), localRev, cur.AuthorityRevision))
}

// ============================================================================
// 工具
// ============================================================================

// getPeerJSON 向主网关内部 API 发 GET 并解析 JSON。
func (s *PeerSyncService) getPeerJSON(path string, out interface{}) error {
	base := strings.TrimRight(strings.TrimSpace(s.cfg.Signing.PeerInternalUrl), "/")
	if base == "" {
		return fmt.Errorf("PeerInternalUrl 为空")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Internal-Key", s.cfg.Signing.PeerInternalKey)

	resp, err := peerSyncHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("401 未授权（PeerInternalKey 与主网关 Admin.InternalKey 不一致）")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// 限 4 MiB：事件/版本元数据都是小 JSON，防对端异常返回超大 body
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("解析响应: %w", err)
	}
	return nil
}

// itoa 是 strconv.FormatInt 的短封装（避免为此单独 import strconv）。
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ============================================================================
// ③ 登录兜底反查主网关（评估文档 5.4）
//
// 场景：玩家在主网关注册，立刻到从网关登录 —— 从网关本地没有这个账号，
// 直接报"账号不存在"。反查主网关拿到凭据后懒建本地副本，之后走本地路径。
//
// ★ 为什么反查的是**凭据**而不是"是否存在"：
//   只确认存在毫无用处 —— 本地没有 pwd_hash 就验不了密，玩家照样登不进。
//   必须拿到 pwd_hash + salt 才能用同一套算法验密。
//
// ★ 300ms 硬超时（评估文档给的数）：
//   反查在登录关键路径上，主网关慢一点不该把玩家卡住。
//   超时就按"查不到"处理（原有逻辑报账号不存在），失败方向是保守的。
// ============================================================================

// PeerCredential 是从主网关反查到的账号凭据。
type PeerCredential struct {
	Exists  bool
	PwdHash string
	Salt    string
	MId     string
}

// credentialResponse 对应 httprouter 的 AccountCredentialResponse。
type credentialResponse struct {
	OK      bool   `json:"ok"`
	Exists  bool   `json:"exists"`
	PwdHash string `json:"pwd_hash"`
	Salt    string `json:"salt"`
	MId     string `json:"m_id"`
}

// lookupTimeout 是反查的硬超时（评估文档 5.4 指定 300ms）。
const lookupTimeout = 300 * time.Millisecond

// LookupCredential 向主网关反查账号凭据。
//
// 返回 nil 的情况（都等价于"本地判定"，不改变原有行为）：
//   - 未启用同步（没配 PeerInternalUrl）
//   - 超时 / 网络错 / 401 / 非 200
//   - 主网关也查不到（Exists=false）
//
// ★ 返回 nil 绝不等于"账号被封"或"拒绝登录"，只表示"没有额外信息"。
func (s *PeerSyncService) LookupCredential(name string) *PeerCredential {
	if !s.Enabled() || name == "" {
		return nil
	}

	base := strings.TrimRight(strings.TrimSpace(s.cfg.Signing.PeerInternalUrl), "/")
	url := base + "/internal/account/credential?name=" + urlQueryEscape(name)

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Internal-Key", s.cfg.Signing.PeerInternalKey)

	// ★ 用独立的客户端：peerSyncHTTP 是 10s 超时，反查必须 300ms。
	//   复用同一个 client 也没问题（context 会先到期），但独立更清晰。
	resp, err := lookupHTTP.Do(req)
	if err != nil {
		// 超时是最常见的（主网关慢/跨网段抖动），用 Info 避免刷屏
		s.log.Info(fmt.Sprintf("[PeerSync] 反查凭据失败（按本地判定）name=%s: %v", name, err))
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.log.Info(fmt.Sprintf("[PeerSync] 反查凭据返回 %d（按本地判定）name=%s", resp.StatusCode, name))
		return nil
	}

	var cr credentialResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&cr); err != nil {
		return nil
	}
	if !cr.OK || !cr.Exists || cr.PwdHash == "" {
		return nil
	}

	s.log.Info(fmt.Sprintf("[PeerSync] 反查命中主网关账号 name=%s m_id=%s", name, cr.MId))
	return &PeerCredential{Exists: true, PwdHash: cr.PwdHash, Salt: cr.Salt, MId: cr.MId}
}

// lookupHTTP 是反查凭据专用客户端（超时由 context 控制，这里给个上限兜底）。
var lookupHTTP = &http.Client{Timeout: 2 * time.Second}

// urlQueryEscape 对查询参数做最小转义（账号名只允许字母数字，理论上是安全的，
// 但反查路径不该假设上游已经校验过）。
func urlQueryEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}
