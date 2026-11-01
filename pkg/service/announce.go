package service

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
)

// AnnounceService 是全服公告的**唯一真源**。
//
// 三个职责：
//  1. 持有公告配置的内存快照（插件每几秒从内部 API 拉一次，读的必须是内存而不是每次查库）；
//  2. 接收游戏服务端插件上报的事件、补全账号信息并落库；
//  3. 管理弹窗队列（后台入队、插件拉走）。
//
// 双进程部署下**只有网关进程**持有本服务（admin 进程走内部 API 转发写操作），
// 因为"配置快照 + 弹窗投递状态"是网关内存态，绕过它就会出现"库里改了、内存没改"。
type AnnounceService struct {
	db  *database.Database
	log *logger.ConsoleLogger

	cfgMu sync.RWMutex
	cfg   models.AnnounceConfig

	// 角色 → m_id 的反查缓存。
	// 上报事件只带 character_id，而管理后台要按账号检索；
	// 每个事件都去游戏库 join 一次没必要 —— 角色到账号的映射在角色生命周期内不变。
	midMu    sync.RWMutex
	midCache map[int64]string
	midMiss  map[int64]struct{}

	stopOnce sync.Once
	stopCh   chan struct{}

	// 排行榜缓存：登录器榜单页会连续拉几次，而榜单是重聚合查询。
	rankMu     sync.Mutex
	rankCache  []models.AnnounceRanking
	rankCached int64
}

// 榜单缓存时长。登录器打开榜单页时会连续发几次请求，缓存 30 秒足够；
// 也保证即使有人刷这个公开接口，也不会把 SQLite 单写者连接占满。
const announceRankingCacheSeconds = 30

// midCacheLimit 反查缓存上限。超了就整体清空 —— 简单、无淘汰算法、不会无限增长。
const midCacheLimit = 20000

// NewAnnounceService 构造公告服务。调用方随后应调 Start()。
func NewAnnounceService(db *database.Database, log *logger.ConsoleLogger) *AnnounceService {
	return &AnnounceService{
		db:       db,
		log:      log,
		cfg:      models.DefaultAnnounceConfig(),
		midCache: map[int64]string{},
		midMiss:  map[int64]struct{}{},
		stopCh:   make(chan struct{}),
	}
}

// Start 从库里加载配置，并启动事件保留期清理循环。
func (s *AnnounceService) Start() {
	if cfg, err := s.db.LoadAnnounceConfig(); err != nil {
		s.log.Error(fmt.Sprintf("[Announce] 加载配置失败，使用出厂默认值: %v", err))
	} else {
		s.cfgMu.Lock()
		s.cfg = cfg
		s.cfgMu.Unlock()
		s.log.Info(fmt.Sprintf("[Announce] 配置已加载: enabled=%v report=%v revision=%d retention=%d天",
			cfg.Enabled, cfg.Report, cfg.Revision, cfg.EventRetentionDays))
	}
	go s.retentionLoop()
}

// Stop 停止后台循环。
func (s *AnnounceService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Config 返回配置快照（并发安全）。
//
// 返回的是值拷贝，但 DifficultyNames 是切片 —— 调用方只读即可，不要改。
func (s *AnnounceService) Config() models.AnnounceConfig {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// UpdateConfig 保存配置并热替换内存快照。
//
// **不重启服务端**：插件下次轮询（默认 3 秒内）就拿到新配置。
func (s *AnnounceService) UpdateConfig(cfg models.AnnounceConfig) (models.AnnounceConfig, error) {
	// 空值兜底：模板被清空会让公告变成空白行，不如回落到出厂文案。
	defaults := models.DefaultAnnounceConfig()
	if strings.TrimSpace(cfg.TemplateCleared) == "" {
		cfg.TemplateCleared = defaults.TemplateCleared
	}
	if strings.TrimSpace(cfg.TemplateIncomplete) == "" {
		cfg.TemplateIncomplete = defaults.TemplateIncomplete
	}
	if strings.TrimSpace(cfg.TemplatePickup) == "" {
		cfg.TemplatePickup = defaults.TemplatePickup
	}
	if strings.TrimSpace(cfg.HellDifficultyName) == "" {
		cfg.HellDifficultyName = defaults.HellDifficultyName
	}
	if len(cfg.DifficultyNames) == 0 {
		cfg.DifficultyNames = defaults.DifficultyNames
	}
	if cfg.AnnounceDurationMs < 1000 || cfg.AnnounceDurationMs > 60000 {
		cfg.AnnounceDurationMs = defaults.AnnounceDurationMs
	}
	if cfg.PopupMode < 0 || cfg.PopupMode > 255 {
		cfg.PopupMode = 0
	}
	if cfg.EventRetentionDays < 0 || cfg.EventRetentionDays > 3650 {
		cfg.EventRetentionDays = defaults.EventRetentionDays
	}
	// 消息样式：非法值/禁用值(34/35/36)归一成空串 = "不指定"，由服务端退回默认样式。
	// 注意**不要**在这里填默认 56：那等于把服务端的默认值抄一份到网关，
	// 以后服务端换默认值时网关会一直压着旧值。
	cfg.NoticeStyleCleared = models.NormalizeAnnounceNoticeStyle(cfg.NoticeStyleCleared)
	cfg.NoticeStyleIncomplete = models.NormalizeAnnounceNoticeStyle(cfg.NoticeStyleIncomplete)

	saved, err := s.db.SaveAnnounceConfig(cfg)
	if err != nil {
		return s.Config(), err
	}

	s.cfgMu.Lock()
	s.cfg = saved
	s.cfgMu.Unlock()

	s.log.Info(fmt.Sprintf("[Announce] 配置已热更新: revision=%d enabled=%v cleared=%v incomplete=%v pickup=%v",
		saved.Revision, saved.Enabled, saved.Cleared, saved.Incomplete, saved.Pickup))
	return saved, nil
}

// ============================================================================
// 事件上报
// ============================================================================

// IngestEvents 落库一批上报事件，并补全账号字段。
//
// 限流与条数上限由内部 API 层控制；这里只做字段清洗。
// 返回真正写进去的条数。
func (s *AnnounceService) IngestEvents(events []models.AnnounceEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	for i := range events {
		e := &events[i]
		e.Kind = strings.TrimSpace(e.Kind)
		e.CharacterName = clampString(e.CharacterName, 64)
		e.DungeonName = clampString(e.DungeonName, 128)
		e.ItemName = clampString(e.ItemName, 128)
		e.EquipmentType = clampString(e.EquipmentType, 32)
		e.Account = clampString(e.Account, 64)

		if e.Account == "" && e.CharacterID > 0 {
			e.Account = s.resolveMId(e.CharacterID)
		}
	}
	return s.db.InsertAnnounceEvents(events)
}

// resolveMId 反查角色所属账号的 m_id（带缓存）。
//
// 查不到会记进 miss 集合：同一个未落库 m_id 的角色可能反复上报，
// 每次都去 join 一遍游戏库是纯粹的浪费。
func (s *AnnounceService) resolveMId(characterID int64) string {
	s.midMu.RLock()
	if mid, ok := s.midCache[characterID]; ok {
		s.midMu.RUnlock()
		return mid
	}
	if _, missed := s.midMiss[characterID]; missed {
		s.midMu.RUnlock()
		return ""
	}
	s.midMu.RUnlock()

	mid, err := s.db.ResolveMIdByCharacterID(characterID)
	if err != nil {
		// 查询失败不缓存（下次还会重试），也不上抛 —— 事件本身比账号字段重要。
		return ""
	}

	s.midMu.Lock()
	if mid == "" {
		s.midMiss[characterID] = struct{}{}
	} else {
		s.midCache[characterID] = mid
	}
	if len(s.midCache)+len(s.midMiss) > midCacheLimit {
		s.midCache = map[int64]string{}
		s.midMiss = map[int64]struct{}{}
	}
	s.midMu.Unlock()
	return mid
}

// ============================================================================
// 弹窗队列
// ============================================================================

// PullPopups 给插件取走待投递的弹窗。
//
// ttlSeconds 之后仍未送达的 pending 会被标记 expired —— 插件离线时队列不该无限堆积，
// 一条「10 分钟后维护」的弹窗晚一小时才弹出来是有害的。
func (s *AnnounceService) PullPopups(limit, ttlSeconds int) ([]models.AnnouncePopup, error) {
	if ttlSeconds <= 0 {
		ttlSeconds = 600
	}
	return s.db.TakePendingAnnouncePopups(limit, ttlSeconds)
}

// SendPopup 由管理后台发起一条弹窗公告（入队，等插件下一次轮询拉走）。
func (s *AnnounceService) SendPopup(message string, mode int, createdBy string) (int64, error) {
	id, err := s.db.EnqueueAnnouncePopup(message, mode, createdBy)
	if err != nil {
		return 0, err
	}
	s.log.Info(fmt.Sprintf("[Announce] 弹窗入队: id=%d mode=%d len=%d by=%s",
		id, mode, len([]rune(message)), createdBy))
	return id, nil
}

// ============================================================================
// 查询与聚合（纯读，转发给 database）
// ============================================================================

// QueryEvents 分页查询事件流水。
func (s *AnnounceService) QueryEvents(f database.AnnounceEventFilter) (int, []models.AnnounceEvent, error) {
	return s.db.QueryAnnounceEvents(f)
}

// EventStats 返回各类事件的累计条数。
func (s *AnnounceService) EventStats() (map[string]int64, error) {
	return s.db.AnnounceEventStats()
}

// QueryPopups 分页查询弹窗历史。
func (s *AnnounceService) QueryPopups(status string, page, pageSize int) (int, []models.AnnouncePopup, error) {
	return s.db.QueryAnnouncePopups(status, page, pageSize)
}

// DeletePopup 删除一条未投递的弹窗。
func (s *AnnounceService) DeletePopup(id int64) (bool, error) {
	return s.db.DeleteAnnouncePopup(id)
}

// Rankings 返回三个品级榜单（史诗 / 传说 / 神器），带内存缓存。
//
// sinceDays <= 0 表示不限时间。limit 是每榜的玩家条数与物品条数上限。
func (s *AnnounceService) Rankings(limit, sinceDays int) ([]models.AnnounceRanking, error) {
	now := time.Now().Unix()

	s.rankMu.Lock()
	if s.rankCache != nil && now-s.rankCached < announceRankingCacheSeconds {
		cached := s.rankCache
		s.rankMu.Unlock()
		return cached, nil
	}
	s.rankMu.Unlock()

	since := int64(0)
	if sinceDays > 0 {
		since = now - int64(sinceDays)*86400
	}

	rankings, err := s.db.BuildAnnounceRankings(limit, since)
	if err != nil {
		return nil, err
	}

	s.rankMu.Lock()
	s.rankCache = rankings
	s.rankCached = now
	s.rankMu.Unlock()
	return rankings, nil
}

// ============================================================================
// 保留期清理
// ============================================================================

// retentionLoop 每小时检查一次是否该清理事件表。
//
// 清理由网关进程独占执行：admin 进程不跑这个循环，否则两个进程会同时 DELETE，
// 在 SQLite 单写者模型下互相等锁。
func (s *AnnounceService) retentionLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	// 启动后先等 2 分钟再清：刚起来时 PVF 预热、账号迁移都在抢库，
	// 别让一次全表 DELETE 挤在启动窗口里。
	select {
	case <-time.After(2 * time.Minute):
	case <-s.stopCh:
		return
	}

	for {
		s.purgeOnce()
		select {
		case <-ticker.C:
		case <-s.stopCh:
			return
		}
	}
}

func (s *AnnounceService) purgeOnce() {
	days := s.Config().EventRetentionDays
	if days <= 0 {
		return
	}
	before := time.Now().AddDate(0, 0, -days).Unix()
	n, err := s.db.PurgeAnnounceEvents(before)
	if err != nil {
		s.log.Error(fmt.Sprintf("[Announce] 事件清理失败: %v", err))
		return
	}
	if n > 0 {
		s.log.Info(fmt.Sprintf("[Announce] 事件清理: 删除 %d 条（保留 %d 天）", n, days))
	}
}

// clampString 截断超长字符串（按 rune 计），避免一个畸形上报把库撑大。
func clampString(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}
