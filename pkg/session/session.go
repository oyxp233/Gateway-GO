package session

import (
	"fmt"
	"net"
	"sync"
	"time"

	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
	"s4a21-gateway/pkg/security"
)

// SessionManager 管理在线会话。
type SessionManager struct {
	mu        sync.RWMutex
	sessions  map[string]*models.Session     // token -> session
	ipIndex   map[string]map[string]struct{} // ip -> {token, ...}
	gameSlots map[string]int                 // ip -> 已占用的 Game 连接数
	// gameSlotsByMId 是方案 D 的按账号槽位：m_id -> 已占用的 Game 连接数。
	// 与 gameSlots（按 IP）并立——凭证准入的连接按 m_id 计，
	// 回退白名单的连接仍按 IP 计，两个维度互不占用。
	gameSlotsByMId map[string]int
	onFirst        func()
	onLast         func()
}

// NewSessionManager 创建会话管理器。
func NewSessionManager(onFirstSession func(), onLastSessionRemoved func()) *SessionManager {
	return &SessionManager{
		sessions:       make(map[string]*models.Session),
		ipIndex:        make(map[string]map[string]struct{}),
		gameSlots:      make(map[string]int),
		gameSlotsByMId: make(map[string]int),
		onFirst:        onFirstSession,
		onLast:         onLastSessionRemoved,
	}
}

// CreateSession 创建新会话。
//
// gameId 是本次登录选服的 Id（2026-10-17 双服；空串 = 默认服）。
func (sm *SessionManager) CreateSession(account, mId, ip, deviceSecret, gameId string) (string, error) {
	token, err := security.GenerateToken()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	session := &models.Session{
		Token:                token,
		Account:              account,
		MId:                  mId,
		ClientIP:             ip,
		DeviceSecret:         deviceSecret,
		GameId:               gameId,
		CreatedAt:            now,
		LastHeartbeat:        now,
		BonusGranted:         0,
		ProxyConnections:     make(map[net.Conn]struct{}),
		GameProxyConnections: make(map[net.Conn]struct{}),
	}

	sm.mu.Lock()
	sm.sessions[token] = session
	if sm.ipIndex[ip] == nil {
		sm.ipIndex[ip] = make(map[string]struct{})
	}
	sm.ipIndex[ip][token] = struct{}{}
	wasFirst := len(sm.sessions) == 1
	sm.mu.Unlock()

	if wasFirst && sm.onFirst != nil {
		sm.onFirst()
	}

	return token, nil
}

// FindSessionByAccount 查找该账号的现有会话（存在多个时取最早创建的那个）。
func (sm *SessionManager) FindSessionByAccount(account string) (*models.Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var best *models.Session
	for _, s := range sm.sessions {
		if s.Account != account {
			continue
		}
		// 同 FindSessionByMId：CreatedAt 是秒级，同秒多会话时用 token 字典序
		// 兜底，避免 map 随机遍历顺序让「谁算重复登录」变得不确定。
		if best == nil || s.CreatedAt < best.CreatedAt ||
			(s.CreatedAt == best.CreatedAt && s.Token < best.Token) {
			best = s
		}
	}
	return best, best != nil
}

// FindStaleSessionForReconnect 找出该账号「可判定为掉线重连」的旧会话。
//
// 背景（2026-10-10 生产 18:30 卡顿掉线复盘）：客户端掉线后玩家重开登录器登录，
// 旧会话还没到 TimeoutSeconds 就被判定"已在线"，登录器弹窗等玩家点确认 ——
// 玩家不在电脑前就一直进不去，几秒的网络抖动被放大成几十秒掉线。
//
// 判据（两条必须**同时**成立，缺一不可）：
//  1. 旧会话心跳已停滞超过 staleSeconds（客户端进程确实死了，不是"卡了一下"）；
//  2. 新登录来自**同一端**：同 IP，或同 device_secret（两边都为空时不算）。
//     这一条把"异地顶号"挡在外面 —— 那种情况仍然走 1023 弹窗由玩家自己确认，
//     顶号保护不受影响。
//
// staleSeconds <= 0 表示功能关闭，恒返回 false（退回原有的一律弹窗行为）。
//
// 返回的是**会话副本**：调用方只读，避免把内部对象暴露出去被无锁并发写。
func (sm *SessionManager) FindStaleSessionForReconnect(
	account, ip, deviceSecret string, staleSeconds int) (models.Session, bool) {
	if account == "" || staleSeconds <= 0 {
		return models.Session{}, false
	}

	now := time.Now().Unix()
	cutoff := now - int64(staleSeconds)

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var stale *models.Session
	for _, s := range sm.sessions {
		if s.Account != account || s.LastHeartbeat >= cutoff {
			continue
		}
		if !sameClientEndpoint(s.ClientIP, s.DeviceSecret, ip, deviceSecret) {
			continue
		}
		// 同 FindSessionByAccount：同秒多会话时用 token 字典序兜底，保证归属确定。
		if stale == nil || s.CreatedAt < stale.CreatedAt ||
			(s.CreatedAt == stale.CreatedAt && s.Token < stale.Token) {
			stale = s
		}
	}
	if stale == nil {
		return models.Session{}, false
	}
	return *stale, true
}

// sameClientEndpoint 判断两次登录是否来自"同一端"。
//
// device_secret 两边都为空时不算命中 —— 老客户端/新机器还没领到 secret 时
// 两边都是空串，拿空串判等会让"任意机器"都算同一端，直接把顶号保护打穿。
func sameClientEndpoint(oldIP, oldSecret, newIP, newSecret string) bool {
	if newIP != "" && oldIP == newIP {
		return true
	}
	if oldSecret != "" && newSecret != "" && oldSecret == newSecret {
		return true
	}
	return false
}

// FindSessionByMId 按 m_id 查找会话（游戏连接的**精确归属**用）。
//
// 客户端 launch_args 第 4 段就是该账号的 m_id，游戏协议首包（登录包）里带的也是它
// （服务端 LoginRequestParser：DSTR(m_id) + DSTR(pwd)）。
//
// 同一公网 IP 多开时，只有它能区分会话 —— 只按 IP 挑「心跳最新」会把所有游戏连接
// 都算到最活跃的那个账号头上（实测双开时 msp 的游戏连接与泡点全记到了 msp2 名下）。
//
// 同一 m_id 正常只应有一个会话（单账号单令牌）；若有多个，取创建最早的，
// 与 FindSessionByAccount 口径一致。
func (sm *SessionManager) FindSessionByMId(mId string) (*models.Session, bool) {
	if mId == "" {
		return nil, false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var best *models.Session
	for _, s := range sm.sessions {
		if s.MId != mId {
			continue
		}
		// CreatedAt 是**秒级**，同一秒内存在多个会话（异常态）时，只比 CreatedAt
		// 会让 map 的随机遍历顺序决定结果 —— 归属必须确定，用 token 字典序兜底。
		if best == nil || s.CreatedAt < best.CreatedAt ||
			(s.CreatedAt == best.CreatedAt && s.Token < best.Token) {
			best = s
		}
	}
	return best, best != nil
}

// FindSessionByMIdAndToken 按 m_id + token **同时**匹配查找会话。
//
// 方案 D 的凭证校验用：游戏口首包密码字段的当前形态是客户端上报的会话 token
// （64 位 hex，来自 launch_args 第 5 段）。token 是**每次登录重新生成**的
// 随机值，匹配上即证明「首包确实来自该账号本次登录签发的那个客户端」——
// 与来源 IP 无关（加速器/跨网段玩家的登录 IP 与游戏出口 IP 本就不是一个），
// 也不可能被枚举（2^256）。
//
// 为什么不能只用 FindSessionByMId + 比 token：同一 m_id 异常态下可能存在
// 多个会话（stale reconnect 结转等），只挑一个比会把持另一个 token 的
// 正常客户端判成「凭证不符」。
func (sm *SessionManager) FindSessionByMIdAndToken(mId, token string) (*models.Session, bool) {
	if mId == "" || token == "" {
		return nil, false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var best *models.Session
	for _, s := range sm.sessions {
		if s.MId != mId {
			continue
		}
		// 恒定时间比较，与 verifyAccountPassword 的口径一致
		if !security.ConstantTimeEquals(s.Token, token) {
			continue
		}
		if best == nil || s.CreatedAt < best.CreatedAt {
			best = s
		}
	}
	return best, best != nil
}

// ReplaceAccountSessions 踢掉该账号现有全部会话并创建新会话（单账号单令牌）。
//
// carryOver=true 时把旧会话的登录时间与泡点累计结转到新会话 ——
// 重复登录视为同一玩家继续在线，在线时长与泡点进度不清零
// （历史版本每次登录都新建会话，重复登录后在线时长归零、泡点重新计算）。
//
// gameId 是本次登录选服的 Id（2026-10-17 双服；空串 = 默认服）。
// 切服登录（S4A21 ⇄ S5A95）天然被单账号单令牌覆盖：旧会话连坐骑一起
// 被踢，新会话带新服的 GameId。
//
// 返回新 token。旧会话挂着的代理连接会被逐个 Close（真断开）。
func (sm *SessionManager) ReplaceAccountSessions(account, mId, ip, deviceSecret, gameId string, carryOver bool) (string, error) {
	token, err := security.GenerateToken()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	session := &models.Session{
		Token:                token,
		Account:              account,
		MId:                  mId,
		ClientIP:             ip,
		DeviceSecret:         deviceSecret,
		GameId:               gameId,
		CreatedAt:            now,
		LastHeartbeat:        now,
		BonusGranted:         0,
		ProxyConnections:     make(map[net.Conn]struct{}),
		GameProxyConnections: make(map[net.Conn]struct{}),
	}

	sm.mu.Lock()
	var removed []*models.Session
	for t, s := range sm.sessions {
		if s.Account == account {
			removed = append(removed, s)
			delete(sm.sessions, t)
			if sm.ipIndex[s.ClientIP] != nil {
				delete(sm.ipIndex[s.ClientIP], t)
				if len(sm.ipIndex[s.ClientIP]) == 0 {
					delete(sm.ipIndex, s.ClientIP)
				}
			}
		}
	}
	if carryOver && len(removed) > 0 {
		// 在线时长取最早登录时间；泡点累计取最大值（都是同一账号的在线事实）。
		earliest := removed[0].CreatedAt
		maxBonus := removed[0].BonusGranted
		maxOnline := removed[0].GameOnlineSeconds
		for _, s := range removed {
			if s.CreatedAt < earliest {
				earliest = s.CreatedAt
			}
			if s.BonusGranted > maxBonus {
				maxBonus = s.BonusGranted
			}
			if s.GameOnlineSeconds > maxOnline {
				maxOnline = s.GameOnlineSeconds
			}
		}
		session.CreatedAt = earliest
		session.BonusGranted = maxBonus
		// 未满一个计费周期的秒数余数也结转，否则玩家靠重复登录就能
		// 把「不足一分钟不发」的零头刷掉、或者反过来被清零吃亏。
		// BonusTickAt 不从旧会话继承：旧会话的游戏频道连接已被 Close，
		// 新会话要等玩家重新连上游戏频道才重新计时（下一轮结算时置为 now）。
		session.GameOnlineSeconds = maxOnline
	}
	sm.sessions[token] = session
	if sm.ipIndex[ip] == nil {
		sm.ipIndex[ip] = make(map[string]struct{})
	}
	sm.ipIndex[ip][token] = struct{}{}
	wasFirst := len(sm.sessions) == 1
	conns := collectSessionConns(removed...)
	sm.mu.Unlock()

	if wasFirst && sm.onFirst != nil {
		sm.onFirst()
	}
	closeConns(conns)

	return token, nil
}

// ValidateToken 验证 token 并返回会话。
func (sm *SessionManager) ValidateToken(token string) (*models.Session, bool) {
	if token == "" {
		return nil, false
	}

	sm.mu.RLock()
	session, ok := sm.sessions[token]
	sm.mu.RUnlock()

	if !ok {
		return nil, false
	}
	return session, true
}

// UpdateHeartbeat 更新会话心跳时间。
func (sm *SessionManager) UpdateHeartbeat(token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if session, ok := sm.sessions[token]; ok {
		session.LastHeartbeat = time.Now().Unix()
	}
}

// RemoveSession 移除会话并清理关联的代理连接。
//
// 只删表不断连接的话，玩家的 TCP 代理链路还活着照常游戏：
// 心跳里发现 banned 的路径（httprouter.handleHeartbeat）尤其明显 ——
// 会话没了但连接还在，要等游戏侧 idle 超时（默认 1800s）才真正断开，
// 于是"封禁"在玩家侧表现为"还能继续玩 30 分钟"。
// 与 KickAccount/KickAll/KickNonAdminAccounts/ReplaceAccountSessions 保持一致：
// 锁内收集 + 清空连接表，锁外逐个 Close。
func (sm *SessionManager) RemoveSession(token string) {
	sm.mu.Lock()
	session, ok := sm.sessions[token]
	if !ok {
		sm.mu.Unlock()
		return
	}
	delete(sm.sessions, token)

	if sm.ipIndex[session.ClientIP] != nil {
		delete(sm.ipIndex[session.ClientIP], token)
		if len(sm.ipIndex[session.ClientIP]) == 0 {
			delete(sm.ipIndex, session.ClientIP)
		}
	}
	last := len(sm.sessions) == 0
	conns := collectSessionConns(session)
	sm.mu.Unlock()

	if last && sm.onLast != nil {
		sm.onLast()
	}
	closeConns(conns)
}

// GetAllSessions 获取所有会话的**快照**（值拷贝）。
//
// G-9（2026-10-04 审查）：原先返回会话对象**裸指针**，调用方（backends.List）在锁外
// 读 Account/ClientIP/LastHeartbeat/BonusGranted，而 UpdateHeartbeat / CollectBonusAwards
// 同时在写同一批字段 —— 真实数据竞争（go test -race 可复现），32 位平台的 int64 还会撕裂。
// 现在在 RLock 内逐个值拷贝，调用方拿到的是脱离共享状态的副本。
//
// 注意：ProxyConnections / GameProxyConnections 是 map（引用类型），值拷贝共享其底层。
// 快照的用途是**只读展示**，调用方不得经由它们改动状态；要踢连接请走 Kick* 系列。
func (sm *SessionManager) GetAllSessions() []models.Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make([]models.Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		if s == nil {
			continue
		}
		result = append(result, *s)
	}
	return result
}

// SessionCount 返回当前在线会话数。
func (sm *SessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// IsIPAllowed 检查 IP 是否在已登录玩家白名单中。
func (sm *SessionManager) IsIPAllowed(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.ipIndex[ip]
	return ok
}

// FindByIP 根据 IP 查找会话，返回第一个匹配的会话。
func (sm *SessionManager) FindByIP(ip string) (*models.Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	tokens, ok := sm.ipIndex[ip]
	if !ok || len(tokens) == 0 {
		return nil, fmt.Errorf("no session found for IP: %s", ip)
	}

	// 返回第一个匹配的会话
	for token := range tokens {
		if session, ok := sm.sessions[token]; ok {
			return session, nil
		}
	}

	return nil, fmt.Errorf("no session found for IP: %s", ip)
}

// TryGetSessionForChannelProxy 为 Channel 代理查找可用会话。
// 返回该 IP 对应且尚未占用代理连接的会话。
func (sm *SessionManager) TryGetSessionForChannelProxy(ip string) (*models.Session, bool) {
	sm.mu.RLock()
	tokens, ok := sm.ipIndex[ip]
	if !ok || len(tokens) == 0 {
		sm.mu.RUnlock()
		return nil, false
	}

	var candidates []*models.Session
	for token := range tokens {
		if s, exists := sm.sessions[token]; exists {
			candidates = append(candidates, s)
		}
	}
	sm.mu.RUnlock()

	// 查找未占用代理连接的会话
	for _, s := range candidates {
		sm.mu.Lock()
		if len(s.ProxyConnections) == 0 {
			sm.mu.Unlock()
			return s, true
		}
		sm.mu.Unlock()
	}

	return nil, false
}

// TryGetSessionForGameProxy 为 Game 代理查找归属会话。
func (sm *SessionManager) TryGetSessionForGameProxy(ip string) (*models.Session, bool) {
	sm.mu.RLock()
	tokens, ok := sm.ipIndex[ip]
	if !ok || len(tokens) == 0 {
		sm.mu.RUnlock()
		return nil, false
	}

	// 按最近心跳确定性选择
	var best *models.Session
	var bestHb int64 = -1
	for token := range tokens {
		if s, exists := sm.sessions[token]; exists {
			if s.LastHeartbeat > bestHb {
				bestHb = s.LastHeartbeat
				best = s
			}
		}
	}
	sm.mu.RUnlock()

	if best != nil {
		return best, true
	}
	return nil, false
}

// TryAcquireGameSlot 尝试获取 IP 的 Game 连接槽位。
//
// 检查与预留是**同一次原子操作**：通过即已占位，调用方必须在连接结束时
// 调用 ReleaseGameSlot 释放，否则该 IP 的额度会被永久占用。
//
// 不能改为"统计各会话的 GameProxyConnections 长度"——那样有两个漏洞：
//  1. 检查与登记之间存在窗口，并发连接可同时通过检查；
//  2. 未关联会话的连接（session 为 nil）根本不会被统计，上限形同虚设。
func (sm *SessionManager) TryAcquireGameSlot(ip string, maxPerIP int) bool {
	if maxPerIP <= 0 {
		return true
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.gameSlots[ip] >= maxPerIP {
		return false
	}
	sm.gameSlots[ip]++
	return true
}

// ReleaseGameSlot 释放 IP 的 Game 连接槽位。
// 必须与成功的 TryAcquireGameSlot 配对调用（用 defer 保证）。
func (sm *SessionManager) ReleaseGameSlot(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	n, ok := sm.gameSlots[ip]
	if !ok {
		return
	}
	if n <= 1 {
		// 归零时直接删键，避免 map 无限增长
		delete(sm.gameSlots, ip)
		return
	}
	sm.gameSlots[ip] = n - 1
}

// GameSlotCount 返回指定 IP 当前占用的 Game 连接数（用于状态查询与测试）。
func (sm *SessionManager) GameSlotCount(ip string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.gameSlots[ip]
}

// TryAcquireGameSlotByMId 尝试获取**账号维度**的 Game 连接槽位（方案 D）。
//
// 为什么需要这个维度：按 IP 计槽位时，加速器/网吧/NAT 共享出口的多个玩家
// 会互相挤占（正式服2 事件二：同一出口 IP 半天 49 次连接全被拒）。
// 凭证准入（首包 m_id + token/口令）的连接改按 m_id 计，一个账号最多
// maxPerMId 条游戏连接，与同出口的其他玩家再无关系。
//
// 检查与预留是同一次原子操作，语义与 TryAcquireGameSlot 一致；
// 未准入（回退白名单）的连接仍走 IP 维度，两个维度分开计数。
func (sm *SessionManager) TryAcquireGameSlotByMId(mId string, maxPerMId int) bool {
	if maxPerMId <= 0 {
		return true
	}
	if mId == "" {
		return false
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.gameSlotsByMId[mId] >= maxPerMId {
		return false
	}
	sm.gameSlotsByMId[mId]++
	return true
}

// ReleaseGameSlotByMId 释放账号维度的 Game 连接槽位。
// 必须与成功的 TryAcquireGameSlotByMId 配对调用（用 defer 保证）。
func (sm *SessionManager) ReleaseGameSlotByMId(mId string) {
	if mId == "" {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	n, ok := sm.gameSlotsByMId[mId]
	if !ok {
		return
	}
	if n <= 1 {
		// 归零时直接删键，避免 map 无限增长
		delete(sm.gameSlotsByMId, mId)
		return
	}
	sm.gameSlotsByMId[mId] = n - 1
}

// GameSlotCountByMId 返回指定账号当前占用的 Game 连接数（用于状态查询与测试）。
func (sm *SessionManager) GameSlotCountByMId(mId string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.gameSlotsByMId[mId]
}

// AddProxyConnection 向会话添加代理连接。
func (sm *SessionManager) AddProxyConnection(session *models.Session, conn net.Conn) {
	if session == nil || conn == nil {
		return
	}
	sm.mu.Lock()
	session.ProxyConnections[conn] = struct{}{}
	sm.mu.Unlock()
}

// RemoveProxyConnection 从会话移除代理连接。
func (sm *SessionManager) RemoveProxyConnection(session *models.Session, conn net.Conn) {
	if session == nil || conn == nil {
		return
	}
	sm.mu.Lock()
	delete(session.ProxyConnections, conn)
	sm.mu.Unlock()
}

// AddGameProxyConnection 向会话添加 Game 代理连接。
//
// ★ 游戏频道连接数 0 → 1 的这一刻 = **泡点计费时钟起表时刻**：
// 玩家通过网关真正连上游戏频道才开始计时（见 CollectBonusAwards）。
// 之前停在登录器 / 频道选择界面的时间不计入泡点。
func (sm *SessionManager) AddGameProxyConnection(session *models.Session, conn net.Conn) {
	sm.addGameProxyConnectionAt(session, conn, time.Now().Unix())
}

// addGameProxyConnectionAt 是 AddGameProxyConnection 的可注入时间版本，
// 供单元测试构造确定的时间线。
func (sm *SessionManager) addGameProxyConnectionAt(session *models.Session, conn net.Conn, now int64) {
	if session == nil || conn == nil {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	first := len(session.GameProxyConnections) == 0
	session.GameProxyConnections[conn] = struct{}{}
	if first {
		session.BonusTickAt = now
	}
}

// RemoveGameProxyConnection 从会话移除 Game 代理连接。
//
// ★ 游戏频道连接数 1 → 0 的这一刻 = **泡点计费时钟停表时刻**：
// 玩家退出游戏，先把最后不足一个计费周期的秒数结算进 GameOnlineSeconds
// 再停表，保证「退出后不再计时、但退出前那一小段不白玩」。
func (sm *SessionManager) RemoveGameProxyConnection(session *models.Session, conn net.Conn) {
	sm.removeGameProxyConnectionAt(session, conn, time.Now().Unix())
}

// removeGameProxyConnectionAt 是 RemoveGameProxyConnection 的可注入时间版本。
func (sm *SessionManager) removeGameProxyConnectionAt(session *models.Session, conn net.Conn, now int64) {
	if session == nil || conn == nil {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := session.GameProxyConnections[conn]; !ok {
		return
	}
	delete(session.GameProxyConnections, conn)
	if len(session.GameProxyConnections) == 0 {
		accumulateGameSeconds(session, now, 0)
		session.BonusTickAt = now
	}
}

// accumulateGameSeconds 把 [BonusTickAt, now] 这段「在游戏内」的秒数累进
// GameOnlineSeconds，并把基准推进到 now。
//
// maxDelta > 0 时单次累计封顶（防主循环卡顿 / 泡点被长时间禁用后一次性补发）；
// maxDelta <= 0 表示不封顶（停表结算走这条路，那一段是真实在游戏内的时长）。
//
// 基准非法（<=0，或时钟回拨导致基准在未来）时不动累计，交由调用方重置基准。
func accumulateGameSeconds(s *models.Session, now, maxDelta int64) {
	if s == nil || s.BonusTickAt <= 0 || s.BonusTickAt > now {
		return
	}
	delta := now - s.BonusTickAt
	if delta <= 0 {
		return
	}
	if maxDelta > 0 && delta > maxDelta {
		delta = maxDelta
	}
	s.GameOnlineSeconds += delta
}

// closeConns 关掉一批连接（踢下线的"真断开"动作）。
// Close 是幂等的，代理 handler 的 defer Close 重复调用无害；
// 双向 copy goroutine 会因读/写失败立即退出，资源随之回收。
func closeConns(conns []net.Conn) {
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
}

// collectSessionConns 取出一组会话挂着的全部代理连接并清空登记。
// 调用方必须已持有 sm.mu（写锁）。
func collectSessionConns(sessions ...*models.Session) []net.Conn {
	var conns []net.Conn
	for _, s := range sessions {
		if s == nil {
			continue
		}
		for c := range s.ProxyConnections {
			conns = append(conns, c)
		}
		for c := range s.GameProxyConnections {
			conns = append(conns, c)
		}
		s.ProxyConnections = make(map[net.Conn]struct{})
		s.GameProxyConnections = make(map[net.Conn]struct{})
	}
	return conns
}

// KickAccount 踢指定账号下线。
//
// 返回被踢下线的会话数，以及本次实际移除的会话 token 列表
// （`0` 表示该账号当时不在线；调用方可据此打日志或做提示）。
//
// 除了删除会话表，还会**逐个 Close 该会话挂着的代理连接** ——
// 只删表不断连接的话，玩家的 Channel/Game 链路还活着，照常游戏。
func (sm *SessionManager) KickAccount(account string) (int, []string) {
	sm.mu.Lock()
	var toRemove []string
	var removed []*models.Session
	for token, s := range sm.sessions {
		if s.Account == account {
			toRemove = append(toRemove, token)
			removed = append(removed, s)
		}
	}
	for _, token := range toRemove {
		s := sm.sessions[token]
		delete(sm.sessions, token)
		if sm.ipIndex[s.ClientIP] != nil {
			delete(sm.ipIndex[s.ClientIP], token)
			if len(sm.ipIndex[s.ClientIP]) == 0 {
				delete(sm.ipIndex, s.ClientIP)
			}
		}
	}
	last := len(sm.sessions) == 0
	conns := collectSessionConns(removed...)
	sm.mu.Unlock()

	if last && sm.onLast != nil {
		sm.onLast()
	}
	closeConns(conns)

	return len(toRemove), toRemove
}

// KickAll 踢所有在线玩家下线。
//
// 返回被踢下线的会话数，以及本次实际移除的会话 token 列表。
// 同 KickAccount：被移除会话的代理连接会一并断开。
func (sm *SessionManager) KickAll() (int, []string) {
	sm.mu.Lock()
	tokens := make([]string, 0, len(sm.sessions))
	var removed []*models.Session
	for token, s := range sm.sessions {
		tokens = append(tokens, token)
		removed = append(removed, s)
	}
	count := len(sm.sessions)
	sm.sessions = make(map[string]*models.Session)
	sm.ipIndex = make(map[string]map[string]struct{})
	conns := collectSessionConns(removed...)
	sm.mu.Unlock()

	if count > 0 && sm.onLast != nil {
		sm.onLast()
	}
	closeConns(conns)

	return count, tokens
}

// KickNonAdminAccounts 踢掉非管理员账号的在线会话（维护模式用）。
// 被移除会话的代理连接会一并断开。
func (sm *SessionManager) KickNonAdminAccounts(adminAccounts []string) int {
	adminSet := make(map[string]struct{})
	for _, a := range adminAccounts {
		adminSet[a] = struct{}{}
	}

	sm.mu.Lock()
	var toRemove []string
	var removed []*models.Session
	for token, s := range sm.sessions {
		_, isAdmin := adminSet[s.Account]
		if !isAdmin {
			toRemove = append(toRemove, token)
			removed = append(removed, s)
		}
	}
	for _, token := range toRemove {
		s := sm.sessions[token]
		delete(sm.sessions, token)
		if sm.ipIndex[s.ClientIP] != nil {
			delete(sm.ipIndex[s.ClientIP], token)
			if len(sm.ipIndex[s.ClientIP]) == 0 {
				delete(sm.ipIndex, s.ClientIP)
			}
		}
	}
	last := len(sm.sessions) == 0
	conns := collectSessionConns(removed...)
	sm.mu.Unlock()

	if last && sm.onLast != nil {
		sm.onLast()
	}
	closeConns(conns)

	return len(toRemove)
}

// ExpiredSessionInfo 一次超时清理里被清掉的会话明细（运维判据用）。
type ExpiredSessionInfo struct {
	Account   string
	MId       string
	ClientIP  string
	StaleSecs int64 // 心跳停滞秒数（相对清理时刻）
	// GameConns 清理瞬间挂着的 Game 频道连接数。> 0 说明玩家当时是真的在游戏里
	// （不是在登录器界面），被清掉 = 实打实的一次掉线，值得单独看一眼。
	GameConns int
	// ProxyConns 挂着的 Channel 代理连接数。
	ProxyConns int
}

// CleanExpiredSessionsWithDetails 同 CleanExpiredSessions，但额外返回被清会话的明细。
//
// 起因（2026-10-10 复盘）：原来只有一行「清理超时会话: N」，出事后回答不了
// "清的是谁、心跳停了多久、当时有没有在游戏里" —— 只能靠翻 400MB 的 game log 反推。
// 主循环据此逐条打点，下次可直接判"是清错了还是真掉线"。
func (sm *SessionManager) CleanExpiredSessionsWithDetails(timeoutSeconds int) (int, []ExpiredSessionInfo) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	now := time.Now().Unix()
	cutoff := now - int64(timeoutSeconds)

	sm.mu.Lock()
	var toRemove []string
	var removed []*models.Session
	var details []ExpiredSessionInfo
	for token, s := range sm.sessions {
		if s.LastHeartbeat < cutoff {
			toRemove = append(toRemove, token)
			removed = append(removed, s)
			details = append(details, ExpiredSessionInfo{
				Account:    s.Account,
				MId:        s.MId,
				ClientIP:   s.ClientIP,
				StaleSecs:  now - s.LastHeartbeat,
				GameConns:  len(s.GameProxyConnections),
				ProxyConns: len(s.ProxyConnections),
			})
		}
	}
	for _, token := range toRemove {
		s := sm.sessions[token]
		delete(sm.sessions, token)
		if sm.ipIndex[s.ClientIP] != nil {
			delete(sm.ipIndex[s.ClientIP], token)
			if len(sm.ipIndex[s.ClientIP]) == 0 {
				delete(sm.ipIndex, s.ClientIP)
			}
		}
	}
	last := len(sm.sessions) == 0
	conns := collectSessionConns(removed...)
	sm.mu.Unlock()

	if last && sm.onLast != nil {
		sm.onLast()
	}
	closeConns(conns)

	return len(toRemove), details
}

// CleanExpiredSessions 清理超时会话。
//
// 同 KickAccount：被清掉的会话挂着的代理连接要一并断开。
// 不关的话，玩家客户端崩溃后代理 goroutine 还在双向 copy，
// 只能等游戏侧 idle 超时（默认 1800s）才回收，资源回收凭空推迟半小时。
//
// 需要明细（账号 / 心跳停滞 / 当时是否在游戏内）时改用 CleanExpiredSessionsWithDetails。
func (sm *SessionManager) CleanExpiredSessions(timeoutSeconds int) int {
	n, _ := sm.CleanExpiredSessionsWithDetails(timeoutSeconds)
	return n
}

// BonusAward 一轮泡点计费的结算结果。
type BonusAward struct {
	Account string
	MId     string
	// Intervals 本轮结算出的完整计费周期数（>=1）。
	Intervals int64
	// Granted 该会话累计已发放的周期数（含本次），用于后台「泡点累计」展示。
	Granted int64
	// Remainder 结算后不足一个周期的秒数余数（跨轮保留）。
	Remainder int64
}

// CollectBonusAwards 按玩家「真实在游戏频道内的时长」结算泡点。
//
// 计费口径（2026-09-23 调整，取代旧的「最近 N 分钟内有 HTTP 心跳就发」）：
//
//  0. 计费时钟的起表/停表由连接事件驱动：玩家连上游戏频道
//     （addGameProxyConnectionAt，0→1）起表，退出游戏
//     （removeGameProxyConnectionAt，1→0）结算并停表。
//     本函数只负责把"上次结算到现在"这一段补上，因此计时精度不受
//     主循环周期影响，也不会把连接断开后的时间算进去。
//  1. **只有游戏频道连接存活时（len(GameProxyConnections) > 0）才累计时长**。
//     玩家通过网关连上游戏频道才开始计时；停在登录器、频道选择界面不计时。
//  2. 玩家退出游戏（连接断开）即停止计时；会话被清理 / 踢下线后，
//     会话已不在会话表里，这里遍历不到它 —— **不可能再发放**。
//     （这正是旧实现「会话已清理还在发泡点」的根因：旧实现查的是网关库
//     accounts.last_heartbeat，与内存会话表完全脱钩。）
//  3. 累计满一个 intervalSeconds 才发一次，**不足一个周期不发放**；
//     余数保留到下一轮（也跨"退出再进"保留），不会因为结算时点与
//     进入时刻错位而少发。
//
// 单轮最多累计 2 个周期：泡点被长时间禁用或主循环卡顿后重新开始时，
// 不能把中间那段「无人计费」的时间一次性补给玩家。
//
// 返回值只含本轮真的应发放的会话；BonusGranted 已在锁内累加。
func (sm *SessionManager) CollectBonusAwards(now int64, intervalSeconds int64) []BonusAward {
	if intervalSeconds <= 0 {
		return nil
	}
	maxDelta := intervalSeconds * 2

	sm.mu.Lock()
	defer sm.mu.Unlock()

	var awards []BonusAward
	for _, s := range sm.sessions {
		if s == nil {
			continue
		}

		// 只有仍然"在游戏内"才继续累计；时钟的起表/停表在
		// addGameProxyConnectionAt / removeGameProxyConnectionAt 里，
		// 这里只负责把上次结算到现在的这一段补上。
		if len(s.GameProxyConnections) > 0 {
			if s.BonusTickAt <= 0 || s.BonusTickAt > now {
				// 基准缺失（历史会话）或时钟回拨：以 now 重新起算，本轮不补
				s.BonusTickAt = now
			} else {
				accumulateGameSeconds(s, now, maxDelta)
				s.BonusTickAt = now
			}
		}

		if s.GameOnlineSeconds < intervalSeconds {
			continue
		}
		n := s.GameOnlineSeconds / intervalSeconds
		s.GameOnlineSeconds -= n * intervalSeconds
		s.BonusGranted += n
		awards = append(awards, BonusAward{
			Account:   s.Account,
			MId:       s.MId,
			Intervals: n,
			Granted:   s.BonusGranted,
			Remainder: s.GameOnlineSeconds,
		})
	}
	return awards
}

// FormatSessionInfo 格式化会话信息。
func FormatSessionInfo(s *models.Session) map[string]interface{} {
	return map[string]interface{}{
		"account":       s.Account,
		"ip":            s.ClientIP,
		"onlineMinutes": int((time.Now().Unix() - s.CreatedAt) / 60),
		"lastHeartbeat": s.LastHeartbeat,
		"bonusGranted":  s.BonusGranted,
	}
}

// LogKickAccount 记录一次“踢账号下线”操作。
//
// 第二个参数保留 interface{} 以兼容历史调用点，实际取值规则：
//   - 传 *logger.ConsoleLogger 时写入其日志流（推荐）；
//   - 传 nil 或其它类型时退回全局 logger（logger.Global()）。
//
// 原实现直接 fmt.Printf 到 stdout，绕过了日志文件与统一格式，已修正。
func LogKickAccount(account string, log interface{}) {
	logger.LogKick(logger.Normalize(log), account)
}

// LogKickAll 记录一次“全服踢下线”操作，参数规则同 LogKickAccount。
func LogKickAll(log interface{}) {
	logger.LogKickAll(logger.Normalize(log))
}
