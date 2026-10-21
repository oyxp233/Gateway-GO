package httprouter

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"s4a21-gateway/pkg/database"
)

// ============================================================================
// 登录器公开接口：更新公告 + 在线角色
//
// 这两个路由只在**网关进程**注册（registerPublicRoutes），admin 进程没有它们 ——
// 在线状态与会话表都在网关内存里，admin 侧无法独立回答。
//
// 两个接口都免鉴权（玩家登录器在登录前/登录后都要能看），因此有两条硬约束：
//   ① 绝不能暴露账号名与 IP —— 只给角色级信息（角色名本来就在物品榜单里公开）；
//   ② 必须限流 —— pathGroups 里挂 GroupLauncher（见 ratelimiter.go）。
// ============================================================================

// launcherOnlineCacheTTL 是在线角色响应的缓存窗口。
const launcherOnlineCacheTTL = 5 * time.Second

// launcherServerInfo 是公开接口下发的服清单条目。
//
// 只给 id / name / protocol 三个字段：
//   - id      登录器把它和自己配置里的 GameProfile.Id 对齐；
//   - name    界面展示（运营改名不用发登录器）；
//   - protocol  登录器**发密码前**必须知道的事（见下）。
//
// ★ 为什么要公开 protocol（2026-10-21）：
// S5A3 的账号 API 收**明文密码**，S4A21/S5A95 只收 MD5。登录器不能对所有服
// 都发明文（那等于给老服降级），也不能都不发（S5A3 登不进去）。它必须在发
// 登录请求之前就知道这一服的协议，而此刻它还没有 token、拿不到 policy。
// 所以把协议放进这个免鉴权的公告响应里 —— 登录器启动时本来就拉它。
type launcherServerInfo struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// launcherServers 返回启用服清单（保持配置顺序）。
//
// 只列**启用**的服：停用服登录会被 1039 拒，没必要让玩家在列表里选到它。
func (s *Server) launcherServers() []launcherServerInfo {
	out := make([]launcherServerInfo, 0, len(s.config.GameServers))
	for _, entry := range s.config.GameServers {
		if !entry.IsEnabled() {
			continue
		}
		out = append(out, launcherServerInfo{
			Id:       entry.Id,
			Name:     entry.Name,
			Protocol: entry.Protocol,
		})
	}
	return out
}

// handleLauncherNotice 下发登录器「更新内容」区展示的更新公告。
//
// 配置源是网关进程内存里的 config.Launcher.UpdateNotice（管理后台「客户端配置」页维护），
// 改完立刻生效，不需要重启网关，也不需要重启登录器。
func (s *Server) handleLauncherNotice(w http.ResponseWriter, r *http.Request) {
	// G-5（2026-10-04 审查）：Launcher 段由管理后台在运行中改写，读走快照。
	lz := s.config.LauncherSnapshot()
	notice := strings.TrimSpace(lz.UpdateNotice)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":            true,
		"update_notice": notice,
		// 一并带上版本策略，登录器可以只发一次请求拿到全部展示所需信息
		"min_version": lz.MinVersion,
		"download_url": lz.DownloadUrl,
		// 单机多开上限（2026-10-19）。0 = 不限制；键缺失（老网关）时登录器
		// 同样按不限制处理 —— 与配置缺省语义一致。
		"max_instances": lz.MaxInstances,
		// 启用服清单（含协议）：登录器据此决定用明文还是 MD5 上报密码。
		"servers":     s.launcherServers(),
		"server_time": time.Now().UTC().Unix(),
	})
}

// launcherOnlineRole 在线账号当前在玩的角色。
type launcherOnlineRole struct {
	CharacterId int64  `json:"character_id"`
	Name        string `json:"name"`
	Level       int    `json:"level"`
	Job         int    `json:"job"`
	// LastActiveAt 是推定依据：characters.updated_at（UTC）。
	// 它表示「最后一次数据变更」，不等于在线时长 —— 挂机玩家可能很久不刷新，
	// 所以一并下发，让前端能如实展示而不是假装精确。
	LastActiveAt string `json:"last_active_at"`
}

// launcherOnlinePlayer 一条在线账号记录。
//
// 刻意**不下发账号名与 IP**：这是免鉴权公开接口，账号名/来源 IP 属于隐私。
// 玩家侧只需要知道「谁在线上」，角色名足够。
type launcherOnlinePlayer struct {
	OnlineMinutes int                 `json:"online_minutes"`
	LastHeartbeat int64               `json:"last_heartbeat"`
	Role          *launcherOnlineRole `json:"role"`       // 当前角色；账号停在选人界面时为 null
	RoleCount     int                 `json:"role_count"` // 该账号存活角色总数
}

// handleLauncherOnline 返回当前在线角色。
//
// 数据来源分两层，各司其职：
//
//	① 「谁在线」—— 网关内存会话表（权威、实时）；
//	② 「在玩哪个角色」—— 游戏库 characters.updated_at 最新的那个。
//	   服务端不把在线状态落库，但每次角色数据变更都会刷新 updated_at，
//	   所以同一账号名下最新的那条就是在玩的角色（见 database.OnlineRoleCandidate）。
//
// game 查询参数（2026-10-17 双服）：为空 = 全部服的汇总视图；
// 带值 = 只看该服（GameServers[].Id）的在线玩家，payload 带 "game" 回显。
// 两种视图的缓存分槽存放（见 Server.onlineCacheBody 注释），互不污染。
func (s *Server) handleLauncherOnline(w http.ResponseWriter, r *http.Request) {
	game := strings.TrimSpace(r.URL.Query().Get("game"))

	// 非强制刷新时先看缓存（按 game 分槽）
	if r.URL.Query().Get("force") != "1" {
		s.onlineCacheMu.Lock()
		if body, ok := s.onlineCacheBody[game]; ok && len(body) > 0 && time.Since(s.onlineCacheAt[game]) < launcherOnlineCacheTTL {
			s.onlineCacheMu.Unlock()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		s.onlineCacheMu.Unlock()
	}

	payload, err := s.buildLauncherOnline(game)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok": false, "error": err.Error(),
			"count": 0, "role_count": 0, "players": []interface{}{},
		})
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	s.onlineCacheMu.Lock()
	if s.onlineCacheAt == nil {
		s.onlineCacheAt = make(map[string]time.Time)
	}
	if s.onlineCacheBody == nil {
		s.onlineCacheBody = make(map[string][]byte)
	}
	s.onlineCacheAt[game] = time.Now()
	s.onlineCacheBody[game] = body
	s.onlineCacheMu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// buildLauncherOnline 组装在线视图（2026-10-17 双服）。
//
// game 为空 = 汇总视图：players 含全部在线账号，另附 "games" 按服计数
// （空 GameId 的老会话归入默认服键，由登录器识别）；
// game 非空 = 单服视图：只统计该服在线账号，payload 回显 "game"。
func (s *Server) buildLauncherOnline(game string) (map[string]interface{}, error) {
	online, err := s.sessions.List()
	if err != nil {
		return nil, err
	}

	// 单服视图：先按 GameId 过滤。空 GameId 的会话（老登录器/默认服登录）
	// 只在 game 也为空（或 game 为默认服 Id）时出现 —— 精确匹配空串会让
	// 默认服玩家在选服界面里消失，那不是想要的行为。
	filtered := online
	if game != "" {
		filtered = make([]OnlinePlayer, 0, len(online))
		for _, p := range online {
			if p.GameId == game {
				filtered = append(filtered, p)
			}
		}
	}

	names := make([]string, 0, len(filtered))
	for _, p := range filtered {
		names = append(names, p.Account)
	}

	// 账号名 → m_id → 当前角色。两步都做成批量查询，不要按人循环打库。
	mIds := map[string]string{}
	if s.db != nil && len(names) > 0 {
		if m, err := s.db.GetMIdsByNames(names); err == nil {
			mIds = m
		}
	}

	mIdList := make([]string, 0, len(mIds))
	for _, m := range mIds {
		mIdList = append(mIdList, m)
	}
	candidates := map[string]database.OnlineRoleCandidate{}
	if s.db != nil && len(mIdList) > 0 {
		if got, err := s.db.GetCurrentRolesByMIds(mIdList); err == nil {
			candidates = got
		}
	}

	players := make([]launcherOnlinePlayer, 0, len(filtered))
	roleTotal := 0
	// games 按服计数（汇总视图用）：GameId → 在线账号数。
	// 用 map 而不是预定义服列表：网关配置里服的集合是运行时可变的，
	// 硬编码列表会让新加的服在在线视图里"隐身"。
	games := map[string]int{}
	for _, p := range filtered {
		item := launcherOnlinePlayer{
			OnlineMinutes: p.OnlineMinutes,
			LastHeartbeat: p.LastHeartbeat,
		}
		if mId, ok := mIds[p.Account]; ok {
			if c, ok := candidates[mId]; ok {
				item.Role = &launcherOnlineRole{
					CharacterId:  c.CharacterId,
					Name:         c.Name,
					Level:        c.Level,
					Job:          c.Job,
					LastActiveAt: c.LastActiveAt,
				}
				item.RoleCount = c.RoleCount
				roleTotal++
			}
		}
		players = append(players, item)
		games[p.GameId]++
	}

	// 维持「在线时长倒序」：玩得久的排前面，观感上比按账号排稳定
	sortOnlinePlayers(players)

	payload := map[string]interface{}{
		"ok":          true,
		"count":       len(players), // 在线账号数（= 在线角色数，一个账号同时只跑一个角色）
		"role_count":  roleTotal,    // 关联到角色的数量；剩下的停在选人界面
		"server_time": time.Now().UTC().Unix(),
		// precision 如实说明口径：在线是账号级，角色是按最近活动推定的
		"precision": "account-session+character.updated_at",
		"players":   players,
	}
	if game != "" {
		payload["game"] = game
	} else {
		payload["games"] = games
	}
	return payload, nil
}

// sortOnlinePlayers 按在线时长倒序（插入排序：在线人数很少，没必要引入 sort 依赖）。
func sortOnlinePlayers(list []launcherOnlinePlayer) {
	for i := 1; i < len(list); i++ {
		cur := list[i]
		j := i - 1
		for j >= 0 && list[j].OnlineMinutes < cur.OnlineMinutes {
			list[j+1] = list[j]
			j--
		}
		list[j+1] = cur
	}
}
