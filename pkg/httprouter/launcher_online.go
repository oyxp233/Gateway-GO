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

// handleLauncherNotice 下发登录器「更新内容」区展示的更新公告。
//
// 配置源是网关进程内存里的 config.Launcher.UpdateNotice（管理后台「客户端配置」页维护），
// 改完立刻生效，不需要重启网关，也不需要重启登录器。
func (s *Server) handleLauncherNotice(w http.ResponseWriter, r *http.Request) {
	notice := strings.TrimSpace(s.config.Launcher.UpdateNotice)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":            true,
		"update_notice": notice,
		// 一并带上版本策略，登录器可以只发一次请求拿到全部展示所需信息
		"min_version":  s.config.Launcher.MinVersion,
		"download_url": s.config.Launcher.DownloadUrl,
		"server_time":  time.Now().UTC().Unix(),
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
func (s *Server) handleLauncherOnline(w http.ResponseWriter, r *http.Request) {
	// 非强制刷新时先看缓存
	if r.URL.Query().Get("force") != "1" {
		s.onlineCacheMu.Lock()
		if len(s.onlineCacheBody) > 0 && time.Since(s.onlineCacheAt) < launcherOnlineCacheTTL {
			body := s.onlineCacheBody
			s.onlineCacheMu.Unlock()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
		s.onlineCacheMu.Unlock()
	}

	payload, err := s.buildLauncherOnline()
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
	s.onlineCacheAt = time.Now()
	s.onlineCacheBody = body
	s.onlineCacheMu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) buildLauncherOnline() (map[string]interface{}, error) {
	online, err := s.sessions.List()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(online))
	for _, p := range online {
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

	players := make([]launcherOnlinePlayer, 0, len(online))
	roleTotal := 0
	for _, p := range online {
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
	}

	// 维持「在线时长倒序」：玩得久的排前面，观感上比按账号排稳定
	sortOnlinePlayers(players)

	return map[string]interface{}{
		"ok":          true,
		"count":       len(players), // 在线账号数（= 在线角色数，一个账号同时只跑一个角色）
		"role_count":  roleTotal,    // 关联到角色的数量；剩下的停在选人界面
		"server_time": time.Now().UTC().Unix(),
		// precision 如实说明口径：在线是账号级，角色是按最近活动推定的
		"precision": "account-session+character.updated_at",
		"players":   players,
	}, nil
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
