package ratelimiter

import (
	"strings"
	"sync"
	"time"
)

// RateLimiter 基于令牌桶的 IP 限流器。
type RateLimiter struct {
	mu             sync.Mutex
	enabled        bool
	requestsPerMin int
	tokens         map[string]*bucket
	lastSweep      time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter 创建 IP 限流器。
func NewRateLimiter(enabled bool, requestsPerMin int) *RateLimiter {
	return &RateLimiter{
		enabled:        enabled,
		requestsPerMin: requestsPerMin,
		tokens:         make(map[string]*bucket),
		lastSweep:      time.Now(),
	}
}

// TryAcquire 尝试获取令牌，成功返回 true。
func (rl *RateLimiter) TryAcquire(ip string) bool {
	if !rl.enabled || rl.requestsPerMin <= 0 {
		return true
	}

	now := time.Now()

	// 过期清理刻意放在**取业务锁之前**，且内部用 TryLock：
	// 原来这段 sweep 写在 Lock/Unlock 之间，于是"每 60s 那一个恰好触发清理的请求"
	// 要持着锁遍历整张表，期间所有请求排队。现在命中 sweep 的请求拿不到锁就直接跳过，
	// 由下一个请求（或 60s 后的下一轮）来扫。
	rl.sweepIfDue(now)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rate := float64(rl.requestsPerMin) / 60.0 // 每秒填充速率
	maxTokens := float64(rl.requestsPerMin)

	b, exists := rl.tokens[ip]
	if !exists {
		b = &bucket{tokens: maxTokens, last: now}
		rl.tokens[ip] = b
	}

	// 填充令牌
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rate
	if b.tokens > maxTokens {
		b.tokens = maxTokens
	}
	b.last = now

	// 消费令牌
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// sweepIfDue 清理超过 60s 未活动的令牌桶。
//
// 拿不到锁就跳过这一轮：宁可不清理（下一个请求、或 60s 后的下一轮会做），
// 也不要让清理去等锁从而阻塞调用方。
//
// 已知限制（刻意保留，未改数据结构）：sweep 仍需持锁遍历整张表，
// 与 sweep 并发的请求会在 mu.Lock() 上等一次 O(N)。桶数 = 独立 IP × 分组，
// 私服规模（万级以内）实测为微秒~毫秒级。要彻底消除得改成分片锁，
// 属结构性改动，风险大于收益。
func (rl *RateLimiter) sweepIfDue(now time.Time) {
	if !rl.mu.TryLock() {
		return
	}
	defer rl.mu.Unlock()

	if now.Sub(rl.lastSweep) <= 60*time.Second {
		return
	}
	for key, b := range rl.tokens {
		if now.Sub(b.last) > 60*time.Second {
			delete(rl.tokens, key)
		}
	}
	rl.lastSweep = now
}

// HttpRateLimiter HTTP 端点限流器。
type HttpRateLimiter struct {
	limiter *RateLimiter
}

// NewHttpRateLimiter 创建 HTTP 限流器。
func NewHttpRateLimiter(enabled bool, requestsPerMin int) *HttpRateLimiter {
	return &HttpRateLimiter{
		limiter: NewRateLimiter(enabled, requestsPerMin),
	}
}

// IsProtected 检查路径是否受限流保护。
func IsProtected(path string) bool {
	return PathGroup(path) != ""
}

// 限流分组名。不同分组的流量互不挤占令牌，
// 避免玩家客户端的高频心跳把后台管理请求挤掉（或反之）。
const (
	GroupAdmin     = "admin"
	GroupHeartbeat = "heartbeat"
	GroupLauncher  = "launcher"
	// GroupAntiCheat 客户端反作弊插件上报。
	//
	// 单独成组而不是并进 launcher：上报量由插件按异常事件触发（正常游戏期间为 0），
	// 一旦某台机器疯狂上报，限流只该丢它的上报，不该顺带把同 IP 的策略/榜单请求一起饿死。
	GroupAntiCheat = "anticheat"

	// GroupLauncherBinary 登录器插件文件下载（2026-09-30 插件增量更新）。
	//
	// 单独成桶的理由与上面几条同理，但**不是**为了提速 ——
	// 本限流器的速率由 RateLimit.HttpRequestsPerMinute 全局决定，分组只分桶、
	// 不改变速率。分开是为了让"一次冷启动拉 12 个插件文件"不占掉
	// 同 IP 的策略(policy)/榜单(item-ranking) 额度，反之亦然。
	//
	// 额度是否够（单 IP 120/分）：冷启动最坏 = 1 次清单 + 12 个文件 = 13 次；
	// 每次下载最多重试 3 次 → 39 次。120/分 有 3 倍余量。
	GroupLauncherBinary = "launcher-binary"
)

// pathGroups 受保护路径前缀 -> 分组名。
//
// 匹配必须是"前缀后紧跟 / 或字符串结束"，否则 /api/adminxxx 会被误判为受保护路径。
var pathGroups = []struct {
	prefix string
	group  string
}{
	{"/api/admin", GroupAdmin},
	{"/api/heartbeat", GroupHeartbeat},
	// 登录器公开接口：/api/launcher/policy 与 /api/launcher/item-ranking。
	// item-ranking 是聚合查询，必须限流（它是无鉴权公开接口）；
	// /api/launcher/version 沿用历史行为保持不限流。
	// ★ 顺序敏感：更具体的 /plugins/file 必须排在 /plugins 之前。
	// PathGroup 是线性扫描、命中即返回，反过来的话下载会被归进清单那一桶。
	{"/api/launcher/plugins/file", GroupLauncherBinary},
	// PVF 增量包下载（2026-09-30 PVF 增量更新）。同样是"版本更新时才发生一次"的
	// 大文件传输（实测 219 KB ~ 10.8 MB），与插件下载共用一个桶：
	// 两者都是登录启动阶段的一次性拉取，不会互相挤占（同一时刻只会发生一件）。
	{"/api/launcher/pvf/delta", GroupLauncherBinary},
	// 插件清单（2026-09-30 插件增量更新）。与 policy 同类：公开只读的策略下发，
	// 每次启动打一次，归 launcher 桶。
	{"/api/launcher/plugins", GroupLauncher},
	// 登录器自更新（2026-10-04 审查 G-3）：/api/launcher/update（清单）、
	// /update/exe（134 MiB 全量 exe）、/update/delta（差分）原先**完全不在限流表里** ——
	// PathGroup() 返回空串，限流中间件直接放行。而 /update/exe 是无鉴权大文件下载、
	// /update/delta 会对整个 exe 重算 SHA-256 + 块索引，外部可直接打满出口带宽与 CPU。
	// 归 launcher-binary 桶（与插件文件、PVF 增量同类：登录启动阶段的一次性拉取）。
	// ★ 前缀匹配覆盖整条 /update 子树（清单 / exe / delta），无需逐条列。
	{"/api/launcher/update", GroupLauncherBinary},
	{"/api/launcher/item-ranking", GroupLauncher},
	{"/api/launcher/policy", GroupLauncher},
	// online 免鉴权且每次要 join 游戏库查角色（带 5s 缓存），仍必须限流：
	// 缓存挡的是"同一时刻的突发"，挡不住持续打点。
	{"/api/launcher/online", GroupLauncher},
	// 反作弊上报：校验会话 token 就能反复 POST 任意大小 body，原先不在任何限流组里。
	// 上限依据（实测插件源码）：只有检测队列非空才发，且两次上报间隔 ≥ ini 的 intervalMs；
	// 登录器渲染的模板是 intervalMs=2000 → 单实例最多 30 次/分，远低于 120 次/分。
	// 只有"一直在报异常"的客户端才可能撞上限流，那正是应该被丢的那类流量。
	{"/api/anticheat", GroupAntiCheat},
}

// PathGroup 返回路径所属的限流分组；不受保护时返回空串。
func PathGroup(path string) string {
	for _, pg := range pathGroups {
		if !strings.HasPrefix(path, pg.prefix) {
			continue
		}
		// 前缀边界校验：/api/admin 应匹配 /api/admin 与 /api/admin/xxx，
		// 不应匹配 /api/adminxxx
		if len(path) == len(pg.prefix) || path[len(pg.prefix)] == '/' {
			return pg.group
		}
	}
	return ""
}

// TryAcquire 尝试获取 HTTP 令牌。
func (h *HttpRateLimiter) TryAcquire(ip string) bool {
	return h.limiter.TryAcquire(ip)
}

// TryAcquireGroup 尝试获取指定分组的令牌。
//
// 按 "IP + 分组" 分桶：后台管理、客户端心跳、登录器策略三类流量各自计数，
// 互不挤占。用 IP 单独做 key 会让高频的心跳流量耗尽令牌，
// 导致管理后台被误伤限流。
func (h *HttpRateLimiter) TryAcquireGroup(ip, group string) bool {
	if group == "" {
		return true
	}
	return h.limiter.TryAcquire(ip + "\x00" + group)
}
