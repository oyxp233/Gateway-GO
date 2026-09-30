package utils

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// userHZ 是 Linux 的 USER_HZ（clock tick 频率）。
//
// 它和内核编译时的 CONFIG_HZ **不是一回事**：USER_HZ 属于内核 ABI，在 x86_64 上
// 恒为 100，不随内核配置变化。因此 /proc/<pid>/stat 的 starttime 除以 100 就是秒数，
// 无需 getconf（那要走 cgo，交叉编译会跟着复杂起来）。
const userHZ = 100

// ProcStats 单个进程的运行时长与常驻内存。
type ProcStats struct {
	// StartedAt 进程启动时刻（Unix 秒）。0 表示读不到。
	StartedAt int64
	// UptimeSeconds 已运行秒数。负数按 0 处理。
	UptimeSeconds int64
	// RSSBytes 常驻内存（/proc/<pid>/status 的 VmRSS）。0 表示读不到。
	RSSBytes int64
}

// ReadProcStats 读取指定进程的运行时长与内存占用。
//
// 为什么用 /proc 而不是 `systemctl show -p MemoryCurrent,ActiveEnterTimestamp`：
//   - MemoryCurrent 依赖 cgroup 内存记账，单元没开 MemoryAccounting 时恒为
//     [not set]，后台就只能显示"-"；VmRSS 任何时候都读得到。
//   - ActiveEnterTimestamp 是本地化过的可读时间（"Thu 2026-09-24 03:05:26 UTC"），
//     解析要跟着宿主机 locale 走；用 starttime + uptime 两个纯数字相减没有这个问题。
//
// 任何一步失败都只让对应字段保持 0，不返回错误 —— 管理页的"运行时长/内存"
// 是辅助信息，不该因为它读不到就让整个状态接口失败。
func ReadProcStats(pid int) *ProcStats {
	stats := &ProcStats{}
	if pid <= 0 {
		return stats
	}

	startTicks, ok := readStartTicks(pid)
	if !ok {
		return stats
	}

	upSeconds, ok := readUptimeSeconds()
	if !ok {
		return stats
	}

	startedSeconds := float64(startTicks) / float64(userHZ)
	uptime := upSeconds - startedSeconds
	if uptime < 0 {
		uptime = 0
	}
	stats.UptimeSeconds = int64(uptime)
	stats.StartedAt = time.Now().Unix() - stats.UptimeSeconds
	stats.RSSBytes = readRSSBytes(pid)
	return stats
}

// readStartTicks 从 /proc/<pid>/stat 取出 starttime（第 22 个字段，单位 clock tick）。
func readStartTicks(pid int) (uint64, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	return parseProcStatStart(string(data))
}

// parseProcStatStart 解析 /proc/<pid>/stat 里的 starttime。
//
// 格式：`pid (comm) state ppid ...`。comm 是进程名，**允许包含空格和括号**
// （例如 "my (weird) name"），所以不能按空格直接切 —— 必须先跳到**最后一个
// 右括号**之后，再对剩余字段计数：切出来的第 0 个是 state（即字段 3），
// 于是字段 N 对应下标 N-3。starttime 是字段 22，即下标 19。
func parseProcStatStart(stat string) (uint64, bool) {
	close := strings.LastIndexByte(stat, ')')
	if close < 0 || close+2 > len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[close+1:])
	const starttimeIndex = 22 - 3
	if len(fields) <= starttimeIndex {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[starttimeIndex], 10, 64)
	if err != nil {
		return 0, false
	}
	return ticks, true
}

// readUptimeSeconds 读 /proc/uptime 的第一字段（系统已运行秒数，含小数）。
func readUptimeSeconds() (float64, bool) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	return parseUptime(string(data))
}

func parseUptime(raw string) (float64, bool) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return seconds, true
}

// readRSSBytes 读 /proc/<pid>/status 的 VmRSS（单位 kB，转换成字节）。
func readRSSBytes(pid int) int64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	return parseProcStatusRSS(string(data))
}

func parseProcStatusRSS(status string) int64 {
	for _, line := range strings.Split(status, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "VmRSS:"))
		if len(fields) == 0 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || kb < 0 {
			return 0
		}
		return kb * 1024
	}
	return 0
}
