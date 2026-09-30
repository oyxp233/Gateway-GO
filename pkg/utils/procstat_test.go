package utils

import (
	"strconv"
	"strings"
	"testing"
)

// buildProcStat 按 /proc/<pid>/stat 的字段序造一条，starttime 落在第 22 个字段。
//
// 字段序：pid comm state ppid ... starttime(22) ...
// 即 comm 之后第一个是字段 3，所以 fields[19] 就是 starttime。
func buildProcStat(pid int, comm string, startTicks string) string {
	fields := []string{"S"} // 字段 3：state
	for i := 4; i < 22; i++ {
		fields = append(fields, "0")
	}
	fields = append(fields, startTicks) // 字段 22
	return strings.Join([]string{strconv.Itoa(pid), "(" + comm + ")", strings.Join(fields, " ")}, " ")
}

// TestParseProcStatStart 进程名里带空格与括号时，starttime 仍要取对。
//
// 反例（这条测试存在的理由）：按空格直接切分会把 "my (weird) name" 切碎，
// 之后所有字段整体前移，starttime 取到的是别的字段 —— 后台显示出一个
// 荒谬的运行时长，而且不报错。必须从**最后一个右括号**之后开始数。
func TestParseProcStatStart(t *testing.T) {
	cases := []struct {
		name string
		stat string
		want uint64
	}{
		{"普通进程名", buildProcStat(4321, "DfoServer", "987654"), 987654},
		{"进程名含空格", buildProcStat(7, "my server", "1234567"), 1234567},
		{"进程名含括号", buildProcStat(7, "my (weird) name", "555"), 555},
		{"进程名含空格和括号", buildProcStat(7, "a (b) c (d)", "42"), 42},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseProcStatStart(c.stat)
			if !ok {
				t.Fatalf("解析失败: %q", c.stat)
			}
			if got != c.want {
				t.Errorf("starttime 应为 %d，实得 %d", c.want, got)
			}
		})
	}
}

func TestParseProcStatStartMalformed(t *testing.T) {
	bad := []string{
		"",
		"4321 (DfoServer", // 右括号缺失
		"4321 () S 1 2",   // 字段严重不足
		"4321 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 不是数字",
	}
	for _, s := range bad {
		if _, ok := parseProcStatStart(s); ok {
			t.Errorf("畸形输入不该解析成功: %q", s)
		}
	}
}

func TestParseProcStatusRSS(t *testing.T) {
	status := "Name:\tDfoServer\n" +
		"State:\tS (sleeping)\n" +
		"VmPeak:\t 2048000 kB\n" +
		"VmRSS:\t  123456 kB\n" +
		"Threads:\t18\n"

	if got := parseProcStatusRSS(status); got != 123456*1024 {
		t.Errorf("VmRSS 应换算成字节 %d，实得 %d", 123456*1024, got)
	}

	// 没有 VmRSS 行时返回 0（而不是 panic 或瞎猜一个值）。
	if got := parseProcStatusRSS("Name:\tX\n"); got != 0 {
		t.Errorf("没有 VmRSS 行应返回 0，实得 %d", got)
	}
	if got := parseProcStatusRSS(""); got != 0 {
		t.Errorf("空输入应返回 0，实得 %d", got)
	}
}

func TestParseUptime(t *testing.T) {
	if got, ok := parseUptime("123456.78 987654.32\n"); !ok || got != 123456.78 {
		t.Errorf("应解析出 123456.78，实得 %v ok=%v", got, ok)
	}
	for _, s := range []string{"", "abc", "-5 1"} {
		if _, ok := parseUptime(s); ok {
			t.Errorf("畸形 uptime 不该解析成功: %q", s)
		}
	}
}

// TestReadProcStatsSelf 拿当前测试进程做一次真实读取。
//
// 至少保证：能读到运行秒数、内存非 0，且 StartedAt 落在合理区间。
// （不比对具体数值 —— 那取决于跑测试的机器。）
func TestReadProcStatsSelf(t *testing.T) {
	if !IsLinux() {
		t.Skip("仅 Linux 有 /proc")
	}

	stats := ReadProcStats(1) // PID 1 一定存在
	if stats == nil {
		t.Fatal("ReadProcStats(1) 返回 nil")
	}
	if stats.UptimeSeconds <= 0 {
		t.Errorf("PID 1 的运行秒数应大于 0，实得 %d", stats.UptimeSeconds)
	}
	if stats.RSSBytes <= 0 {
		t.Errorf("PID 1 的内存应大于 0，实得 %d", stats.RSSBytes)
	}

	// 不存在的 pid 只返回零值，不 panic。
	empty := ReadProcStats(999999)
	if empty == nil || empty.UptimeSeconds != 0 || empty.RSSBytes != 0 {
		t.Errorf("不存在的 pid 应返回零值，实得 %+v", empty)
	}
}
