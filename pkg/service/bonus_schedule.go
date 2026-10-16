package service

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	// tzdata 让二进制自带时区数据库。
	//
	// 本文件按 IANA 时区名（如 Asia/Shanghai）判定星期与时间段，走的是
	// time.LoadLocation。网关是 CGO_ENABLED=0 的静态二进制，部署到**精简镜像/
	// 没装 tzdata 的机器**时，不带这份内嵌数据会导致 LoadLocation 报
	// "unknown time zone" —— 于是「看似配好了时区」却被校验挡在门外，
	// 症状极难定位。带上它只多几百 KB，换的是"到哪都能跑"。
	_ "time/tzdata"
)

// ============================================================================
// 泡点分档：按「星期 + 时间段」发放不同数量的点券
//
// 需求形态（2026-10-16）：
//   周一~周五 06:00~24:00 → 120 点；00:00~06:00 → 60 点
//   周六~周日 06:00~24:00 → 150 点；00:00~06:00 → 80 点
//
// 设计要点：
//   1. **向后兼容**：rules 为空（老 bonus.json 没这个键）时走
//      amount_per_interval，与改造前逐字节等价 —— 存量配置不用迁移。
//   2. **计费周期仍是全局的** interval_seconds，各档只换"每周期发多少"。
//      这样"在线时长累计/余数跨轮保留"这套既有机制一行都不用改。
//   3. **首条命中即用**，规则的书写顺序就是优先级 —— 运营按从特殊到一般
//      排即可，不需要理解覆盖语义。
//   4. 一条规则都没命中时**不拒绝发放**，回落到默认档。宁可少发的几块钱，
//      也不能因为配了一条没覆盖全天的规则就让泡点整轮停摆。
// ============================================================================

// bonusDefaultSlotName 没有规则命中时的档位名（写进日志，便于对账）。
const bonusDefaultSlotName = "默认档"

// bonusMaxRules 规则条数上限。
//
// 每轮结算要按序遍历规则，条数失控会让主循环变慢；更重要的是运营侧
// 几十条互相覆盖的规则本身就是事故源 —— 早失败比慢慢失控好。
const bonusMaxRules = 64

// bonusMaxAmount 单档每周期发放上限（与既有 amount_per_interval 同口径）。
const bonusMaxAmount = 10000000

// BonusRule 一条分档规则（对应 bonus.json 的 rules[] 一项）。
//
// days 用 ISO-8601 口径：**1 = 周一 … 7 = 周日**（与 Go time.Weekday 的
// 周日 = 0 不同，这里是刻意的 —— 配置文件给人看的，别让人下标错位）。
// days 为空表示「每天」。
type BonusRule struct {
	Name string `json:"name"`
	// Days 生效的星期（1~7）；空数组 = 每天。
	Days []int `json:"days"`
	// Start 起始时刻 "HH:MM"（含该刻）。
	Start string `json:"start"`
	// End 结束时刻 "HH:MM"（不含该刻）；"24:00" 表示到当天末尾。
	// ★ start > end 视为**跨零点**时段（如 22:00 ~ 06:00），一条就够，
	//   不必拆成两段写。start == end 视为全天。
	End string `json:"end"`
	// Amount 该档位**每个计费周期**发放的点券数。
	Amount int `json:"amount"`
}

// bonusRuleCompiled 编译后的规则：把 "HH:MM" 预先算成分钟数，避免每轮重复解析。
type bonusRuleCompiled struct {
	name     string
	amount   int
	days     map[int]struct{}
	startMin int
	endMin   int
	// wraps 是否跨零点。
	wraps bool
}

// Location 返回判定星期/时间段所用的时区。
//
// Timezone 留空 → 服务器本地时区（改造前的默认行为，存量配置不受影响）。
// 显式配了但解析不出来 → **报错**，绝不悄悄退回 Local：
// 那样"配了上海、实际按 UTC 发"会变成查不出来的钱账不对。
func (cfg *BonusConfig) Location() (*time.Location, error) {
	tz := strings.TrimSpace(cfg.Timezone)
	if tz == "" {
		return time.Local, nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("timezone %q 无法解析（须为 IANA 名称，如 Asia/Shanghai）: %w", tz, err)
	}
	return loc, nil
}

// ResolveBonus 判定时刻 t 该按哪一档发放。
//
// 返回 (每周期发放点数, 档位名, 错误)。错误只来自"配置本身不可用"
// （时区解析失败 / 规则非法）；**没有任何规则命中不是错误**，走默认档。
func (cfg *BonusConfig) ResolveBonus(t time.Time) (int, string, error) {
	loc, err := cfg.Location()
	if err != nil {
		return 0, "", err
	}
	compiled, err := compileBonusRules(cfg.Rules)
	if err != nil {
		return 0, "", err
	}
	local := t.In(loc)
	for _, r := range compiled {
		if r.matches(local) {
			return r.amount, r.name, nil
		}
	}
	return cfg.AmountPerInterval, bonusDefaultSlotName, nil
}

// matches 判断时刻 t（已换算到配置时区）是否落在本规则内。
func (r bonusRuleCompiled) matches(t time.Time) bool {
	nowMin := t.Hour()*60 + t.Minute()
	wd := isoWeekday(t)

	// 跨零点时段归属到**它的起始日**：22:00~06:00 配了「周五」时，
	// 周六凌晨 3 点仍算这一夜的一部分。若按自然日判，周五通宵到凌晨
	// 就掉了档 —— 运营写 22:00~06:00 想要的就是"这一晚"。
	if r.wraps && nowMin < r.endMin {
		wd = isoWeekday(t.AddDate(0, 0, -1))
	}

	if len(r.days) > 0 {
		if _, ok := r.days[wd]; !ok {
			return false
		}
	}
	if r.wraps {
		return nowMin >= r.startMin || nowMin < r.endMin
	}
	return nowMin >= r.startMin && nowMin < r.endMin
}

// isoWeekday ISO-8601 星期：1 = 周一 … 7 = 周日。
func isoWeekday(t time.Time) int {
	w := int(t.Weekday())
	if w == 0 {
		return 7
	}
	return w
}

// compileBonusRules 校验并预编译规则集。先整体校验再产出，
// 保证调用方拿到的要么全是好规则、要么是个错误 —— 不会出现"编译到一半"。
func compileBonusRules(rules []BonusRule) ([]bonusRuleCompiled, error) {
	if err := validateBonusRules(rules); err != nil {
		return nil, err
	}
	out := make([]bonusRuleCompiled, 0, len(rules))
	for i, r := range rules {
		startMin, _ := parseClock(r.Start)
		endMin, _ := parseClock(r.End)
		if startMin == endMin {
			// 起止相同 = 全天。
			startMin, endMin = 0, 1440
		}
		days := make(map[int]struct{}, len(r.Days))
		for _, d := range r.Days {
			days[d] = struct{}{}
		}
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = fmt.Sprintf("规则%d", i+1)
		}
		out = append(out, bonusRuleCompiled{
			name:     name,
			amount:   r.Amount,
			days:     days,
			startMin: startMin,
			endMin:   endMin,
			wraps:    startMin > endMin,
		})
	}
	return out, nil
}

// validateBonusRules 校验 rules 数组的每一项。
//
// ★ 这里刻意**不拒绝空 rules**：那份配置的语义是"只有默认档"，
//   等于改造前的老配置，必须继续跑得起来。
func validateBonusRules(rules []BonusRule) error {
	if len(rules) > bonusMaxRules {
		return fmt.Errorf("rules 条数过多（最多 %d 条），实得 %d", bonusMaxRules, len(rules))
	}
	for i, r := range rules {
		label := strings.TrimSpace(r.Name)
		if label == "" {
			label = fmt.Sprintf("第 %d 条", i+1)
		}
		if _, err := parseClock(r.Start); err != nil {
			return fmt.Errorf("规则「%s」起始时间非法: %w", label, err)
		}
		if _, err := parseClock(r.End); err != nil {
			return fmt.Errorf("规则「%s」结束时间非法: %w", label, err)
		}
		if r.Amount < 0 || r.Amount > bonusMaxAmount {
			return fmt.Errorf("规则「%s」的 amount 取值范围 0~%d，实得 %d", label, bonusMaxAmount, r.Amount)
		}
		for _, d := range r.Days {
			if d < 1 || d > 7 {
				return fmt.Errorf("规则「%s」的 days 取值须为 1~7（1=周一…7=周日），实得 %d", label, d)
			}
		}
	}
	return nil
}

// parseClock 把 "HH:MM" 解析成当日分钟数（0~1440）。
//
// 宽松接受 "6:00"、" 06:00 " 这类手写形式（配置是人写的，别为一个前导零
// 把整份泡点挡在门外），但范围严格：24 点只允许写作 24:00。
func parseClock(s string) (int, error) {
	raw := strings.TrimSpace(s)
	i := strings.Index(raw, ":")
	if i < 0 {
		return 0, fmt.Errorf("时间须写成 HH:MM，实得 %q", s)
	}
	h, errH := strconv.Atoi(strings.TrimSpace(raw[:i]))
	m, errM := strconv.Atoi(strings.TrimSpace(raw[i+1:]))
	if errH != nil || errM != nil {
		return 0, fmt.Errorf("时间须写成 HH:MM，实得 %q", s)
	}
	if h < 0 || h > 24 || m < 0 || m > 59 {
		return 0, fmt.Errorf("时间超出范围（00:00~24:00），实得 %q", s)
	}
	if h == 24 && m != 0 {
		return 0, fmt.Errorf("24 点只能写成 24:00，实得 %q", s)
	}
	return h*60 + m, nil
}
