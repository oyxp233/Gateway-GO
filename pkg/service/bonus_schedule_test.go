package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"s4a21-gateway/pkg/session"
)

// ============================================================================
// 泡点分档规则的单元测试（2026-10-16）
//
// 这一批测试的分量在于**时间边界**：星期几、06:00 的那一秒、跨零点归属、
// 时区。这些都配错不会报错，只会让钱发错且查不出来 —— 所以必须逐条钉住。
//
// ★ 每条断言先自问："把实现换回旧逻辑（永远返回 AmountPerInterval），
//   这条会不会红？" 会红才算断言。TestBonusGrantUsesMatchedSlotAmount 那条
//   是专门为此设计的：它断言工作日下午发的是 120 而不是 100。
// ============================================================================

const testTZ = "Asia/Shanghai"

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("加载时区 %s 失败（tzdata 没编进产物？）: %v", name, err)
	}
	return loc
}

// mustAt 按 "2006-01-02 15:04:05" 解析出某时区下的确定时刻。
func mustAt(t *testing.T, loc *time.Location, s string) time.Time {
	t.Helper()
	tt, err := time.ParseInLocation("2006-01-02 15:04:05", s, loc)
	if err != nil {
		t.Fatalf("解析时刻 %q 失败: %v", s, err)
	}
	return tt
}

// TestBonusFixtureWeekdays 前置自检：下面所有用例都依赖"这几个日期确实是那个星期几"。
//
// 不写这条的话，万一 fixture 日期算错，一堆用例会以一种看似自洽的方式全绿
// （"周三"其实是周四），功能真正错时反而不红了。
func TestBonusFixtureWeekdays(t *testing.T) {
	cn := mustLoc(t, testTZ)
	cases := map[string]int{
		"2026-10-12 12:00:00": 1, // 周一
		"2026-10-14 12:00:00": 3, // 周三
		"2026-10-16 12:00:00": 5, // 周五
		"2026-10-17 12:00:00": 6, // 周六
		"2026-10-18 12:00:00": 7, // 周日
	}
	for s, want := range cases {
		if got := isoWeekday(mustAt(t, cn, s)); got != want {
			t.Errorf("%s 的星期应为 %d，实得 %d", s, want, got)
		}
	}
}

// sampleConfig 用户在需求里给的那套样例：
//
//	周一~周五 06:00~24:00 → 120；00:00~06:00 → 60
//	周六~周日 06:00~24:00 → 150；00:00~06:00 → 80
func sampleConfig() *BonusConfig {
	return &BonusConfig{
		Enabled:           true,
		IntervalSeconds:   60,
		AmountPerInterval: 100, // 兜底档：样例规则已经覆盖全天圆周，理论用不上
		Timezone:          testTZ,
		Rules: []BonusRule{
			{Name: "工作日白天", Days: []int{1, 2, 3, 4, 5}, Start: "06:00", End: "24:00", Amount: 120},
			{Name: "工作日凌晨", Days: []int{1, 2, 3, 4, 5}, Start: "00:00", End: "06:00", Amount: 60},
			{Name: "周末白天", Days: []int{6, 7}, Start: "06:00", End: "24:00", Amount: 150},
			{Name: "周末凌晨", Days: []int{6, 7}, Start: "00:00", End: "06:00", Amount: 80},
		},
	}
}

// TestBonusResolveNoRulesKeepsLegacyBehavior —— 向后兼容铁证。
//
// 老 bonus.json 没有 rules 键，必须逐字节等价于改造前：不管什么时刻，
// 都发 amount_per_interval。少了这条，"存量机器升级后被改了发钱口径"没人会发现。
func TestBonusResolveNoRulesKeepsLegacyBehavior(t *testing.T) {
	cn := mustLoc(t, testTZ)
	legacy := &BonusConfig{Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100}

	for _, s := range []string{
		"2026-10-12 03:00:00",
		"2026-10-14 08:00:00",
		"2026-10-17 23:59:59",
	} {
		amount, slot, err := legacy.ResolveBonus(mustAt(t, cn, s))
		if err != nil {
			t.Fatalf("%s 不该报错: %v", s, err)
		}
		if amount != 100 {
			t.Errorf("%s 无规则时应发默认档 100，实得 %d", s, amount)
		}
		if slot != bonusDefaultSlotName {
			t.Errorf("%s 档位名应为 %q，实得 %q", s, bonusDefaultSlotName, slot)
		}
	}
}

// TestBonusResolveSampleSchedule 逐档验证用户给的那套样例。
func TestBonusResolveSampleSchedule(t *testing.T) {
	cn := mustLoc(t, testTZ)
	cfg := sampleConfig()

	cases := []struct {
		at    string
		want  int
		slot  string
		label string
	}{
		{"2026-10-12 12:00:00", 120, "工作日白天", "周一中午"},
		{"2026-10-14 03:00:00", 60, "工作日凌晨", "周三凌晨"},
		{"2026-10-16 20:30:00", 120, "工作日白天", "周五晚上"},
		{"2026-10-17 12:00:00", 150, "周末白天", "周六中午"},
		{"2026-10-18 02:00:00", 80, "周末凌晨", "周日凌晨"},
		{"2026-10-18 23:00:00", 150, "周末白天", "周日深夜"},
	}
	for _, c := range cases {
		amount, slot, err := cfg.ResolveBonus(mustAt(t, cn, c.at))
		if err != nil {
			t.Fatalf("%s: %v", c.label, err)
		}
		if amount != c.want || slot != c.slot {
			t.Errorf("%s（%s）应命中「%s」发 %d，实得「%s」发 %d",
				c.label, c.at, c.slot, c.want, slot, amount)
		}
	}
}

// TestBonusResolveBoundarySeconds 时间段的开闭步长 1 秒都不能含糊。
//
// 口径：**含起点、不含终点**。05:59:59 仍属凌晨档，06:00:00 起就是白天档；
// 23:59:59 属于当天最后一个时段（24:00 前），00:00:00 属于新一天的凌晨档。
func TestBonusResolveBoundarySeconds(t *testing.T) {
	cn := mustLoc(t, testTZ)
	cfg := sampleConfig()

	cases := []struct {
		at   string
		want int
	}{
		{"2026-10-14 05:59:59", 60},  // 差 1 秒到 6 点：还是凌晨档
		{"2026-10-14 06:00:00", 120}, // 到点切换
		{"2026-10-14 23:59:59", 120}, // 当天最后一秒仍在白天档
		{"2026-10-15 00:00:00", 60},  // 跨天瞬间归凌晨档
		{"2026-10-17 05:59:59", 80},  // 周六凌晨
		{"2026-10-17 06:00:00", 150}, // 周六白天
	}
	for _, c := range cases {
		amount, _, err := cfg.ResolveBonus(mustAt(t, cn, c.at))
		if err != nil {
			t.Fatalf("%s: %v", c.at, err)
		}
		if amount != c.want {
			t.Errorf("%s 应发 %d，实得 %d", c.at, c.want, amount)
		}
	}
}

// TestBonusResolveCrossMidnightBelongsToStartDay 跨零点时段归属到"起始日"。
//
// 运营写「周五 22:00~06:00」想要的是"周五这一夜"，所以周六凌晨 3 点必须
// 继续命中这条 —— 按自然日判就会在这时掉回默认档，是这套配置最容易挨骂的坑。
func TestBonusResolveCrossMidnightBelongsToStartDay(t *testing.T) {
	cn := mustLoc(t, testTZ)
	cfg := &BonusConfig{
		Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100, Timezone: testTZ,
		Rules: []BonusRule{{Name: "周五通宵", Days: []int{5}, Start: "22:00", End: "06:00", Amount: 200}},
	}

	cases := []struct {
		at   string
		want int
		slot string
	}{
		{"2026-10-16 21:59:59", 100, bonusDefaultSlotName}, // 周五 22 点前：不命中
		{"2026-10-16 22:00:00", 200, "周五通宵"},             // 起始
		{"2026-10-16 23:30:00", 200, "周五通宵"},             // 当天深夜
		{"2026-10-17 03:00:00", 200, "周五通宵"},             // 周六凌晨：仍属周五这一夜
		{"2026-10-17 05:59:59", 200, "周五通宵"},             // 结束前 1 秒
		{"2026-10-17 06:00:00", 100, bonusDefaultSlotName}, // 到点退出
	}
	for _, c := range cases {
		amount, slot, err := cfg.ResolveBonus(mustAt(t, cn, c.at))
		if err != nil {
			t.Fatalf("%s: %v", c.at, err)
		}
		if amount != c.want || slot != c.slot {
			t.Errorf("%s 应为「%s」发 %d，实得「%s」发 %d", c.at, c.slot, c.want, slot, amount)
		}
	}
}

// TestBonusResolveEmptyDaysMeansEveryDay days 省略 = 每天生效。
func TestBonusResolveEmptyDaysMeansEveryDay(t *testing.T) {
	cn := mustLoc(t, testTZ)
	cfg := &BonusConfig{
		Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100, Timezone: testTZ,
		Rules: []BonusRule{{Name: "全天档", Start: "00:00", End: "24:00", Amount: 66}},
	}
	for _, s := range []string{
		"2026-10-12 01:00:00", "2026-10-15 09:00:00", "2026-10-17 17:00:00", "2026-10-18 23:00:00",
	} {
		amount, _, err := cfg.ResolveBonus(mustAt(t, cn, s))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if amount != 66 {
			t.Errorf("%s 每天生效的规则应发 66，实得 %d", s, amount)
		}
	}
}

// TestBonusResolveFirstMatchWins 规则顺序 = 优先级，先写先生效。
//
// 这条是"按顺序覆盖"这一语义的前提：运营要配特例（如某天的活动倍率）
// 就把它写在最前面。用例刻意让两条规则同时命中，靠金额与档位名区分走到哪条。
func TestBonusResolveFirstMatchWins(t *testing.T) {
	cn := mustLoc(t, testTZ)
	at := mustAt(t, cn, "2026-10-14 10:00:00")

	first := &BonusConfig{Rules: []BonusRule{
		{Name: "特例", Days: []int{3}, Start: "00:00", End: "24:00", Amount: 999},
		{Name: "常规", Days: []int{3}, Start: "00:00", End: "24:00", Amount: 111},
	}}
	if amount, slot, _ := first.ResolveBonus(at); amount != 999 || slot != "特例" {
		t.Errorf("首条应优先命中「特例」999，实得「%s」%d", slot, amount)
	}

	// 顺序颠倒后结果必须跟着变 —— 证明"命中"确实是按数组顺序走的，
	// 而不是碰巧只有一条匹配。
	second := &BonusConfig{Rules: []BonusRule{
		{Name: "常规", Days: []int{3}, Start: "00:00", End: "24:00", Amount: 111},
		{Name: "特例", Days: []int{3}, Start: "00:00", End: "24:00", Amount: 999},
	}}
	if amount, slot, _ := second.ResolveBonus(at); amount != 111 || slot != "常规" {
		t.Errorf("颠倒后应命中「常规」111，实得「%s」%d", slot, amount)
	}
}

// TestBonusResolveStartEqualsEndMeansAllDay 起止相同 = 全天。
//
// 运营忘改结束时间、写成了 06:00~06:00 时，不能理解成"零长度时段"
// （那就永远命中不了、静默失效），按全天处理才不会让人以为配好了其实没生效。
func TestBonusResolveStartEqualsEndMeansAllDay(t *testing.T) {
	cn := mustLoc(t, testTZ)
	cfg := &BonusConfig{
		Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100, Timezone: testTZ,
		Rules: []BonusRule{{Name: "全天", Days: []int{3}, Start: "06:00", End: "06:00", Amount: 45}},
	}
	for _, s := range []string{"2026-10-14 00:00:00", "2026-10-14 06:00:00", "2026-10-14 23:59:59"} {
		amount, _, err := cfg.ResolveBonus(mustAt(t, cn, s))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if amount != 45 {
			t.Errorf("%s 起止相同的规则应按全天生效发 45，实得 %d", s, amount)
		}
	}
	// 但别的星期不生效：days 仍然起作用，别把 each day 也一起放开了。
	if amount, _, _ := cfg.ResolveBonus(mustAt(t, cn, "2026-10-15 12:00:00")); amount != 100 {
		t.Errorf("周四不该命中只配了周三的规则，实得 %d", amount)
	}
}

// TestBonusResolveTimezoneMatters 同一 UTC 时刻在不同时区必须落到不同档位。
//
// 这条是"为什么要显式配 timezone"的证据：服务器若在 UTC，写 "06:00" 配的是
// 伦敦时间的早上六点。没有这条断言，跨机器部署同一份 bonus.json 会静默错发。
func TestBonusResolveTimezoneMatters(t *testing.T) {
	utc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatalf("加载 UTC 失败: %v", err)
	}
	// 取点刻意让"星期"和"时段"两个维度同时错开，区分度最大：
	//   UTC 2026-10-16 20:00 = 北京时间 2026-10-17 04:00（+8h 跨到了次日）
	//   按 UTC 读：周五 20:00 → 工作日白天 120
	//   按北京读：周六 04:00 → 周末凌晨   80
	// 任一实现漏掉时区换算，两条都会红。
	instant := time.Date(2026, 10, 16, 20, 0, 0, 0, utc)

	asUTC := &BonusConfig{Timezone: "UTC", Rules: sampleConfig().Rules}
	asCN := &BonusConfig{Timezone: testTZ, Rules: sampleConfig().Rules}

	if amount, slot, _ := asUTC.ResolveBonus(instant); amount != 120 || slot != "工作日白天" {
		t.Errorf("按 UTC 判应是周五 20:00 的工作日白天档 120，实得「%s」%d", slot, amount)
	}
	if amount, slot, _ := asCN.ResolveBonus(instant); amount != 80 || slot != "周末凌晨" {
		t.Errorf("按北京时间判应是周六 04:00 的周末凌晨档 80，实得「%s」%d", slot, amount)
	}
}

// TestBonusResolveBadTimezoneIsError 配了解析不出来的时区 → 必须报错，不能悄悄用 Local。
func TestBonusResolveBadTimezoneIsError(t *testing.T) {
	cfg := &BonusConfig{Timezone: "Mars/Olympus", AmountPerInterval: 100}
	if _, _, err := cfg.ResolveBonus(time.Now()); err == nil {
		t.Fatal("无效时区应返回错误，而不是静默退回本地时区")
	}
}

// TestBonusParseClock 时间字符串解析的范围与容错。
func TestBonusParseClock(t *testing.T) {
	good := map[string]int{
		"00:00": 0, "6:00": 360, "06:00": 360, " 06:00 ": 360, "23:59": 1439, "24:00": 1440,
	}
	for s, want := range good {
		got, err := parseClock(s)
		if err != nil {
			t.Errorf("%q 应能解析: %v", s, err)
			continue
		}
		if got != want {
			t.Errorf("%q 应为 %d 分钟，实得 %d", s, want, got)
		}
	}
	bad := []string{"", "6", "06", "25:00", "24:01", "12:60", "-1:00", "abc:de", "12:xx"}
	for _, s := range bad {
		if _, err := parseClock(s); err == nil {
			t.Errorf("%q 是非法时间，应报错", s)
		}
	}
}

// TestBonusValidateRejectsBadRules 各类配错都必须被 validateConfig 挡住。
func TestBonusValidateRejectsBadRules(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	bad := map[string]*BonusConfig{
		"起始时间缺冒号":   {Rules: []BonusRule{{Start: "0600", End: "24:00", Amount: 1}}},
		"起始时间越界":   {Rules: []BonusRule{{Start: "25:00", End: "24:00", Amount: 1}}},
		"结束时间分越界":  {Rules: []BonusRule{{Start: "00:00", End: "06:60", Amount: 1}}},
		"24 点带分钟":  {Rules: []BonusRule{{Start: "00:00", End: "24:30", Amount: 1}}},
		"amount 负数": {Rules: []BonusRule{{Start: "00:00", End: "24:00", Amount: -1}}},
		"amount 超限": {Rules: []BonusRule{{Start: "00:00", End: "24:00", Amount: bonusMaxAmount + 1}}},
		"days 出现 0": {Rules: []BonusRule{{Start: "00:00", End: "24:00", Days: []int{0}, Amount: 1}}},
		"days 出现 8": {Rules: []BonusRule{{Start: "00:00", End: "24:00", Days: []int{1, 8}, Amount: 1}}},
		"时区非法":     {Timezone: "Not/AZone", AmountPerInterval: 1},
	}
	for label, cfg := range bad {
		cfg.Enabled = true
		cfg.IntervalSeconds = 60
		if cfg.AmountPerInterval == 0 {
			cfg.AmountPerInterval = 100
		}
		if err := svc.validateConfig(cfg); err == nil {
			t.Errorf("%s 应被判非法", label)
		}
	}

	// 条数上限：超过就拒。这条防的是"配置堆了几百条互相覆盖"这种事故源。
	tooMany := &BonusConfig{Enabled: true, IntervalSeconds: 60, AmountPerInterval: 100}
	for i := 0; i < bonusMaxRules+1; i++ {
		tooMany.Rules = append(tooMany.Rules, BonusRule{Start: "00:00", End: "24:00", Amount: i})
	}
	if err := svc.validateConfig(tooMany); err == nil {
		t.Errorf("规则超过 %d 条应被拒绝", bonusMaxRules)
	}
}

// TestBonusSaveConfigRoundTripsRules 保存后能原样读回 rules 与 timezone。
//
// ★ 这条同时是"两个二进制必须同批部署"的探测点：admin 若还是旧二进制，
//   它转发的 JSON 里没有 rules 键，读回来就是空 —— 症状是"后台点了保存、
//   页面看着有规则，网关却在按默认档发"。
func TestBonusSaveConfigRoundTripsRules(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	in := sampleConfig()
	if err := svc.SaveConfig(in); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	out, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if len(out.Rules) != 4 {
		t.Fatalf("规则应保留 4 条，实得 %d", len(out.Rules))
	}
	// 逐字段比对（BonusRule 含 []int，不能直接 ==）：顺序与内容都必须原样保留。
	for i := range in.Rules {
		if out.Rules[i].Name != in.Rules[i].Name ||
			out.Rules[i].Start != in.Rules[i].Start ||
			out.Rules[i].End != in.Rules[i].End ||
			out.Rules[i].Amount != in.Rules[i].Amount ||
			len(out.Rules[i].Days) != len(in.Rules[i].Days) {
			t.Errorf("第 %d 条规则往返后不一致:\n写入 %+v\n读回 %+v", i, in.Rules[i], out.Rules[i])
			continue
		}
		for j := range in.Rules[i].Days {
			if out.Rules[i].Days[j] != in.Rules[i].Days[j] {
				t.Errorf("第 %d 条规则 days 往返后不一致: %v vs %v",
					i, in.Rules[i].Days, out.Rules[i].Days)
			}
		}
	}
	if out.Timezone != testTZ {
		t.Errorf("timezone 应保留为 %s，实得 %q", testTZ, out.Timezone)
	}

	// 落盘必须是合法 JSON —— 主循环每轮读它，半截 JSON 会让整轮不发放。
	raw, err := os.ReadFile(svc.ConfigPath())
	if err != nil {
		t.Fatalf("读盘失败: %v", err)
	}
	var parsed BonusConfig
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("落盘内容不是合法 JSON: %v\n%s", err, raw)
	}
	if len(parsed.Rules) != 4 {
		t.Errorf("落盘 JSON 里应有 4 条规则，实得 %d", len(parsed.Rules))
	}
}

// TestBonusSaveConfigRejectsBadRulesKeepsGoodFile 规则配错时**整份拒绝**，老配置一字不动。
func TestBonusSaveConfigRejectsBadRulesKeepsGoodFile(t *testing.T) {
	db, gwPath := setupBonusWorld(t)
	svc := newBonusSvcForTest(t, db, gwPath)

	if err := svc.SaveConfig(sampleConfig()); err != nil {
		t.Fatalf("保存基准配置失败: %v", err)
	}

	broken := sampleConfig()
	broken.Rules[1].Start = "25:00"
	if err := svc.SaveConfig(broken); err == nil {
		t.Fatal("规则非法的整份配置应被拒绝")
	}

	out, err := svc.GetConfig()
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if len(out.Rules) != 4 || out.Rules[1].Start != "00:00" {
		t.Errorf("非法保存不该动到已有配置，实得 %+v", out.Rules)
	}
}

// TestBonusGrantUsesMatchedSlotAmount ★ 端到端：钱真的按命中的档位发。
//
// 这一条是整套断言里最有区分力的：工作日下午结算应发 120（命中「工作日白天」），
// 而不是 AmountPerInterval 的 100。把实现退回旧逻辑它立刻变红。
func TestBonusGrantUsesMatchedSlotAmount(t *testing.T) {
	cn := mustLoc(t, testTZ)
	// 周三 14:00 → 工作日白天档 120
	daytime := mustAt(t, cn, "2026-10-14 14:00:00")
	// 周三 02:00 → 工作日凌晨档 60
	night := mustAt(t, cn, "2026-10-14 02:00:00")

	for _, tc := range []struct {
		label string
		now   time.Time
		want  int64
	}{
		{"工作日白天", daytime, 120},
		{"工作日凌晨", night, 60},
	} {
		t.Run(tc.label, func(t *testing.T) {
			db, gamePath := setupBonusWorld(t)
			execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES ('10001', 0)")
			seedAccount(t, db, "10001", "alice")

			sm := session.NewSessionManager(nil, nil)
			token, err := sm.CreateSession("alice", "10001", "10.0.0.1", "", "")
			if err != nil {
				t.Fatalf("建会话失败: %v", err)
			}
			sess, _ := sm.ValidateToken(token)
			sm.AddGameProxyConnection(sess, fakeConn{})
			// 计费基准回拨 65 秒 → 刚好够一个周期
			sess.BonusTickAt = tc.now.Unix() - 65

			svc := newBonusSvcForTest(t, db, filepath.Join(t.TempDir(), "gateway.db"))
			svc.SetSessionManager(sm)

			slot, err := svc.grantBonusAt(sampleConfig(), tc.now)
			if err != nil {
				t.Fatalf("结算失败: %v", err)
			}
			acc, err := db.GetAccountByName("alice")
			if err != nil || acc == nil {
				t.Fatalf("读账号失败: %v", err)
			}
			if acc.Cera != tc.want {
				t.Errorf("%s 应发 %d cera，实得 %d（档位 %s）", tc.label, tc.want, acc.Cera, slot)
			}
			if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10001'"); got != tc.want {
				t.Errorf("%s 游戏库应写入 %d，实得 %d", tc.label, tc.want, got)
			}
		})
	}
}

// TestBonusGrantStopsWhenRulesBroken 规则不可用 → 一分不发并返回错误。
//
// 宁可停一轮也不能"猜一个金额发下去" —— 钱账一旦错发就收不回来。
func TestBonusGrantStopsWhenRulesBroken(t *testing.T) {
	db, gamePath := setupBonusWorld(t)
	execOnGame(t, gamePath, "INSERT INTO accounts (m_id, cera) VALUES ('10001', 0)")
	seedAccount(t, db, "10001", "alice")

	sm := session.NewSessionManager(nil, nil)
	token, _ := sm.CreateSession("alice", "10001", "10.0.0.1", "", "")
	sess, _ := sm.ValidateToken(token)
	sm.AddGameProxyConnection(sess, fakeConn{})
	sess.BonusTickAt = time.Now().Unix() - 65

	svc := newBonusSvcForTest(t, db, filepath.Join(t.TempDir(), "gateway.db"))
	svc.SetSessionManager(sm)

	broken := sampleConfig()
	broken.Timezone = "Nowhere/Land"
	if _, err := svc.grantBonusAt(broken, time.Now()); err == nil {
		t.Fatal("档位不可解时应返回错误")
	}

	acc, _ := db.GetAccountByName("alice")
	if acc != nil && acc.Cera != 0 {
		t.Errorf("规则不可用却发了点券，cera=%d", acc.Cera)
	}
	if got := queryOnGame(t, gamePath, "SELECT cera FROM accounts WHERE m_id='10001'"); got != 0 {
		t.Errorf("规则不可用却写了游戏库，cera=%d", got)
	}
}
