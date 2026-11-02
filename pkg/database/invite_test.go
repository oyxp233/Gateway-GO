package database

// ============================================================================
// 邀请码测试（2026-10-24）
//
// 覆盖六条不变量：
//   ① 生成：数量正确、码格式正确（字符集/长度）、互不重复
//   ② 归一化：大小写/空格/连字符/不换行空格 都归一成同一个码
//   ③ 消耗：未用 → OK；再消耗同一个码 → Used（★ 一码一用）
//   ④ ★ 并发：同一个码被 N 个 goroutine 同时消耗，只能成功 1 个
//   ⑤ 过期 / 作废 都被拒，且给出**具体**原因
//   ⑥ 列表筛选：unused/used/expired/disabled 互不串台
// ============================================================================

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"s4a21-gateway/pkg/utils"
)

func newInviteTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           filepath.Join(dir, "inventory.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("开库: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("建表: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// TestGenerateInvites 锁定"数量/格式/唯一性"。
func TestGenerateInvites(t *testing.T) {
	db := newInviteTestDB(t)

	codes, err := db.GenerateInvites(50, "测试批次", "admin:test", 0)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(codes) != 50 {
		t.Fatalf("应生成 50 个，实得 %d", len(codes))
	}

	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if len(c) != inviteCodeLength {
			t.Fatalf("码长度应为 %d，实得 %d（%q）", inviteCodeLength, len(c), c)
		}
		// 字符必须全部来自 alphabet（去掉易混字符）
		for _, ch := range c {
			if !containsRune(inviteAlphabet, ch) {
				t.Fatalf("码 %q 含非法字符 %q（不在 alphabet 内）", c, ch)
			}
		}
		if seen[c] {
			t.Fatalf("生成重复的码: %s", c)
		}
		seen[c] = true
	}

	// 落库确认
	n, err := db.CountUnusedInvites()
	if err != nil {
		t.Fatalf("CountUnusedInvites: %v", err)
	}
	if n != 50 {
		t.Fatalf("可用数应为 50，实得 %d", n)
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

// TestNormalizeInviteCode 锁定归一化口径。
//
// ★ 这条决定了玩家体验：从群里复制码时常带空格、大小写混乱、带连字符。
//   归一化不一致 = "码明明是对的但提示无效"。
func TestNormalizeInviteCode(t *testing.T) {
	want := "K7M2P9QX"
	cases := []string{
		"K7M2P9QX",
		"k7m2p9qx",
		"K7M2-P9QX",
		" k7m2 p9qx ",
		"K7M2_P9QX",
		"\tK7M2.P9QX\n",
		"K7M2\u00a0P9QX", // 不换行空格（网页复制常见）
	}
	for _, raw := range cases {
		if got := NormalizeInviteCode(raw); got != want {
			t.Fatalf("NormalizeInviteCode(%q) = %q，期望 %q", raw, got, want)
		}
	}

	// 空 / 纯分隔符 → 空串
	for _, raw := range []string{"", "   ", "---", "  - _ .  "} {
		if got := NormalizeInviteCode(raw); got != "" {
			t.Fatalf("NormalizeInviteCode(%q) 应为空串，实得 %q", raw, got)
		}
	}
}

// TestFormatInviteCode 锁定展示形式（XXXX-XXXX）。
func TestFormatInviteCode(t *testing.T) {
	if got := FormatInviteCode("K7M2P9QX"); got != "K7M2-P9QX" {
		t.Fatalf("展示形式应为 K7M2-P9QX，实得 %q", got)
	}
	// 长度不对时原样返回（不 panic、不乱插连字符）
	if got := FormatInviteCode("ABC"); got != "ABC" {
		t.Fatalf("长度不对时应原样返回，实得 %q", got)
	}
}

// TestConsumeInviteOnce 锁定"一码一用"。
func TestConsumeInviteOnce(t *testing.T) {
	db := newInviteTestDB(t)
	codes, _ := db.GenerateInvites(1, "", "", 0)
	code := codes[0]

	if r := db.ConsumeInvite(code, "user1"); r != InviteConsumeOK {
		t.Fatalf("首次消耗应成功，实得 %d", r)
	}
	if r := db.ConsumeInvite(code, "user2"); r != InviteConsumeUsed {
		t.Fatalf("二次消耗应报已用，实得 %d", r)
	}

	// 归一化后同一个码（带连字符/小写）也该被认出已用
	display := FormatInviteCode(code)
	if r := db.ConsumeInvite(display, "user3"); r != InviteConsumeUsed {
		t.Fatalf("带连字符的展示形式也应识别为已用，实得 %d", r)
	}
}

// TestConsumeInviteConcurrent 锁定"并发同码只成功一次"。
//
// ★ 这是邀请码的**安全核心**：如果这里漏了，一个码可以被并发请求用掉多次，
//   邀请码就等于没用（玩家把码发群里，N 个人同时注册都成功）。
//
// 实现靠 UPDATE ... WHERE used_by='' + RowsAffected，不是"先查再改"。
func TestConsumeInviteConcurrent(t *testing.T) {
	db := newInviteTestDB(t)
	codes, _ := db.GenerateInvites(1, "", "", 0)
	code := codes[0]

	const goroutines = 20
	var okCount int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			<-start // 同时起跑，最大化竞争
			if db.ConsumeInvite(code, "user"+itoa64(int64(n))) == InviteConsumeOK {
				atomic.AddInt32(&okCount, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if okCount != 1 {
		t.Fatalf("并发 %d 次消耗同一个码，成功次数应为 1，实得 %d —— 一码一用失效", goroutines, okCount)
	}
}

// TestConsumeInviteExpired 锁定"过期码被拒"。
func TestConsumeInviteExpired(t *testing.T) {
	db := newInviteTestDB(t)

	// 生成一个"1 秒前就过期"的码
	past := utils.NowUnix() - 10
	codes, err := db.GenerateInvites(1, "", "", past)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}

	if r := db.ConsumeInvite(codes[0], "u"); r != InviteConsumeExpired {
		t.Fatalf("过期码应报 Expired，实得 %d", r)
	}

	// 过期码不该算进"可用"
	n, _ := db.CountUnusedInvites()
	if n != 0 {
		t.Fatalf("过期码不该算可用，实得 %d", n)
	}
}

// TestConsumeInviteDisabled 锁定"作废码被拒"。
func TestConsumeInviteDisabled(t *testing.T) {
	db := newInviteTestDB(t)
	codes, _ := db.GenerateInvites(1, "", "", 0)

	changed, err := db.RevokeInvite(codes[0])
	if err != nil {
		t.Fatalf("作废失败: %v", err)
	}
	if !changed {
		t.Fatal("作废应返回 changed=true")
	}

	if r := db.ConsumeInvite(codes[0], "u"); r != InviteConsumeDisabled {
		t.Fatalf("作废码应报 Disabled，实得 %d", r)
	}
}

// TestRevokeUsedInviteNoop 锁定"已用的码不能被作废"（追溯记录要保干净）。
func TestRevokeUsedInviteNoop(t *testing.T) {
	db := newInviteTestDB(t)
	codes, _ := db.GenerateInvites(1, "", "", 0)
	db.ConsumeInvite(codes[0], "u")

	changed, err := db.RevokeInvite(codes[0])
	if err != nil {
		t.Fatalf("作废失败: %v", err)
	}
	if changed {
		t.Fatal("已使用的码不该被作废（否则追溯记录含混）")
	}
}

// TestConsumeInviteNotFound 锁定"不存在的码"。
func TestConsumeInviteNotFound(t *testing.T) {
	db := newInviteTestDB(t)
	if r := db.ConsumeInvite("NOSUCHCD", "u"); r != InviteConsumeNotFound {
		t.Fatalf("不存在的码应报 NotFound，实得 %d", r)
	}
	if r := db.ConsumeInvite("", "u"); r != InviteConsumeNormalized {
		t.Fatalf("空码应报 Normalized，实得 %d", r)
	}
}

// TestListInvitesFilters 锁定"状态筛选互不串台"。
func TestListInvitesFilters(t *testing.T) {
	db := newInviteTestDB(t)

	// 4 个码：unused / used / expired / disabled
	codes, _ := db.GenerateInvites(2, "批A", "admin:1", 0)
	unusedCode, usedCode := codes[0], codes[1]
	db.ConsumeInvite(usedCode, "someone")

	expCodes, _ := db.GenerateInvites(1, "批B", "admin:1", utils.NowUnix()-10)
	expiredCode := expCodes[0]

	disCodes, _ := db.GenerateInvites(1, "批C", "admin:1", 0)
	disabledCode := disCodes[0]
	db.RevokeInvite(disabledCode)

	now := utils.NowUnix()

	// unused：只有 unusedCode
	total, rows, err := db.ListInvites(string(InviteStatusUnused), "", 1, 50)
	if err != nil {
		t.Fatalf("ListInvites(unused): %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Code != unusedCode {
		t.Fatalf("unused 筛选不对: total=%d rows=%+v", total, rows)
	}
	if rows[0].Status(now) != InviteStatusUnused {
		t.Fatalf("状态判定不对: %s", rows[0].Status(now))
	}

	// used
	total, rows, _ = db.ListInvites(string(InviteStatusUsed), "", 1, 50)
	if total != 1 || rows[0].Code != usedCode || rows[0].UsedBy != "someone" {
		t.Fatalf("used 筛选不对: total=%d rows=%+v", total, rows)
	}

	// expired
	total, rows, _ = db.ListInvites(string(InviteStatusExpired), "", 1, 50)
	if total != 1 || rows[0].Code != expiredCode {
		t.Fatalf("expired 筛选不对: total=%d rows=%+v", total, rows)
	}

	// disabled
	total, rows, _ = db.ListInvites(string(InviteStatusDisabled), "", 1, 50)
	if total != 1 || rows[0].Code != disabledCode {
		t.Fatalf("disabled 筛选不对: total=%d rows=%+v", total, rows)
	}

	// 全部
	total, _, _ = db.ListInvites("", "", 1, 50)
	if total != 4 {
		t.Fatalf("全部应为 4 条，实得 %d", total)
	}

	// 关键词按备注
	total, _, _ = db.ListInvites("", "批A", 1, 50)
	if total != 2 {
		t.Fatalf("按备注「批A」应查到 2 条，实得 %d", total)
	}

	// 关键词按使用者
	total, _, _ = db.ListInvites("", "someone", 1, 50)
	if total != 1 {
		t.Fatalf("按使用者应查到 1 条，实得 %d", total)
	}
}

// TestExportUnusedInvites 锁定"导出只含可用码"。
func TestExportUnusedInvites(t *testing.T) {
	db := newInviteTestDB(t)

	codes, _ := db.GenerateInvites(3, "", "", 0)
	db.ConsumeInvite(codes[0], "u1")      // 用掉一个
	db.RevokeInvite(codes[1])             // 作废一个
	// 剩 codes[2] 可用

	got, err := db.ExportUnusedInvites(0)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	if len(got) != 1 || got[0] != codes[2] {
		t.Fatalf("导出应只含 1 个可用码 %s，实得 %v", codes[2], got)
	}
}

// TestGenerateInvitesLimits 锁定生成数量边界。
func TestGenerateInvitesLimits(t *testing.T) {
	db := newInviteTestDB(t)

	if _, err := db.GenerateInvites(0, "", "", 0); err == nil {
		t.Fatal("count=0 应报错")
	}
	if _, err := db.GenerateInvites(-5, "", "", 0); err == nil {
		t.Fatal("count 为负应报错")
	}

	// 超上限自动截断到 500（不报错，避免运维误操作失败）
	codes, err := db.GenerateInvites(600, "", "", 0)
	if err != nil {
		t.Fatalf("超上限应截断而非报错: %v", err)
	}
	if len(codes) != 500 {
		t.Fatalf("超上限应截断到 500，实得 %d", len(codes))
	}
}

// TestInviteExpiresAtZeroMeansNever 锁定"expires_at=0 = 永不过期"。
func TestInviteExpiresAtZeroMeansNever(t *testing.T) {
	db := newInviteTestDB(t)
	codes, _ := db.GenerateInvites(1, "", "", 0)

	// 模拟很久以后（不真的等）
	var rec InviteCode
	_, rows, _ := db.ListInvites("", "", 1, 10)
	if len(rows) > 0 {
		rec = rows[0]
	}
	if rec.ExpiresAt != 0 {
		t.Fatalf("expires_at 应为 0，实得 %d", rec.ExpiresAt)
	}
	// 100 年后仍然是 unused
	future := utils.NowUnix() + 100*365*24*3600
	if rec.Status(future) != InviteStatusUnused {
		t.Fatalf("永不过期的码在 100 年后仍应可用，实得 %s", rec.Status(future))
	}
	// 而且能真的消耗掉
	if r := db.ConsumeInvite(codes[0], "u"); r != InviteConsumeOK {
		t.Fatalf("永不过期的码应能消耗，实得 %d", r)
	}
}
