package database

import (
	"encoding/hex"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
)

// newDigestTestDB 只建网关库（digest 签发不碰游戏库）。
func newDigestTestDB(t *testing.T) *Database {
	t.Helper()
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(t.TempDir(), "gateway.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	if err := db.EnsureInitialized(); err != nil {
		db.Close()
		t.Fatalf("初始化网关库 schema 失败: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func seedDigestAccount(t *testing.T, db *Database, name string) {
	t.Helper()
	if err := db.InsertAccount(&Account{
		MId: "m" + name, Name: name, PwdHash: "hash", Salt: "salt", CreatedAt: NowUnix(),
	}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
}

// digestShape 是 DNF95 服务端 LoginCredentials.IsDigest 的口径：
// 32 位十六进制（大小写均可，服务端会 ToLowerInvariant）。
var digestShape = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

func TestEnsureS5A9DigestIssuesOnceAndReuses(t *testing.T) {
	db := newDigestTestDB(t)
	seedDigestAccount(t, db, "digestuser")

	first, err := db.EnsureS5A9Digest("digestuser")
	if err != nil {
		t.Fatalf("首次签发失败: %v", err)
	}
	if !digestShape.MatchString(first) {
		t.Fatalf("digest 必须是 32 位 hex，实得 %q", first)
	}

	// 之后每次登录必须拿回同一个值 —— DNF95 服务端存的就是它的 PBKDF2
	// 派生哈希，换了就对不上（玩家会被永久拒登）。
	for i := 0; i < 3; i++ {
		again, err := db.EnsureS5A9Digest("digestuser")
		if err != nil {
			t.Fatalf("第 %d 次读取失败: %v", i+2, err)
		}
		if again != first {
			t.Fatalf("digest 必须复用：首次 %q，第 %d 次 %q", first, i+2, again)
		}
	}

	// 落库校验：直接读列，确认不是"内存里凑的"。
	var stored string
	if err := db.gatewayDB.QueryRow(
		"SELECT s5a9_digest FROM accounts WHERE name = ?", "digestuser").Scan(&stored); err != nil {
		t.Fatalf("读库失败: %v", err)
	}
	if stored != first {
		t.Fatalf("库里的 digest 与签发值不一致: %q vs %q", stored, first)
	}
}

func TestEnsureS5A9DigestSurvivesPasswordChange(t *testing.T) {
	db := newDigestTestDB(t)
	seedDigestAccount(t, db, "pwdchange")

	before, err := db.EnsureS5A9Digest("pwdchange")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	// 改密码（网关侧流程）：digest 必须原样保留。
	// 这是"不透传密码 MD5"设计的关键锚 —— 透传会让改密账号被 S5A9 后端锁死。
	if err := db.UpdateAccountPwd("pwdchange", "newhash", "newsalt"); err != nil {
		t.Fatalf("改密码失败: %v", err)
	}

	after, err := db.EnsureS5A9Digest("pwdchange")
	if err != nil {
		t.Fatalf("改密后读取失败: %v", err)
	}
	if after != before {
		t.Fatalf("改密码后 digest 被重置: %q → %q", before, after)
	}
}

func TestEnsureS5A9DigestConcurrentSingleIssue(t *testing.T) {
	db := newDigestTestDB(t)
	seedDigestAccount(t, db, "concurrent")

	// 并发签发：条件 UPDATE（仅当为空才写）保证只有一个写入生效，
	// 其余 goroutine 必须读回胜者的值 —— 绝不能出现两个不同 digest。
	const n = 16
	var wg sync.WaitGroup
	results := make([]string, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx], errs[idx] = db.EnsureS5A9Digest("concurrent")
		}(i)
	}
	close(start)
	wg.Wait()

	winner := ""
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d 失败: %v", i, errs[i])
		}
		if !digestShape.MatchString(results[i]) {
			t.Fatalf("goroutine %d 拿到非法 digest %q", i, results[i])
		}
		if winner == "" {
			winner = results[i]
		}
		if results[i] != winner {
			t.Fatalf("并发签发出现分裂：goroutine %d 拿到 %q，其余是 %q", i, results[i], winner)
		}
	}
}

func TestEnsureS5A9DigestMissingAccount(t *testing.T) {
	db := newDigestTestDB(t)

	got, err := db.EnsureS5A9Digest("nosuchuser")
	if err != nil {
		t.Fatalf("账号不存在应返回 (\"\", nil)，实得 error %v", err)
	}
	if got != "" {
		t.Fatalf("账号不存在应返回空 digest，实得 %q", got)
	}
}

// TestS5A9DigestColumnMigrated 老库缺列时迁移必须补上。
//
// 场景：用 CREATE TABLE 的老形态建 accounts（不含 s5a9_digest），
// 再走 EnsureInitialized 的迁移路径，列必须被补出且默认空串。
func TestS5A9DigestColumnMigrated(t *testing.T) {
	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(t.TempDir(), "gateway.db"),
		WalMode:            true,
		BusyTimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("打开测试网关库失败: %v", err)
	}
	defer db.Close()

	// 先建表（正常初始化路径），再删掉按"改造前的 schema"重建 ——
	// 模拟一台从旧版本升级上来的生产机。
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("首次 EnsureInitialized 失败: %v", err)
	}
	if _, err := db.gatewayDB.Exec("DROP TABLE accounts"); err != nil {
		t.Fatalf("删除 accounts 失败: %v", err)
	}
	if _, err := db.gatewayDB.Exec(`
		CREATE TABLE accounts (
			m_id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			pwd_hash TEXT NOT NULL,
			salt TEXT NOT NULL,
			cera INTEGER DEFAULT 0,
			token_cera INTEGER DEFAULT 0,
			happy_token_cera INTEGER DEFAULT 0,
			device_secret TEXT DEFAULT '',
			device_secret_issued_at TEXT DEFAULT '',
			device_history TEXT DEFAULT '',
			device_secret_last_rotated INTEGER DEFAULT 0,
			last_login_at INTEGER DEFAULT 0,
			last_login_ip TEXT DEFAULT '',
			failed_login_count INTEGER DEFAULT 0,
			lockout_until INTEGER DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER DEFAULT 0,
			last_heartbeat INTEGER DEFAULT 0
		);`); err != nil {
		t.Fatalf("按老 schema 重建 accounts 失败: %v", err)
	}

	// 走完整迁移（与生产升级同一条路径）。
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("EnsureInitialized 失败: %v", err)
	}

	// 迁移后老行补列读出来应是空串（不是 NULL —— Scan 进 string 会直接报错）。
	if err := db.InsertAccount(&Account{
		MId: "m-migrated", Name: "migrated", PwdHash: "h", Salt: "s", CreatedAt: NowUnix(),
	}); err != nil {
		t.Fatalf("迁移后插入账号失败: %v", err)
	}
	got, err := db.EnsureS5A9Digest("migrated")
	if err != nil {
		t.Fatalf("迁移后签发失败: %v", err)
	}
	if !digestShape.MatchString(got) {
		t.Fatalf("迁移后签发的 digest 非法: %q", got)
	}
}

// TestInsertAccountCarriesDigest 插入时显式带的 digest 必须落库。
// （EnsureS5A9Digest 是签发路径；导入/同步类插入走这条。）
func TestInsertAccountCarriesDigest(t *testing.T) {
	db := newDigestTestDB(t)
	want := "0123456789abcdef0123456789abcdef"
	if err := db.InsertAccount(&Account{
		MId: "m-carry", Name: "carry", PwdHash: "h", Salt: "s",
		CreatedAt: NowUnix(), S5A9Digest: want,
	}); err != nil {
		t.Fatalf("插入账号失败: %v", err)
	}
	acc, err := db.GetAccountByName("carry")
	if err != nil || acc == nil {
		t.Fatalf("读回账号失败: %v", err)
	}
	if acc.S5A9Digest != want {
		t.Fatalf("插入的 digest 未落库: %q vs %q", acc.S5A9Digest, want)
	}
}

// TestS5A9DigestHexCharset 抽查签发值只含小写 hex（hex.EncodeToString 口径）。
// 服务端 ToLowerInvariant 后比对，大写也能过，但统一小写减少排障时的视觉噪声。
func TestS5A9DigestHexCharset(t *testing.T) {
	db := newDigestTestDB(t)
	seedDigestAccount(t, db, "charset")
	got, err := db.EnsureS5A9Digest("charset")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("digest 长度应为 32，实得 %d", len(got))
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("digest 不是合法 hex: %v", err)
	}
}
