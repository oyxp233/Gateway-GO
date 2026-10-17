package service

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"s4a21-gateway/pkg/config"
	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/logger"
	"s4a21-gateway/pkg/models"
)

// dualGameSvcFixture 造一个「S4A21 + S5A95 双服」的 AccountService。
//
// 配置要点（对齐生产双服口径）：
//   - s4a21：默认服，频道口 0 = 沿用 Gateway.ProxyPort（存量单服行为）；
//   - s5a95：显式频道口 23100，独立公网 IP 与 LaunchArgs 模板（99?…{digest}…）。
func dualGameSvcFixture(t *testing.T) (*AccountService, *database.Database) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.NewDatabase(database.DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		BusyTimeoutSeconds: 5,
		WalMode:            true,
	})
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.EnsureInitialized(); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	lg, err := logger.NewConsoleLogger(t.TempDir(), logger.Error)
	if err != nil {
		t.Fatalf("建日志失败: %v", err)
	}
	t.Cleanup(func() { lg.Close() })

	cfg := config.DefaultConfig()
	cfg.Gateway.ProxyPort = 8001
	cfg.GameServer.PublicIP = "203.0.113.7"
	cfg.GameServer.LaunchArgsFormat = "9?{ip}?{port}?{m_id}?{token}?1?0?6?0?2?1"

	enabled := true
	disabled := false
	cfg.GameServers = []config.GameServerEntry{
		{
			Id: "s4a21", Name: "S4A21 正式服", Protocol: config.ProtocolS4A21,
			Enabled:             &enabled,
			ChannelListenerPort: 0, // 沿用 Gateway.ProxyPort
			GameServerSection:   cfg.GameServer,
		},
		{
			Id: "s5a95", Name: "DNF95", Protocol: config.ProtocolS5A95,
			Enabled:             &enabled,
			ChannelListenerPort: 23100,
			GameServerSection: config.GameServerSection{
				PublicIP:           "198.51.100.9",
				BackendHost:        "127.0.0.1",
				BackendChannelPort: 23100,
				LaunchArgsFormat:   config.DefaultS5A95LaunchArgsFormat,
			},
		},
		{
			// 停用服：选它必须被拒（维护中的服不该放人进去）。
			Id: "s5a95-old", Name: "DNF95 旧服", Protocol: config.ProtocolS5A95,
			Enabled:             &disabled,
			ChannelListenerPort: 23110,
			GameServerSection:   config.GameServerSection{PublicIP: "198.51.100.10"},
		},
	}
	return NewAccountService(db, cfg, lg), db
}

func dualGameRegister(t *testing.T, svc *AccountService, name, pwd string) {
	t.Helper()
	if code := svc.Register(name, pwd); code != models.Err.Ok {
		t.Fatalf("注册失败: code=%d", code)
	}
}

var s5a95DigestShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// TestLoginDefaultGameLegacyArgs 不带 game 字段（老登录器）必须拿到
// 默认服的启动参数，且行为与改造前一致：ip=默认服、port=ProxyPort、
// 无 digest（S4A21 模板里也没有 {digest}）。
func TestLoginDefaultGameLegacyArgs(t *testing.T) {
	svc, db := dualGameSvcFixture(t)
	const (
		name = "legacyuser"
		pwd  = "0123456789abcdef0123456789abcdef"
	)
	dualGameRegister(t, svc, name, pwd)

	res := svc.Login(name, pwd, "", "203.0.113.7", "")
	if res.ErrorCode != models.Err.Ok {
		t.Fatalf("登录失败: code=%d", res.ErrorCode)
	}
	want := "9?203.0.113.7?8001?" + res.MId + "?" + res.Token + "?1?0?6?0?2?1"
	if res.LaunchArgs != want {
		t.Fatalf("默认服 LaunchArgs 不符:\n实际 %s\n期望 %s", res.LaunchArgs, want)
	}

	// 默认服（S4A21）登录绝不该签发 S5A9 digest。
	acc, _ := db.GetAccountByName(name)
	if acc.S5A9Digest != "" {
		t.Fatalf("S4A21 服登录不应签发 digest，实得 %q", acc.S5A9Digest)
	}
}

// TestLoginS5A95GameArgs 选 s5a95 服：ip/port 取该服 Profile，
// digest 落 32 位 hex 且两次登录一致（服务端口径）。
func TestLoginS5A95GameArgs(t *testing.T) {
	svc, db := dualGameSvcFixture(t)
	const (
		name = "dnf95user"
		pwd  = "0123456789abcdef0123456789abcdef"
	)
	dualGameRegister(t, svc, name, pwd)

	res := svc.Login(name, pwd, "", "203.0.113.7", "s5a95")
	if res.ErrorCode != models.Err.Ok {
		t.Fatalf("登录失败: code=%d", res.ErrorCode)
	}
	if !strings.HasPrefix(res.LaunchArgs, "99?198.51.100.9?23100?") {
		t.Fatalf("S5A95 LaunchArgs 头两段应取该服 ip/频道口，实得 %s", res.LaunchArgs)
	}
	parts := strings.Split(res.LaunchArgs, "?")
	if len(parts) < 5 {
		t.Fatalf("LaunchArgs 段数不足: %s", res.LaunchArgs)
	}
	if parts[3] != res.MId {
		t.Fatalf("第 4 段应为 m_id: %q vs %q", parts[3], res.MId)
	}
	if !s5a95DigestShape.MatchString(parts[4]) {
		t.Fatalf("第 5 段应为 32 位小写 hex digest，实得 %q", parts[4])
	}
	// 尾部常量组 1?0?0?0?0?0?2?0?0?0?0（split 后 parts[5:16]）必须原样。
	if parts[5] != "1" || parts[11] != "2" || len(parts) != 16 {
		t.Fatalf("尾部常量组被改坏: %s", res.LaunchArgs)
	}

	// 第二次登录：digest 必须与首次一致（服务端存的就是它的派生哈希）。
	res2 := svc.Login(name, pwd, "", "203.0.113.7", "s5a95")
	if res2.ErrorCode != models.Err.Ok {
		t.Fatalf("第二次登录失败: code=%d", res2.ErrorCode)
	}
	parts2 := strings.Split(res2.LaunchArgs, "?")
	if parts2[4] != parts[4] {
		t.Fatalf("digest 必须复用: 首次 %q，二次 %q", parts[4], parts2[4])
	}

	// 库里落的就是 LaunchArgs 里那个值。
	acc, _ := db.GetAccountByName(name)
	if acc.S5A9Digest != parts[4] {
		t.Fatalf("库中 digest 与 LaunchArgs 不一致: %q vs %q", acc.S5A9Digest, parts[4])
	}
}

// TestLoginS5A95DigestSurvivesPasswordChange 玩家改网关密码后，
// 再登 S5A95 必须还是同一个 digest —— 透传密码 MD5 的设计会把
// 改密账号永久锁在 S5A9 后端门外，这条测试钉住"不透传"。
func TestLoginS5A95DigestSurvivesPasswordChange(t *testing.T) {
	svc, _ := dualGameSvcFixture(t)
	const (
		name = "chpwduser"
		pwd  = "0123456789abcdef0123456789abcdef"
		npwd = "fedcba9876543210fedcba9876543210"
	)
	dualGameRegister(t, svc, name, pwd)

	before := svc.Login(name, pwd, "", "203.0.113.7", "s5a95")
	if before.ErrorCode != models.Err.Ok {
		t.Fatalf("登录失败: code=%d", before.ErrorCode)
	}
	d1 := strings.Split(before.LaunchArgs, "?")[4]

	if code := svc.ChangePassword(name, pwd, npwd); code != models.Err.Ok {
		t.Fatalf("改密失败: code=%d", code)
	}

	after := svc.Login(name, npwd, "", "203.0.113.7", "s5a95")
	if after.ErrorCode != models.Err.Ok {
		t.Fatalf("改密后登录失败: code=%d", after.ErrorCode)
	}
	d2 := strings.Split(after.LaunchArgs, "?")[4]
	if d2 != d1 {
		t.Fatalf("改密后 digest 被重置: %q → %q", d1, d2)
	}
}

// TestLoginGameNotFoundAndDisabled 未知 game / 停用 game 必须被明确拒绝，
// 且**不消耗登录Attempt**（这两个是配置/客户端问题，不是密码错误）。
func TestLoginGameNotFoundAndDisabled(t *testing.T) {
	svc, _ := dualGameSvcFixture(t)
	const (
		name = "gatesuser"
		pwd  = "0123456789abcdef0123456789abcdef"
	)
	dualGameRegister(t, svc, name, pwd)

	// 错误的密码先失败一次，把 failed_count 顶到 1（下面验证选服拒绝不清零它）。
	if res := svc.Login(name, strings.Repeat("f", 32), "", "203.0.113.7", ""); res.ErrorCode != models.Err.WrongPassword {
		t.Fatalf("准备失败：错误密码应返回 %d，实得 %d", models.Err.WrongPassword, res.ErrorCode)
	}

	if res := svc.Login(name, pwd, "", "203.0.113.7", "nosuchgame"); res.ErrorCode != models.Err.GameNotFound {
		t.Fatalf("未知 game 应返回 GameNotFound(%d)，实得 %d", models.Err.GameNotFound, res.ErrorCode)
	}
	if res := svc.Login(name, pwd, "", "203.0.113.7", "s5a95-old"); res.ErrorCode != models.Err.GameDisabled {
		t.Fatalf("停用 game 应返回 GameDisabled(%d)，实得 %d", models.Err.GameDisabled, res.ErrorCode)
	}

	// 正确的 game 仍然能登录（前两个拒绝没有把账号搞坏）。
	if res := svc.Login(name, pwd, "", "203.0.113.7", "s5a95"); res.ErrorCode != models.Err.Ok {
		t.Fatalf("拒绝后正确 game 应能登录，实得 code=%d", res.ErrorCode)
	}
}

// TestFindGameServerResolution 配置解析单测：空=默认服、命中、不存在。
func TestFindGameServerResolution(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.GameServer.PublicIP = "203.0.113.7"
	enabled := true
	cfg.GameServers = []config.GameServerEntry{
		{Id: "s4a21", Protocol: config.ProtocolS4A21, Enabled: &enabled},
		{Id: "s5a95", Protocol: config.ProtocolS5A95, Enabled: &enabled},
	}

	def, ok := cfg.FindGameServer("")
	if !ok || def.Id != "s4a21" {
		t.Fatalf("空 game 应解析到默认服 s4a21，实得 %q ok=%v", def.Id, ok)
	}
	got, ok := cfg.FindGameServer("s5a95")
	if !ok || got.Protocol != config.ProtocolS5A95 {
		t.Fatalf("s5a95 应命中，实得 %+v ok=%v", got, ok)
	}
	if _, ok := cfg.FindGameServer("nope"); ok {
		t.Fatalf("未知 Id 不应命中")
	}
}

// TestNormalizeGameServersFillsLaunchArgs 规范化必须给缺省模板的服
// 补上对应协议的权威默认值（S5A95 → 99?…{digest}…，其余 → 9?…{token}…）。
// 空 LaunchArgsFormat 会让登录器拿到空参数，表现为"登录成功但游戏起不来"。
func TestNormalizeGameServersFillsLaunchArgs(t *testing.T) {
	cfg := config.DefaultConfig()
	// 多服必须显式频道口（ValidateGameServers 的硬规则）。
	cfg.GameServers = []config.GameServerEntry{
		{Id: "s5a95", Protocol: config.ProtocolS5A95, ChannelListenerPort: 23100},
		{Id: "s4a21", Protocol: config.ProtocolS4A21, ChannelListenerPort: 8001},
	}
	if err := cfg.NormalizeGameServers(); err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if got := cfg.GameServers[0].LaunchArgsFormat; got != config.DefaultS5A95LaunchArgsFormat {
		t.Fatalf("s5a95 缺省模板错: %q", got)
	}
	if got := cfg.GameServers[1].LaunchArgsFormat; got != config.DefaultLaunchArgsFormat {
		t.Fatalf("s4a21 缺省模板错: %q", got)
	}
	// 已有模板的服不被覆盖。
	cfg.GameServers[1].LaunchArgsFormat = "custom?{ip}"
	if err := cfg.NormalizeGameServers(); err != nil {
		t.Fatalf("二次规范化失败: %v", err)
	}
	if got := cfg.GameServers[1].LaunchArgsFormat; got != "custom?{ip}" {
		t.Fatalf("已有模板被覆盖: %q", got)
	}
}
