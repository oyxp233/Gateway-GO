package service

import (
	"strings"
	"testing"

	"s4a21-gateway/pkg/models"
)

// P2-1：登录时「账号不存在」与「密码错误」两条路径必须付出等量级的哈希代价。
//
// 断言手段：把 deriveHashFn 换成计数钩子，数两条路径各算了几次哈希。
// 修复前 `account == nil` 直接 return（0 次），而密码错误要算一次 SHA256(MD5+salt)
// —— 账号存不存在，从响应时延上就能被区分出来，等于给了一个用户名枚举接口。
//
// 为什么数调用次数而不是计时：一次 SHA256 只有微秒级，本机跑计时断言会被
// 调度抖动淹没，变成一条时灵时不灵的 flaky 测试。而"有没有做这件事"是确定性的，
// 时延差正由它决定。
func TestLoginTimingEqualizedOnMissingAccount(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)

	const (
		name = "p2timinguser"
		pwd  = "0123456789abcdef0123456789abcdef"
		ip   = "203.0.113.7"
	)
	if code := svc.Register(name, pwd); code != models.Err.Ok {
		t.Fatalf("准备失败：注册返回 code=%d", code)
	}

	orig := deriveHashFn
	t.Cleanup(func() { deriveHashFn = orig })

	var calls int
	deriveHashFn = func(md5, salt string) string {
		calls++
		return orig(md5, salt)
	}

	// (1) 密码错误：账号存在，走一次加盐哈希
	calls = 0
	wrong := svc.Login(name, strings.Repeat("f", 32), "", ip, "")
	if wrong.ErrorCode != models.Err.WrongPassword {
		t.Fatalf("准备失败：错误密码应返回 %d，实际 %d", models.Err.WrongPassword, wrong.ErrorCode)
	}
	wrongPwdCalls := calls

	// (2) 账号不存在：修复后同样要算一次
	calls = 0
	missing := svc.Login("p2nosuchuser", pwd, "", ip, "")
	if missing.ErrorCode != models.Err.AccountNotFound {
		t.Fatalf("账号不存在应返回 %d，实际 %d", models.Err.AccountNotFound, missing.ErrorCode)
	}
	missingCalls := calls

	if wrongPwdCalls == 0 {
		t.Fatalf("前提不成立：密码错误路径一次哈希都没算，本用例失去意义")
	}
	if missingCalls == 0 {
		t.Fatalf("账号不存在路径零次哈希计算 —— 响应时延可枚举用户名（P2-1 未修复）")
	}
	if missingCalls != wrongPwdCalls {
		t.Fatalf("两条路径哈希次数不等（不存在=%d / 密码错=%d），时延仍可区分",
			missingCalls, wrongPwdCalls)
	}
}

// P2-1 的反向断言：抹平时延不能改变对外语义。
// 账号不存在依旧返回 AccountNotFound(1007)，不能因为多算了一次哈希就串成别的码
// —— 哈希结果是丢弃的，绝不能参与判定。
func TestEqualizeLoginTimingDoesNotAlterVerdict(t *testing.T) {
	svc, _ := newAccountSvcFixture(t)

	const pwd = "0123456789abcdef0123456789abcdef"
	if code := svc.Register("p2verdictuser", pwd); code != models.Err.Ok {
		t.Fatalf("准备失败：注册返回 code=%d", code)
	}

	// 用一个会造成碰撞的假 salt 也不能影响结果：equalizeLoginTiming 的返回值被丢弃。
	orig := deriveHashFn
	t.Cleanup(func() { deriveHashFn = orig })
	deriveHashFn = func(md5, salt string) string {
		// 故意返回一个"万能哈希"：若它被误用于比较，密码错会变成登录成功。
		return "0b1d2f3a4c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
	}

	res := svc.Login("p2verdictuser", strings.Repeat("9", 32), "", "203.0.113.8", "")
	if res.ErrorCode != models.Err.WrongPassword {
		t.Fatalf("抹平时延的哈希结果被用于判定：期望 %d，实际 %d",
			models.Err.WrongPassword, res.ErrorCode)
	}

	missing := svc.Login("p2nosuchuser", pwd, "", "203.0.113.9", "")
	if missing.ErrorCode != models.Err.AccountNotFound {
		t.Fatalf("期望 %d，实际 %d", models.Err.AccountNotFound, missing.ErrorCode)
	}
}
