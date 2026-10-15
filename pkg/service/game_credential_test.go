package service

import (
	"strings"
	"testing"

	"s4a21-gateway/pkg/database"
	"s4a21-gateway/pkg/models"
)

// TestVerifyAccountCredential 游戏口凭证校验器（方案 D 的口令路径）。
//
// 关键约束：必须复用全网关唯一的密码判定入口（verifyAccountPassword），
// 注册账号（加盐 SHA256）与迁移账号（空 salt、MD5 直比）两条路径都要覆盖 ——
// 漏掉后者，161 上 106 个迁移账号在游戏口会被误判成"凭证不符"。
func TestVerifyAccountCredential(t *testing.T) {
	svc, db := newAccountSvcFixture(t)

	const (
		name = "gamecreduser"
		pwd  = "0123456789abcdef0123456789abcdef"
	)
	if code := svc.Register(name, pwd); code != models.Err.Ok {
		t.Fatalf("准备失败：注册返回 code=%d", code)
	}
	acct, err := db.GetAccountByName(name)
	if err != nil || acct == nil {
		t.Fatalf("准备失败：取账号 err=%v acct=%v", err, acct)
	}

	// 正确口令 ⇒ 匹配
	if ok, err := svc.VerifyAccountCredential(acct.MId, pwd); err != nil || !ok {
		t.Fatalf("正确口令应匹配: ok=%v err=%v", ok, err)
	}

	// 错误口令 ⇒ 确定不匹配
	if ok, err := svc.VerifyAccountCredential(acct.MId, strings.Repeat("f", 32)); err != nil || ok {
		t.Fatalf("错误口令不应匹配: ok=%v err=%v", ok, err)
	}

	// 陌生 m_id ⇒ (false, nil)：确定不匹配，但不是"无法验证"
	if ok, err := svc.VerifyAccountCredential("999999999", pwd); err != nil || ok {
		t.Fatalf("陌生 m_id 应返回 (false, nil): ok=%v err=%v", ok, err)
	}

	// 迁移账号（空 salt，游戏库 v11 口径：password_hash 就是 pwd_md5）⇒ MD5 直比
	migrated := "migrated001"
	if err := db.InsertAccount(&database.Account{
		MId:     migrated,
		Name:    migrated,
		PwdHash: pwd,
		Salt:    "",
	}); err != nil {
		t.Fatalf("插迁移账号失败: %v", err)
	}
	if ok, err := svc.VerifyAccountCredential(migrated, pwd); err != nil || !ok {
		t.Fatalf("迁移账号（空 salt）应走 MD5 直比: ok=%v err=%v", ok, err)
	}
}
