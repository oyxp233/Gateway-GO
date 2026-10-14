package database

import (
	"database/sql"
	"errors"
	"runtime/debug"
	"testing"
)

// TestExecTxBothRollsBackOnFnError 是 G-12（2026-10-04 审查）的区分力测试。
//
// 修复前：`if err := fn(...); err != nil` 用短声明造了**新** err，
// 两个 defer 闭包捕获的却是 BeginTx 那个外层 err（恒为 nil）⇒ fn 失败时
// 两个事务都不回滚，连接一直被占用到 GC finalizer 才归还。
//
// 判据取「连接的归还」而不是「行是否可见」：未提交的行本来就在别的连接上
// 不可见，拿行计数是弱断言、区分不出来。database/sql 的 *sql.DB.Stats().InUse
// 直接反映"连接是否还被事务占着"，且这里关掉 GC 以免 finalizer 把症状抹掉。
func TestExecTxBothRollsBackOnFnError(t *testing.T) {
	// database/sql 给每个 *sql.Tx 挂了 finalizer（GC 时 Rollback）。
	// 不关 GC 的话，"没回滚"会被偶发的 GC 抹平，用例就不确定了。
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	db := newTwoDBTestDB(t)
	baseInUse := db.gatewayDB.Stats().InUse

	sentinel := errors.New("boom")
	err := db.ExecTxBoth(func(txGw, txGame *sql.Tx) error {
		if _, e := txGw.Exec(
			"INSERT INTO accounts(m_id,name,pwd_hash,salt,created_at) VALUES('777','n','h','s',1)"); e != nil {
			return e
		}
		if _, e := txGame.Exec(
			"INSERT INTO accounts(m_id, cera, token_cera, happy_token_cera) VALUES('777', 1, 1, 1)"); e != nil {
			return e
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("应原样返回 fn 的错误，实得 %v", err)
	}

	// ① 弱断言：两侧都不该能查到 '777'（未提交行本就跨连接不可见）。
	for _, name := range []string{"gateway", "game"} {
		h := db.gatewayDB
		if name == "game" {
			h = db.gameDB
		}
		var n int
		if e := h.QueryRow("SELECT COUNT(*) FROM accounts WHERE m_id='777'").Scan(&n); e != nil {
			t.Fatalf("统计 %s 库失败: %v", name, e)
		}
		if n != 0 {
			t.Fatalf("%s 库不该有 '777'，实得 %d 行", name, n)
		}
	}

	// ② 强断言（区分力所在）：两个事务都必须真被 Rollback，连接归还池子。
	if now := db.gatewayDB.Stats().InUse; now > baseInUse {
		t.Fatalf("网关库连接仍被事务占用（InUse %d -> %d）—— defer 里的 Rollback 没触发（G-12 变量遮蔽）",
			baseInUse, now)
	}
	if now := db.gameDB.Stats().InUse; now > 0 {
		t.Fatalf("游戏库连接仍被事务占用（InUse -> %d）—— defer 里的 Rollback 没触发（G-12 变量遮蔽）", now)
	}
}

// 正对照：正常路径必须两侧都提交（证明上面的"回滚"断言不是靠"什么都不做"过关）。
func TestExecTxBothCommitsOnSuccess(t *testing.T) {
	db := newTwoDBTestDB(t)
	if err := db.ExecTxBoth(func(txGw, txGame *sql.Tx) error {
		if _, e := txGw.Exec(
			"INSERT INTO accounts(m_id,name,pwd_hash,salt,created_at) VALUES('888','n','h','s',1)"); e != nil {
			return e
		}
		if _, e := txGame.Exec(
			"INSERT INTO accounts(m_id, cera, token_cera, happy_token_cera) VALUES('888', 5, 0, 0)"); e != nil {
			return e
		}
		return nil
	}); err != nil {
		t.Fatalf("正常路径不该报错: %v", err)
	}

	var n int
	if e := db.gatewayDB.QueryRow("SELECT COUNT(*) FROM accounts WHERE m_id='888'").Scan(&n); e != nil || n != 1 {
		t.Fatalf("网关库应提交 '888'（n=%d err=%v）", n, e)
	}
	if e := db.gameDB.QueryRow("SELECT COUNT(*) FROM accounts WHERE m_id='888'").Scan(&n); e != nil || n != 1 {
		t.Fatalf("游戏库应提交 '888'（n=%d err=%v）", n, e)
	}
}
