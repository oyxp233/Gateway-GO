package database

import (
	"fmt"
	"path/filepath"
	"testing"
)

// newTwoDBTestDB 造一个「网关库 + 游戏库都在」的测试实例。
// 游戏库 accounts 表按游戏侧真实形态建（m_id + 三币种 + created_at）。
func newTwoDBTestDB(t *testing.T) *Database {
	t.Helper()
	dir := t.TempDir()
	gamePath := filepath.Join(dir, "inventory.db")

	game, err := openSQLite(gamePath, 5)
	if err != nil {
		t.Fatalf("打开测试游戏库失败: %v", err)
	}
	if _, err := game.Exec(`
		CREATE TABLE accounts (
			account_id       INTEGER PRIMARY KEY AUTOINCREMENT,
			m_id             TEXT NOT NULL UNIQUE,
			cera             INTEGER NOT NULL DEFAULT 0,
			token_cera       INTEGER NOT NULL DEFAULT 0,
			happy_token_cera INTEGER NOT NULL DEFAULT 0,
			created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`); err != nil {
		game.Close()
		t.Fatalf("建测试游戏库 schema 失败: %v", err)
	}
	game.Close()

	db, err := NewDatabase(DatabaseConfig{
		Path:               filepath.Join(dir, "gateway.db"),
		GamePath:           gamePath,
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

// TestGetCurrencyTriplesByMIdsMatchesPerRow 是 G-11（2026-10-04 审查）的区分力测试。
//
// 修复前 ListAccounts 逐行调 GetCurrencyTripleByMId（一页最多 500 次跨库查询）；
// 修复后走一次批量 IN 查询。这里用「批量结果必须与逐行版逐字段一致」来锁住等价性 ——
// 批量实现一旦漏字段 / 漏行 / 多出行，本用例立刻变红。
func TestGetCurrencyTriplesByMIdsMatchesPerRow(t *testing.T) {
	db := newTwoDBTestDB(t)
	rows := []struct {
		mid             string
		c, tk, hp int64
	}{
		{"10038", 111, 222, 333},
		{"2030", 444, 555, 666},
	}
	for _, r := range rows {
		if _, err := db.gameDB.Exec(
			"INSERT INTO accounts(m_id, cera, token_cera, happy_token_cera) VALUES(?,?,?,?)",
			r.mid, r.c, r.tk, r.hp); err != nil {
			t.Fatalf("插入游戏库账号失败: %v", err)
		}
	}

	// 入参故意混入：不存在的 m_id、空串、重复 id。
	batch := db.GetCurrencyTriplesByMIds([]string{"10038", "2030", "99999", "", "10038"})
	if len(batch) != 2 {
		t.Fatalf("批量结果应恰好 2 条（去重 + 过滤空串 + 不存在的行不返回），实得 %d: %v", len(batch), batch)
	}
	for _, r := range rows {
		c, tk, hp, ok := db.GetCurrencyTripleByMId(r.mid)
		if !ok {
			t.Fatalf("逐行版应能查到 %s", r.mid)
		}
		got, present := batch[r.mid]
		if !present {
			t.Fatalf("批量结果缺 %s", r.mid)
		}
		if got.Cera != c || got.TokenCera != tk || got.HappyTokenCera != hp {
			t.Fatalf("%s 批量与逐行不一致: 批量=%+v 逐行=(%d,%d,%d)", r.mid, got, c, tk, hp)
		}
	}
	if _, present := batch["99999"]; present {
		t.Fatal("游戏库里没有的 m_id 不应出现在批量结果里")
	}
	if _, present := batch[""]; present {
		t.Fatal("空 m_id 不应出现在批量结果里")
	}
}

// TestGetCurrencyTriplesByMIdsChunking 覆盖 >500 的分块拼接（IN 列表按 500 切）。
func TestGetCurrencyTriplesByMIdsChunking(t *testing.T) {
	db := newTwoDBTestDB(t)
	const n = 620

	tx, err := db.gameDB.Begin()
	if err != nil {
		t.Fatalf("开启测试写入事务失败: %v", err)
	}
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%05d", i)
		ids = append(ids, id)
		if _, err := tx.Exec(
			"INSERT INTO accounts(m_id, cera, token_cera, happy_token_cera) VALUES(?,?,0,0)",
			id, i); err != nil {
			tx.Rollback()
			t.Fatalf("插入第 %d 行失败: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交测试数据失败: %v", err)
	}

	batch := db.GetCurrencyTriplesByMIds(ids)
	if len(batch) != n {
		t.Fatalf("跨分块应取回 %d 条，实得 %d", n, len(batch))
	}
	for i := 0; i < n; i++ {
		got, ok := batch[fmt.Sprintf("%05d", i)]
		if !ok || got.Cera != int64(i) {
			t.Fatalf("第 %d 条不符: %+v ok=%v", i, got, ok)
		}
	}
}
