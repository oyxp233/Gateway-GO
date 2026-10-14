package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"s4a21-gateway/pkg/pvfdiff"
)

// ────────────────────────────────────────────────────────────────────────
// PVF 历史版本 / 回退 / 按需增量（2026-09-30 方案①）
//
// 钉死的静默失效路径：
//   · 上传后历史没入档      → 回退/按需增量悄悄少一个版本，UI 上看不出来；
//   · 按需增量 from/to 对不上却下发 → 玩家本地 PVF 被合成成错误内容；
//   · 回退后固定 delta 没重建 → 回退版玩家全量更新（功能退化但不报错）；
//   · 换版后旧按需缓存没清   → 下发给玩家的包 to 过期（有双校验兜底，但会 404 卡人）。
// ────────────────────────────────────────────────────────────────────────

// 上传一版并返回其 hash。
func uploadVersion(t *testing.T, svc *PvfService, pvfPath string, body []byte, name string) string {
	t.Helper()
	if _, err := svc.ReplacePvf(bytes.NewReader(body), name, "Script-test.pvf"); err != nil {
		t.Fatalf("上传 %q 失败: %v", name, err)
	}
	return svc.GetPvfInfo().Hash
}

// ⑤ 上传必须把新旧两版都入历史，且内容寻址去重、备注只认首次。
func TestReplacePvfArchivesHistory(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(11, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()

	v2 := append([]byte(nil), v1...)
	v2[128] ^= 0x55
	uploadVersion(t, svc, pvfPath, v2, "神器进深渊池")

	entries := svc.GetHistory()
	if len(entries) != 2 {
		t.Fatalf("上传后历史应有 2 版（旧+新），实得 %d: %+v", len(entries), entries)
	}
	// GetHistory 新→旧
	if entries[0].Hash != svc.GetPvfInfo().Hash {
		t.Fatalf("最新历史条目应是当前版，实得 %s", shortHash(entries[0].Hash))
	}
	if entries[0].Name != "神器进深渊池" {
		t.Fatalf("新版备注应入史，实得 %q", entries[0].Name)
	}
	if entries[0].Filename != "Script-test.pvf" {
		t.Fatalf("上传文件名应入史，实得 %q", entries[0].Filename)
	}

	// 再次上传同 v2 内容（换备注）⇒ 去重：仍是 2 条，备注不覆盖
	uploadVersion(t, svc, pvfPath, append([]byte(nil), v2...), "重复上传不该新建记录")
	entries = svc.GetHistory()
	if len(entries) != 2 {
		t.Fatalf("同内容重复上传不该新增历史，实得 %d 条", len(entries))
	}
	for _, e := range entries {
		if e.Name == "重复上传不该新建记录" {
			t.Fatal("重复上传不该覆盖既有备注")
		}
	}

	// 历史文件本体必须可回退（内容寻址文件存在）
	if !fileExistsQuiet(filepath.Join(svc.HistoryDir(), entries[1].Hash+".pvf")) {
		t.Fatal("旧版历史文件 pvf_history/<hash>.pvf 不存在")
	}
}

func fileExistsQuiet(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ⑥ GetHistory 的惰性 seed：从未走过上传的部署（只有磁盘文件 + .bak），
//    打开历史页也必须能看到两版 —— 这是「回退到上一版」在任何状态可用的保证。
func TestGetHistorySeedsCurrentAndBak(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(21, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()
	// 模拟一个"上一版"：直接造 .bak（绕过 ReplacePvf，等价于历史部署）
	v0 := randBody(20, testPvfSize)
	if err := os.WriteFile(pvfPath+".bak", v0, 0o644); err != nil {
		t.Fatal(err)
	}

	entries := svc.GetHistory()
	if len(entries) != 2 {
		t.Fatalf("惰性 seed 后历史应有 2 版（当前+.bak），实得 %d", len(entries))
	}
}

// ⑦ 回退走完整链路：替换成功 + 固定 delta 从「回退前版」指向「回退版」
//    （在回退前版上的玩家因此能增量降级）。
func TestRollbackPvfFullChain(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(31, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()
	v1Hash := svc.GetPvfInfo().Hash

	v2 := append([]byte(nil), v1...)
	v2[256] ^= 0x77
	v2Hash := uploadVersion(t, svc, pvfPath, v2, "v2")

	// 回退到 v1
	info, err := svc.RollbackPvf(v1Hash)
	if err != nil {
		t.Fatalf("回退失败: %v", err)
	}
	if info.Hash != v1Hash {
		t.Fatalf("回退后当前版应是 v1，实得 %s", shortHash(info.Hash))
	}
	d := svc.GetDelta()
	if d == nil {
		t.Fatal("回退后必须重建固定增量（v2 玩家靠它增量降级）")
	}
	if d.FromHash != v2Hash || d.ToHash != v1Hash {
		t.Fatalf("回退后固定增量应是 v2→v1，实得 %s→%s",
			shortHash(d.FromHash), shortHash(d.ToHash))
	}

	// 回退到当前版必须被拒绝
	if _, err := svc.RollbackPvf(v1Hash); err == nil {
		t.Fatal("回退到当前版应报错，实际成功了")
	}
	// 回退到不存在的版本必须被拒绝
	if _, err := svc.RollbackPvf(strings.Repeat("A", 64)); err == nil {
		t.Fatal("回退到不存在的版本应报错")
	}
	// 非法 hash（路径穿越尝试）必须被拒绝
	for _, evil := range []string{"../../etc/passwd", "ab", "", strings.Repeat("Z", 64)} {
		if _, err := svc.RollbackPvf(evil); err == nil {
			t.Fatalf("非法 hash %q 应被拒绝", evil)
		}
	}
}

// ⑧ 按需增量：落后两版的客户端带 ?from=<自己的版本> 也能拿到可用的包。
func TestOnDemandDeltaFromOldVersion(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(41, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()
	v1Hash := svc.GetPvfInfo().Hash

	v2 := append([]byte(nil), v1...)
	v2[512] ^= 0x99
	uploadVersion(t, svc, pvfPath, v2, "v2")

	v3 := append([]byte(nil), v2...)
	v3[1024] ^= 0xAA
	v3Hash := uploadVersion(t, svc, pvfPath, v3, "v3")

	// v1 客户端（落后两版）按需请求
	d := svc.GetOnDemandDelta(v1Hash)
	if d == nil {
		t.Fatal("历史里有 v1，按需增量不该为 nil")
	}
	if d.FromHash != v1Hash || d.ToHash != v3Hash {
		t.Fatalf("按需增量应是 v1→v3，实得 %s→%s",
			shortHash(d.FromHash), shortHash(d.ToHash))
	}
	// ★ 端到端：v1 + 按需 delta 合成必须逐字节等于 v3
	out := filepath.Join(t.TempDir(), "on-demand.pvf")
	if err := pvfdiff.Apply(filepath.Join(svc.HistoryDir(), v1Hash+".pvf"), d.Path, out); err != nil {
		t.Fatalf("按需增量合成失败: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, v3) {
		t.Fatal("按需增量合成结果 != v3（下发的包不可用）")
	}

	// 第二次请求同一 from ⇒ 命中缓存（同一路径、仍可用）
	d2 := svc.GetOnDemandDelta(v1Hash)
	if d2 == nil || d2.Path != d.Path {
		t.Fatal("同 from 二次请求应命中缓存")
	}
}

// ⑨ 按需增量的拒绝路径：已是最新 / 历史没有 / 非法参数。
func TestOnDemandDeltaRejections(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(51, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()
	v1Hash := svc.GetPvfInfo().Hash

	v2 := append([]byte(nil), v1...)
	v2[64] ^= 0x01
	v2Hash := uploadVersion(t, svc, pvfPath, v2, "v2")

	// 已是最新（v2 客户端）→ nil
	if d := svc.GetOnDemandDelta(v2Hash); d != nil {
		t.Fatal("from == 当前版（已是最新）应返回 nil")
	}
	// 历史里没有的版本 → nil（此处用一个没出现过的合法 hash）
	if d := svc.GetOnDemandDelta(strings.Repeat("B", 64)); d != nil {
		t.Fatal("历史没有的版本应返回 nil")
	}
	// 非法参数（穿越/短串/空）→ nil
	for _, evil := range []string{"", "xyz", "../../etc/passwd", strings.Repeat("g", 64), strings.Repeat("0", 63)} {
		if d := svc.GetOnDemandDelta(evil); d != nil {
			t.Fatalf("非法 from %q 应返回 nil", evil)
		}
	}
	// v1 合法 → 有
	if d := svc.GetOnDemandDelta(v1Hash); d == nil {
		t.Fatal("v1 在历史里，应返回按需增量")
	}
}

// ⑩ 换版后旧的按需缓存必须作废：v1 客户端在新版下重新拿到的包 to 必须指向新当前版。
func TestOnDemandDeltaCacheInvalidatedOnReplace(t *testing.T) {
	svc, pvfPath := newPvfDeltaService(t)

	v1 := randBody(61, testPvfSize)
	if err := os.WriteFile(pvfPath, v1, 0o644); err != nil {
		t.Fatal(err)
	}
	svc.RefreshCache()
	v1Hash := svc.GetPvfInfo().Hash

	v2 := append([]byte(nil), v1...)
	v2[32] ^= 0x02
	uploadVersion(t, svc, pvfPath, v2, "v2")
	if d := svc.GetOnDemandDelta(v1Hash); d == nil {
		t.Fatal("前置条件不成立：v1 按需增量应可用")
	}

	// 再上传 v3 ⇒ 上传流程应清掉 from_*.delta 缓存
	v3 := append([]byte(nil), v2...)
	v3[96] ^= 0x03
	v3Hash := uploadVersion(t, svc, pvfPath, v3, "v3")

	// 直接检查缓存目录已无残留
	items, _ := os.ReadDir(svc.DeltaDir())
	for _, it := range items {
		if strings.HasPrefix(it.Name(), "from_") {
			t.Fatalf("换版后按需缓存应被清除，残留 %s", it.Name())
		}
	}
	// v1 再次按需 ⇒ 新包 to 必须是 v3
	d := svc.GetOnDemandDelta(v1Hash)
	if d == nil {
		t.Fatal("v1 仍应能按需更新到 v3")
	}
	if d.ToHash != v3Hash {
		t.Fatalf("换版后按需增量 to 应是 v3，实得 %s", shortHash(d.ToHash))
	}
}

// ⑪ NormalizeHashArg：大小写归一 + 严格十六进制。
func TestNormalizeHashArg(t *testing.T) {
	if got := NormalizeHashArg(" " + strings.ToLower(strings.Repeat("ab32", 16)) + " "); got != strings.Repeat("AB32", 16) {
		t.Fatalf("小写+空白应归一为大写，实得 %q", got)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("G", 64), strings.Repeat("0", 63), "../../x"} {
		if got := NormalizeHashArg(bad); got != "" {
			t.Fatalf("%q 应判定非法，实得 %q", bad, got)
		}
	}
}
