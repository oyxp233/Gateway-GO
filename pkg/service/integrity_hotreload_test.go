package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"s4a21-gateway/pkg/models"
)

// writePolicyFile 模拟"另一个进程（管理后台）重写 policy 文件"：
// 直接 MarshalIndent 落盘，不走 IntegrityStore 的任何方法。
// 顺便把 mtime 推到未来 —— Windows/Linux 上同一纳秒内连续写两次会让指纹不变，
// 而这里要验证的正是"指纹变了就必须重载"这件事本身。
func writePolicyFile(t *testing.T, path string, snap *models.IntegritySnapshot) {
	t.Helper()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("Chtimes 失败: %v", err)
	}
}

// TestIntegrityStoreHotReloadExternalChange 是本次修复的核心用例：
// 管理后台（另一个进程）落盘后的名单，网关进程必须**不重启**就能看到。
//
// 修复前 IntegrityStore 只在 NewIntegrityStore 里 load 一次，
// 这个用例会挂在最后一条断言上（拿到的还是 1 条白名单）。
func TestIntegrityStoreHotReloadExternalChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, IntegrityPolicyFileName)

	// 起 store 时盘上还没有文件 —— 等价于网关首次启动。
	st := NewIntegrityStore(dir, nil)
	if st.ConfigPath() != path {
		t.Fatalf("策略路径不对: %s", st.ConfigPath())
	}
	if got := st.Snapshot(); len(got.WhiteList) != 0 {
		t.Fatalf("空策略应有 0 条白名单，实得 %d", len(got.WhiteList))
	}

	// 模拟管理后台写了第一版：2 条白名单 + 1 条黑名单 + 1 个放行模块。
	writePolicyFile(t, path, &models.IntegritySnapshot{
		Revision:       7,
		UpdatedAt:      "2026-10-12T00:00:00Z",
		WhiteList:      []models.FingerprintEntry{{FileName: "a.dll", Hash: "hash-a"}, {FileName: "b.dll", Hash: "hash-b"}},
		BlackList:      []models.FingerprintEntry{{FileName: "cheat.dll", Hash: "hash-c"}},
		AllowedModules: []string{"helper.dll"},
	})

	got := st.Snapshot()
	if len(got.WhiteList) != 2 || len(got.BlackList) != 1 || len(got.AllowedModules) != 1 {
		t.Fatalf("外部写入的新名单没被网关看到: 白=%d 黑=%d 放行=%d",
			len(got.WhiteList), len(got.BlackList), len(got.AllowedModules))
	}
	if got.Revision != 7 {
		t.Fatalf("revision 应来自磁盘上的 7，实得 %d", got.Revision)
	}
	if got.WhiteList[0].FileName != "a.dll" {
		t.Fatalf("白名单首项应为 a.dll，实得 %q", got.WhiteList[0].FileName)
	}

	// 再改一版（后台删掉一条）：必须同样能看到，而不是只认第一次的变化。
	writePolicyFile(t, path, &models.IntegritySnapshot{
		Revision:  8,
		UpdatedAt: "2026-10-12T00:10:00Z",
		WhiteList: []models.FingerprintEntry{{FileName: "a.dll", Hash: "hash-a"}},
	})
	got2 := st.Snapshot()
	if len(got2.WhiteList) != 1 {
		t.Fatalf("第二次外部改写没生效，白名单仍有 %d 条", len(got2.WhiteList))
	}
	if got2.Revision != 8 {
		t.Fatalf("revision 应为 8，实得 %d", got2.Revision)
	}
	// 黑名单那一版的数据必须被整体替换掉，不是叠加。
	if len(got2.BlackList) != 0 {
		t.Fatalf("新策略里没有黑名单，实得 %d 条（重载不是整体替换？）", len(got2.BlackList))
	}
}

// TestIntegrityStoreOwnSaveSurvives 自己的写入不能被"当成外部改写"回退掉。
// 这条防的是另一种写坏法：热加载如果在每次 save 之后把自己覆盖回磁盘内容，
// AddEntries 这种只改内存+落盘的路径会被下一次 Snapshot 冲成 Empty。
func TestIntegrityStoreOwnSaveSurvives(t *testing.T) {
	dir := t.TempDir()
	st := NewIntegrityStore(dir, nil)

	added := st.AddEntries(true, []models.FingerprintEntry{{FileName: "own.dll", Hash: "hash-own"}})
	if added != 1 {
		t.Fatalf("应新增 1 条，实得 %d", added)
	}
	// 保存后连续读多次：自己的改动必须一直在。
	for i := 0; i < 3; i++ {
		got := st.Snapshot()
		if len(got.WhiteList) != 1 || got.WhiteList[0].FileName != "own.dll" {
			t.Fatalf("第 %d 次读取时自己的保存丢失了: %+v", i+1, got.WhiteList)
		}
	}
	st.RemoveEntry(true, "own.dll", "hash-own")
	if got := st.Snapshot(); len(got.WhiteList) != 0 {
		t.Fatalf("删除后应为空，实得 %d 条", len(got.WhiteList))
	}
}

// TestIntegrityStoreMissingFileKeepsSnapshot 策略文件读不到时（被误删 / 权限问题）
// 要保持现有内存名单，既不清空也不 panic —— 宁可继续下发旧名单。
func TestIntegrityStoreMissingFileKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, IntegrityPolicyFileName)
	writePolicyFile(t, path, &models.IntegritySnapshot{
		Revision:  3,
		WhiteList: []models.FingerprintEntry{{FileName: "keep.dll", Hash: "hash-k"}},
	})

	st := NewIntegrityStore(dir, nil)
	if got := st.Snapshot(); len(got.WhiteList) != 1 {
		t.Fatalf("启动时应加载到 1 条，实得 %d", len(got.WhiteList))
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("删除策略文件失败: %v", err)
	}
	got := st.Snapshot()
	if len(got.WhiteList) != 1 || got.WhiteList[0].FileName != "keep.dll" {
		t.Fatalf("文件被删后应保持现有名单，实得 %+v", got.WhiteList)
	}

	// 文件恢复回来（哪怕又是另一份内容）必须能重新感知。
	writePolicyFile(t, path, &models.IntegritySnapshot{
		Revision:  4,
		WhiteList: []models.FingerprintEntry{{FileName: "restored.dll", Hash: "hash-r"}},
	})
	if got := st.Snapshot(); len(got.WhiteList) != 1 || got.WhiteList[0].FileName != "restored.dll" {
		t.Fatalf("文件恢复后应重新加载，实得 %+v", got.WhiteList)
	}
}

// TestIntegrityStoreUnchangedKeepsSameContent 指纹没变时不重载：这是"有没有区分力"的反向保险，
// 防止有人图省事写成"每次 Snapshot 都 ReadFile"。
// （实现方式本身无法在读之外观测，这里退一步：断言内容稳定 + 不覆盖内存中未经落盘的改动。）
func TestIntegrityStoreUnchangedKeepsSameContent(t *testing.T) {
	dir := t.TempDir()
	st := NewIntegrityStore(dir, nil)
	st.AddEntries(true, []models.FingerprintEntry{{FileName: "x.dll", Hash: "h1"}})

	first := st.Snapshot()
	rev1 := first.Revision
	for i := 0; i < 5; i++ {
		got := st.Snapshot()
		if got.Revision != rev1 || len(got.WhiteList) != 1 {
			t.Fatalf("文件没动，快照却被改动了: rev=%d 白=%d", got.Revision, len(got.WhiteList))
		}
	}
}
