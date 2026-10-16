package database

import (
	"os"
	"path/filepath"
	"testing"
)

// TestListBackupsIncludesTarGz 备份列表必须把 .tar.gz 算进去。
//
// 2026-10-16 起产物从「散装 .db/.pvf」改成「db-/pvf-/logs-<时间戳>.tar.gz」。
// 扩展名白名单里漏掉 .gz 的直接后果，就是这条注释上方那条历史缺陷原样重演：
// **备份明明成功、后台列表却显示"暂无备份"** —— 而且没有任何报错。
// 每加一种产物格式都必须回来看这里。
func TestListBackupsIncludesTarGz(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{
		"db-20261016-211726.tar.gz",
		"pvf-20261016-211726.tar.gz",
		"logs-20261016-211726.tar.gz",
		"inventory-20261016-211726.db", // 旧格式仍要列出来
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatalf("造文件失败: %v", err)
		}
	}
	// 正在打包中的半截文件不该被当成成品
	if err := os.WriteFile(filepath.Join(dir, "db-20261016-211800.tar.gz.tmp"), []byte("half"), 0o644); err != nil {
		t.Fatalf("造临时文件失败: %v", err)
	}

	list, err := ListBackups(dir)
	if err != nil {
		t.Fatalf("列备份失败: %v", err)
	}
	if len(list) != 4 {
		names := make([]string, 0, len(list))
		for _, b := range list {
			names = append(names, b.Name)
		}
		t.Fatalf("应列出 4 个文件，实得 %d: %v", len(list), names)
	}
	for _, b := range list {
		if b.Name == "db-20261016-211800.tar.gz.tmp" {
			t.Errorf("半截的 .tmp 不该被列出来")
		}
		if b.Size <= 0 {
			t.Errorf("%s 的大小没带出来", b.Name)
		}
	}
}
