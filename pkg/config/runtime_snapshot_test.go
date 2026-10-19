package config

import (
	"sync"
	"testing"
	"time"
)

func cfgStrPtr(s string) *string { return &s }
func cfgBoolPtr(b bool) *bool    { return &b }

// TestLauncherSnapshotIsIsolated 是 G-5（2026-10-04 审查）的区分力测试。
//
// 修复前 `b.cfg.Launcher.MinVersion` 是直接读写共享字段；修复后读写都过
// LauncherSnapshot / SetLauncherRuntime（RWMutex）。本用例证明「取到的快照」
// 与「随后的写入」互不影响 —— 这正是"锁内拷出一份一致的值"的行为特征。
func TestLauncherSnapshotIsIsolated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SetLauncherRuntime(cfgStrPtr("1.0.0"), cfgStrPtr("http://a/"), cfgStrPtr("notice-1"), nil)

	snap := cfg.LauncherSnapshot()
	if snap.MinVersion != "1.0.0" || snap.DownloadUrl != "http://a/" || snap.UpdateNotice != "notice-1" {
		t.Fatalf("快照内容不符: %+v", snap)
	}

	cfg.SetLauncherRuntime(cfgStrPtr("2.0.0"), nil, nil, nil)
	if snap.MinVersion != "1.0.0" {
		t.Fatalf("已取出的快照被后续写入污染: %s", snap.MinVersion)
	}
	if snap.DownloadUrl != "http://a/" || snap.UpdateNotice != "notice-1" {
		t.Fatalf("传 nil 的字段不应被改动: %+v", snap)
	}
	if now := cfg.LauncherSnapshot(); now.MinVersion != "2.0.0" ||
		now.DownloadUrl != "http://a/" || now.UpdateNotice != "notice-1" {
		t.Fatalf("重新取快照应看到新值且保留未改字段: %+v", now)
	}

	// 传 nil 不改动任何字段。
	cfg.SetLauncherRuntime(nil, nil, nil, nil)
	if cfg.LauncherSnapshot().MinVersion != "2.0.0" {
		t.Fatal("全 nil 调用不应改动配置")
	}
}

// TestMaintenanceRuntimeCopiesAdmins 覆盖 G-5 里最危险的一处：
// AdminAccounts 是**切片**（多字头），后台整体替换、认证侧并发遍历 ⇒ 可能撕裂崩溃。
// 现在写入与快照读取都做切片拷贝。
func TestMaintenanceRuntimeCopiesAdmins(t *testing.T) {
	cfg := DefaultConfig()

	admins := []string{"root", "ops"}
	cfg.SetMaintenanceRuntime(cfgBoolPtr(true), cfgStrPtr("维护中"), admins)

	// 调用方之后复用/改动自己的切片，不得影响已存值。
	admins[0] = "MUTATED"
	if got := cfg.MaintenanceSnapshot(); got.AdminAccounts[0] != "root" {
		t.Fatalf("存值应做切片拷贝，实得 %v", got.AdminAccounts)
	}

	// 快照也必须拷贝：外部改快照不得影响内部状态。
	s1 := cfg.MaintenanceSnapshot()
	s1.AdminAccounts[0] = "X"
	if got := cfg.MaintenanceSnapshot(); got.AdminAccounts[0] != "root" {
		t.Fatalf("快照应做切片拷贝，实得 %v", got.AdminAccounts)
	}

	if got := cfg.MaintenanceSnapshot(); !got.Enabled || got.Message != "维护中" {
		t.Fatalf("维护段内容不符: %+v", got)
	}
}

// TestRuntimeConfigConcurrentAccess 在 -race 下必须零告警。
// 修复前这里是"一边写 b.cfg.Maintenance.* / 一边读 auth 侧 h.config.Maintenance"，
// 加锁后不再有竞争。
func TestRuntimeConfigConcurrentAccess(t *testing.T) {
	cfg := DefaultConfig()
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				cfg.SetMaintenanceRuntime(cfgBoolPtr(true), cfgStrPtr("m"), []string{"a", "b"})
				cfg.SetLauncherRuntime(cfgStrPtr("9.9.9"), cfgStrPtr("u"), cfgStrPtr("n"), nil)
			}
		}
	}()

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					m := cfg.MaintenanceSnapshot()
					for _, a := range m.AdminAccounts {
						_ = a
					}
					lz := cfg.LauncherSnapshot()
					_ = lz.MinVersion
				}
			}
		}()
	}

	time.Sleep(60 * time.Millisecond)
	close(stop)
	wg.Wait()
}
