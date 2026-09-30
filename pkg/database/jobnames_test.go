package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestJobDisplayNameAnchors 锁定几个锚点。
//
// 这些值来自 _jobdump 对 Script.pvf 的真实解析，人工核对过：
//
//	job 0  = swordman 鬼剑士，grow_type 低4位=转职、高4位=觉醒
//	job 13 = demonic lancer 魔枪士（注意：服务端 GetJobName 里 13 写成「圣职者（女）」是猜错的）
func TestJobDisplayNameAnchors(t *testing.T) {
	cases := []struct {
		job, growType int
		want          string
	}{
		{0, 0, "鬼剑士（男）"},  // 未转职未觉醒，补性别区分男/女鬼
		{11, 0, "鬼剑士（女）"}, // 同基础名的另一个 job
		{0, 1, "剑魂"},      // 一转
		{0, 17, "剑圣"},     // first=1 second=1（0x11）
		{0, 33, "剑神"},     // first=1 second=2（0x21）
		{0, 19, "狱血魔神"},   // first=3 second=1
		{0, 3, "狂战士"},
		{5, 33, "绯红玫瑰"}, // at gunner（女枪）二觉
		{9, 0, "黑暗武士"},  // 外传职业，只有 grow_type 0
		{9, 16, "黑暗武士"}, // 它的 [growtype 1] 段 = 未转职直接觉醒
		{10, 0, "缔造者"},
		{13, 1, "征战者"},
		{13, 33, "不灭战神"},
		{4, 0, "圣职者"},    // 没有同名对立版本 → 不补性别
		{6, 0, "暗夜使者"},   // 同上
		{99, 0, "职业 99"}, // 未知 job 不能返回空串
		{0, 0x46, "鬼剑士"}, // first=6 越界 → 回退基础名（且 growType!=0，不补性别）
		{0, 0x51, "剑魂"},  // second=5 超出该分支的觉醒数 → 回退到一转名
	}
	for _, c := range cases {
		if got := JobDisplayName(c.job, c.growType); got != c.want {
			t.Errorf("JobDisplayName(%d, %d) = %q, want %q", c.job, c.growType, got, c.want)
		}
	}
}

// TestJobCatalogMatchesDump 把 Go 表逐条对拍 _jobdump 导出的 PVF 解析结果。
//
// 这是防止「改了 PVF 忘了重新生成」的唯一硬约束：_jobdump/out/job_names.json
// 是 jobdump 直接读 Script.pvf 的产物，两边必须完全一致。
// _jobdump 不在（例如只拉了 S4A21Gateway-GO 子目录）时跳过。
func TestJobCatalogMatchesDump(t *testing.T) {
	// 测试的工作目录是 pkg/database，_jobdump 在仓库根下。
	path := filepath.Join("..", "..", "..", "_jobdump", "out", "job_names.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("跳过：读不到 PVF 导出件 %s（%v）", path, err)
	}

	var dump struct {
		Jobs []struct {
			Job int `json:"job"`
		} `json:"jobs"`
		Resolved map[string]string `json:"resolved"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		t.Fatalf("job_names.json 解析失败: %v", err)
	}
	if len(dump.Resolved) == 0 {
		t.Fatal("job_names.json 的 resolved 为空，导出件不完整")
	}

	// 性别后缀只在 grow_type==0 时补，导出件里没有，对拍时按同一规则还原。
	total, checked := 0, 0
	for key, want := range dump.Resolved {
		var job, growType int
		if _, err := fmt.Sscanf(key, "%d|%d", &job, &growType); err != nil {
			t.Fatalf("键格式异常 %q: %v", key, err)
		}
		total++
		if growType == 0 {
			if g, ok := jobBaseGender[job]; ok {
				want += "（" + g + "）"
			}
		}
		if _, known := jobCatalog[job]; !known {
			continue
		}
		checked++
		if got := JobDisplayName(job, growType); got != want {
			t.Fatalf("job=%d grow_type=%d 与 PVF 导出件不一致: Go=%q PVF=%q", job, growType, got, want)
		}
	}
	t.Logf("对拍 %d 条（其中 %d 条落在已知职业上）", total, checked)
}
