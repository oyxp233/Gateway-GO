package service

//
// 备份「可勾选目标 + 分类 tar.gz」的单测（2026-10-16）
//
// 本文件的每一条断言都要能回答一个问题：
// **把实现换回改造前的旧逻辑，这条会不会红？** 不会红的就是装饰，不是断言。
// 文件末尾的 TestBackupRevertCheck 系列（在临时回退脚本里跑）负责实证这一点。
//

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"s4a21-gateway/pkg/config"
)

// ────────────────────────────────────────────────────────────────────────
// 夹具
// ────────────────────────────────────────────────────────────────────────

// backupFixture 造一套完整的备份现场：两个库 + PVF + 四种日志。
//
// 日志目录刻意建在**临时根下的 logs/ 与 logs-admin/**，
// 然后把进程 cwd 切到那里 —— resolveGatewayLogDir 的第一条候选就是
// cwd 相对的 "logs"（与 GatewayManager 同一口径），这样单测能真实覆盖
// 目录发现逻辑，而不是靠 mock 掉它。
type backupFixture struct {
	root    string
	cfg     *config.GatewayConfig
	backups string
	files   map[string]string // key -> 绝对路径
}

func newBackupFixture(t *testing.T) *backupFixture {
	t.Helper()
	root := t.TempDir()

	data := filepath.Join(root, "data")
	logs := filepath.Join(root, "logs")
	adminLogs := filepath.Join(root, "logs-admin")
	for _, d := range []string{data, logs, adminLogs, filepath.Join(root, "backups")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("建目录失败: %v", err)
		}
	}

	f := &backupFixture{root: root, backups: filepath.Join(root, "backups"), files: map[string]string{}}

	// 两个库（真 SQLite，好让 VACUUM INTO 路径被真走到）
	for key, name := range map[string]string{TargetGameDB: "inventory.db", TargetGatewayDB: "gateway.db"} {
		p := filepath.Join(data, name)
		db := openTestSQLite(t, p)
		if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
			t.Fatalf("建表失败: %v", err)
		}
		if _, err := db.Exec("INSERT INTO t (v) VALUES (?)", "marker-"+name); err != nil {
			t.Fatalf("插入失败: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("关闭失败: %v", err)
		}
		f.files[key] = p
	}

	// PVF（二进制，随便造点不可压缩性低的字节）
	pvfPath := filepath.Join(root, "pvf", "Script.pvf")
	if err := os.MkdirAll(filepath.Dir(pvfPath), 0o755); err != nil {
		t.Fatalf("建 PVF 目录失败: %v", err)
	}
	if err := os.WriteFile(pvfPath, bytes.Repeat([]byte("PVF-BODY-"), 2048), 0o644); err != nil {
		t.Fatalf("造 PVF 失败: %v", err)
	}
	f.files[TargetPvf] = pvfPath

	// 四种日志 + 服务端日志
	logSpecs := map[string]string{
		TargetGatewayLog:    filepath.Join(logs, "gateway.log"),
		TargetGatewayErrLog: filepath.Join(logs, "error.log"),
		TargetAdminLog:      filepath.Join(adminLogs, "gateway.log"),
		TargetAdminErrLog:   filepath.Join(adminLogs, "error.log"),
		TargetServerLog:     filepath.Join(root, "server.log"),
		TargetPacketLog:     filepath.Join(root, "packet.log"),
	}
	for key, p := range logSpecs {
		// 内容刻意做成高重复（日志的真实形态），让"压缩率"这个观测量有意义
		if err := os.WriteFile(p, bytes.Repeat([]byte("2026-10-16 line of log\n"), 500), 0o644); err != nil {
			t.Fatalf("造日志失败: %v", err)
		}
		f.files[key] = p
	}

	cfg := config.DefaultConfig()
	cfg.Server.BackupDir = f.backups
	cfg.Database.GamePath = f.files[TargetGameDB]
	cfg.Database.Path = f.files[TargetGatewayDB]
	cfg.Server.PvfPath = pvfPath
	cfg.Server.LogPath = f.files[TargetServerLog]
	cfg.Server.WorkDir = root
	cfg.Pvf.FilePath = ""
	// 审计清理会把线上库清一遍，本文件不测它（audit_purge_test.go 已覆盖）
	no := false
	cfg.Server.BackupPurgeAuditLog = &no
	cfg.Server.BackupRetainCount = 0
	f.cfg = cfg

	// 切 cwd 到临时根，让日志目录发现能命中
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("取 cwd 失败: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("切 cwd 失败: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	return f
}

func (f *backupFixture) mgr() *ServerManager {
	return &ServerManager{config: f.cfg}
}

// ────────────────────────────────────────────────────────────────────────
// 目标清单
// ────────────────────────────────────────────────────────────────────────

// TestListBackupTargetsCoversEveryDef 清单必须覆盖全部 9 项目标，且文件齐时全为 Exists。
//
// 这条是"可勾选"这个功能存在的前提：漏一项就等于那项永远没法通过界面备份
// （历史上日志就是这么漏掉的）。
func TestListBackupTargetsCoversEveryDef(t *testing.T) {
	f := newBackupFixture(t)
	list := f.mgr().ListBackupTargets()

	if len(list) != len(backupTargetDefs) {
		t.Fatalf("目标数 = %d，期望 %d", len(list), len(backupTargetDefs))
	}
	seen := map[string]bool{}
	for _, it := range list {
		seen[it.Key] = true
		// game_mysql 是 S5A3 专属的「导出产物」目标：本 fixture 用的是 S4A21 配置
		// （没有 GameDSN），它本来就该是 Exists=false、Path 为空 ——
		// 强行要求它可用，等于要求 S4A21 也去连一个不存在的 MySQL。
		// 它的可用性由 TestListBackupTargetsGameMySQLOnlyForS5A3 单独覆盖。
		if it.Key == TargetGameMySQL {
			if it.Exists {
				t.Errorf("S4A21 配置下 game_mysql 不该标记为可用")
			}
			continue
		}
		if !it.Exists {
			t.Errorf("%s 应存在，实得 Exists=false（path=%s）", it.Key, it.Path)
		}
		if it.Size <= 0 {
			t.Errorf("%s 的大小没带出来: %d", it.Key, it.Size)
		}
		if it.Path == "" {
			t.Errorf("%s 没解析出路径", it.Key)
		}
	}
	for _, d := range backupTargetDefs {
		if !seen[d.key] {
			t.Errorf("目标 %s 不在清单里", d.key)
		}
	}
}

// TestListBackupTargetsMarksMissing 解析不到的目标要**照样列出来**且 Exists=false。
//
// 反过来的做法（不存在就不显示）会让运维只会看到勾选项变少，
// 不知道该去查哪条配置路径 —— 那是"静默少备一份"的温床。
func TestListBackupTargetsMarksMissing(t *testing.T) {
	f := newBackupFixture(t)
	if err := os.Remove(f.files[TargetPacketLog]); err != nil {
		t.Fatalf("删样本失败: %v", err)
	}
	f.cfg.Server.PvfPath = filepath.Join(f.root, "nope", "Script.pvf")

	var packet, pvf *BackupTarget
	for i, it := range f.mgr().ListBackupTargets() {
		switch it.Key {
		case TargetPacketLog:
			packet = &f.mgr().ListBackupTargets()[i]
		case TargetPvf:
			pvf = &f.mgr().ListBackupTargets()[i]
		}
	}
	if packet == nil || pvf == nil {
		t.Fatalf("清单里找不到 packet_log / pvf")
	}
	if packet.Exists {
		t.Errorf("删掉的封包日志应 Exists=false")
	}
	if pvf.Exists || pvf.Path != "" {
		t.Errorf("PVF 解析不到时应 Exists=false 且 Path 为空，实得 %+v", pvf)
	}
}

// TestResolveGatewayLogDirFollowsCwd 日志目录发现：cwd 下的 logs/ 优先，
// 且 logs-admin/ 由它同级推导（不是另一套独立候选）。
func TestResolveGatewayLogDirFollowsCwd(t *testing.T) {
	f := newBackupFixture(t)
	if got := resolveGatewayLogDir(); got != "logs" && got != filepath.Join(f.root, "logs") {
		t.Errorf("网关日志目录 = %q，期望命中 cwd 下的 logs/", got)
	}
	if got := resolveAdminLogDir(); !strings.HasSuffix(filepath.ToSlash(got), "logs-admin") {
		t.Errorf("后台日志目录 = %q，期望以 logs-admin 结尾", got)
	}
}

// ────────────────────────────────────────────────────────────────────────
// 打包
// ────────────────────────────────────────────────────────────────────────

// extractTarGz 解开一个包，返回 条目名 -> 内容。
func extractTarGz(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开归档失败: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("不是合法 gzip（压缩尾部没写出去？）: %v", err)
	}
	defer gz.Close()

	out := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("读归档条目失败（tar 结尾块没写？）: %v", err)
		}
		buf := &bytes.Buffer{}
		if _, err := io.Copy(buf, tr); err != nil {
			t.Fatalf("解出条目 %s 失败: %v", h.Name, err)
		}
		out[h.Name] = buf.Bytes()
	}
	return out
}

// TestBackupThreeArchivesByKind 勾选全部 → 产出 db / pvf / logs 三个包。
//
// 这是"分类分包"这条需求的核心断言：改造前是三份散装文件，
// 改造后必须是三个 .tar.gz，且每类各归各的包。
func TestBackupThreeArchivesByKind(t *testing.T) {
	f := newBackupFixture(t)
	res := f.mgr().BackupWith(BackupOptions{Targets: []string{
		TargetGameDB, TargetGatewayDB, TargetPvf,
		TargetGatewayLog, TargetGatewayErrLog, TargetAdminLog, TargetAdminErrLog,
		TargetServerLog, TargetPacketLog,
	}})
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}
	if len(res.Archives) != 3 {
		t.Fatalf("产出包数 = %d，期望 3（db/pvf/logs）: %+v", len(res.Archives), res.Archives)
	}
	kinds := map[string]bool{}
	for _, a := range res.Archives {
		kinds[a.Kind] = true
		if !strings.HasSuffix(a.Name, ".tar.gz") {
			t.Errorf("%s 不是 .tar.gz", a.Name)
		}
		if !strings.HasPrefix(a.Name, a.Kind+"-") {
			t.Errorf("包名 %s 与类别 %s 不匹配", a.Name, a.Kind)
		}
	}
	for _, k := range []string{backupKindDB, backupKindPvf, backupKindLogs} {
		if !kinds[k] {
			t.Errorf("缺少 %s 包", k)
		}
	}
}

// TestBackupArchiveEntriesAndBytes 包内条目名与内容必须与源文件对得上。
//
// 三条分开看，任一出错都对应一种真实事故：
//   - 条目名不含时间戳 → 多次备份解压后互相覆盖；
//   - 日志条目平铺 → gateway.log 与 admin/gateway.log 撞名，解压只剩一份；
//   - 内容不一致 → 备份是废的（历史上 VACUUM 尾部没写完就会这样）。
func TestBackupArchiveEntriesAndBytes(t *testing.T) {
	f := newBackupFixture(t)
	res := f.mgr().BackupWith(BackupOptions{Targets: []string{
		TargetGameDB, TargetGatewayDB, TargetPvf,
		TargetGatewayLog, TargetAdminLog, TargetServerLog,
	}})
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}

	byKind := map[string]BackupArchive{}
	for _, a := range res.Archives {
		byKind[a.Kind] = a
	}

	// db 包：两个库，条目名带时间戳
	dbEntries := extractTarGz(t, byKind[backupKindDB].Path)
	if len(dbEntries) != 2 {
		t.Fatalf("db 包条目数 = %d，期望 2: %v", len(dbEntries), keysOf(dbEntries))
	}
	var invName, gwName string
	for n := range dbEntries {
		if strings.HasPrefix(n, "inventory-") {
			invName = n
		}
		if strings.HasPrefix(n, "gateway-") {
			gwName = n
		}
	}
	if invName == "" || gwName == "" {
		t.Fatalf("db 包条目名不合预期: %v", keysOf(dbEntries))
	}
	// 解压出来的必须是一个能打开、且数据完整的 SQLite 库
	assertSQLiteHasMarker(t, dbEntries[invName], "marker-inventory.db")

	// pvf 包
	pvfEntries := extractTarGz(t, byKind[backupKindPvf].Path)
	if len(pvfEntries) != 1 {
		t.Fatalf("pvf 包条目数 = %d，期望 1: %v", len(pvfEntries), keysOf(pvfEntries))
	}
	var pvfName string
	for n := range pvfEntries {
		pvfName = n
	}
	if !strings.HasPrefix(pvfName, "Script-") || !strings.HasSuffix(pvfName, ".pvf") {
		t.Errorf("pvf 条目名 = %s，期望 Script-<时间戳>.pvf", pvfName)
	}
	rawPvf, _ := os.ReadFile(f.files[TargetPvf])
	if !bytes.Equal(pvfEntries[pvfName], rawPvf) {
		t.Errorf("PVF 内容与源文件不一致")
	}

	// logs 包：网关与后台的 gateway.log 必须靠子目录区分开
	logEntries := extractTarGz(t, byKind[backupKindLogs].Path)
	for _, want := range []string{"gateway/gateway.log", "admin/gateway.log", "server/server.log"} {
		if _, ok := logEntries[want]; !ok {
			t.Errorf("logs 包缺少条目 %s，实得 %v", want, keysOf(logEntries))
		}
	}
	rawGwLog, _ := os.ReadFile(f.files[TargetGatewayLog])
	rawAdminLog, _ := os.ReadFile(f.files[TargetAdminLog])
	if !bytes.Equal(logEntries["gateway/gateway.log"], rawGwLog) {
		t.Errorf("网关日志内容不一致")
	}
	if !bytes.Equal(logEntries["admin/gateway.log"], rawAdminLog) {
		t.Errorf("后台日志内容不一致（两条同名日志有没有被子目录分开？）")
	}
}

// TestBackupLogsActuallyCompressed 日志必须真的被压缩（产物显著小于原始）。
//
// 用户要压缩包的动机就是省硬盘。如果哪天有人把 gzip 换成了只打包不压缩，
// 这条会立刻红 —— 而"文件生成了、名字也对"这类断言全绿。
func TestBackupLogsActuallyCompressed(t *testing.T) {
	f := newBackupFixture(t)
	res := f.mgr().BackupWith(BackupOptions{Targets: []string{TargetGatewayLog, TargetAdminLog, TargetServerLog}})
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}
	if len(res.Archives) != 1 || res.Archives[0].Kind != backupKindLogs {
		t.Fatalf("应只产出 logs 包，实得 %+v", res.Archives)
	}
	a := res.Archives[0]
	if a.RawBytes == 0 {
		t.Fatalf("RawBytes 没统计出来，压缩率没法验证")
	}
	if a.Size >= a.RawBytes {
		t.Fatalf("没压缩：原始 %d -> 产物 %d", a.RawBytes, a.Size)
	}
	if ratio := float64(a.Size) / float64(a.RawBytes); ratio > 0.3 {
		t.Errorf("压缩率太差（%.1f%%）：日志是高度重复的文本，压不到 30%% 以下是可疑的", ratio*100)
	}
}

// TestBackupExplicitLogsOnly 只勾日志 → 只出 logs 包，绝不顺手把库也备了。
func TestBackupExplicitLogsOnly(t *testing.T) {
	f := newBackupFixture(t)
	res := f.mgr().BackupWith(BackupOptions{Targets: []string{TargetGatewayLog, TargetServerLog}})
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}
	if len(res.Archives) != 1 || res.Archives[0].Kind != backupKindLogs {
		t.Fatalf("应只有 logs 包，实得 %+v", res.Archives)
	}
	names, _ := filepath.Glob(filepath.Join(f.backups, "*"))
	if len(names) != 1 {
		t.Fatalf("备份目录里应只有 1 个文件，实得 %v", names)
	}
}

// TestBackupDefaultTargetsSkipLogs 不传 targets（旧前端 / 向导第 8 步的空 body）
// → 仍是"两个库 + PVF"，**不把日志卷进来**。
//
// 这条是向后兼容的底线：向导那一步的语义就是"备份数据库"，
// 悄悄加上几百 MB 的日志会把那一步从几秒拖到几十秒。
func TestBackupDefaultTargetsSkipLogs(t *testing.T) {
	f := newBackupFixture(t)
	res := f.mgr().Backup()
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}
	kinds := map[string]bool{}
	for _, a := range res.Archives {
		kinds[a.Kind] = true
	}
	if !kinds[backupKindDB] || !kinds[backupKindPvf] {
		t.Fatalf("默认集应产出 db + pvf，实得 %+v", res.Archives)
	}
	if kinds[backupKindLogs] {
		t.Errorf("默认集不该把日志卷进来：%+v", res.Archives)
	}
	// 默认集允许缺文件（PVF 常没有）—— 换掉 PVF 后仍应成功
	if err := os.Remove(f.files[TargetPvf]); err != nil {
		t.Fatalf("删样本失败: %v", err)
	}
	res2 := f.mgr().Backup()
	if !res2.Ok {
		t.Fatalf("默认集缺 PVF 时应宽容通过，实得失败: %s", res2.Error)
	}
}

// TestBackupUnknownTargetRejected 未知 key 必须报错，**且一个包都不产**。
//
// 静默丢掉未知 key 的后果：前端改了 key 名而后端没跟上 → 运维勾了"网关日志"、
// 界面显示"备份完成"，实际那次备份里什么日志都没有。备份功能最坏的一类故障。
func TestBackupUnknownTargetRejected(t *testing.T) {
	f := newBackupFixture(t)
	res := f.mgr().BackupWith(BackupOptions{Targets: []string{TargetGameDB, "gateway.log"}})
	if res.Ok {
		t.Fatalf("未知 key 必须失败，实得 Ok=true")
	}
	if !strings.Contains(res.Error, "未知的备份目标") {
		t.Errorf("错误信息没说清是 key 未知: %s", res.Error)
	}
	if len(res.Archives) != 0 {
		t.Errorf("失败时不该产出任何包，实得 %+v", res.Archives)
	}
	if names, _ := filepath.Glob(filepath.Join(f.backups, "*")); len(names) != 0 {
		t.Errorf("失败时备份目录应为空，实得 %v", names)
	}
}

// TestBackupExplicitMissingTargetRejected 显式点名要一个不存在的文件 → 报错。
//
// 与默认集的宽容行为刻意不对称：你点名要它，静默跳过就是骗人。
func TestBackupExplicitMissingTargetRejected(t *testing.T) {
	f := newBackupFixture(t)
	if err := os.Remove(f.files[TargetPacketLog]); err != nil {
		t.Fatalf("删样本失败: %v", err)
	}
	res := f.mgr().BackupWith(BackupOptions{Targets: []string{TargetGatewayLog, TargetPacketLog}})
	if res.Ok {
		t.Fatalf("显式勾选的缺失目标必须失败，实得 Ok=true")
	}
	if !strings.Contains(res.Error, "封包日志") {
		t.Errorf("错误信息应指出是哪一项: %s", res.Error)
	}
}

// TestBackupStagedDbCopyNotLeftBehind db 的一致性副本用完必须删掉，
// 且**不能**以成品的样子留在备份目录里。
//
// 残留会污染"备份列表"与"保留 N 份"的计数（副本大小与成品相当，几百 MB）。
func TestBackupStagedDbCopyNotLeftBehind(t *testing.T) {
	f := newBackupFixture(t)
	res := f.mgr().BackupWith(BackupOptions{Targets: []string{TargetGameDB, TargetGatewayDB}})
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}
	names, _ := filepath.Glob(filepath.Join(f.backups, "*"))
	if len(names) != 1 {
		t.Fatalf("备份目录里应只剩 1 个成品包，实得 %v", names)
	}
	if strings.Contains(filepath.Base(names[0]), ".tmp") {
		t.Errorf("残留了临时文件: %s", names[0])
	}
	// 隐藏文件（点号开头）也不该留：它们不会被列表跳过规则之外的逻辑清掉
	hidden, _ := filepath.Glob(filepath.Join(f.backups, ".*"))
	for _, h := range hidden {
		if filepath.Base(h) != "." && filepath.Base(h) != ".." {
			t.Errorf("残留了隐藏临时文件: %s", h)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────
// 时间戳
// ────────────────────────────────────────────────────────────────────────

// TestBackupStampIsBeijing 文件名时间戳必须是北京时间，不是 UTC。
//
// 用例带反向断言（`!=` UTC 的格式化结果）：服务器时区改成 UTC 时，
// 光断言"等于北京时间"会因为进程恰好也在 UTC 而假绿。
func TestBackupStampIsBeijing(t *testing.T) {
	// UTC 2026-10-16 13:17:26 == 北京时间 2026-10-16 21:17:26
	instant := time.Date(2026, 10, 16, 13, 17, 26, 0, time.UTC)
	got := backupStamp(instant)
	want := "20261016-211726"
	if got != want {
		t.Fatalf("时间戳 = %s，期望 %s（北京时间）", got, want)
	}
	if utc := instant.UTC().Format("20060102-150405"); got == utc {
		t.Fatalf("时间戳跟着 UTC 走了（%s）—— 与服务器时区相关的假绿", utc)
	}
	// 跨零点：UTC 16:30 == 北京次日 00:30 —— 日期必须跟着变
	cross := time.Date(2026, 10, 16, 16, 30, 0, 0, time.UTC)
	if got := backupStamp(cross); got != "20261017-003000" {
		t.Errorf("跨零点时间戳 = %s，期望 20261017-003000", got)
	}
}

// TestBackupSameSecondDoesNotOverwrite 同一秒内连做两次备份，两份都要留下。
//
// 时间戳只到秒，同秒两次会算出同一个文件名 —— 直接写就是后者覆盖前者，
// 表现为"备份了两次、只留一份"，且毫无报错。对备份来说静默丢一份是最坏的故障。
func TestBackupSameSecondDoesNotOverwrite(t *testing.T) {
	f := newBackupFixture(t)
	for i := 0; i < 3; i++ {
		res := f.mgr().BackupWith(BackupOptions{Targets: []string{TargetGatewayLog}})
		if !res.Ok {
			t.Fatalf("第 %d 次备份失败: %s", i+1, res.Error)
		}
	}
	pkgs, _ := filepath.Glob(filepath.Join(f.backups, "logs-*.tar.gz"))
	if len(pkgs) != 3 {
		t.Fatalf("同秒三次备份应留下 3 个包，实得 %d: %v", len(pkgs), pkgs)
	}
	names := map[string]bool{}
	for _, p := range pkgs {
		names[filepath.Base(p)] = true
	}
	if len(names) != 3 {
		t.Errorf("包名出现重复（发生了覆盖）: %v", pkgs)
	}
}

// ────────────────────────────────────────────────────────────────────────
// 保留 N 份
// ────────────────────────────────────────────────────────────────────────

// TestPruneBackupsKeepsNewestPerKind 按类别保留最近 N 份，且**只动新命名族**。
//
// 三条边界：
//   - 同类别内按名字（= 时间戳）保留最新的；
//   - 别的类别一个都不动（否则 db 包会把 logs 包挤没）；
//   - 改造前散装的 inventory-*.db 绝不能被自动删（那是越权）。
func TestPruneBackupsKeepsNewestPerKind(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{
		"db-20261001-010101.tar.gz", "db-20261002-010101.tar.gz",
		"db-20261003-010101.tar.gz", "db-20261004-010101.tar.gz",
		"db-20261005-010101.tar.gz",
		"logs-20261001-010101.tar.gz", "logs-20261002-010101.tar.gz",
		"inventory-20261001-010101.db", "gateway-20261001-010101.db",
		"Script-20261001-010101.pvf",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatalf("造文件失败: %v", err)
		}
	}

	removed, err := pruneBackups(dir, backupKindDB, 2)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if removed != 3 {
		t.Errorf("应删掉 3 个旧 db 包，实得 %d", removed)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	sort.Strings(left)
	var got []string
	for _, p := range left {
		got = append(got, filepath.Base(p))
	}
	want := []string{
		"Script-20261001-010101.pvf",
		"db-20261004-010101.tar.gz",
		"db-20261005-010101.tar.gz",
		"gateway-20261001-010101.db",
		"inventory-20261001-010101.db",
		"logs-20261001-010101.tar.gz",
		"logs-20261002-010101.tar.gz",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("清理后剩余不符:\n实得 %v\n期望 %v", got, want)
	}
}

// TestPruneBackupsDisabledByDefault 保留数 <= 0 时一个都不删（默认关）。
func TestPruneBackupsDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 4; i++ {
		p := filepath.Join(dir, fmt.Sprintf("db-2026100%d-010101.tar.gz", i+1))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("造文件失败: %v", err)
		}
	}
	if n, err := pruneBackups(dir, backupKindDB, 0); n != 0 || err != nil {
		t.Fatalf("默认关时不该删任何东西，实得 n=%d err=%v", n, err)
	}
	var cfg config.ServerSection
	if cfg.BackupRetainCount != 0 {
		t.Fatalf("未配置时保留数应为 0（不清理），实得 %d", cfg.BackupRetainCount)
	}
}

// TestBackupRetainCountApplied 端到端：配了 BackupRetainCount 后真的会清理旧包。
func TestBackupRetainCountApplied(t *testing.T) {
	f := newBackupFixture(t)
	for i := 1; i <= 4; i++ {
		p := filepath.Join(f.backups, fmt.Sprintf("logs-2026100%d-010101.tar.gz", i))
		if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
			t.Fatalf("造旧包失败: %v", err)
		}
	}
	f.cfg.Server.BackupRetainCount = 2

	res := f.mgr().BackupWith(BackupOptions{Targets: []string{TargetGatewayLog}})
	if !res.Ok {
		t.Fatalf("备份失败: %s", res.Error)
	}
	logsPkgs, _ := filepath.Glob(filepath.Join(f.backups, "logs-*.tar.gz"))
	if len(logsPkgs) != 2 {
		t.Fatalf("保留 2 份后应剩 2 个 logs 包，实得 %d: %v", len(logsPkgs), logsPkgs)
	}
	// 保留的必须是本次这份 + 最新的一份旧包
	names := make([]string, 0, len(logsPkgs))
	for _, p := range logsPkgs {
		names = append(names, filepath.Base(p))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if names[0] != res.Archives[0].Name {
		t.Errorf("本次备份的包应被保留，实得最新的是 %s（本次是 %s）", names[0], res.Archives[0].Name)
	}
	if names[1] != "logs-20261004-010101.tar.gz" {
		t.Errorf("第二新的应是 logs-20261004，实得 %s", names[1])
	}
}

// ────────────────────────────────────────────────────────────────────────
// 辅助
// ────────────────────────────────────────────────────────────────────────

// extractLatestArchive 解开备份目录里最新一份 <kind>-*.tar.gz，返回 条目名 -> 内容。
//
// 2026-10-16 起产物进包了，老测试里"在备份目录里找 inventory-*.db"那套写法失效。
// 这类断言**绝不能删**（删了就等于放弃"备份有没有真的带上这份数据"的监督），
// 只能把"找散装文件"换成"去包里找条目"—— 语义完全等价。
func extractLatestArchive(t *testing.T, dir, kind string) map[string][]byte {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, kind+"-*.tar.gz"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("备份目录里没有 %s 包（dir=%s）", kind, dir)
	}
	sort.Strings(matches)
	return extractTarGz(t, matches[len(matches)-1])
}

// extractEntryBytes 从包里取出第一个符合前缀条件的条目内容。
func extractEntryBytes(t *testing.T, dir, kind, prefix string) []byte {
	t.Helper()
	entries := extractLatestArchive(t, dir, kind)
	var names []string
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			return entries[n]
		}
	}
	t.Fatalf("%s 包里没有以 %q 开头的条目，实得 %v", kind, prefix, names)
	return nil
}

// countAuditRowsInBytes 把一段库字节落成临时文件再数审计行数。
// 复用 countAuditRows（它只认路径），避免在两处各写一份 SQL。
func countAuditRowsInBytes(t *testing.T, lib []byte) int {
	t.Helper()
	p := filepath.Join(t.TempDir(), "probe.db")
	if err := os.WriteFile(p, lib, 0o644); err != nil {
		t.Fatalf("写出待检库失败: %v", err)
	}
	return countAuditRows(t, p)
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertSQLiteHasMarker 把 libBytes 当 SQLite 库打开，断言里面能查到 marker。
//
// 为什么必须真的打开：只比字节数的话，"复制了一个半写入状态的库"也照样通过。
func assertSQLiteHasMarker(t *testing.T, libBytes []byte, marker string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "probe.db")
	if err := os.WriteFile(p, libBytes, 0o644); err != nil {
		t.Fatalf("写出待检库失败: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+p+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("打开备份出来的库失败: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.QueryRow("SELECT count(*) FROM t WHERE v = ?", marker).Scan(&n); err != nil {
		t.Fatalf("备份出来的库查不到数据（副本不一致？）: %v", err)
	}
	if n != 1 {
		t.Fatalf("备份出来的库里 marker 行数 = %d，期望 1", n)
	}
}

// TestListBackupTargetsGameMySQLOnlyForS5A3 锁死「MySQL 目标只在 S5A3 下可用」。
//
// 这条防的是"两头都错"：
//   - S5A3 上没这个目标 ⇒ 默认备份备不到玩家数据（只剩网关库 + PVF）；
//   - S4A21 上有这个目标 ⇒ 点一下就去连不存在的 MySQL，备份直接报错。
func TestListBackupTargetsGameMySQLOnlyForS5A3(t *testing.T) {
	// S4A21：没有 GameDSN
	f := newBackupFixture(t)
	for _, it := range f.mgr().ListBackupTargets() {
		if it.Key == TargetGameMySQL && it.Exists {
			t.Fatal("S4A21 配置下 game_mysql 不该可用")
		}
	}

	// S5A3：配了 GameDSN
	f2 := newBackupFixture(t)
	f2.cfg.Database.GameDSN = "dnf:secret@tcp(127.0.0.1:3306)/dnf_local?parseTime=true"
	var found bool
	for _, it := range f2.mgr().ListBackupTargets() {
		if it.Key != TargetGameMySQL {
			continue
		}
		found = true
		if !it.Exists {
			t.Fatal("S5A3 配置下 game_mysql 应可用")
		}
		if !strings.Contains(it.Path, "mysql://") {
			t.Fatalf("game_mysql 的 Path 应显示成连接串，实得 %q", it.Path)
		}
		// ★ 密码绝不能出现在给前端的 Path 里。
		if strings.Contains(it.Path, "secret") {
			t.Fatalf("Path 里泄露了密码: %q", it.Path)
		}
	}
	if !found {
		t.Fatal("清单里没有 game_mysql")
	}

	// 默认备份集也要跟着换：S5A3 的默认集必须包含 game_mysql 且不含 game_db。
	def := f2.mgr().defaultBackupTargets()
	if !containsStr(def, TargetGameMySQL) || containsStr(def, TargetGameDB) {
		t.Fatalf("S5A3 默认备份集不对: %v", def)
	}
	// S4A21 保持原样。
	def21 := f.mgr().defaultBackupTargets()
	if !containsStr(def21, TargetGameDB) || containsStr(def21, TargetGameMySQL) {
		t.Fatalf("S4A21 默认备份集不该变: %v", def21)
	}
}
