package service

//
// 备份：可勾选目标 + 分类 tar.gz 打包（2026-10-16 升级）
//
// 改造前的形态：一次备份固定把「游戏库 / 网关库 / 服务端 PVF」三份文件**原样**落进
// 备份目录，不压缩、不能挑。161 上 /opt/backups 因此堆到 676MB（单份游戏库备份就
// 590MB），而且**日志从来不在备份里** —— 排障要看的历史日志全靠服务器上的活文件，
// 一旦被覆盖就找不回来。
//
// 改造后的形态：
//   1. 后台列出「可备份目标」（两个库 + PVF + 网关日志/error 日志 + 后台日志 +
//      服务端日志/封包日志），运维按需勾选；
//   2. 勾选的目标按**类别**打成三个包：db / pvf / logs，各一个 .tar.gz；
//   3. 文件名用**北京时间**（运维按本地时钟找备份，不用心算 8 小时）；
//   4. 可选「只保留最近 N 份」（默认关，见 Server.BackupRetainCount）。
//
// 为什么按类别分包而不是「一次备份一个大包」：游戏库一个就 590MB，压完仍有几百 MB。
// 只想翻日志时不必把整个大包解开；只想恢复库时也不必先腾出日志的空间。
// 类别各自独立成包后，"保留最近 N 份"也能按类别分别计数，不会互相挤掉。
//

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"s4a21-gateway/pkg/utils"
)

// 备份目标的三个类别，同时也是产出包名的前缀。
const (
	backupKindDB   = "db"
	backupKindPvf  = "pvf"
	backupKindLogs = "logs"
)

// backupKindOrder 决定产出的顺序（库最先 —— 它是最要紧的数据，
// 万一后面 PVF/日志打包失败，至少库已经落盘了）。
var backupKindOrder = []string{backupKindDB, backupKindPvf, backupKindLogs}

// 目标 key。前端按这些 key 勾选，后端按它们解析路径 ——
// 两侧共用同一份字符串，改名必须两边一起改。
const (
	TargetGameDB        = "game_db"
	TargetGatewayDB     = "gateway_db"
	TargetPvf           = "pvf"
	TargetGatewayLog    = "gateway_log"
	TargetGatewayErrLog = "gateway_error_log"
	TargetAdminLog      = "admin_log"
	TargetAdminErrLog   = "admin_error_log"
	TargetServerLog     = "server_log"
	TargetPacketLog     = "packet_log"
)

// backupTargetDef 一个静态目标定义。
type backupTargetDef struct {
	key   string
	label string
	kind  string
	// entryName 是打进 tar.gz 后的包内相对路径。
	//
	// 刻意带一层子目录（gateway/ admin/ server/）：网关与后台的日志都叫
	// gateway.log / error.log，平铺会互相覆盖（tar 允许同名条目，但解压时
	// 后者把前者盖掉 —— 那正是"备份了却恢复不出来"的经典形态）。
	entryName string
}

var backupTargetDefs = []backupTargetDef{
	{TargetGameDB, "游戏库存库（inventory.db）", backupKindDB, ""},
	{TargetGatewayDB, "网关库（gateway.db）", backupKindDB, ""},
	{TargetPvf, "服务端 PVF（Script.pvf）", backupKindPvf, ""},
	{TargetGatewayLog, "网关日志", backupKindLogs, "gateway/gateway.log"},
	{TargetGatewayErrLog, "网关错误日志", backupKindLogs, "gateway/error.log"},
	{TargetAdminLog, "管理后台日志", backupKindLogs, "admin/gateway.log"},
	{TargetAdminErrLog, "管理后台错误日志", backupKindLogs, "admin/error.log"},
	{TargetServerLog, "服务端日志（server.log）", backupKindLogs, "server/server.log"},
	{TargetPacketLog, "服务端封包日志（packet.log）", backupKindLogs, "server/packet.log"},
}

// backupDefaultTargets 未显式指定目标时的默认集合 ——
// 就是改造前那一批（两个库 + PVF）。
//
// 为什么保留默认集：现有「更新流程向导 → 备份数据库」这一步发的还是空 body，
// 它的语义就是"备份数据库"，不该因为这次升级悄悄把日志也卷进来（日志几百 MB
// 的文本，会让这一步从几秒变成几十秒）。日志必须**显式勾选**才备。
var backupDefaultTargets = []string{TargetGameDB, TargetGatewayDB, TargetPvf}

// BackupTarget 一个可备份目标（给后台列表用）。
type BackupTarget struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	// Exists=false 时 Size/ModifiedAt 无意义（0）。后台据此把行置灰，
	// 而不是让运维勾一个"看起来能备"实际不存在的文件。
	Exists     bool   `json:"exists"`
	Size       int64  `json:"size"`
	ModifiedAt int64  `json:"modified_at"`
	EntryName  string `json:"entry_name"`
}

// BackupOptions 备份选项。
type BackupOptions struct {
	// Targets 为空 = 用默认集（两个库 + PVF），保持旧按钮的行为。
	Targets []string `json:"targets"`
}

// BackupArchive 产出的一个压缩包。
type BackupArchive struct {
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Size      int64    `json:"size"`       // 压缩包字节数
	RawBytes  int64    `json:"raw_bytes"`  // 打包前原始字节数（算压缩率用）
	Entries   []string `json:"entries"`    // 包内条目名
	PrunedOld int      `json:"pruned_old"` // 本次因保留策略删掉的旧包数
}

// ListBackupTargets 列出所有可备份目标及其现状（只读，不写盘）。
//
// 目标**不存在也要列出来**：后台要显示"这一项现在没有文件"，
// 否则运维只会看到勾选项变少了，不知道该去查哪条配置路径。
func (s *ServerManager) ListBackupTargets() []BackupTarget {
	out := make([]BackupTarget, 0, len(backupTargetDefs))
	for _, d := range backupTargetDefs {
		t := BackupTarget{Key: d.key, Label: d.label, Kind: d.kind, EntryName: d.entryName}
		path := s.resolveBackupTargetPath(d.key)
		t.Path = path
		if path != "" {
			if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
				t.Exists = true
				t.Size = fi.Size()
				t.ModifiedAt = fi.ModTime().Unix()
			}
		}
		out = append(out, t)
	}
	return out
}

// resolveBackupTargetPath 解析单个目标的绝对路径。解析不出来返回 ""。
func (s *ServerManager) resolveBackupTargetPath(key string) string {
	switch key {
	case TargetGameDB:
		return s.config.Database.GamePath
	case TargetGatewayDB:
		return s.config.Database.Path
	case TargetPvf:
		// PVF 的解析本来就会在拿不到时返回错误；列表里按"没这个文件"展示。
		p, err := s.resolvePvfPath()
		if err != nil {
			return ""
		}
		return p
	case TargetGatewayLog, TargetGatewayErrLog:
		dir := resolveGatewayLogDir()
		name := "gateway.log"
		if key == TargetGatewayErrLog {
			name = "error.log"
		}
		return filepath.Join(dir, name)
	case TargetAdminLog, TargetAdminErrLog:
		dir := resolveAdminLogDir()
		name := "gateway.log"
		if key == TargetAdminErrLog {
			name = "error.log"
		}
		return filepath.Join(dir, name)
	case TargetServerLog:
		return s.resolveLogPath("server")
	case TargetPacketLog:
		return s.resolveLogPath("packet")
	}
	return ""
}

// resolveGatewayLogDir 定位网关日志目录。
//
// 三条候选，按顺序取第一个存在的：
//  1. 进程工作目录下的 logs/ —— 与 GatewayManager 完全同一口径（它构造时用的就是
//     filepath.Join(workDir, "logs")），而 gateway 与 gateway-admin 两个 unit 的
//     systemd WorkingDirectory 都是 /opt/gateway（161 实测），所以后台进程用相对
//     路径就能取到网关日志，不必再引一份配置；
//  2. <可执行文件所在目录>/logs —— 二进制就装在网关目录里，cwd 被改动时也找得到；
//  3. /opt/gateway/logs —— 兜底。
//
// 全都不存在时返回第 1 条：让目标行的 Exists=false 把"找不到"显示出来，
// 而不是在列表里凭空少一行。
func resolveGatewayLogDir() string {
	fallback := filepath.Join("logs")
	cands := []string{fallback}
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(exe), "logs"))
	}
	cands = append(cands, "/opt/gateway/logs")
	for _, c := range cands {
		if utils.DirExists(c) {
			return c
		}
	}
	return fallback
}

// resolveAdminLogDir 定位管理后台日志目录（与 logs/ 同级的 logs-admin/）。
//
// 不单独做一套候选：它和网关日志目录必然同级（161 实测 /opt/gateway/logs 与
// /opt/gateway/logs-admin），由网关目录推导即可，少一处漂移。
func resolveAdminLogDir() string {
	return filepath.Join(filepath.Dir(resolveGatewayLogDir()), "logs-admin")
}

// backupLocation 备份文件名用的时区 —— 固定北京时间。
//
// 为什么写死：改造前用 UTC，161 上文件名比本地时间早 8 小时（22:04 的备份叫
// ...140425），运维按本地时钟找备份每次都要心算。而服务器时区并不统一
// （161 是 Asia/Shanghai、202 是 UTC），用 time.Local 等于把命名口径交给部署环境。
//
// LoadLocation 失败（精简镜像缺 tzdata）时退回固定 +8 偏移 —— 结果一致，
// 只是没有 DST 概念（中国不用 DST，所以无差别）。
func backupLocation() *time.Location {
	if loc, err := time.LoadLocation("Asia/Shanghai"); err == nil {
		return loc
	}
	return time.FixedZone("CST", 8*60*60)
}

// backupStamp 生成文件名时间戳（北京时间 20060102-150405）。
func backupStamp(t time.Time) string {
	return t.In(backupLocation()).Format("20060102-150405")
}

// resolvedTarget 一个已解析、确认要备份的目标。
type resolvedTarget struct {
	def  backupTargetDef
	path string
	size int64
}

// BackupWith 按勾选的目标备份，产出分类 tar.gz。
//
// 与旧 Backup() 的关系：Backup() 等价于 BackupWith(BackupOptions{})，
// 走默认目标集。详见文件头注释。
func (s *ServerManager) BackupWith(opts BackupOptions) *BackupResult {
	dir := s.config.Server.BackupDir
	if dir == "" {
		return &BackupResult{Ok: false, Error: "未配置备份目录 BackupDir"}
	}
	if err := utils.MkdirAll(dir); err != nil {
		return &BackupResult{Ok: false, Error: err.Error()}
	}

	explicit := len(opts.Targets) > 0
	selected, err := s.resolveSelected(opts.Targets)
	if err != nil {
		return &BackupResult{Ok: false, Error: err.Error()}
	}

	stamp := backupStamp(time.Now())
	result := &BackupResult{Ok: true}
	var archives []BackupArchive
	var errs []string
	gameBackedUp := false

	// 按类别产出。故意不并发：同一块盘上三个大包并行写只会互相抢 IO，
	// 而且是"库先落盘"这条顺序保证的前提。
	for _, kind := range backupKindOrder {
		var items []resolvedTarget
		for _, it := range selected {
			if it.def.kind == kind {
				items = append(items, it)
			}
		}
		if len(items) == 0 {
			continue
		}

		name := fmt.Sprintf("%s-%s.tar.gz", kind, stamp)
		// 同一秒第二次备份时换名（-2/-3），绝不覆盖刚产出的那份。
		dst := uniqueArchivePath(dir, name)
		name = filepath.Base(dst)
		// 先落 .tmp 再改名：备份列表会跳过 .tmp 后缀，
		// 免得"正在打包"的半截文件被当成一份可用备份列出来。
		tmp := dst + ".tmp"
		_ = os.Remove(tmp)

		arch, buildErr := s.buildArchive(tmp, kind, name, items, stamp)
		if buildErr != nil {
			_ = os.Remove(tmp)
			// 单个类别失败不回滚已产出的其他类别 —— 库已经备好了就该留着，
			// 但必须把失败报出来（Ok=false）。
			errs = append(errs, fmt.Sprintf("%s: %v", kind, buildErr))
			continue
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			errs = append(errs, fmt.Sprintf("%s: 归档落盘失败: %v", kind, err))
			continue
		}
		arch.Path = dst
		archives = append(archives, arch)
		if kind == backupKindDB {
			for _, it := range items {
				if it.def.key == TargetGameDB {
					gameBackedUp = true
				}
			}
		}
		if s.logger != nil {
			s.logger.Info(fmt.Sprintf("[备份] %s -> %s（%s，%d 项，原始 %s）",
				kind, name, humanBytes(arch.Size), len(items), humanBytes(arch.RawBytes)))
		}
	}

	result.Archives = archives
	result.Selected = make([]string, 0, len(selected))
	for _, it := range selected {
		result.Selected = append(result.Selected, it.def.key)
	}

	// 一个包都没产出来：要么没勾东西，要么全失败了。
	if len(archives) == 0 && len(errs) == 0 {
		if explicit {
			return &BackupResult{Ok: false, Error: "勾选的目标里没有可备份的文件"}
		}
		return &BackupResult{Ok: false, Error: "没有找到可备份的目标文件（请检查 GamePath / Path / PvfPath 配置）"}
	}

	// 保留策略：只清理本次产出涉及的类别，各留最近 N 份。
	if keep := s.config.Server.BackupRetainCount; keep > 0 {
		for _, kind := range backupKindOrder {
			var idx = -1
			for i, a := range archives {
				if a.Kind == kind {
					idx = i
					break
				}
			}
			if idx < 0 {
				continue
			}
			removed, perr := pruneBackups(dir, kind, keep)
			if perr != nil {
				// 清理失败**不算备份失败**（备份本身已经落盘），但必须让人看见。
				result.RetainError = append(result.RetainError, perr.Error())
				if s.logger != nil {
					s.logger.Warn(fmt.Sprintf("[备份] 旧备份清理失败（%s）: %v", kind, perr))
				}
				continue
			}
			archives[idx].PrunedOld = removed
			if removed > 0 && s.logger != nil {
				s.logger.Info(fmt.Sprintf("[备份] 保留最近 %d 份：%s 类清理了 %d 个旧包", keep, kind, removed))
			}
		}
	}

	if len(errs) > 0 {
		if s.logger != nil {
			s.logger.Error(fmt.Sprintf("[备份] 部分失败: %v，成功 %d 个包", errs, len(archives)))
		}
		result.Ok = false
		result.Error = strings.Join(errs, "; ")
		// 失败时也要走下面的审计清理判断吗？不要 —— 审计清理的前提是"游戏库
		// 已经进备份"，库没备成就绝不能清线上数据。gameBackedUp 此时必为 false。
		return result
	}

	// 审计日志清理 + 库文件收缩（只在游戏库**确实进了压缩包**之后做）。
	// 顺序不能反：清掉之后这些日志就只存在于备份里了。
	if !s.config.Server.PurgeAuditLogEnabled() {
		result.AuditPurgeSkipped = "未启用（Server.BackupPurgeAuditLog=false）"
	} else if !gameBackedUp {
		if explicit {
			result.AuditPurgeSkipped = "本次未勾选游戏库，为避免丢数据跳过清理"
		} else {
			result.AuditPurgeSkipped = "游戏库未备份（GamePath 未配置或文件不存在），为避免丢数据跳过清理"
		}
	} else {
		rows, before, after, perr := purgeGameAuditLog(s.config.Database.GamePath, s.logger)
		result.AuditPurgedRows = rows
		result.GameDbBytesBefore = before
		result.GameDbBytesAfter = after
		if perr != nil {
			result.AuditPurgeError = perr.Error()
			if s.logger != nil {
				s.logger.Warn(fmt.Sprintf("[备份] 审计日志清理告警: %v", perr))
			}
		} else if rows > 0 && s.logger != nil {
			s.logger.Info(fmt.Sprintf("[备份] 已清理审计日志 %d 条，游戏库 %.1fMB -> %.1fMB",
				rows, float64(before)/1048576.0, float64(after)/1048576.0))
		}
	}

	if s.logger != nil {
		s.logger.Info(fmt.Sprintf("[备份] 完成，共 %d 个包 -> %s", len(archives), dir))
	}
	return result
}

// resolveSelected 把前端传来的 key 列表解析成目标。
//
// 两条容易踩的口径：
//   - **空列表 = 默认集**，不是"什么都不备"（旧前端与向导步骤发的是空 body）；
//   - **未知 key 要报错**，不能静默丢掉 —— 否则前端改了 key 名、后端还是老的那套，
//     运维勾了"网关日志"结果什么都没备，界面还显示成功。这是备份功能最坏的一类故障。
//
// 默认集里缺文件是**允许**的（PVF 常常没有）：沿用改造前的宽容行为，只记 ERROR 日志。
// 显式勾选却缺文件则报错 —— 你明明点名要它，静默跳过就是骗人。
func (s *ServerManager) resolveSelected(keys []string) ([]resolvedTarget, error) {
	if len(keys) == 0 {
		keys = backupDefaultTargets
		// 默认集走宽容模式，见下方 missing 处理
	}
	explicit := true
	if len(keys) == len(backupDefaultTargets) && sameStringSet(keys, backupDefaultTargets) {
		explicit = false
	}

	var out []resolvedTarget
	for _, k := range keys {
		var def *backupTargetDef
		for i := range backupTargetDefs {
			if backupTargetDefs[i].key == k {
				def = &backupTargetDefs[i]
				break
			}
		}
		if def == nil {
			return nil, fmt.Errorf("未知的备份目标: %s", k)
		}
		path := s.resolveBackupTargetPath(def.key)
		if path == "" || !utils.FileExists(path) {
			msg := fmt.Sprintf("%s 的路径解析不到或文件不存在", def.label)
			if def.key == TargetPvf {
				if p, err := s.resolvePvfPath(); err != nil {
					msg = fmt.Sprintf("跳过 PVF：%v", err)
				} else {
					msg = fmt.Sprintf("跳过 PVF：解析到的路径上还没有文件（%s）", p)
				}
			}
			if s.logger != nil {
				s.logger.Error(fmt.Sprintf("[备份] %s", msg))
			}
			if explicit {
				return nil, fmt.Errorf("%s（%s）", def.label, msg)
			}
			continue
		}
		fi, err := os.Stat(path)
		if err != nil {
			if s.logger != nil {
				s.logger.Error(fmt.Sprintf("[备份] 跳过 %s：%v", def.label, err))
			}
			if explicit {
				return nil, fmt.Errorf("%s：%v", def.label, err)
			}
			continue
		}
		out = append(out, resolvedTarget{def: *def, path: path, size: fi.Size()})
	}
	return out, nil
}

// buildArchive 把一个类别的目标打成 tar.gz。
//
// 数据库的特殊处理：不能直接把**正在写入**的 .db 拖进包里 ——
// 服务端在跑，WAL 里还有没并回主库的页，复制出来的副本会停在半写入状态。
// 所以 db 类先走 backupSqliteFile（VACUUM INTO，或者 checkpoint 后复制）拿到一份
// 一致性副本，再把副本打进包，最后删掉副本。
func (s *ServerManager) buildArchive(dst, kind, name string, items []resolvedTarget, stamp string) (BackupArchive, error) {
	arch := BackupArchive{Kind: kind, Name: name}

	f, err := os.Create(dst)
	if err != nil {
		return arch, fmt.Errorf("创建归档失败: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	var temps []string
	defer func() {
		// db 的一致性副本是临时的，用完就删（不管成功失败）。
		for _, p := range temps {
			_ = os.Remove(p)
		}
	}()

	dir := s.config.Server.BackupDir
	for _, it := range items {
		src := it.path
		if it.def.kind == backupKindDB {
			tmp, err := stageSQLiteCopy(dir, it.def.key, src, stamp)
			if err != nil {
				return arch, err
			}
			temps = append(temps, tmp)
			src = tmp
		}

		fi, err := os.Stat(src)
		if err != nil {
			return arch, fmt.Errorf("%s 读取失败: %w", it.def.label, err)
		}
		entryName := tarEntryName(it.def, src, stamp)
		if err := tw.WriteHeader(&tar.Header{
			Name:    entryName,
			Mode:    0o644,
			Size:    fi.Size(),
			ModTime: fi.ModTime(),
		}); err != nil {
			return arch, fmt.Errorf("%s 写归档头失败: %w", it.def.label, err)
		}
		srcFile, err := os.Open(src)
		if err != nil {
			return arch, fmt.Errorf("%s 打开失败: %w", it.def.label, err)
		}
		n, err := io.Copy(tw, srcFile)
		srcFile.Close()
		if err != nil {
			return arch, fmt.Errorf("%s 写入归档失败: %w", it.def.label, err)
		}
		arch.RawBytes += n
		arch.Entries = append(arch.Entries, entryName)
	}

	// 顺序要紧：tar 的结尾块（两个 512B 全零）与 gzip 的 CRC/长度尾部
	// 必须由 Close 写出去。少了它们，解压工具会报"unexpected EOF"，
	// 而文件看起来是完整的 —— 那种备份是废的。
	if err := tw.Close(); err != nil {
		return arch, fmt.Errorf("归档收尾失败: %w", err)
	}
	if err := gz.Close(); err != nil {
		return arch, fmt.Errorf("压缩收尾失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		return arch, fmt.Errorf("归档落盘失败: %w", err)
	}
	if fi, err := f.Stat(); err == nil {
		arch.Size = fi.Size()
	}
	return arch, nil
}

// stageSQLiteCopy 把一个 SQLite 库做成一致性副本，返回副本路径。
//
// 副本落在备份目录下的**点号开头**临时文件：ListBackups 会跳过 . 开头的文件，
// 所以打包过程中没人会把它当成一份备份。
func stageSQLiteCopy(dir, key, src, stamp string) (string, error) {
	base := "inventory"
	if key == TargetGatewayDB {
		base = "gateway"
	}
	tmp, err := os.CreateTemp(dir, fmt.Sprintf(".%s-%s-*.tmp", base, stamp))
	if err != nil {
		return "", fmt.Errorf("创建临时副本失败: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	if err := backupSqliteFile(src, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("%s 一致性副本失败: %w", src, err)
	}
	return tmpPath, nil
}

// tarEntryName 决定包内条目名。
//
// 日志用 def.entryName 里那层子目录（gateway/ admin/ server/）避免同名覆盖；
// 库与 PVF 沿用改造前的命名（inventory-<时间戳>.db 等），运维认得。
func tarEntryName(def backupTargetDef, src, stamp string) string {
	if def.entryName != "" {
		return def.entryName
	}
	switch def.key {
	case TargetGameDB:
		return fmt.Sprintf("inventory-%s.db", stamp)
	case TargetGatewayDB:
		return fmt.Sprintf("gateway-%s.db", stamp)
	case TargetPvf:
		return fmt.Sprintf("Script-%s.pvf", stamp)
	}
	return filepath.Base(src)
}

// uniqueArchivePath 返回一个**当前不存在**的归档路径，必要时加 -2 / -3 后缀。
//
// 为什么必须有这一步：文件名时间戳只到秒，同一秒内跑两次备份（人肉连点、
// 向导与按钮各触发一次）会得到同一个名字 —— 后者直接把前者覆盖掉，
// 于是"备份了两次、实际只留下一份"，而且**没有任何报错**。
// 对备份功能来说，静默丢一份比报错严重得多。
func uniqueArchivePath(dir, name string) string {
	const ext = ".tar.gz"
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	base := strings.TrimSuffix(name, ext)
	for i := 2; i < 1000; i++ {
		cand := filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
	// 到这一步说明目录里有上千个同名族的文件 —— 不猜了，交给 rename 报错。
	return p
}

// pruneBackups 保留 dir 下某类别最近的 keep 个 .tar.gz，删掉更旧的。
//
// 只认「<kind>-<时间戳>.tar.gz」这一个命名族：历史上散装的
// inventory-*.db / gateway-*.db / Script-*.pvf **一个都不删** ——
// 那是改造前的产物，没有经过"保留 N 份"这道同意，自动删掉属于越权。
// 排序按**文件名**（时间戳零填充、字典序 == 时间序），比 mtime 更稳：
// 复制/恢复操作会改 mtime，但改不了名字里的时间。
func pruneBackups(dir, kind string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	prefix := kind + "-"
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ".tar.gz") {
			continue
		}
		names = append(names, n)
	}
	if len(names) <= keep {
		return 0, nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	removed := 0
	for _, n := range names[keep:] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			return removed, fmt.Errorf("删除旧备份 %s 失败: %w", n, err)
		}
		removed++
	}
	return removed, nil
}

// sameStringSet 判两个字符串列表是不是同一集合（忽略顺序、忽略重复）。
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	for _, v := range seen {
		if v != 0 {
			return false
		}
	}
	return true
}

// humanBytes 给人看的体积。service 包里已有若干处拼 "%.1fMB"，
// 这里单独写一个，避免为了一句日志去动别的文件。
func humanBytes(n int64) string {
	switch {
	case n >= 1024*1024*1024:
		return fmt.Sprintf("%.2fGB", float64(n)/1073741824.0)
	case n >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(n)/1048576.0)
	case n >= 1024:
		return fmt.Sprintf("%.1fKB", float64(n)/1024.0)
	}
	return fmt.Sprintf("%dB", n)
}
