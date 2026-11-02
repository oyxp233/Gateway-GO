package service

// ============================================================================
// S5A3 游戏库备份（MySQL 在线导出，2026-11-01）
//
// 背景：备份模块是给 S4A21 写的 —— 它的游戏库是本地 SQLite（Database.GamePath），
// 直接 cp 文件就行。S5A3 的游戏数据在**服务端自己的 MySQL**（dnf_local）里，
// GamePath 必须是空串（网关那条硬规则：GamePath 非空会抢在 GameDSN 前面被选成
// "游戏库"），于是「游戏库」这个备份目标在 S5A3 下永远是"文件不存在"，
// 备份出来只有网关库和 PVF —— 玩家数据一份都没备到。
//
// 做法：调 mysqldump 导出一个 .sql 到备份目录下的临时文件，当成一个普通文件目标
// 打进同一个 db-<时间戳>.tar.gz，打完立刻删临时文件。
//
// ★ 为什么不直接 `mysqldump > 最终包`：保留策略按 db-*.tar.gz 命名族清理，
//   裸 .sql 不在清理范围里，会无限堆积。
//
// ★ 密码不落命令行：mysqldump 的 -p<密码> 会出现在 `ps` 里，同机任何用户都能看到。
//   这里用 MYSQL_PWD 环境变量传给子进程（只在它自己的 env 里）。
// ============================================================================

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"s4a21-gateway/pkg/utils"
)

// mysqlDumpTimeout 单次导出的上限。几百 MB 的库在机械盘上可能要好几分钟，
// 给 30 分钟；超时就报错，不让后台请求无限挂着。
const mysqlDumpTimeout = 30 * time.Minute

// s5a3DSNPattern 拆 GameDSN：user:pass@tcp(host:port)/db?params
var s5a3DSNPattern = regexp.MustCompile(`^([^:@]+):([^@]*)@tcp\(([^)]+)\)/([^?]+)`)

// s5a3MySQLParams 从 GameDSN 解出的连接参数。
type s5a3MySQLParams struct {
	User string
	Pass string
	Host string
	Port string
	DB   string
}

// parseS5A3DSN 解析 GameDSN；格式不认识时返回 false。
func parseS5A3DSN(dsn string) (s5a3MySQLParams, bool) {
	m := s5a3DSNPattern.FindStringSubmatch(strings.TrimSpace(dsn))
	if m == nil {
		return s5a3MySQLParams{}, false
	}
	host, port := m[3], "3306"
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host, port = host[:i], host[i+1:]
	}
	return s5a3MySQLParams{User: m[1], Pass: m[2], Host: host, Port: port, DB: m[4]}, true
}

// isS5A3Game 判断本机游戏库是不是 S5A3 的 MySQL。
//
// 判据与 database.GameBackend() 一致：**配了 GameDSN 就是 S5A3**。
// 这里不直接问 db 是为了让 ServerManager 保持不依赖数据库句柄
// （备份模块现在只认 config，改成依赖 db 会牵出一串初始化顺序问题）。
func (s *ServerManager) isS5A3Game() bool {
	return s != nil && s.config != nil && strings.TrimSpace(s.config.Database.GameDSN) != ""
}

// gameMySQLDumpPath 是导出文件的固定落点。
//
// 用固定名而不是带时间戳：它只是打包前的中间产物，同一时刻只会有一次备份在跑
// （备份按钮本身不是高频操作），固定名还能在异常退出后覆盖掉上次的残留。
func (s *ServerManager) gameMySQLDumpPath() string {
	return filepath.Join(s.config.Server.BackupDir, ".gamedb-dump.sql")
}

// dumpS5A3GameMySQL 把 S5A3 游戏库导出到 dst。
//
// 返回导出的字节数。失败时把 mysqldump 的 stderr 带出来 —— 最常见的是
// "mysqldump: command not found"（没装 mysql-client）和 Access denied（DSN 不对）。
func (s *ServerManager) dumpS5A3GameMySQL(dst string) (int64, error) {
	params, ok := parseS5A3DSN(s.config.Database.GameDSN)
	if !ok {
		return 0, fmt.Errorf("GameDSN 格式无法解析（期望 user:pass@tcp(host:port)/db）")
	}
	if err := utils.MkdirAll(filepath.Dir(dst)); err != nil {
		return 0, err
	}
	_ = os.Remove(dst)

	ctx, cancel := context.WithTimeout(context.Background(), mysqlDumpTimeout)
	defer cancel()

	// --single-transaction：InnoDB 下拿到一致性快照且不锁表，
	//   玩家正在打游戏时备份不会把他们卡住（这是在线备份的前提）。
	// --no-tablespaces：MySQL 8 上没这参数会因为 PROCESS 权限不足直接失败。
	// --routines/--events：S5A3 的存储过程与事件也要备（漏了恢复后行为会变）。
	cmd := exec.CommandContext(ctx, "mysqldump",
		"--single-transaction",
		"--quick",
		"--no-tablespaces",
		"--routines",
		"--events",
		"--default-character-set=utf8mb4",
		"-h", params.Host,
		"-P", params.Port,
		"-u", params.User,
		params.DB,
	)
	// ★ 密码走环境变量，不上命令行（ps 可见）。
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+params.Pass)

	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	cmd.Stdout = out

	var stderr strings.Builder
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		_ = os.Remove(dst)
		if ctx.Err() != nil {
			return 0, fmt.Errorf("mysqldump 超时（%s）", mysqlDumpTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return 0, fmt.Errorf("mysqldump 失败: %s", msg)
	}

	fi, err := os.Stat(dst)
	if err != nil {
		return 0, err
	}
	if fi.Size() == 0 {
		_ = os.Remove(dst)
		return 0, fmt.Errorf("mysqldump 产出为空文件（库名或权限有问题？）")
	}
	return fi.Size(), nil
}
