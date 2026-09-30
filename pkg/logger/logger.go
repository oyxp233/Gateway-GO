package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level 定义日志级别。
type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
)

func (l Level) String() string {
	switch l {
	case Debug:
		return "Debug"
	case Info:
		return "Info"
	case Warn:
		return "Warning"
	case Error:
		return "Error"
	case Fatal:
		return "Fatal"
	default:
		return "Unknown"
	}
}

// ParseLevel 将字符串转换为日志级别。
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(s) {
	case "debug":
		return Debug, true
	case "information", "info":
		return Info, true
	case "warning", "warn":
		return Warn, true
	case "error":
		return Error, true
	case "fatal":
		return Fatal, true
	}
	return Info, false
}

// FileLogger 写入文件的标准日志记录器。
type FileLogger struct {
	mu        sync.Mutex
	dir       string
	level     Level
	infoFile  *os.File
	errorFile *os.File
	journal   *os.File
}

// NewFileLogger 创建文件日志记录器，日志写入 dir 目录下的 gateway.log 和 error.log。
func NewFileLogger(dir string, level Level) (*FileLogger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create log dir %s: %w", dir, err)
	}

	infoPath := filepath.Join(dir, "gateway.log")
	errorPath := filepath.Join(dir, "error.log")

	infoFile, err := os.OpenFile(infoPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open info log %s: %w", infoPath, err)
	}

	errorFile, err := os.OpenFile(errorPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open error log %s: %w", errorPath, err)
	}

	return &FileLogger{
		dir:       dir,
		level:     level,
		infoFile:  infoFile,
		errorFile: errorFile,
	}, nil
}

func (l *FileLogger) Log(level Level, msg string) {
	if level < l.level {
		return
	}

	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05.000"), level.String(), msg)

	l.mu.Lock()
	defer l.mu.Unlock()

	if level >= Warn {
		l.errorFile.WriteString(line)
	}

	if level == Fatal {
		l.errorFile.WriteString(line)
		l.infoFile.WriteString(line)
		return
	}

	l.infoFile.WriteString(line)
}

// Debug 写入 Debug 级别日志。
func (l *FileLogger) Debug(msg string) { l.Log(Debug, msg) }

// Info 写入 Info 级别日志。
func (l *FileLogger) Info(msg string) { l.Log(Info, msg) }

// Warn 写入 Warning 级别日志。
func (l *FileLogger) Warn(msg string) { l.Log(Warn, msg) }

// Error 写入 Error 级别日志。
func (l *FileLogger) Error(msg string) { l.Log(Error, msg) }

// Fatal 写入 Fatal 级别日志。
func (l *FileLogger) Fatal(msg string) { l.Log(Fatal, msg) }

// Close 关闭日志文件。
func (l *FileLogger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.infoFile != nil {
		l.infoFile.Close()
	}
	if l.errorFile != nil {
		l.errorFile.Close()
	}
}

// ConsoleLogger 同时写入控制台和文件的日志记录器。
type ConsoleLogger struct {
	fileLogger *FileLogger
}

// NewConsoleLogger 创建同时写入控制台和文件的日志记录器。
func NewConsoleLogger(dir string, level Level) (*ConsoleLogger, error) {
	fl, err := NewFileLogger(dir, level)
	if err != nil {
		return nil, err
	}
	return &ConsoleLogger{fileLogger: fl}, nil
}

func (l *ConsoleLogger) Log(level Level, msg string) {
	// 同时输出到控制台和文件
	prefix := ""
	if level == Fatal {
		prefix = "[Fatal] "
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg)
	l.fileLogger.Log(level, msg)
}

// Debug 写入 Debug 级别日志。
func (l *ConsoleLogger) Debug(msg string) { l.Log(Debug, msg) }

// Info 写入 Info 级别日志。
func (l *ConsoleLogger) Info(msg string) { l.Log(Info, msg) }

// Warn 写入 Warning 级别日志。
func (l *ConsoleLogger) Warn(msg string) { l.Log(Warn, msg) }

// Error 写入 Error 级别日志。
func (l *ConsoleLogger) Error(msg string) { l.Log(Error, msg) }

// Fatal 写入 Fatal 级别日志。
func (l *ConsoleLogger) Fatal(msg string) { l.Log(Fatal, msg) }

// Close 关闭日志。
func (l *ConsoleLogger) Close() {
	l.fileLogger.Close()
}

// Dir 返回日志目录。
func (l *ConsoleLogger) Dir() string {
	return l.fileLogger.dir
}

// Level 返回日志级别。
func (l *ConsoleLogger) Level() Level {
	return l.fileLogger.level
}

// 全局日志实例（由 main 初始化）
var (
	globalLogger *ConsoleLogger
	globalMu     sync.RWMutex
)

// SetGlobal 设置全局日志实例。
func SetGlobal(l *ConsoleLogger) {
	globalMu.Lock()
	globalLogger = l
	globalMu.Unlock()
}

// Global 返回全局日志实例，未设置时返回 nil。
func Global() *ConsoleLogger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogger
}

// PrintJournal 将消息写入控制台 journal（启动期用，不写日志文件）。
func PrintJournal(msg string) {
	fmt.Println(msg)
}

// Normalize 把调用方传入的“任意 logger 形态”归一为 *ConsoleLogger。
//
// 支持：
//   - *ConsoleLogger（推荐）：直接返回；
//   - nil 或其它类型：退回全局实例；全局未初始化时返回 nil。
//
// 该函数供 session 等不方便直接依赖具体日志实例的包使用，
// 便于它们保留 interface{} 形参的历史签名而不丢日志。
func Normalize(v interface{}) *ConsoleLogger {
	if l, ok := v.(*ConsoleLogger); ok && l != nil {
		return l
	}
	return Global()
}

// LogKick 记录“踢指定账号下线”。
func LogKick(l *ConsoleLogger, account string) {
	if l == nil {
		return
	}
	l.Warn(fmt.Sprintf("[KICK] 踢下线账号: %s", account))
}

// LogKickAll 记录“全服踢下线”。
func LogKickAll(l *ConsoleLogger) {
	if l == nil {
		return
	}
	l.Warn("[KICK] 全服踢下线：已清空全部在线会话")
}
