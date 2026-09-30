package utils

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TailFile 从文件尾部读取最多 maxLines 行。
//
// 采用从文件尾部反向分块读取的方式，不把整个日志文件读入内存
// （日志文件可达数百 MB，全量读会造成明显的瞬时内存占用）。
func TailFile(path string, maxLines int) ([]string, error) {
	if maxLines <= 0 {
		return []string{}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size == 0 {
		return []string{}, nil
	}

	const chunkSize int64 = 64 * 1024
	// 上限保护：最多回读 8 MiB，避免单行超长时无限回退
	const maxScan int64 = 8 << 20

	var (
		buf     []byte
		offset  = size
		scanned int64
	)

	for offset > 0 && scanned < maxScan {
		readSize := chunkSize
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize
		scanned += readSize

		chunk := make([]byte, readSize)
		if _, err := f.ReadAt(chunk, offset); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(chunk, buf...)

		// 已读到的换行符数量足够时提前停止
		if int64(bytes.Count(buf, []byte("\n"))) > int64(maxLines) {
			break
		}
	}

	lines := strings.Split(string(buf), "\n")
	// 文件末尾若以换行结尾，Split 会产出一个空尾元素，去掉它
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, nil
}

// FileStats 获取文件信息。
type FileStats struct {
	Size        int64
	ModifiedUtc string
}

// GetFileStats 获取文件统计信息。
func GetFileStats(path string) (*FileStats, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return &FileStats{
		Size:        info.Size(),
		ModifiedUtc: info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}

// FileExists 检查文件是否存在。
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// DirExists 检查目录是否存在。
func DirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// MkdirAll 创建目录。
func MkdirAll(path string) error {
	return os.MkdirAll(path, 0755)
}

// CopyFile 流式复制文件，避免把整个文件读入内存（PVF 可达数百 MB）。
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	// 显式 Close 才能暴露写入错误（defer 里的错误会被丢弃）
	return out.Close()
}

// BackupFile 备份文件为 .bak。
func BackupFile(path string) error {
	bakPath := path + ".bak"
	return CopyFile(path, bakPath)
}

// ParseTimezoneOffset 解析时区偏移小时数。
func ParseTimezoneOffset(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// FormatUtcTime 格式化 UTC 时间。
func FormatUtcTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// NowUnix 返回当前 Unix 时间戳。
func NowUnix() int64 {
	return time.Now().Unix()
}

// NowUnixNano 返回当前 Unix 纳秒时间戳。
func NowUnixNano() int64 {
	return time.Now().UnixNano()
}

// IsSameDay 检查两个时间戳是否在同一天。
func IsSameDay(ts1, ts2 int64) bool {
	t1 := time.Unix(ts1, 0)
	t2 := time.Unix(ts2, 0)
	return t1.Year() == t2.Year() && t1.YearDay() == t2.YearDay()
}

// PathJoin 拼接路径。
func PathJoin(parts ...string) string {
	return filepath.Join(parts...)
}

// TrimSpace 去除首尾空白。
func TrimSpace(s string) string {
	return strings.TrimSpace(s)
}

// Contains 检查字符串切片是否包含指定值。
func Contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// ValidateAccountName 校验账号名称格式。
func ValidateAccountName(name string) (bool, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, "账号不能为空"
	}
	if len(name) < 3 || len(name) > 20 {
		return false, "账号长度不符合要求"
	}
	for _, ch := range name {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			return false, "账号包含非法字符"
		}
	}
	return true, ""
}

// ValidatePasswordMd5 校验密码 MD5 格式。
func ValidatePasswordMd5(pwdMd5 string) (bool, string) {
	pwdMd5 = strings.TrimSpace(pwdMd5)
	if pwdMd5 == "" {
		return false, "密码不能为空"
	}
	if len(pwdMd5) != 32 {
		return false, "密码长度不符合要求"
	}
	for _, ch := range pwdMd5 {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false, "密码格式非法"
		}
	}
	return true, ""
}

// ValidateAuthKey 验证管理密钥，使用恒定时间比较避免时序侧信道。
func ValidateAuthKey(input, expected string) bool {
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(input), []byte(expected)) == 1
}

// ValidatePort 验证端口号范围。
func ValidatePort(port int) bool {
	return port >= 0 && port <= 65535
}

// ShortHash 安全截取哈希前 16 位用于展示，不足 16 位时原样返回（避免切片越界 panic）。
func ShortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:16]
}

// SanitizeErrorMessage 清理错误消息，去除可能泄露内部信息的内容。
func SanitizeErrorMessage(msg string) string {
	// 去除文件路径
	if idx := strings.LastIndex(msg, "/"); idx >= 0 {
		return msg[idx+1:]
	}
	return msg
}

// FormatError 格式化错误消息。
func FormatError(prefix string, err error) string {
	return fmt.Sprintf("%s: %v", prefix, err)
}
