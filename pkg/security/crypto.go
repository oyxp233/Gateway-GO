package security

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// HashMD5 计算字符串的 MD5 哈希，返回 32 位十六进制字符串。
func HashMD5(input string) string {
	h := md5.Sum([]byte(input))
	return hex.EncodeToString(h[:])
}

// HashSHA256 计算数据的 SHA-256 哈希，返回**小写**十六进制字符串。
//
// 注意：本函数同时被账号密码派生（DeriveHash）与内部摘要（listDigest 等）使用，
// 其返回值大小写必须与既有数据库中的历史值保持一致，**不要**直接改成大写，
// 否则全部现存账号将无法登录。需要大写对外指纹请用 HashSHA256Upper。
func HashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// HashSHA256Upper 计算数据的 SHA-256 哈希，返回**大写**十六进制字符串。
//
// 用于对外暴露的指纹（TLS pin、PVF 全文件指纹、登录器校验），
// 登录器侧统一按大写比对。
func HashSHA256Upper(data []byte) string {
	return strings.ToUpper(HashSHA256(data))
}

// HashSHA256Str 计算字符串的 SHA-256 哈希（小写）。
func HashSHA256Str(input string) string {
	return HashSHA256([]byte(input))
}

// DeriveHash 使用 SHA256(MD5(密码) + salt) 派生密码哈希。
// 返回 64 位十六进制字符串（小写，与历史数据一致）。
func DeriveHash(passwordMd5, salt string) string {
	return HashSHA256Str(passwordMd5 + salt)
}

// ConstantTimeEquals 恒定时间比较两个字符串，防止时序攻击。
func ConstantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

// GenerateSalt 生成 32 字节的随机 salt，返回 hex 字符串。
func GenerateSalt() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateToken 生成 32 字节的随机 session token，返回 hex 字符串。
func GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// GenerateDeviceSecret 生成设备密钥，返回 hex 字符串。
func GenerateDeviceSecret() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

// CeraToBytes 将点券数量编码为 4 字节大端序字节数组。
func CeraToBytes(cera int64) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(cera))
	return buf
}

// BytesToCera 从 4 字节大端序字节数组解码点券数量。
func BytesToCera(buf []byte) int64 {
	if len(buf) < 4 {
		return 0
	}
	return int64(binary.BigEndian.Uint32(buf))
}

// EncodeCera 将点券数量编码为登录器期望的格式。
func EncodeCera(cera int64) string {
	return fmt.Sprintf("%d", cera)
}

// channelKeySuffix 频道列表密钥的固定后缀（与游戏端约定，不可更改）。
const channelKeySuffix = "000006"

// KeyDate 返回用于频道列表密钥的日期字符串（格式 20060102）。
//
// offsetHours 为时区偏移小时数：游戏服与网关可能不在同一时区，跨零点时
// 两端的“今天”必须一致，否则解密必然失败。偏移 0 表示直接用本机时间。
//
// 该函数是**唯一**的密钥日期来源，proxy.ChannelListRewriter 与其它调用方
// 都应走这里，避免出现两份可能行为不一致的实现。
func KeyDate(offsetHours int) string {
	return shiftedNow(offsetHours).Format("20060102")
}

// ChannelKey 返回指定时区偏移下的当天频道列表密钥（日期 + 固定后缀）。
func ChannelKey(offsetHours int) string {
	return KeyDate(offsetHours) + channelKeySuffix
}

// ChannelKeyPreviousDay 返回昨天（按 offsetHours 偏移后）的频道列表密钥。
//
// 用途：游戏端与网关的“今天”切换时刻可能相差几秒，跨零点附近需要回退
// 到昨天的密钥再试一次。
func ChannelKeyPreviousDay(offsetHours int) string {
	return shiftedNow(offsetHours).AddDate(0, 0, -1).Format("20060102") + channelKeySuffix
}

// shiftedNow 返回按小时偏移后的当前时间；偏移为 0 时返回本机时间。
func shiftedNow(offsetHours int) time.Time {
	now := timeNow()
	if offsetHours == 0 {
		return now
	}
	return now.Add(time.Duration(offsetHours) * time.Hour)
}
