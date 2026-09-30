package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// FileFingerprintAlgo 文件指纹算法标识。
//
// 统一为带连字符的 "SHA-256"，与 PvfService 侧保持一致；
// 该字段仅用于展示，不参与哈希比对。
const FileFingerprintAlgo = "SHA-256"

// ComputeFileFingerprint 计算文件内容的 SHA-256 指纹。
//
// 返回 (hash, algo)。hash 为**大写**十六进制字符串 —— 登录器侧统一按大写比对；
// 采用流式读取，避免把整个文件（PVF 可达数百 MB）读进内存。
func ComputeFileFingerprint(reader io.Reader) (string, string) {
	h := sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		// 读取失败时返回空指纹，由调用方按"指纹不可用"处理，
		// 而不是拿一个基于残缺数据的哈希去比对。
		return "", FileFingerprintAlgo
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), FileFingerprintAlgo
}

// ComputeFileFingerprintPath 计算磁盘文件的 SHA-256 指纹（大写）。
func ComputeFileFingerprintPath(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hash, _ := ComputeFileFingerprint(f)
	if hash == "" {
		return "", fmt.Errorf("读取文件失败: %s", path)
	}
	return hash, nil
}
