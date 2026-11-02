// Package signing 提供 Ed25519 签名与验签能力，用于网关向登录器
// 下发服清单时的完整性保护。
//
// 设计动机（见 评估-三服合一登录器-20261023.md 第三章）：
//   - TLS pin 保护传输层，但万一某个服的 bootstrap 走明文（内网测试），
//     MITM 就能往清单里塞自己的服 → 需要 Ed25519 签名兜底
//   - 私钥只在网关，公钥编译进登录器 exe，玩家改 launcher-config.json
//     改不动这两样 → 拿不到任何绕过收益
//
// 签名格式：对清单 JSON 的 canonical bytes 做 Ed25519 Sign，
// 返回 hex 编码签名。验签时对 canonical bytes 做 Verify。
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PrivateKeyFile 是私钥文件的默认文件名（放在网关运行目录下）。
const PrivateKeyFile = "signing.key"

// PublicKeyHex 返回公钥的十六进制编码字符串（编译进登录器用）。
func PublicKeyHex(pk ed25519.PrivateKey) string {
	return hex.EncodeToString(pk.Public().(ed25519.PublicKey))
}

// GenerateKeyPair 生成一对 Ed25519 密钥。
// 返回 (privateKey, publicKeyHex, error)。
func GenerateKeyPair() (ed25519.PrivateKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	return priv, hex.EncodeToString(pub), nil
}

// SavePrivateKey 将私钥写入文件，权限 0600（仅属主可读写）。
func SavePrivateKey(pk ed25519.PrivateKey, path string) error {
	if len(pk) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: %d", len(pk))
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create key directory: %w", err)
		}
	}
	if err := os.WriteFile(path, pk, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
}

// LoadPrivateKey 从文件读取私钥。
// 文件必须是 64 字节的原始 Ed25519 私钥（ed25519.PrivateKeySize）。
//
// 启动自检：
//   - 文件不存在 → 返回 ErrKeyNotFound（调用方应生成新密钥）
//   - 文件大小不对 → 返回错误（可能是被篡改或格式不匹配）
//   - 文件权限过宽（非 0600 且非 Windows）→ 返回 ErrKeyPermissions
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("read private key: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d, expected %d", len(data), ed25519.PrivateKeySize)
	}

	// 权限自检（非 Windows）
	if !isWindows() {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat private key: %w", err)
		}
		perm := info.Mode().Perm()
		if perm != 0o600 {
			return nil, &KeyPermissionError{Path: path, Perm: perm}
		}
	}

	pk := ed25519.PrivateKey(data)
	return pk, nil
}

// EnsurePrivateKey 确保私钥文件存在且有效。
// 不存在时自动生成新密钥并保存；存在时加载已有密钥。
//
// 这是网关启动时调用的入口：首次启动自动生成密钥，
// 后续启动加载已有密钥（保证登录器 exe 里编译的公钥不变）。
func EnsurePrivateKey(path string) (ed25519.PrivateKey, string, error) {
	pk, err := LoadPrivateKey(path)
	if err == nil {
		return pk, PublicKeyHex(pk), nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, "", err
	}

	// 生成新密钥
	pk, pubHex, err := GenerateKeyPair()
	if err != nil {
		return nil, "", err
	}
	if err := SavePrivateKey(pk, path); err != nil {
		return nil, "", err
	}
	return pk, pubHex, nil
}

// Sign 对数据做 Ed25519 签名，返回 hex 编码的签名字符串。
func Sign(pk ed25519.PrivateKey, data []byte) string {
	sig := ed25519.Sign(pk, data)
	return hex.EncodeToString(sig)
}

// VerifyHex 验证 hex 编码签名的有效性。
// publicKeyHex 是 hex 编码的公钥，sigHex 是 hex 编码的签名。
func VerifyHex(publicKeyHex string, sigHex string, data []byte) bool {
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), data, sig)
}

// CanonicalJSON 将任意 Go 值序列化为确定性 JSON（字段顺序固定），
// 用于签名前规范化清单数据。
//
// 确定性保证：map 的 key 排序后输出，没有多余空格，没有换行。
// 这样同一份清单在网关和登录器两端序列化出来的字节完全一致。
//
// 实现方式：先 json.Marshal 再用 json.Decoder 重新解析为
// interface{}（Go 的 json.Unmarshal 把 JSON object 放进
// map[string]interface{}），然后按排序后的 key 递归序列化。
// 用 json.Encoder 的 SetEscapeHTML(false) 避免 <>& 被转义。
func CanonicalJSON(v interface{}) ([]byte, error) {
	// 先序列化再反序列化，把 struct 转成 map[string]interface{}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("canonical: unmarshal: %w", err)
	}
	var buf strings.Builder
	if err := canonicalEncode(&buf, decoded); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// canonicalEncode 递归将值按确定性顺序写入 buf。
func canonicalEncode(buf *strings.Builder, v interface{}) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		// json.Marshal 会把 number 输出为 float64 的默认格式，
		// 这里用 json.Marshal 保持一致
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	case string:
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalEncode(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		buf.WriteByte('{')
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := canonicalEncode(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// 回退到 json.Marshal 处理未知类型
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("canonical: unsupported type %T: %w", val, err)
		}
		buf.Write(b)
	}
	return nil
}

// --- 错误类型 ---

// ErrKeyNotFound 私钥文件不存在。
var ErrKeyNotFound = errors.New("signing key not found")

// KeyPermissionError 私钥文件权限过宽。
type KeyPermissionError struct {
	Path string
	Perm os.FileMode
}

func (e *KeyPermissionError) Error() string {
	return fmt.Sprintf("signing key %s has insecure permissions %o, expected 0600", e.Path, e.Perm)
}

func (e *KeyPermissionError) Unwrap() error { return nil }

// --- 内部工具 ---

func isWindows() bool {
	return filepath.Separator == '\\' && strings.Contains(os.Getenv("OS"), "Windows")
}
