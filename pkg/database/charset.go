package database

import (
	"fmt"
	"strings"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// 游戏库文字列的编码约定（与 DfoServer 的 Infrastructure/ClientTextEncoding 对齐）：
//
//	schema v11 起，**来自客户端协议的字符串**（角色名、副本名等）以 GBK(936)
//	裸字节写进 sqlite。列声明是 TEXT 而写入的是 byte[]，SQLite 不会把 BLOB
//	转成 TEXT，所以这些行的 typeof(name) = 'blob'。
//
// 网关若按 string 直接读，会拿到一串非法 UTF-8；encoding/json 再把每个坏字节
// 替换成 U+FFFD —— 这就是管理后台「中文角色名乱码」的根因
// （实测：\xcd\xc3\xcd\xc3「兔兔」显示成「????」）。
//
// ⚠️ 判定**只能看列类型，不能用 utf8.Valid**：
// 相当一部分 GBK 双字节序列恰好构成合法 UTF-8（如 \xc3\xa8\xc3\xa8 会被读成
// "èè"），用「无效才转码」的写法会漏掉一半名字（实测 cid=65「猫猫拳打你」）。

// DecodeGameText 按列类型把游戏库的原始字节转成 UTF-8 文本。
//
//	colType = "text" → 已经是文本（历史 UTF-8 行或纯 ASCII），原样返回
//	colType = "blob" → GBK(936) 裸字节，解码
//	其它（含 NULL）  → 空串
func DecodeGameText(raw []byte, colType string) string {
	if len(raw) == 0 {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(colType), "text") {
		return string(raw)
	}
	return DecodeGBK(raw)
}

// DecodeGBK 把 GBK(936) 字节解码成 UTF-8。
//
// 解码失败时原样返回：宁可显示成乱码，也不要因为一个坏字节丢掉整条数据。
// GBK 是 ASCII 的超集，纯英文名字（Msp / 123123）解出来与原值完全一致。
func DecodeGBK(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	out, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), raw)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// EncodeGBK 把 UTF-8 文本编码成游戏库要求的 GBK(936) 裸字节。
//
// 写回游戏库的文字列（角色名等）必须是 GBK 裸字节，写 UTF-8 会让游戏里显示成乱码，
// 而库里看着「正常」（见 DecodeGameText 的说明）。
//
// ★ 必须做**回环校验**：x/text 的 GBK 编码器遇到无法表示的字符时
// **不报错**，而是替换成 '?'（如 emoji、日文假名）——
// 不做校验就会把玩家的角色名静默改成 "??"，且没有任何错误可查。
// 编码结果解回来必须与原文逐字符相同，否则拒绝。
func EncodeGBK(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	encoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(s))
	if err != nil {
		return nil, fmt.Errorf("GBK 编码失败: %w", err)
	}
	back, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), encoded)
	if err != nil || string(back) != s {
		return nil, fmt.Errorf("含 GBK 无法表示的字符（游戏内不支持）")
	}
	return encoded, nil
}
