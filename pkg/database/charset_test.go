package database

import "testing"

// TestDecodeGBKRealCharacterNames 用**正式服库里的真实字节**验证角色名解码。
//
// 这些字节取自 inventory.db（characters 表，typeof(name)='blob'）。
// 编码约定见 charset.go：schema v11 起角色名以 GBK(936) 裸字节落库。
func TestDecodeGBKRealCharacterNames(t *testing.T) {
	cases := []struct {
		raw  []byte
		want string
		note string
	}{
		{[]byte{0x4d, 0x73, 0x70}, "Msp", "纯 ASCII，GBK 是 ASCII 超集"},
		{[]byte{0xcd, 0xc3, 0xcd, 0xc3}, "兔兔", "全中文"},
		{[]byte{0xb0, 0xa2, 0xc1, 0xc1}, "阿亮", "全中文"},
		{[]byte{0xc1, 0xb3, 0xb0, 0xd7, 0xb1, 0xac, 0xd6, 0xd5, 0xbc, 0xab}, "脸白爆终极", "全中文"},
		{[]byte{0xb4, 0xf3, 0x4a, 0x38, 0xb2, 0xe5, 0xd2, 0xbb, 0xcf, 0xc2}, "大J8插一下", "中英混排"},
		{[]byte{0xb6, 0xbe, 0xc4, 0xcc}, "毒奶", "全中文"},
		// 这条是关键回归：这串字节里有一段恰好构成合法 UTF-8
		//（\xc3\xa8\xc3\xa8 会被直接读成 "èè"），
		// 所以绝不能用 utf8.Valid 决定是否转码。
		{[]byte{0xc3, 0xa8, 0xc3, 0xa8, 0xc8, 0xad, 0xb4, 0xf2, 0xc4, 0xe3}, "猫猫拳打你", "GBK 恰好是合法 UTF-8，必须仍按 GBK 解"},
		{[]byte{0xc0, 0xb2, 0xc0, 0xb2, 0xc0, 0xb2, 0xc0, 0xb2}, "啦啦啦啦", "全中文"},
		{[]byte{0xdf, 0xf7, 0xdf, 0xf7, 0xdf, 0xf7}, "喵喵喵", "全中文"},
		{nil, "", "NULL 列"},
		{[]byte{}, "", "空字节"},
	}

	for _, tc := range cases {
		if got := DecodeGameText(tc.raw, "blob"); got != tc.want {
			t.Errorf("DecodeGameText(% x, blob) = %q, want %q  (%s)", tc.raw, got, tc.want, tc.note)
		}
	}
}

// TestDecodeGameTextByColumnType 锁定「按列类型分支」的语义：
// text 列必须是原样透传（历史 UTF-8 行不能被二次转码），blob 列才走 GBK。
func TestDecodeGameTextByColumnType(t *testing.T) {
	// 「兔兔」的 UTF-8 字节放进 text 列 → 必须原样返回
	utf8Bytes := []byte{0xe5, 0x85, 0x94, 0xe5, 0x85, 0x94}
	if got := DecodeGameText(utf8Bytes, "text"); got != "兔兔" {
		t.Errorf("text 列原样透传失败: got %q, want 兔兔", got)
	}
	// 同样的 UTF-8 字节放进 blob 列 → 按 GBK 解，必然不是「兔兔」
	if got := DecodeGameText(utf8Bytes, "blob"); got == "兔兔" {
		t.Error("blob 列不应被当作 UTF-8 处理（会把 GBK 名字读成乱码）")
	}
	// 列类型的判定必须大小写无关：sqlite typeof 返回小写，
	// 但别把正确性押在驱动实现上。判成 text 就走透传（此处不相等是预期的，
	// 因为 \xcd\xc3 在 UTF-8 下不是「兔兔」）。
	if got := DecodeGameText([]byte{0xcd, 0xc3, 0xcd, 0xc3}, " TEXT "); got != string([]byte{0xcd, 0xc3, 0xcd, 0xc3}) {
		t.Errorf("大写列类型未被识别为 text（应透传）: got %q", got)
	}
	// blob 一律走 GBK
	if got := DecodeGameText([]byte{0xcd, 0xc3, 0xcd, 0xc3}, "BLOB"); got != "兔兔" {
		t.Errorf("大写 blob 未走 GBK 解码: got %q, want 兔兔", got)
	}
	// 未知/缺失列类型按 blob 处理（宁可解，不要漏）
	if got := DecodeGameText([]byte{0xcd, 0xc3, 0xcd, 0xc3}, ""); got != "兔兔" {
		t.Errorf("空列类型未按 blob 处理: got %q, want 兔兔", got)
	}
}
