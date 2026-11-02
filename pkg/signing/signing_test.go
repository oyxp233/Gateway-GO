package signing

import (
	"encoding/json"
	"os"
	"testing"
)

// TestCanonicalJSONDeterministic 锁定 CanonicalJSON 的确定性 ——
// 这是 Ed25519 签名链路成立的前提：网关签的字节必须与登录器验的字节逐字节相同。
//
// 同一份数据（哪怕 map 插入顺序不同）序列化结果必须一致。
func TestCanonicalJSONDeterministic(t *testing.T) {
	a := map[string]interface{}{
		"b": 2, "a": 1, "c": map[string]interface{}{"z": "x", "y": "w"},
	}
	b := map[string]interface{}{
		"c": map[string]interface{}{"y": "w", "z": "x"}, "a": 1, "b": 2,
	}

	ja, err := CanonicalJSON(a)
	if err != nil {
		t.Fatalf("CanonicalJSON(a): %v", err)
	}
	jb, err := CanonicalJSON(b)
	if err != nil {
		t.Fatalf("CanonicalJSON(b): %v", err)
	}

	if string(ja) != string(jb) {
		t.Fatalf("同一份数据序列化结果不一致:\n a=%s\n b=%s", ja, jb)
	}

	// 键必须按字典序
	want := `{"a":1,"b":2,"c":{"y":"w","z":"x"}}`
	if string(ja) != want {
		t.Fatalf("键序不是字典序:\n got=%s\nwant=%s", ja, want)
	}
}

// TestCanonicalJSONStructSlice 锁定结构体切片（服清单的实际形态）的序列化稳定性。
func TestCanonicalJSONStructSlice(t *testing.T) {
	type entry struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		AuthPort int      `json:"auth_port"`
		Caps     []string `json:"caps"`
	}
	list := []entry{
		{ID: "s4a21", Name: "A21", AuthPort: 8000, Caps: []string{"pvf", "plugins"}},
		{ID: "s5a3", Name: "S5A3", AuthPort: 8001, Caps: []string{}},
	}

	j1, err := CanonicalJSON(list)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	j2, err := CanonicalJSON(list)
	if err != nil {
		t.Fatalf("CanonicalJSON(2): %v", err)
	}
	if string(j1) != string(j2) {
		t.Fatalf("两次序列化结果不一致:\n 1=%s\n 2=%s", j1, j2)
	}

	// 必须是合法 JSON 且能反解回原结构
	var back []entry
	if err := json.Unmarshal(j1, &back); err != nil {
		t.Fatalf("反序列化失败: %v (json=%s)", err, j1)
	}
	if len(back) != 2 || back[0].ID != "s4a21" || back[1].ID != "s5a3" {
		t.Fatalf("反序列化结果不对: %+v", back)
	}
}

// TestSignVerifyRoundTrip 锁定签名/验签的往返正确性。
func TestSignVerifyRoundTrip(t *testing.T) {
	priv, pubHex, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	data := []byte(`{"servers":[]}`)
	sig := Sign(priv, data)

	if !VerifyHex(pubHex, sig, data) {
		t.Fatal("正确签名验签失败")
	}

	// 篡改数据必须验签失败
	if VerifyHex(pubHex, sig, []byte(`{"servers":[{"id":"evil"}]}`)) {
		t.Fatal("篡改数据后验签竟然通过")
	}

	// 篡改签名必须失败
	badSig := sig[:len(sig)-2] + "00"
	if VerifyHex(pubHex, badSig, data) {
		t.Fatal("篡改签名后验签竟然通过")
	}

	// 换一把公钥必须失败（防 MITM 换密钥对）
	_, otherPubHex, _ := GenerateKeyPair()
	if VerifyHex(otherPubHex, sig, data) {
		t.Fatal("用另一把公钥验签竟然通过")
	}
}

// TestSaveLoadPrivateKey 锁定私钥落盘/加载与权限自检。
func TestSaveLoadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/signing.key"

	priv, pubHex, err := EnsurePrivateKey(path)
	if err != nil {
		t.Fatalf("EnsurePrivateKey: %v", err)
	}

	// 二次调用必须加载同一把（公钥不变）—— 这是"登录器 exe 里编译的公钥长期有效"的前提
	priv2, pubHex2, err := EnsurePrivateKey(path)
	if err != nil {
		t.Fatalf("EnsurePrivateKey(2): %v", err)
	}
	if pubHex != pubHex2 {
		t.Fatalf("两次 EnsurePrivateKey 生成了不同密钥: %s vs %s", pubHex, pubHex2)
	}
	if !priv.Equal(priv2) {
		t.Fatal("两次 EnsurePrivateKey 加载的私钥不一致")
	}

	// 签名可被公钥验证
	data := []byte("hello")
	if !VerifyHex(pubHex2, Sign(priv2, data), data) {
		t.Fatal("从文件加载的密钥签名验签失败")
	}
}

// TestLoadPrivateKeyWrongSize 锁定"文件大小不对必须报错"，不能静默当空密钥用。
func TestLoadPrivateKeyWrongSize(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.key"
	if err := os.WriteFile(path, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil {
		t.Fatal("大小不对的私钥文件竟然加载成功")
	}
}
