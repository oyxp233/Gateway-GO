package security

import (
	"encoding/asn1"
	"errors"
	"os"
	"strings"
	"testing"

	"s4a21-gateway/pkg/security/petest"
)

// ============================================================================
// PE 内嵌 Authenticode 签名校验的单测。
//
// 夹具来自 pkg/security/petest（自造签名 PE），理由见那个包的文档：
// 真实驱动动辄几 MB、不入库，而且没法证明"改一个字节会被抓到"。
// 自造夹具能钉死三件必须成立的事：
//
//	① 摘要算法与三段切分正确（造出来的文件必须校验通过）；
//	② **改一个字节必须被抓到**（这是本功能存在的理由，也是回退验证的锚点）；
//	③ 没有证书表 / 不是 PE 时给出正确的分类错误。
//
// 另有 env 门控的真实文件复核（TestVerifyPERealSignedFile）：拿真实签名驱动
// 人工验一次，默认跳过、不污染常规回归。
// ============================================================================

// TestVerifyPESignedPasses 合法签名的 PE 必须通过，并解出签名者展示名。
func TestVerifyPESignedPasses(t *testing.T) {
	pe, err := petest.SignedPE([]byte("driver payload"), petest.SHA256)
	if err != nil {
		t.Fatalf("造夹具失败: %v", err)
	}

	sig, err := VerifyPEBytes(pe)
	if err != nil {
		t.Fatalf("合法签名 PE 不该被拒: %v", err)
	}
	if sig.DigestAlgorithm != "SHA-256" {
		t.Fatalf("摘要算法应为 SHA-256，实际 %q", sig.DigestAlgorithm)
	}
	if len(sig.Digest) != 64 {
		t.Fatalf("摘要应为 64 位十六进制，实际 %q", sig.Digest)
	}
	if !strings.Contains(sig.Signer, "Test Vendor") {
		t.Fatalf("签名者展示名应含 Test Vendor，实际 %q", sig.Signer)
	}
}

// TestVerifyPESignedSHA1 SHA-1 签名的老驱动也要认得（用的是签名里声明的算法）。
func TestVerifyPESignedSHA1(t *testing.T) {
	pe, err := petest.SignedPE([]byte("legacy driver"), petest.SHA1)
	if err != nil {
		t.Fatalf("造夹具失败: %v", err)
	}

	sig, err := VerifyPEBytes(pe)
	if err != nil {
		t.Fatalf("SHA-1 签名的 PE 不该被拒: %v", err)
	}
	if sig.DigestAlgorithm != "SHA-1" {
		t.Fatalf("摘要算法应为 SHA-1，实际 %q", sig.DigestAlgorithm)
	}
}

// TestVerifyPETamperedIsRejected ★ 本功能存在的理由：签名后被改一个字节就必须被拒。
//
// 这条同时是回退验证的锚点 —— 把"重算摘要后比对"那一步去掉，本用例必须变红。
func TestVerifyPETamperedIsRejected(t *testing.T) {
	pe, err := petest.SignedPE([]byte("driver payload"), petest.SHA256)
	if err != nil {
		t.Fatalf("造夹具失败: %v", err)
	}

	pe[petest.PayloadOffset] ^= 0xFF

	if _, err := VerifyPEBytes(pe); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("被改过的文件必须报 ErrDigestMismatch，实际: %v", err)
	}
}

// TestVerifyPEExcludedFieldsDoNotAffectDigest 反例的另一半：
// CheckSum 字段**刻意不参与**摘要，改它不该报"被篡改"。
//
// 这条防的是"实现把整段头部都拿去哈希"——那样虽然也能拒绝篡改，
// 但会把所有真实签名文件判成不一致（真实文件里这个字段是有值的）。
//
// 安全目录条目(8 字节)的排除由 TestVerifyPESignedPasses 天然覆盖：
// 夹具算摘要时那两个字段还是 0，校验时已被回填成真实偏移 —— 若实现把它们算进摘要，那条必然红。
func TestVerifyPEExcludedFieldsDoNotAffectDigest(t *testing.T) {
	pe, err := petest.SignedPE([]byte("driver payload"), petest.SHA256)
	if err != nil {
		t.Fatalf("造夹具失败: %v", err)
	}

	pe[petest.CheckSumOffset] = 0xEF
	pe[petest.CheckSumOffset+1] = 0xBE
	pe[petest.CheckSumOffset+2] = 0xAD
	pe[petest.CheckSumOffset+3] = 0xDE

	if _, err := VerifyPEBytes(pe); err != nil {
		t.Fatalf("CheckSum 字段不参与摘要，改它不该判为篡改: %v", err)
	}
}

// TestVerifyPEWithoutCertTable 没有证书表的 PE 必须报"未签名"。
func TestVerifyPEWithoutCertTable(t *testing.T) {
	pe := petest.UnsignedPE([]byte("unsigned driver"))

	if _, err := VerifyPEBytes(pe); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("未签名文件必须报 ErrNoSignature，实际: %v", err)
	}
}

// TestVerifyPENotPE 非 PE 输入必须报 ErrNotPE。
func TestVerifyPENotPE(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("MZ"), []byte("hello world, definitely not a PE")} {
		if _, err := VerifyPEBytes(in); !errors.Is(err, ErrNotPE) {
			t.Fatalf("非 PE 输入(%q) 必须报 ErrNotPE，实际: %v", in, err)
		}
	}
}

// TestVerifyPEDerHelpersLocked 把 DER 走查的基础函数钉死（防以后被"优化"坏）。
func TestVerifyPEDerHelpersLocked(t *testing.T) {
	// derTLV 的 content / full / rest 边界
	tag, content, full, rest, err := derTLV([]byte{0x04, 0x02, 0xAA, 0xBB, 0x99})
	if err != nil || tag != 0x04 || len(content) != 2 || len(full) != 4 || len(rest) != 1 {
		t.Fatalf("derTLV 解析异常: tag=%02X content=%v full=%v rest=%v err=%v", tag, content, full, rest, err)
	}
	// OID 往返（含 base-128 多字节段）
	oid, _, err := derOID(derOIDEncode(oidSHA256))
	if err != nil || !oid.Equal(oidSHA256) {
		t.Fatalf("OID 往返失败: %v err=%v", oid, err)
	}
	// 长格式长度段
	if l, n := derLength([]byte{0x81, 0x80}); l != 128 || n != 2 {
		t.Fatalf("长格式长度段解析异常: l=%d n=%d", l, n)
	}
	// 越界必须报错，不能越读
	if _, _, _, _, err := derTLV([]byte{0x04, 0x05, 0x01}); err == nil {
		t.Fatal("长度超出可用字节时必须报错")
	}
}

// derOIDEncode 把 OID 编成完整 TLV（仅测试用）。
func derOIDEncode(oid asn1.ObjectIdentifier) []byte {
	body := []byte{byte(oid[0]*40 + oid[1])}
	for _, v := range oid[2:] {
		if v == 0 {
			body = append(body, 0)
			continue
		}
		var tmp []byte
		for x := v; x > 0; x >>= 7 {
			tmp = append([]byte{byte(x & 0x7F)}, tmp...)
		}
		for i := 0; i < len(tmp)-1; i++ {
			tmp[i] |= 0x80
		}
		body = append(body, tmp...)
	}
	return append([]byte{0x06, byte(len(body))}, body...)
}

// TestVerifyPERealSignedFile 拿真实签名驱动复核一次（默认跳过）。
//
// 用法：S4A21_TEST_SIGNED_PE=<path> go test ./pkg/security/ -run TestVerifyPERealSignedFile -v
// 不写进常规回归的理由：真实驱动不入库，且这条断言的是"某个具体文件"，
// 不该让别的机器因为缺文件而红。
//
// 2026-10-16 实测（AMDRyzenMasterDriver.sys，AMD Ryzen Master 驱动）：
//
//	SHA-256 / signer=Advanced Micro Devices
//	chain=Sectigo Public Code Signing Root R46 → CA R36 → Advanced Micro Devices
//
// 这条通过即证明「三段切分 + 摘要算法 + PKCS#7 走查」对**真实签名文件**成立。
func TestVerifyPERealSignedFile(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("S4A21_TEST_SIGNED_PE"))
	if path == "" {
		t.Skip("未设置 S4A21_TEST_SIGNED_PE，跳过真实文件复核")
	}
	sig, err := VerifyPEFile(path)
	if err != nil {
		t.Fatalf("真实签名文件校验失败 %s: %v", path, err)
	}
	if sig.Signer == "" {
		t.Fatalf("真实签名文件必须能解出签名者；实际为空（chain=%v）", sig.Chain)
	}
	t.Logf("OK algo=%s digest=%s signer=%s chain=%v",
		sig.DigestAlgorithm, sig.Digest, sig.Signer, sig.Chain)
}
