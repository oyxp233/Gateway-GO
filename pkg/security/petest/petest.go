// Package petest 提供「自造带内嵌 Authenticode 签名的 PE 文件」这一测试夹具。
//
// 为什么单独成包：需要它的有两处 ——
//   - pkg/security 的单测：校验器必须认得出合法签名、并抓得住被改过的文件；
//   - pkg/httprouter 的单测：上传处理器必须"收下合法签名、拒掉未签名/被改过的"。
//
// 夹具里的 Authenticode 摘要切分（跳过 CheckSum、跳过安全目录条目、排除证书表）和
// PKCS#7 结构都很讲究，复制两份必然出现"只改了一份"的那天 ——
// 于是两边测试照样全绿，而其中一份已经在骗人。集中一处是唯一安全的做法。
//
// ★ 本包刻意**不引用** pkg/security：夹具按规范独立实现，
// 否则就成了"拿实现去验实现"，测试失去区分力。
// 真实签名文件的复核见 pkg/security 里那条 env 门控用例（TestVerifyPERealSignedFile）。
package petest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"time"
)

// Algo 夹具使用的摘要算法。
type Algo string

const (
	// SHA256 现代 Authenticode 签名（绝大多数驱动）。
	SHA256 Algo = "sha256"
	// SHA1 老签名的驱动。
	SHA1 Algo = "sha1"
)

// PE 布局常量（夹具用固定的 PE32 头）。
const (
	headerLen       = 0x200
	checksumOff     = 0x98 // 可选头 + 64
	secDirOff       = 0xD8 // DataDirectory + 4*8（PE32）
	winCertTypePKCS = 0x0002
)

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSPCIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSPCPEImageData  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	oidSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// SignedPE 造一个「payload 区为 payload、带合法内嵌签名」的 PE 文件。
//
// 关键顺序：摘要必须在**证书表还没附加**时算（证书表整体不参与 Authenticode 摘要），
// 算完再把 WIN_CERTIFICATE 追到文件尾部并回填安全目录条目 —— 那两个被回填的字段
// 恰好也都不参与摘要，所以校验端重算出来的值必须与嵌进去的值相等。
func SignedPE(payload []byte, algo Algo) ([]byte, error) {
	if algo != SHA1 && algo != SHA256 {
		return nil, errors.New("petest: 不支持的算法 " + string(algo))
	}
	pe := buildPE(payload)

	var digest []byte
	algoOID := oidSHA256
	if algo == SHA1 {
		algoOID = oidSHA1
		h := sha1.New()
		h.Write(pe[:checksumOff])
		h.Write(pe[checksumOff+4 : secDirOff])
		h.Write(pe[secDirOff+8:])
		digest = h.Sum(nil)
	} else {
		h := sha256.New()
		h.Write(pe[:checksumOff])
		h.Write(pe[checksumOff+4 : secDirOff])
		h.Write(pe[secDirOff+8:])
		digest = h.Sum(nil)
	}

	cert, err := selfSignedCert()
	if err != nil {
		return nil, err
	}
	pkcs7 := buildPKCS7(algoOID, digest, cert)

	// WIN_CERTIFICATE 的长度按 8 字节对齐（PE 规范要求）。
	total := 8 + len(pkcs7)
	padded := (total + 7) / 8 * 8
	winCert := make([]byte, padded)
	binary.LittleEndian.PutUint32(winCert[0:4], uint32(total))
	binary.LittleEndian.PutUint16(winCert[4:6], 0x0200)
	binary.LittleEndian.PutUint16(winCert[6:8], winCertTypePKCS)
	copy(winCert[8:], pkcs7)

	certOff := len(pe)
	full := append(pe, winCert...)
	// 安全目录的 VirtualAddress 是**文件偏移**（不是 RVA）。
	binary.LittleEndian.PutUint32(full[secDirOff:], uint32(certOff))
	binary.LittleEndian.PutUint32(full[secDirOff+4:], uint32(padded))
	return full, nil
}

// UnsignedPE 造一个没有证书表的 PE（用于"必须拒掉未签名文件"的用例）。
func UnsignedPE(payload []byte) []byte { return buildPE(payload) }

// Fields 暴露夹具里的关键偏移，便于用例精确地"改一个字节"。
const (
	// PayloadOffset 是 payload 区的起始偏移（改这里会改变摘要）。
	PayloadOffset = headerLen
	// CheckSumOffset 是 CheckSum 字段偏移（**不参与摘要**）。
	CheckSumOffset = checksumOff
	// SecDirOffset 是安全目录条目偏移（**不参与摘要**）。
	SecDirOffset = secDirOff
)

// buildPE 造一个 PE32 头部块（0x200 字节）+ payload。
func buildPE(payload []byte) []byte {
	pe := make([]byte, headerLen+len(payload))
	copy(pe[0:], "MZ")
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x40) // e_lfanew
	copy(pe[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[0x44:], 0x8664) // Machine = AMD64
	binary.LittleEndian.PutUint16(pe[0x46:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(pe[0x54:], 0xE0)   // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(pe[0x58:], 0x10B)  // Magic = PE32
	binary.LittleEndian.PutUint32(pe[0xB4:], 16)     // NumberOfRvaAndSizes
	copy(pe[headerLen:], payload)
	return pe
}

// selfSignedCert 生成一张自签的"代码签名"证书（Subject 里带 Test Vendor，
// 便于用例断言签名者展示名确实被解出来了）。
func selfSignedCert() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20261016),
		Subject: pkix.Name{
			Organization: []string{"Test Vendor"},
			CommonName:   "Test Vendor Signing",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

// buildPKCS7 把 SpcIndirectDataContent 包成 ContentInfo(SignedData)，并带上证书。
func buildPKCS7(algoOID asn1.ObjectIdentifier, digest, certDER []byte) []byte {
	spc := derSeq(
		derSeq(derOIDEnc(oidSPCPEImageData)),
		derSeq(derSeq(derOIDEnc(algoOID)), derWrap(0x04, digest)),
	)
	signedData := derSeq(
		derWrap(0x02, []byte{0x01}),                               // version
		derWrap(0x31, derSeq(derOIDEnc(algoOID))),                 // digestAlgorithms
		derSeq(derOIDEnc(oidSPCIndirectData), derWrap(0xA0, spc)), // encapContentInfo
		// certificates 是 [0] IMPLICIT SET OF Certificate：内容是各证书 DER 首尾相接
		//（每张证书本身已是 SEQUENCE），**不再**额外套一层 SEQUENCE。
		derWrap(0xA0, certDER),
		derWrap(0x31, nil), // signerInfos（校验端不解析）
	)
	return derSeq(derOIDEnc(oidSignedData), derWrap(0xA0, signedData))
}

// ── 最小 DER 编码 ──

func derWrap(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xFF:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func derSeq(parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return derWrap(0x30, body)
}

func derOIDEnc(oid asn1.ObjectIdentifier) []byte {
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
	return derWrap(0x06, body)
}
