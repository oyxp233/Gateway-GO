package security

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"
)

// ============================================================================
// PE 内嵌 Authenticode 签名校验（驱动白名单上传时的守门）
//
// 为什么需要它：网关后台上传一个 .sys 就能让它进入「登录器内核驱动放行名单」，
// 而放行的对象是**玩家机器上的内核驱动**。上传口没有守门，等于给运营一个
// "一键给全网放行任意文件"的按钮 —— 手滑一次（传错文件、传了个改过的文件）
// 就是全服事故。所以上传必须过两道闸：
//
//	① 文件必须**带内嵌 Authenticode 签名**（拒绝未签名文件）；
//	② 签名内嵌的 Authenticode 摘要必须与本机重算的摘要**逐字节相等**
//	   （拒绝"签名后被改过"的文件，即防篡改）。
//
// ★★ 能力边界（必须如实告知，不要把它说成"验签通过"）：
//   本实现**不做 PKCS#7 签名的密码学验证**，也不做证书链信任判定。
//   也就是说，一个能手工构造 PE 证书表的人，可以用任意自造/借用证书
//   塞一份"自洽"的摘要骗过①②。这里挡的是**运营手滑**（未签名文件、
//   改过的文件），不是"有能力伪造签名结构的攻击者"。
//   运行时真正的安全边界在**客户端**：登录器只按 SHA-256 **精确匹配**放行，
//   加白的就是当时上传的那份字节，改一个字节即失效（见 KernelThreatScanner）。
//
// 为什么不引第三方库：本项目是纯 Go、无 crypto 依赖的生产网关，
// 为一道"运营侧守门"引入 CMS/ASN.1 依赖，风险大于收益（供应链 + 体积 + 升级）。
// 这里只用标准库手写最小的 PE/ASN.1 走查，逻辑量小、可单测钉死。
// ============================================================================

// 支持的单文件上限。驱动（.sys）通常几十 KB ~ 十几 MB，
// 64 MiB 足够覆盖特例（实测最大的 NEPKernel.sys 3.9 MB），同时挡住"传个 2GB 文件当驱动"。
const maxDriverFileBytes = 64 << 20

// 本文件用到的 OID。
var (
	// oidSignedData = PKCS#7 SignedData（1.2.840.113549.1.7.2）。
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// oidSPCIndirectData = Authenticode 的 SpcIndirectDataContent（1.3.6.1.4.1.311.2.1.4）。
	oidSPCIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// 校验失败的分类错误。调用方用 errors.Is 区分，以便给出不同的后台提示。
var (
	// ErrNotPE 不是有效的 PE 文件。
	ErrNotPE = errors.New("不是有效的 PE 文件（缺少 MZ / PE 头）")
	// ErrNoSignature 文件没有内嵌 Authenticode 签名。
	ErrNoSignature = errors.New("文件没有内嵌 Authenticode 签名（未签名的驱动一律拒绝）")
	// ErrBadSignature 签名结构存在但无法解析。
	ErrBadSignature = errors.New("内嵌签名结构无法解析")
	// ErrDigestMismatch 文件内容与签名内嵌摘要不一致（签名后被改过）。
	ErrDigestMismatch = errors.New("文件内容与签名内嵌的摘要不一致（文件在签名之后被改动过）")
	// ErrUnsupportedDigestAlgo 签名的摘要算法不受支持。
	ErrUnsupportedDigestAlgo = errors.New("签名的摘要算法不受支持")
	// ErrFileTooLarge 文件超过单文件上限。
	ErrFileTooLarge = errors.New("驱动文件超过 64 MiB 上限")
)

// PESignature 是一次 PE 签名校验的结果（校验通过才会有值）。
type PESignature struct {
	// DigestAlgorithm 签名声明的摘要算法名（如 "SHA-256"）。
	DigestAlgorithm string
	// Digest 签名内嵌摘要（大写十六进制）；已与重算值比对相等。
	Digest string
	// Signer 签名者展示名（如「Advanced Micro Devices（CN=…）」）。
	Signer string
	// Chain 证书链上各证书的展示名，叶证书在前。
	Chain []string
}

// VerifyPEFile 校验磁盘上 PE 文件的内嵌 Authenticode 签名（见本文件头部的能力边界）。
func VerifyPEFile(path string) (*PESignature, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxDriverFileBytes {
		return nil, fmt.Errorf("%w: %d 字节", ErrFileTooLarge, fi.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return VerifyPEBytes(data)
}

// VerifyPEBytes 校验内存中 PE 文件的内嵌 Authenticode 签名。
//
// 成功时返回签名信息；失败时返回的错误可用 errors.Is 匹配上面那组哨兵错误。
func VerifyPEBytes(data []byte) (*PESignature, error) {
	// ── ① 定位 PE 可选头与两个关键偏移 ──
	layout, err := parsePELayout(data)
	if err != nil {
		return nil, err
	}

	// ── ② 取证书表并解析 PKCS#7，拿到「签名里声明的算法 + 摘要」 ──
	algoOID, embedded, certs, err := parseCertTable(data, layout)
	if err != nil {
		return nil, err
	}

	// ── ③ 本机重算 Authenticode 摘要并比对 ──
	computed, algoName, err := authenticodeDigest(data, algoOID, layout)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(computed, hex.EncodeToString(embedded)) {
		return nil, fmt.Errorf("%w：签名内声明 %s，文件实际 %s",
			ErrDigestMismatch, strings.ToUpper(hex.EncodeToString(embedded)), computed)
	}

	sig := &PESignature{DigestAlgorithm: algoName, Digest: computed}
	sig.Chain, sig.Signer = describeCertificateChain(certs)
	return sig, nil
}

// peLayout 是 PE 头里与本校验相关的几个偏移。
type peLayout struct {
	checksumOff  int // 可选头里 CheckSum 字段的文件偏移（4 字节，参与排除）
	secDirOff    int // 可选头里「安全目录(第 5 项)」条目的文件偏移（8 字节，参与排除）
	certTableOff int // 证书表起始（= 安全目录条目里的 VirtualAddress，是**文件偏移**）
	certTableLen int
	optMagic     uint16
}

// parsePELayout 走一遍 DOS/COFF/可选头，取出校验需要的偏移。
func parsePELayout(data []byte) (peLayout, error) {
	var l peLayout
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return l, ErrNotPE
	}
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOff < 0x40 || peOff+24 > len(data) ||
		data[peOff] != 'P' || data[peOff+1] != 'E' || data[peOff+2] != 0 || data[peOff+3] != 0 {
		return l, ErrNotPE
	}
	coff := peOff + 4
	// COFF 头：SizeOfOptionalHeader 在偏移 16（2 字节）。
	sizeOfOpt := int(binary.LittleEndian.Uint16(data[coff+16 : coff+18]))
	opt := coff + 20
	if sizeOfOpt < 96 || opt+sizeOfOpt > len(data) {
		return l, fmt.Errorf("%w: 可选头长度异常(%d)", ErrNotPE, sizeOfOpt)
	}

	l.optMagic = binary.LittleEndian.Uint16(data[opt : opt+2])
	var dataDirOff int
	switch l.optMagic {
	case 0x10B: // PE32
		dataDirOff = opt + 96
	case 0x20B: // PE32+
		dataDirOff = opt + 112
	default:
		return l, fmt.Errorf("%w: 未知可选头 magic 0x%04X", ErrNotPE, l.optMagic)
	}
	l.checksumOff = opt + 64
	if l.checksumOff+4 > len(data) || dataDirOff+40 > len(data) {
		return l, fmt.Errorf("%w: 头部越界", ErrNotPE)
	}

	numRva := int(binary.LittleEndian.Uint32(data[dataDirOff-4 : dataDirOff]))
	if numRva <= 4 {
		return l, ErrNoSignature
	}
	// 安全目录 = 数据目录第 5 项（index 4）。
	l.secDirOff = dataDirOff + 4*8
	l.certTableOff = int(binary.LittleEndian.Uint32(data[l.secDirOff : l.secDirOff+4]))
	l.certTableLen = int(binary.LittleEndian.Uint32(data[l.secDirOff+4 : l.secDirOff+8]))
	if l.certTableOff == 0 || l.certTableLen == 0 {
		return l, ErrNoSignature
	}
	if l.certTableOff < 0 || l.certTableOff+l.certTableLen > len(data) {
		return l, fmt.Errorf("%w: 证书表越界(off=%d len=%d file=%d)",
			ErrBadSignature, l.certTableOff, l.certTableLen, len(data))
	}
	return l, nil
}

// parseCertTable 解析 WIN_CERTIFICATE 与其中的 PKCS#7，返回签名声明的摘要算法、摘要与证书链。
func parseCertTable(data []byte, l peLayout) (asn1.ObjectIdentifier, []byte, []*x509.Certificate, error) {
	// WIN_CERTIFICATE：dwLength(4) wRevision(2) wCertificateType(2) bCertificate[]
	const winCertHeader = 8
	const winCertTypePKCS = 0x0002
	if l.certTableLen < winCertHeader {
		return nil, nil, nil, fmt.Errorf("%w: 证书表长度不足", ErrBadSignature)
	}
	tbl := data[l.certTableOff : l.certTableOff+l.certTableLen]
	dwLength := int(binary.LittleEndian.Uint32(tbl[0:4]))
	certType := binary.LittleEndian.Uint16(tbl[6:8])
	if certType != winCertTypePKCS {
		return nil, nil, nil, fmt.Errorf("%w: 证书类型 0x%04X 不是 PKCS_SIGNED_DATA", ErrBadSignature, certType)
	}
	if dwLength < winCertHeader || dwLength > len(tbl) {
		return nil, nil, nil, fmt.Errorf("%w: WIN_CERTIFICATE 长度非法(%d)", ErrBadSignature, dwLength)
	}
	pkcs7 := tbl[winCertHeader:dwLength]
	return parsePKCS7Spc(pkcs7)
}

// parsePKCS7Spc 从 PKCS#7 ContentInfo 中取出 Authenticode 的
// 「摘要算法 + 摘要值 + 证书链」。
//
// 走查路径（全部按 DER 手工下钻，不做完整 CMS 语义解析）：
//
//	ContentInfo   ::= SEQ { OID signedData, [0] { SignedData } }
//	SignedData    ::= SEQ { INT version, SET digestAlgs,
//	                        SEQ ContentInfo { OID spcIndirectData, [0]{ SpcIndirectDataContent } },
//	                        [0] certificates OPTIONAL, [1] crls OPTIONAL, SET signerInfos }
//	SpcIndirectDataContent ::= SEQ { SEQ data, SEQ DigestInfo { SEQ algid, OCTET STRING digest } }
func parsePKCS7Spc(pkcs7 []byte) (asn1.ObjectIdentifier, []byte, []*x509.Certificate, error) {
	// ContentInfo ::= SEQ { OID signedData, [0] { SignedData } }
	tag, ciContent, _, _, err := derTLV(pkcs7)
	if err != nil || tag != 0x30 {
		return nil, nil, nil, fmt.Errorf("%w: ContentInfo 头", ErrBadSignature)
	}
	ctOID, ciRest, err := derOID(ciContent)
	if err != nil || !ctOID.Equal(oidSignedData) {
		return nil, nil, nil, fmt.Errorf("%w: 不是 PKCS#7 SignedData", ErrBadSignature)
	}
	exTag, exContent, _, _, err := derTLV(ciRest)
	if err != nil || exTag&0xE0 != 0xA0 {
		return nil, nil, nil, fmt.Errorf("%w: SignedData 包装", ErrBadSignature)
	}
	sdTag, sdBody, _, _, err := derTLV(exContent)
	if err != nil || sdTag != 0x30 {
		return nil, nil, nil, fmt.Errorf("%w: SignedData 头", ErrBadSignature)
	}

	// SignedData.version INTEGER
	vTag, _, _, r2, err := derTLV(sdBody)
	if err != nil || vTag != 0x02 {
		return nil, nil, nil, fmt.Errorf("%w: SignedData.version", ErrBadSignature)
	}
	// SignedData.digestAlgorithms SET
	daTag, _, _, r3, err := derTLV(r2)
	if err != nil || daTag != 0x31 {
		return nil, nil, nil, fmt.Errorf("%w: SignedData.digestAlgorithms", ErrBadSignature)
	}
	// SignedData.encapContentInfo
	ecTag, ecContent, _, r4, err := derTLV(r3)
	if err != nil || ecTag != 0x30 {
		return nil, nil, nil, fmt.Errorf("%w: SignedData.encapContentInfo", ErrBadSignature)
	}
	innerOID, ecRest, err := derOID(ecContent)
	if err != nil || !innerOID.Equal(oidSPCIndirectData) {
		return nil, nil, nil, fmt.Errorf("%w: 内容类型不是 SpcIndirectData", ErrBadSignature)
	}
	exTag2, spcContent, _, _, err := derTLV(ecRest)
	if err != nil || exTag2&0xE0 != 0xA0 {
		return nil, nil, nil, fmt.Errorf("%w: SpcIndirectData 包装", ErrBadSignature)
	}

	// SpcIndirectDataContent ::= SEQ { data SEQ, DigestInfo SEQ }
	spcTag, spcBody, _, _, err := derTLV(spcContent)
	if err != nil || spcTag != 0x30 {
		return nil, nil, nil, fmt.Errorf("%w: SpcIndirectDataContent 头", ErrBadSignature)
	}
	// data（SpcAttributeTypeAndOptionalValue）—— 跳过
	dataTag, _, _, r6, err := derTLV(spcBody)
	if err != nil || dataTag != 0x30 {
		return nil, nil, nil, fmt.Errorf("%w: SpcIndirectDataContent.data", ErrBadSignature)
	}
	// DigestInfo
	diTag, diContent, _, _, err := derTLV(r6)
	if err != nil || diTag != 0x30 {
		return nil, nil, nil, fmt.Errorf("%w: DigestInfo 头", ErrBadSignature)
	}
	// DigestInfo.digestAlgorithm
	algTag, algContent, _, diRest, err := derTLV(diContent)
	if err != nil || algTag != 0x30 {
		return nil, nil, nil, fmt.Errorf("%w: DigestInfo.digestAlgorithm", ErrBadSignature)
	}
	algoOID, _, err := derOID(algContent)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: 摘要算法 OID", ErrBadSignature)
	}
	// DigestInfo.digest OCTET STRING
	dgTag, digest, _, _, err := derTLV(diRest)
	if err != nil || dgTag != 0x04 || len(digest) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: 摘要值", ErrBadSignature)
	}

	// ── 可选块：证书链 [0] IMPLICIT SET OF Certificate ──
	var certs []*x509.Certificate
	if len(r4) > 0 {
		if exTag3, certBlob, _, _, err := derTLV(r4); err == nil && exTag3&0xE0 == 0xA0 {
			for rest := certBlob; len(rest) > 0; {
				cTag, _, cFull, cRest, cerr := derTLV(rest)
				if cerr != nil || cTag != 0x30 {
					break
				}
				if c, perr := x509.ParseCertificate(cFull); perr == nil {
					certs = append(certs, c)
				}
				rest = cRest
			}
		}
	}
	return algoOID, digest, certs, nil
}

// authenticodeDigest 按 Authenticode 规范重算 PE 摘要。
//
// 算法：把下面三段按顺序喂给哈希函数（**排除** CheckSum 字段 4 字节、
// 安全目录条目 8 字节、以及整个证书表）：
//
//	file[0 : checksumOff] + file[checksumOff+4 : secDirOff] + file[secDirOff+8 : certTableOff]
func authenticodeDigest(data []byte, algo asn1.ObjectIdentifier, l peLayout) (string, string, error) {
	h, name, err := hashForOID(algo)
	if err != nil {
		return "", "", err
	}
	if l.checksumOff < 0 || l.checksumOff+4 > l.secDirOff || l.secDirOff+8 > l.certTableOff || l.certTableOff > len(data) {
		return "", "", fmt.Errorf("%w: 摘要区间偏移非法", ErrBadSignature)
	}
	h.Write(data[:l.checksumOff])
	h.Write(data[l.checksumOff+4 : l.secDirOff])
	h.Write(data[l.secDirOff+8 : l.certTableOff])
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), name, nil
}

// hashForOID 把摘要算法 OID 映射到哈希构造器与展示名。
func hashForOID(oid asn1.ObjectIdentifier) (hash.Hash, string, error) {
	switch {
	case oid.Equal(oidSHA1):
		return sha1.New(), "SHA-1", nil
	case oid.Equal(oidSHA256):
		return sha256.New(), "SHA-256", nil
	case oid.Equal(oidSHA384):
		return sha512.New384(), "SHA-384", nil
	case oid.Equal(oidSHA512):
		return sha512.New(), "SHA-512", nil
	default:
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupportedDigestAlgo, oid.String())
	}
}

// describeCertificateChain 从证书里挑出签名者并给出展示名。
//
// 挑法：优先「非 CA 且 Subject 有 CN」的第一张（Authenticode 里叶证书即签名证书）；
// 退而求其次取第一张能解析的证书。全部失败时返回空串，由调用方按"未识别签名者"处理。
func describeCertificateChain(certs []*x509.Certificate) ([]string, string) {
	chain := make([]string, 0, len(certs))
	for _, c := range certs {
		chain = append(chain, certificateSubjectText(c))
	}
	signer := ""
	for _, c := range certs {
		if !c.IsCA && c.Subject.CommonName != "" {
			signer = certificateSubjectText(c)
			break
		}
	}
	if signer == "" && len(chain) > 0 {
		signer = chain[0]
	}
	return chain, signer
}

// certificateSubjectText 把证书主体压成一行展示名，形如「Advanced Micro Devices（CN=Advanced Micro Devices）」。
func certificateSubjectText(c *x509.Certificate) string {
	cn := c.Subject.CommonName
	if len(c.Subject.Organization) > 0 {
		if o := c.Subject.Organization[0]; o != "" {
			if cn != "" && cn != o {
				return o + "（" + cn + "）"
			}
			if cn != "" {
				return o
			}
		}
	}
	if cn != "" {
		return cn
	}
	s := c.Subject.String()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ─────────────────────────────── DER 最小走查 ───────────────────────────────

var errDERShort = errors.New("DER 长度不足")

// derTLV 读取一个单字节 tag 的 DER TLV。
//
// 返回：tag、内容(content)、含 tag+长度+内容的完整字节(full)、其后剩余字节(rest)。
// 只支持单字节 tag（本文件涉及的 PKCS#7/Authentiocde 结构都满足）。
func derTLV(b []byte) (tag byte, content, full, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, nil, errDERShort
	}
	tag = b[0]
	if tag&0x1F == 0x1F {
		return 0, nil, nil, nil, fmt.Errorf("不支持多字节 tag: 0x%02X", tag)
	}
	l, n := derLength(b[1:])
	if n == 0 {
		return 0, nil, nil, nil, errDERShort
	}
	start := 1 + n
	if l < 0 || start+l > len(b) {
		return 0, nil, nil, nil, errDERShort
	}
	return tag, b[start : start+l], b[:start+l], b[start+l:], nil
}

// derLength 解析 DER 长度段，返回长度值与长度段占用的字节数（含首字节）；非法返回 0,0。
func derLength(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0] < 0x80 {
		return int(b[0]), 1
	}
	n := int(b[0] & 0x7F)
	if n == 0 || n > 4 || len(b) < 1+n {
		return 0, 0
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<8 | int(b[1+i])
	}
	return v, 1 + n
}

// derOID 从一段 DER 内容的开头读出 OID，返回 OID 与其后剩余字节。
func derOID(b []byte) (asn1.ObjectIdentifier, []byte, error) {
	tag, content, _, rest, err := derTLV(b)
	if err != nil {
		return nil, nil, err
	}
	if tag != 0x06 {
		return nil, nil, fmt.Errorf("期望 OID(0x06)，实际 0x%02X", tag)
	}
	oid, perr := decodeOIDContent(content)
	if perr != nil {
		return nil, nil, perr
	}
	return oid, rest, nil
}

// decodeOIDContent 解析 OID 的内容字节（不含 tag/length）。
//
// 手写而不用 asn1.Unmarshal：后者要求完整的 TLV，而这里手上只有内容段，
// 拼一个假 TLV 再解容易在长度边界上出岔子，不如直接按 X.690 的 base-128 解。
func decodeOIDContent(b []byte) (asn1.ObjectIdentifier, error) {
	if len(b) == 0 {
		return nil, errors.New("OID 内容为空")
	}
	first := int(b[0])
	oid := asn1.ObjectIdentifier{first / 40, first % 40}
	v := 0
	for i := 1; i < len(b); i++ {
		v = v<<7 | int(b[i]&0x7F)
		if b[i]&0x80 == 0 {
			oid = append(oid, v)
			v = 0
		}
	}
	if v != 0 {
		return nil, errors.New("OID 末尾不完整")
	}
	return oid, nil
}
