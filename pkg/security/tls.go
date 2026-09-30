package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// LoadCertificate 根据 TlsSection 配置加载 TLS 证书。
// 返回 nil 表示 TLS 未启用。
func LoadCertificate(certFormat, certPath, certKeyPath, certPassword string) (*tls.Certificate, error) {
	if certFormat == "" {
		certFormat = "Pfx"
	}

	switch certFormat {
	case "Pfx", "pfx", "P12", "p12":
		return loadPfx(certPath, certPassword)
	case "Pem", "pem", "PEM":
		return loadPem(certPath, certKeyPath)
	default:
		return nil, fmt.Errorf("unsupported certificate format: %s", certFormat)
	}
}

func loadPfx(certPath, password string) (*tls.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read PFX certificate %s: %w", certPath, err)
	}

	// 使用 go-pkcs12 库解析 PFX
	key, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, fmt.Errorf("parse PFX certificate: %w", err)
	}

	// 构建 tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}

	// 解析 leaf 用于验证
	if len(tlsCert.Certificate) > 0 {
		parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		tlsCert.Leaf = parsed
	}

	// 验证证书链
	if err := validateCertChain(tlsCert); err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func loadPem(certPath, certKeyPath string) (*tls.Certificate, error) {
	if certKeyPath == "" {
		certKeyPath = certPath
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", certPath, err)
	}

	keyPEM, err := os.ReadFile(certKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", certKeyPath, err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse PEM certificate: %w", err)
	}

	// 验证证书链（.NET X509Chain 的等价检查）
	if err := validateCertChain(cert); err != nil {
		return nil, err
	}

	return &cert, nil
}

func validateCertChain(cert tls.Certificate) error {
	leaf := cert.Leaf
	if leaf == nil {
		// 尝试解析
		if len(cert.Certificate) > 0 {
			parsed, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return fmt.Errorf("parse certificate: %w", err)
			}
			leaf = parsed
		}
	}

	if leaf == nil {
		return nil
	}

	// 检查 keyUsage（.NET X509Chain 的硬要求）
	// 对于 TLS 服务端证书，需要 digitalSignature 和 keyEncipherment
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 && leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return fmt.Errorf("certificate missing digitalSignature or keyEncipherment key usage (required by TLS)")
	}

	// 自签证书检查：如果 Subject == Issuer，需要 CA 角色
	if leaf.Subject.String() == leaf.Issuer.String() {
		if !leaf.IsCA {
			return fmt.Errorf("self-signed certificate missing CA:TRUE (BasicConstraints)")
		}
		if leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("self-signed certificate missing keyCertSign (KeyUsage)")
		}
	}

	return nil
}
