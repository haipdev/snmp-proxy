package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func EnsureTLSMaterial(cfg Config) error {
	if !cfg.TLSEnabled {
		return nil
	}
	certInfo, certErr := os.Stat(cfg.TLSCertPath)
	keyInfo, keyErr := os.Stat(cfg.TLSKeyPath)
	switch {
	case certErr == nil && keyErr == nil:
		if certInfo.IsDir() || keyInfo.IsDir() {
			return fmt.Errorf("TLS certificate and key paths must be files")
		}
		if _, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
			return fmt.Errorf("load TLS material: %w", err)
		}
		return nil
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		return generateSelfSigned(cfg)
	case os.IsNotExist(certErr) != os.IsNotExist(keyErr):
		return fmt.Errorf("TLS certificate and key must both exist or both be absent")
	default:
		if certErr != nil {
			return fmt.Errorf("stat TLS certificate: %w", certErr)
		}
		return fmt.Errorf("stat TLS key: %w", keyErr)
	}
}

func generateSelfSigned(cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.TLSCertPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.TLSKeyPath), 0o755); err != nil {
		return err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "snmp-proxy development certificate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range cfg.TLSHosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	certFile, err := os.OpenFile(cfg.TLSCertPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	keyFile, err := os.OpenFile(cfg.TLSKeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	return pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}
