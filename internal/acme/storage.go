package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Layout: <cert_dir>/account.key plus, per certificate,
// <cert_dir>/live/<name>/fullchain.pem and privkey.pem — the same
// shape certbot uses, so consumers need no adaptation.

func accountKeyPath(certDir string) string { return filepath.Join(certDir, "account.key") }

func liveDir(certDir, name string) string { return filepath.Join(certDir, "live", name) }

func normalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// loadOrCreateAccountKey loads the persistent ACME account key,
// generating it (ECDSA P-256, 0600) on first use.
func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, bool, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, false, fmt.Errorf("%s: not PEM", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return key, false, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, false, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// writeCert stores the key and the full chain atomically in dir.
func writeCert(dir string, key *ecdsa.PrivateKey, chain [][]byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	var full []byte
	for _, der := range chain {
		full = append(full, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	// Key first: a reader that sees the new fullchain always finds a
	// matching key already in place... except on first issuance, where
	// both are new anyway.
	if err := writeFileAtomic(filepath.Join(dir, "privkey.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "fullchain.pem"), full, 0o640)
}

// readCert parses the leaf certificate of live/<name>/fullchain.pem.
func readCert(dir string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no certificate PEM", dir)
	}
	return x509.ParseCertificate(block.Bytes)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
