package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// selfSigned builds a throwaway certificate chain for storage and
// renewal-decision tests.
func selfSigned(t *testing.T, domains []string, notAfter time.Time) (*ecdsa.PrivateKey, [][]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, [][]byte{der}
}

func TestCertStorageRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "live", "example.com")
	key, chain := selfSigned(t, []string{"example.com", "*.example.com"}, time.Now().Add(90*24*time.Hour))

	if err := writeCert(dir, key, chain); err != nil {
		t.Fatal(err)
	}
	cert, err := readCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 2 || cert.DNSNames[0] != "example.com" {
		t.Fatalf("stored SANs broken: %v", cert.DNSNames)
	}
	// The key file must be private (POSIX modes: production target
	// only, Windows does not track them).
	fi, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("privkey.pem too permissive: %v", fi.Mode())
	}
}

func TestNeedsRenew(t *testing.T) {
	domains := []string{"example.com", "*.example.com"}
	renewBefore := 30 * 24 * time.Hour

	_, chainFresh := selfSigned(t, domains, time.Now().Add(60*24*time.Hour))
	fresh, _ := x509.ParseCertificate(chainFresh[0])
	if needsRenew(fresh, domains, renewBefore) {
		t.Fatal("fresh certificate must not renew")
	}
	// Same set, different order and case: still fresh.
	if needsRenew(fresh, []string{"*.EXAMPLE.com", "example.com."}, renewBefore) {
		t.Fatal("domain comparison must normalize order, case and dots")
	}

	_, chainOld := selfSigned(t, domains, time.Now().Add(10*24*time.Hour))
	old, _ := x509.ParseCertificate(chainOld[0])
	if !needsRenew(old, domains, renewBefore) {
		t.Fatal("expiring certificate must renew")
	}

	if !needsRenew(fresh, []string{"example.com"}, renewBefore) {
		t.Fatal("changed domain set must reissue")
	}
}

func TestAccountKeyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")
	k1, created, err := loadOrCreateAccountKey(path)
	if err != nil || !created {
		t.Fatalf("first load must create: %v %v", created, err)
	}
	k2, created, err := loadOrCreateAccountKey(path)
	if err != nil || created {
		t.Fatalf("second load must reuse: %v %v", created, err)
	}
	if !k1.Equal(k2) {
		t.Fatal("account key must persist")
	}
}

func TestDirectoryPresets(t *testing.T) {
	if url := directoryURL("letsencrypt"); url != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Fatalf("letsencrypt preset broken: %s", url)
	}
	if url := directoryURL("zerossl"); url != "https://acme.zerossl.com/v2/DV90" {
		t.Fatalf("zerossl preset broken: %s", url)
	}
	custom := "https://ca.internal/acme/directory"
	if url := directoryURL(custom); url != custom {
		t.Fatalf("custom URL must pass through: %s", url)
	}
}

func TestCertNameAndDomains(t *testing.T) {
	if got := certName("example.com."); got != "example.com" {
		t.Fatalf("certName = %q", got)
	}
	if got := certName("XN--caf-dma.example."); got != "xn--caf-dma.example" {
		t.Fatalf("certName must lowercase: %q", got)
	}
	d := zoneDomains("example.com.")
	if len(d) != 2 || d[0] != "example.com" || d[1] != "*.example.com" {
		t.Fatalf("zoneDomains broken: %v", d)
	}
}
