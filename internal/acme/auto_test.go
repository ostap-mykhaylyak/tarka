package acme

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
)

func discard() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// fakeZones is a canned ZoneSource; it records the published probes.
type fakeZones struct {
	primaries []string
	set       []string
	cleared   []string
}

func (f *fakeZones) SetDNS01(domain, token string) error {
	f.set = append(f.set, domain)
	return nil
}

func (f *fakeZones) ClearDNS01(domain, token string) error {
	f.cleared = append(f.cleared, domain)
	return nil
}

func (f *fakeZones) PrimaryZones() []string { return f.primaries }

func testManager(t *testing.T, zones ZoneSource, certDir string) *Manager {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "acme:\n  enabled: true\n  email: a@b.c\n  cert_dir: " +
		filepath.ToSlash(certDir) + "\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o640); err != nil {
		t.Fatal(err)
	}
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return NewManager(mgr, zones, discard())
}

func TestAutoSkipsUndelegatedZone(t *testing.T) {
	zones := &fakeZones{primaries: []string{"parked.example."}}
	m := testManager(t, zones, t.TempDir())
	m.delegated = func(ctx context.Context, cfg config.Acme, zone string) error {
		return fmt.Errorf("not visible")
	}

	if clean := m.checkAll(make(chan struct{})); !clean {
		t.Fatal("an undelegated zone must not count as a failure")
	}
	snap := m.Snapshot()
	if len(snap) != 1 || snap[0].Skipped == "" || snap[0].Error != "" || snap[0].Issued {
		t.Fatalf("undelegated zone must be skipped cleanly: %+v", snap)
	}
	if snap[0].Name != "parked.example" ||
		len(snap[0].Domains) != 2 || snap[0].Domains[1] != "*.parked.example" {
		t.Fatalf("candidate derivation broken: %+v", snap[0])
	}
}

func TestAutoFreshCertificateSkipsDelegationCheck(t *testing.T) {
	certDir := t.TempDir()
	key, chain := selfSigned(t, []string{"example.com", "*.example.com"},
		time.Now().Add(60*24*time.Hour))
	if err := writeCert(liveDir(certDir, "example.com"), key, chain); err != nil {
		t.Fatal(err)
	}

	zones := &fakeZones{primaries: []string{"example.com."}}
	m := testManager(t, zones, certDir)
	m.delegated = func(ctx context.Context, cfg config.Acme, zone string) error {
		t.Fatal("fresh certificate must not trigger the delegation probe")
		return nil
	}

	if clean := m.checkAll(make(chan struct{})); !clean {
		t.Fatal("fresh certificate must be a clean cycle")
	}
	snap := m.Snapshot()
	if len(snap) != 1 || !snap[0].Issued || snap[0].Skipped != "" || snap[0].Error != "" {
		t.Fatalf("fresh certificate state broken: %+v", snap)
	}
}

func TestAutoRechecksDelegationWhenRenewalDue(t *testing.T) {
	certDir := t.TempDir()
	key, chain := selfSigned(t, []string{"example.com", "*.example.com"},
		time.Now().Add(5*24*time.Hour)) // inside renew_before
	if err := writeCert(liveDir(certDir, "example.com"), key, chain); err != nil {
		t.Fatal(err)
	}

	zones := &fakeZones{primaries: []string{"example.com."}}
	m := testManager(t, zones, certDir)
	probed := false
	m.delegated = func(ctx context.Context, cfg config.Acme, zone string) error {
		probed = true
		return fmt.Errorf("delegation moved away")
	}

	m.checkAll(make(chan struct{}))
	if !probed {
		t.Fatal("a due renewal must re-verify the delegation")
	}
	snap := m.Snapshot()
	// The old certificate is still on disk, but the renewal is
	// (correctly) suspended: the zone left this server.
	if len(snap) != 1 || !snap[0].Issued || snap[0].Skipped == "" {
		t.Fatalf("moved-away zone must suspend renewal: %+v", snap)
	}
}
