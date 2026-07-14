package views

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func writeViews(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "views.yaml")
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestViewsLookup(t *testing.T) {
	path := writeViews(t, `
Fastweb:
  - 85.18.0.0/16
  - 2.34.0.0/16
TIM:
  - 212.216.0.0/16
  - 79.0.0.1
`)
	m := New(path, discard())
	if !m.Loaded() || m.Count() != 2 {
		t.Fatalf("want 2 providers, got %d", m.Count())
	}
	if v := m.Lookup(netip.MustParseAddr("85.18.1.2")); len(v) != 1 || v[0] != "fastweb" {
		t.Fatalf("Fastweb match broken: %v", v)
	}
	if v := m.Lookup(netip.MustParseAddr("212.216.5.5")); len(v) != 1 || v[0] != "tim" {
		t.Fatalf("TIM match broken: %v", v)
	}
	if v := m.Lookup(netip.MustParseAddr("79.0.0.1")); len(v) != 1 || v[0] != "tim" {
		t.Fatalf("bare-IP match broken: %v", v)
	}
	if v := m.Lookup(netip.MustParseAddr("9.9.9.9")); len(v) != 0 {
		t.Fatalf("unknown resolver must match nothing, got %v", v)
	}
}

func TestViewsMissingFileGraceful(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "absent.yaml"), discard())
	if m.Loaded() || m.Count() != 0 {
		t.Fatal("missing file must load empty, not fatal")
	}
	if v := m.Lookup(netip.MustParseAddr("1.2.3.4")); v != nil {
		t.Fatalf("empty table must match nothing, got %v", v)
	}
	var nilM *Manager
	if nilM.Loaded() || nilM.Lookup(netip.MustParseAddr("1.2.3.4")) != nil {
		t.Fatal("nil manager must be safe")
	}
}

func TestViewsInvalidRangesSkipped(t *testing.T) {
	path := writeViews(t, "Fastweb: [85.18.0.0/16, not-a-cidr]\n")
	m := New(path, discard())
	if v := m.Lookup(netip.MustParseAddr("85.18.1.1")); len(v) != 1 {
		t.Fatalf("valid range must survive an invalid sibling: %v", v)
	}
}
