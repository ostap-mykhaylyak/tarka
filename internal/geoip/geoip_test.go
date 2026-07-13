package geoip

import (
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
)

func discard() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// The resolver must degrade gracefully: a missing or corrupt
// database means "no geo", never an error on the query path.
func TestGracefulDegradation(t *testing.T) {
	r := New(filepath.Join(t.TempDir(), "missing.mmdb"), discard())
	defer r.Close()
	if r.Loaded() {
		t.Fatal("missing database must not load")
	}
	if g := r.Lookup(netip.MustParseAddr("8.8.8.8")); g != (Geo{}) {
		t.Fatalf("lookup without database must be empty, got %+v", g)
	}

	var nilR *Resolver
	if nilR.Loaded() {
		t.Fatal("nil resolver must report not loaded")
	}
	if g := nilR.Lookup(netip.MustParseAddr("8.8.8.8")); g != (Geo{}) {
		t.Fatalf("nil resolver lookup must be empty, got %+v", g)
	}
}
