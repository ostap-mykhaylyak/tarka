package xfr

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/server"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// startCatalogPrimary boots a full master publishing a catalog for
// 127.0.0.1 and returns its address plus the live zones dir.
func startCatalogPrimary(t *testing.T, zoneYAMLs map[string]string) (addr, zonesDir string, store *zone.Store) {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		port := reservePort(t)
		dir := t.TempDir()
		listen := fmt.Sprintf("127.0.0.1:%d", port)
		cfgPath := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte("server:\n  listen: [\""+listen+"\"]\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		mgr, err := config.NewManager(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		zonesDir = filepath.Join(dir, "zones")
		if err := os.MkdirAll(zonesDir, 0o750); err != nil {
			t.Fatal(err)
		}
		for name, yaml := range zoneYAMLs {
			if err := os.WriteFile(filepath.Join(zonesDir, name), []byte(yaml), 0o640); err != nil {
				t.Fatal(err)
			}
		}
		store = zone.NewStore(zonesDir, filepath.Join(dir, "serials.json"), discard())
		store.SetCatalog("catalog.tarka.", []string{"127.0.0.1"}, false, nil)
		store.LoadAll()

		s := server.New(mgr, store, nil, metrics.New(), discard(), discard(), discard())
		if err := s.Start(); err != nil {
			continue
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			s.Shutdown(ctx)
			cancel()
		})
		return listen, zonesDir, store
	}
	t.Fatal("could not bind a shared udp+tcp port")
	return "", "", nil
}

func plainZone(name string) string {
	return strings.ReplaceAll(`
zone: ZONE
soa: {mname: ns1.ZONE., rname: hostmaster.ZONE.}
records:
  - {name: "@", type: NS, value: ns1.ZONE.}
  - {name: ns1, type: A,  value: 203.0.113.10}
  - {name: www, type: A,  value: 203.0.113.10}
`, "ZONE", name)
}

// newCatalogSlave builds a slave with ZERO zone files: everything
// comes from the master's catalog.
func newCatalogSlave(t *testing.T, primaryAddr, stateDir string) (*zone.Store, *Manager) {
	t.Helper()
	dir := t.TempDir()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })

	store := zone.NewStore(filepath.Join(dir, "zones"), filepath.Join(dir, "serials.json"), discard())
	mg := NewManager(store, metrics.New(), discard(), stateDir, stop)
	store.OnLoad = mg.ZoneLoaded
	store.OnRemove = mg.ZoneRemoved
	store.LoadAll()
	mg.SubscribeCatalog("catalog.tarka.", []string{primaryAddr})
	return store, mg
}

func TestCatalogProvisionsSlaveWithoutZoneFiles(t *testing.T) {
	primary, zonesDir, masterStore := startCatalogPrimary(t, map[string]string{
		"one.example.yaml": plainZone("one.example"),
		"two.example.yaml": plainZone("two.example"),
	})
	stateDir := t.TempDir()
	store, mg := newCatalogSlave(t, primary, stateDir)

	// Both member zones appear and answer, with zero YAML files.
	for _, apex := range []string{"one.example.", "two.example."} {
		z := waitLoaded(t, store, apex)
		if res := z.Lookup("www."+apex, dns.TypeA); len(res.Answer) != 1 {
			t.Fatalf("%s must answer after catalog provisioning: %+v", apex, res)
		}
	}

	// A new zone on the master reaches the slave after the catalog
	// refresh: in production fsnotify loads the file and the NOTIFY
	// pokes the slave; the test does both by hand.
	path := filepath.Join(zonesDir, "three.example.yaml")
	if err := os.WriteFile(path, []byte(plainZone("three.example")), 0o640); err != nil {
		t.Fatal(err)
	}
	masterStore.LoadFile(path)

	if rc := mg.HandleNotify("catalog.tarka.", netip.MustParseAddr("127.0.0.1")); rc != dns.RcodeSuccess {
		t.Fatalf("catalog NOTIFY refused: %s", dns.RcodeToString[rc])
	}
	waitLoaded(t, store, "three.example.")
}

func TestCatalogRemovalDropsZone(t *testing.T) {
	primary, zonesDir, masterStore := startCatalogPrimary(t, map[string]string{
		"one.example.yaml": plainZone("one.example"),
		"two.example.yaml": plainZone("two.example"),
	})
	stateDir := t.TempDir()
	store, mg := newCatalogSlave(t, primary, stateDir)
	waitLoaded(t, store, "one.example.")
	waitLoaded(t, store, "two.example.")

	// Master drops a zone: catalog membership changes.
	path := filepath.Join(zonesDir, "two.example.yaml")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	masterStore.RemoveFile(path)

	if rc := mg.HandleNotify("catalog.tarka.", netip.MustParseAddr("127.0.0.1")); rc != dns.RcodeSuccess {
		t.Fatalf("catalog NOTIFY refused: %s", dns.RcodeToString[rc])
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if store.Find("two.example.") == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("zone removed from the catalog must drop from the slave")
}

func TestNotifyForUnknownZoneWakesCatalog(t *testing.T) {
	primary, _, _ := startCatalogPrimary(t, map[string]string{
		"one.example.yaml": plainZone("one.example"),
	})
	store, mg := newCatalogSlave(t, primary, t.TempDir())
	waitLoaded(t, store, "one.example.")

	// Unknown zone from the catalog master: still REFUSED (RFC 1996),
	// but the catalog gets refreshed as a side effect — and from a
	// stranger nothing happens.
	if rc := mg.HandleNotify("ghost.example.", netip.MustParseAddr("127.0.0.1")); rc != dns.RcodeRefused {
		t.Fatalf("unknown zone must stay REFUSED, got %s", dns.RcodeToString[rc])
	}
	if rc := mg.HandleNotify("ghost.example.", netip.MustParseAddr("203.0.113.99")); rc != dns.RcodeRefused {
		t.Fatalf("stranger must be REFUSED, got %s", dns.RcodeToString[rc])
	}
}
