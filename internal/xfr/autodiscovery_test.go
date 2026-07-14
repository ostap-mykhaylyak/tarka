package xfr

import (
	"context"
	"fmt"
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

// End to end with ZERO transfer configuration on the master: the
// slave (127.0.0.1) is discovered from the NS glue of the zone.
func TestAutoDiscoveredSlaveEndToEnd(t *testing.T) {
	zoneYAML := strings.ReplaceAll(`
zone: auto.example
soa: {mname: ns1.ZONE., rname: hostmaster.ZONE.}
records:
  - {name: "@",  type: NS, value: ns1.ZONE.}
  - {name: "@",  type: NS, value: ns2.ZONE.}
  - {name: ns1,  type: A,  value: 198.51.100.1}
  - {name: ns2,  type: A,  value: 127.0.0.1}
  - {name: www,  type: A,  value: 203.0.113.10}
`, "ZONE", "auto.example")

	var primary string
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
		zonesDir := filepath.Join(dir, "zones")
		if err := os.MkdirAll(zonesDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(zonesDir, "auto.example.yaml"), []byte(zoneYAML), 0o640); err != nil {
			t.Fatal(err)
		}
		store := zone.NewStore(zonesDir, filepath.Join(dir, "serials.json"), discard())
		// auto-discovery on, no explicit secondaries; "self" is the
		// master's public IP from the glue, NOT 127.0.0.1.
		store.SetCatalog("catalog.tarka.", nil, true, nil)
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
		primary = listen
		break
	}
	if primary == "" {
		t.Fatal("could not bind a shared udp+tcp port")
	}

	// Slave: subscribes to the catalog, gets the zone with no files
	// and no transfer config anywhere.
	store, _ := newCatalogSlave(t, primary, t.TempDir())
	z := waitLoaded(t, store, "auto.example.")
	if res := z.Lookup("www.auto.example.", dns.TypeA); len(res.Answer) != 1 {
		t.Fatalf("auto-discovered slave must serve the zone: %+v", res)
	}
}
