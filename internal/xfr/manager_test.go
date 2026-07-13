package xfr

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/server"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

func discard() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

const primaryZone = `
zone: example.org
soa: {mname: ns1.example.org., rname: hostmaster.example.org.}
records:
  - {name: "@",  type: NS, value: ns1.example.org.}
  - {name: ns1,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.10}
transfer:
  allow: [127.0.0.1, "::1"]
`

// startPrimary boots a full tarka server whose UDP and TCP listeners
// share one port (like production :53), so a single primaries entry
// serves both the SOA check and the AXFR.
func startPrimary(t *testing.T, zoneYAML string) (addr string) {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		port := reservePort(t)
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.yaml")
		listen := fmt.Sprintf("127.0.0.1:%d", port)
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
		if err := os.WriteFile(filepath.Join(zonesDir, "zone.yaml"), []byte(zoneYAML), 0o640); err != nil {
			t.Fatal(err)
		}
		zones := zone.NewStore(zonesDir, filepath.Join(dir, "serials.json"), discard())
		zones.LoadAll()

		s := server.New(mgr, zones, nil, metrics.New(), discard(), discard(), discard())
		if err := s.Start(); err != nil {
			continue // the reserved port got taken: retry with a new one
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			s.Shutdown(ctx)
			cancel()
		})
		return listen
	}
	t.Fatal("could not bind a shared udp+tcp port")
	return ""
}

// reservePort finds a free port; the caller re-binds it right away.
func reservePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// newSecondary builds a store+manager pair for a secondary of
// example.org pulling from primaryAddr, persisting under stateDir.
func newSecondary(t *testing.T, primaryAddr, stateDir string) (*zone.Store, *Manager) {
	t.Helper()
	dir := t.TempDir()
	yaml := "zone: example.org\ntype: secondary\nprimaries: [\"" + primaryAddr + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "example.org.yaml"), []byte(yaml), 0o640); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })

	store := zone.NewStore(dir, filepath.Join(dir, "serials.json"), discard())
	mg := NewManager(store, metrics.New(), discard(), stateDir, stop)
	store.OnLoad = mg.ZoneLoaded
	store.OnRemove = mg.ZoneRemoved
	store.LoadAll()
	return store, mg
}

func waitLoaded(t *testing.T, store *zone.Store, apex string) *zone.Zone {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if z := store.Find(apex); z != nil && z.Loaded() {
			return z
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("zone %s not transferred in time", apex)
	return nil
}

func TestSecondaryTransfersFromPrimary(t *testing.T) {
	primary := startPrimary(t, primaryZone)
	stateDir := t.TempDir()
	store, _ := newSecondary(t, primary, stateDir)

	z := waitLoaded(t, store, "example.org.")
	res := z.Lookup("www.example.org.", dns.TypeA)
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 1 {
		t.Fatalf("transferred zone must answer: %+v", res)
	}
	if z.Serial == 0 {
		t.Fatal("transferred serial must come from the primary SOA")
	}

	// The transferred copy is persisted for restart resume.
	if _, err := os.Stat(filepath.Join(stateDir, "example.org.zone")); err != nil {
		t.Fatalf("persisted copy missing: %v", err)
	}
}

func TestSecondaryResumesFromPersistedCopy(t *testing.T) {
	primary := startPrimary(t, primaryZone)
	stateDir := t.TempDir()
	store, _ := newSecondary(t, primary, stateDir)
	waitLoaded(t, store, "example.org.")

	// New store+manager, same state dir, but the primary is gone
	// (closed port): the zone must come back from disk.
	dead := fmt.Sprintf("127.0.0.1:%d", reservePort(t))
	store2, _ := newSecondary(t, dead, stateDir)
	z := waitLoaded(t, store2, "example.org.")
	if res := z.Lookup("www.example.org.", dns.TypeA); len(res.Answer) != 1 {
		t.Fatalf("resumed zone must answer: %+v", res)
	}
}

func TestHandleNotify(t *testing.T) {
	primary := startPrimary(t, primaryZone)
	stateDir := t.TempDir()
	store, mg := newSecondary(t, primary, stateDir)
	waitLoaded(t, store, "example.org.")

	primaryIP := netip.MustParseAddr("127.0.0.1")
	if rc := mg.HandleNotify("example.org.", primaryIP); rc != dns.RcodeSuccess {
		t.Fatalf("NOTIFY from a primary must be NOERROR, got %s", dns.RcodeToString[rc])
	}
	if rc := mg.HandleNotify("example.org.", netip.MustParseAddr("203.0.113.99")); rc != dns.RcodeRefused {
		t.Fatalf("NOTIFY from a stranger must be REFUSED, got %s", dns.RcodeToString[rc])
	}
	if rc := mg.HandleNotify("unknown.zone.", primaryIP); rc != dns.RcodeRefused {
		t.Fatalf("NOTIFY for an unknown zone must be REFUSED, got %s", dns.RcodeToString[rc])
	}
}

func TestNotifyFanOutOnPrimaryLoad(t *testing.T) {
	// A fake secondary captures the NOTIFYs a primary zone fans out.
	got := make(chan *dns.Msg, 4)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fake := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		got <- r
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})}
	go fake.ActivateAndServe()
	t.Cleanup(func() { fake.Shutdown() })

	dir := t.TempDir()
	yaml := primaryZone + "  notify: [\"" + pc.LocalAddr().String() + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "example.org.yaml"), []byte(yaml), 0o640); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	store := zone.NewStore(dir, filepath.Join(dir, "serials.json"), discard())
	mg := NewManager(store, metrics.New(), discard(), t.TempDir(), stop)
	store.OnLoad = mg.ZoneLoaded
	store.LoadAll()

	select {
	case msg := <-got:
		if msg.Opcode != dns.OpcodeNotify || msg.Question[0].Name != "example.org." {
			t.Fatalf("unexpected notify: %v", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NOTIFY not received")
	}
}

func TestSerialNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 2, false},
		{1, 1, false},
		{0, 4294967295, true}, // RFC 1982 wraparound
		{4294967295, 0, false},
	} {
		if got := serialNewer(tc.a, tc.b); got != tc.want {
			t.Fatalf("serialNewer(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
