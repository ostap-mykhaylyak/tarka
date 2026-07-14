package xfr

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// soaResponder answers SOA queries for apex with a serial the caller
// can set later (so it can match the master's managed serial).
func soaResponder(t *testing.T, apex string) (addr string, setSerial func(uint32)) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var serial atomic.Uint32
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{&dns.SOA{
			Hdr:    dns.RR_Header{Name: dns.Fqdn(apex), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:     "ns1." + dns.Fqdn(apex),
			Mbox:   "h." + dns.Fqdn(apex),
			Serial: serial.Load(),
		}}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String(), serial.Store
}

func TestLagMonitor(t *testing.T) {
	// One secondary in sync (same serial as ours), one dead.
	inSync, setSerial := soaResponder(t, "mon.example.")
	deadAddr := fmt.Sprintf("127.0.0.1:%d", reservePort(t))

	dir := t.TempDir()
	yaml := `
zone: mon.example
soa: {mname: ns1.mon.example., rname: hostmaster.mon.example.}
records:
  - {name: "@", type: NS, value: ns1.mon.example.}
  - {name: ns1, type: A, value: 203.0.113.10}
`
	if err := os.WriteFile(filepath.Join(dir, "mon.example.yaml"), []byte(yaml), 0o640); err != nil {
		t.Fatal(err)
	}
	store := zone.NewStore(dir, filepath.Join(dir, "serials.json"), discard())
	// Declare both secondaries explicitly (auto-discovery off).
	store.SetCatalog("catalog.tarka.", []string{inSync, deadAddr}, false, nil)
	store.LoadAll()
	// The in-sync responder reports exactly our managed serial.
	setSerial(store.Find("mon.example.").Serial)

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	mg := NewManager(store, metrics.New(), discard(), t.TempDir(), stop)

	mg.checkLag()
	lags := mg.LagSnapshot()
	if len(lags) != 2 {
		t.Fatalf("want 2 probes, got %d: %+v", len(lags), lags)
	}
	var okSync, dead int
	for _, l := range lags {
		switch {
		case l.Reachable && !l.Behind:
			okSync++
		case !l.Reachable:
			dead++
		}
	}
	if okSync != 1 || dead != 1 {
		t.Fatalf("want 1 in-sync + 1 unreachable, got %+v", lags)
	}
}
