package alias

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// resolver answers A/AAAA for one target with fixed addresses.
func resolver(t *testing.T, target, a, aaaa string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == dns.Fqdn(target) {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(a)})
			case dns.TypeAAAA:
				if aaaa != "" {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: net.ParseIP(aaaa)})
				}
			}
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestAliasFlatteningEndToEnd(t *testing.T) {
	res := resolver(t, "lb.provider.net.", "198.51.100.5", "2001:db8::5")

	dir := t.TempDir()
	zonesDir := filepath.Join(dir, "zones")
	if err := os.MkdirAll(zonesDir, 0o750); err != nil {
		t.Fatal(err)
	}
	zoneYAML := `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS,    value: ns1.example.com.}
  - {name: ns1,  type: A,     value: 203.0.113.10}
  - {name: "@",  type: ALIAS, value: lb.provider.net.}
`
	if err := os.WriteFile(filepath.Join(zonesDir, "example.com.yaml"), []byte(zoneYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := "zones:\n  dir: " + filepath.ToSlash(zonesDir) + "\n" +
		"alias:\n  resolvers: [\"" + res + "\"]\n  refresh: 1h\n  ttl: 5m\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store := zone.NewStore(zonesDir, filepath.Join(dir, "serials.json"), discard())
	store.LoadAll()

	m := NewManager(mgr, store, discard())
	m.refreshAll() // one synchronous pass

	z := store.Find("example.com.")
	resA := z.Lookup("example.com.", dns.TypeA)
	if len(resA.Answer) != 1 || resA.Answer[0].(*dns.A).A.String() != "198.51.100.5" {
		t.Fatalf("apex ALIAS must resolve to the A record: %+v", resA)
	}
	resAAAA := z.Lookup("example.com.", dns.TypeAAAA)
	if len(resAAAA.Answer) != 1 || resAAAA.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::5" {
		t.Fatalf("apex ALIAS must resolve to the AAAA record: %+v", resAAAA)
	}
	_ = time.Second
}
