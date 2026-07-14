package zone

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// A zone whose NS set names two slaves (via glue) and the master
// itself: with auto-discovery the slaves get transfer + NOTIFY with
// zero configuration, the master's own IP is ignored.
const autoZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS,   value: ns1.example.com.}
  - {name: "@",  type: NS,   value: ns2.example.com.}
  - {name: "@",  type: NS,   value: ns3.example.com.}
  - {name: ns1,  type: A,    value: 198.51.100.1}   # the master itself
  - {name: ns2,  type: A,    value: 203.0.113.2}    # slave
  - {name: ns3,  type: A,    value: 203.0.113.3}    # slave
  - {name: ns3,  type: AAAA, value: "2001:db8::3"}  # slave, v6
  - {name: www,  type: A,    value: 198.51.100.10}
`

func TestNSGlueAddrs(t *testing.T) {
	z, _, err := Build([]byte(autoZone), "f.yaml", func(string) uint32 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	got := z.NSGlueAddrs()
	if len(got) != 4 {
		t.Fatalf("want 4 glue addrs, got %v", got)
	}
}

func TestAutoDiscoveredSecondaries(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", autoZone)
	s := newTestStore(t, dir)
	self := []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	s.SetCatalog("catalog.tarka.", nil, true, self)
	s.LoadAll()

	z := s.Find("example.com.")
	for _, slave := range []string{"203.0.113.2", "203.0.113.3", "2001:db8::3"} {
		if !z.TransferAllowed(netip.MustParseAddr(slave)) {
			t.Fatalf("NS glue %s must be allowed to transfer", slave)
		}
	}
	// The master's own glue is not a slave; strangers stay refused.
	if z.TransferAllowed(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("self must not become a secondary")
	}
	if z.TransferAllowed(netip.MustParseAddr("203.0.113.99")) {
		t.Fatal("strangers must stay refused")
	}
	// NOTIFY fan-out derived too (self excluded).
	notify := map[string]bool{}
	for _, target := range z.Transfer.Notify {
		notify[target] = true
	}
	if !notify["203.0.113.2:53"] || !notify["203.0.113.3:53"] || len(notify) != 3 {
		t.Fatalf("derived notify fan-out broken: %v", z.Transfer.Notify)
	}

	// The catalog is published for the derived slaves too.
	cat := s.Find("catalog.tarka.")
	if cat == nil || !cat.TransferAllowed(netip.MustParseAddr("203.0.113.2")) {
		t.Fatalf("catalog must be published and transferable by derived slaves: %+v", cat)
	}
}

// Two NS names whose glue points at this same server: no secondaries
// at all — no merged ACL, no catalog published.
func TestAutoDiscoveryAllGlueIsSelf(t *testing.T) {
	dir := t.TempDir()
	writeZoneFile(t, dir, "example.com.yaml", `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: "@",  type: NS, value: ns2.example.com.}
  - {name: ns1,  type: A,  value: 198.51.100.1}
  - {name: ns2,  type: A,  value: 198.51.100.1}
`)
	s := newTestStore(t, dir)
	self := []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	s.SetCatalog("catalog.tarka.", nil, true, self)
	s.LoadAll()

	if s.Find("catalog.tarka.") != nil {
		t.Fatal("no secondaries -> no catalog to publish")
	}
	if s.Find("example.com.").TransferAllowed(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("self glue must not open transfers")
	}
	if len(s.Find("example.com.").Transfer.Notify) != 0 {
		t.Fatalf("self glue must not produce NOTIFY targets: %v", s.Find("example.com.").Transfer.Notify)
	}
}

// Content changes of a member zone must NOTIFY the derived slaves:
// the OnLoad hook receives the SERVING zone, catalog targets merged.
func TestOnLoadCarriesMergedNotifyTargets(t *testing.T) {
	dir := t.TempDir()
	path := writeZoneFile(t, dir, "example.com.yaml", autoZone)
	s := newTestStore(t, dir)
	s.SetCatalog("catalog.tarka.", nil, true, []netip.Addr{netip.MustParseAddr("198.51.100.1")})
	s.LoadAll()

	var got []string
	s.OnLoad = func(z *Zone) {
		if z.Name == "example.com." {
			got = z.Transfer.Notify
		}
	}
	writeZoneFile(t, dir, "example.com.yaml", autoZone+"  - {name: new, type: A, value: 198.51.100.11}\n")
	s.LoadFile(path)

	if len(got) != 3 {
		t.Fatalf("OnLoad must see the derived NOTIFY targets, got %v", got)
	}
	// And the served zone answers the new record (overlay path intact).
	if res := s.Find("example.com.").Lookup("new.example.com.", dns.TypeA); len(res.Answer) != 1 {
		t.Fatalf("reloaded zone must serve the new record: %+v", res)
	}
}
