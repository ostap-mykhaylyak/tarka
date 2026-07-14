package server

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

const viewServerZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: ns1,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 198.51.100.10, view: [Fastweb]}
`

// fakeViews maps addresses to provider views.
type fakeViews map[netip.Addr][]string

func (f fakeViews) Loaded() bool                 { return true }
func (f fakeViews) Lookup(a netip.Addr) []string { return f[a] }

func TestViewAnswerBySourceIP(t *testing.T) {
	// Test queries come from 127.0.0.1: pretend it is a Fastweb
	// resolver.
	fv := fakeViews{netip.MustParseAddr("127.0.0.1"): {"fastweb"}}
	udp, _, _ := startServerOpts(t, viewServerZone, nil, fv, "127.0.0.1:0", "")

	in := query(t, "udp", udp, "www.example.com.", dns.TypeA, false)
	if len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "198.51.100.10" {
		t.Fatalf("Fastweb resolver must get the Fastweb record: %v", in.Answer)
	}
}

func TestViewFallbackWhenNoMatch(t *testing.T) {
	fv := fakeViews{} // 127.0.0.1 belongs to no provider
	udp, _, _ := startServerOpts(t, viewServerZone, nil, fv, "127.0.0.1:0", "")

	in := query(t, "udp", udp, "www.example.com.", dns.TypeA, false)
	if len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "203.0.113.10" {
		t.Fatalf("unknown resolver must get the default record: %v", in.Answer)
	}
}
