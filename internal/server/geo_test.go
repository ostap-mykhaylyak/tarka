package server

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/geoip"
)

const geoZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: ns1,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.30, geo: [IT]}
`

// fakeGeo maps specific addresses to countries.
type fakeGeo map[netip.Addr]geoip.Geo

func (f fakeGeo) Loaded() bool                      { return true }
func (f fakeGeo) Lookup(a netip.Addr) (g geoip.Geo) { return f[a] }

func TestGeoAnswerBySourceIP(t *testing.T) {
	// Every query in tests comes from 127.0.0.1: map it to Italy.
	geo := fakeGeo{netip.MustParseAddr("127.0.0.1"): {Country: "IT", Continent: "EU"}}
	udp, _, _ := startServerGeo(t, geoZone, geo)

	in := query(t, "udp", udp, "www.example.com.", dns.TypeA, false)
	if len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "203.0.113.30" {
		t.Fatalf("Italian client must get the IT record: %v", in.Answer)
	}
}

func TestGeoECSWinsOverSourceIP(t *testing.T) {
	// The connection comes from 127.0.0.1 (unknown to the fake), but
	// the resolver forwards the real client subnet via ECS. Only the
	// prefix travels on the wire (the host bits are masked out), so
	// the lookup sees the /24 base address.
	itPrefix := netip.MustParseAddr("203.0.113.0")
	geo := fakeGeo{itPrefix: {Country: "IT", Continent: "EU"}}
	udp, _, _ := startServerGeo(t, geoZone, geo)

	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1, // IPv4
		SourceNetmask: 24,
		Address:       net.ParseIP("203.0.113.77").To4(),
	})
	m.Extra = append(m.Extra, opt)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	in, _, err := c.Exchange(m, udp)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Answer) != 1 || in.Answer[0].(*dns.A).A.String() != "203.0.113.30" {
		t.Fatalf("ECS client must get the IT record: %v", in.Answer)
	}

	// The response must echo ECS with the honored scope (RFC 7871).
	ropt := in.IsEdns0()
	if ropt == nil {
		t.Fatal("response must carry EDNS")
	}
	var ecs *dns.EDNS0_SUBNET
	for _, o := range ropt.Option {
		if e, ok := o.(*dns.EDNS0_SUBNET); ok {
			ecs = e
		}
	}
	if ecs == nil || ecs.SourceScope != 24 {
		t.Fatalf("ECS must be echoed with scope 24: %+v", ecs)
	}
}

func TestGeoZeroScopeWithoutGeoRecords(t *testing.T) {
	// A zone without geo records answers any-client: scope 0.
	geo := fakeGeo{}
	udp, _, _ := startServerGeo(t, testZone, geo)

	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("203.0.113.77").To4(),
	})
	m.Extra = append(m.Extra, opt)

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	in, _, err := c.Exchange(m, udp)
	if err != nil {
		t.Fatal(err)
	}
	var ecs *dns.EDNS0_SUBNET
	if ropt := in.IsEdns0(); ropt != nil {
		for _, o := range ropt.Option {
			if e, ok := o.(*dns.EDNS0_SUBNET); ok {
				ecs = e
			}
		}
	}
	if ecs == nil || ecs.SourceScope != 0 {
		t.Fatalf("no-geo answers must echo scope 0: %+v", ecs)
	}
}

func TestIPv6Transport(t *testing.T) {
	udp6, tcp6, _ := startServerListen(t, testZone, "[::1]:0")
	for _, net := range []string{"udp", "tcp"} {
		addr := udp6
		if net == "tcp" {
			addr = tcp6
		}
		in := query(t, net, addr, "www.example.com.", dns.TypeA, false)
		if in.Rcode != dns.RcodeSuccess || len(in.Answer) != 1 {
			t.Fatalf("IPv6 %s query broken: %v", net, in)
		}
	}
}
