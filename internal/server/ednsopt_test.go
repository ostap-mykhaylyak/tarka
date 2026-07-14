package server

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// queryOpt sends a query carrying a custom OPT (with the given
// options) and returns the response.
func queryOpt(t *testing.T, addr, qname string, qtype uint16, opts []dns.EDNS0) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(1232)
	o.Option = append(o.Option, opts...)
	m.Extra = append(m.Extra, o)
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	in, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func respEDE(m *dns.Msg) *dns.EDNS0_EDE {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if e, ok := o.(*dns.EDNS0_EDE); ok {
				return e
			}
		}
	}
	return nil
}

func TestNSIDReportsIdentity(t *testing.T) {
	udp, _, _ := startServerIdentity(t, testZone, nil, "127.0.0.1:0", "ns1.example.com")

	// Without an NSID request: no NSID in the response.
	in := queryOpt(t, udp, "www.example.com.", dns.TypeA, nil)
	if opt := in.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_NSID); ok {
				t.Fatal("NSID must not be volunteered unrequested")
			}
		}
	}

	// With an empty NSID option: the server returns its identity.
	in = queryOpt(t, udp, "www.example.com.", dns.TypeA,
		[]dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}})
	var got string
	if opt := in.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if n, ok := o.(*dns.EDNS0_NSID); ok {
				b, _ := hex.DecodeString(n.Nsid)
				got = string(b)
			}
		}
	}
	if got != "ns1.example.com" {
		t.Fatalf("NSID identity broken: %q", got)
	}
}

func TestEDENotAuthoritative(t *testing.T) {
	udp, _, _ := startServer(t, testZone)
	in := queryOpt(t, udp, "www.google.com.", dns.TypeA, nil)
	if in.Rcode != dns.RcodeRefused {
		t.Fatalf("foreign zone must be REFUSED, got %s", dns.RcodeToString[in.Rcode])
	}
	ede := respEDE(in)
	if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeNotAuthoritative {
		t.Fatalf("REFUSED must carry EDE Not Authoritative, got %+v", ede)
	}
}

func TestEDESecondaryServfail(t *testing.T) {
	// An untransferred secondary answers SERVFAIL + EDE.
	udp, _, _ := startServer(t, "zone: example.com\ntype: secondary\nprimaries: [203.0.113.9]\n")
	in := queryOpt(t, udp, "www.example.com.", dns.TypeA, nil)
	if in.Rcode != dns.RcodeServerFailure {
		t.Fatalf("untransferred secondary must SERVFAIL, got %s", dns.RcodeToString[in.Rcode])
	}
	if ede := respEDE(in); ede == nil || ede.InfoCode != dns.ExtendedErrorCodeOther {
		t.Fatalf("SERVFAIL must carry an explanatory EDE, got %+v", ede)
	}
}

func TestNoEDNSNoOptions(t *testing.T) {
	// A plain (non-EDNS) client must still get a valid bare response.
	udp, _, _ := startServer(t, testZone)
	in := query(t, "udp", udp, "www.google.com.", dns.TypeA, false)
	if in.Rcode != dns.RcodeRefused || in.IsEdns0() != nil {
		t.Fatalf("non-EDNS REFUSED must be bare: rcode=%s edns=%v", dns.RcodeToString[in.Rcode], in.IsEdns0())
	}
}
