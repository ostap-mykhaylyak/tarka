package server

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

const xfrZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: ns1,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.10}
transfer:
  allow: [127.0.0.1, "::1"]
`

func axfrIn(t *testing.T, tcpAddr, apex string) ([]dns.RR, error) {
	t.Helper()
	m := new(dns.Msg)
	m.SetAxfr(apex)
	tr := &dns.Transfer{DialTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second}
	env, err := tr.In(m, tcpAddr)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			return nil, e.Error
		}
		rrs = append(rrs, e.RR...)
	}
	return rrs, nil
}

func TestAXFROutAllowed(t *testing.T) {
	_, tcp, _ := startServer(t, xfrZone)
	rrs, err := axfrIn(t, tcp, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	// SOA + NS + 2 A + closing SOA.
	if len(rrs) != 5 {
		t.Fatalf("want 5 records, got %d: %v", len(rrs), rrs)
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Fatalf("transfer must start with the SOA: %v", rrs[0])
	}
	if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
		t.Fatalf("transfer must end with the SOA: %v", rrs[len(rrs)-1])
	}
}

func TestAXFROutRefusedByACL(t *testing.T) {
	// testZone ships no transfer.allow: everyone is refused.
	_, tcp, _ := startServer(t, testZone)
	if _, err := axfrIn(t, tcp, "example.com."); err == nil {
		t.Fatal("AXFR without ACL match must fail")
	}
}

func TestAXFROutNonApexRefused(t *testing.T) {
	_, tcp, _ := startServer(t, xfrZone)
	if _, err := axfrIn(t, tcp, "www.example.com."); err == nil {
		t.Fatal("AXFR below the apex must fail")
	}
}

func TestIXFROverUDPAnswersSOAOnly(t *testing.T) {
	udp, _, _ := startServer(t, xfrZone)
	in := query(t, "udp", udp, "example.com.", dns.TypeIXFR, false)
	if in.Rcode != dns.RcodeSuccess || len(in.Answer) != 1 {
		t.Fatalf("UDP IXFR must answer the SOA alone: %v", in)
	}
	if _, ok := in.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("UDP IXFR answer must be the SOA: %v", in.Answer)
	}
}

func TestNotifyRefusedWithoutReceiver(t *testing.T) {
	udp, _, _ := startServer(t, xfrZone)
	m := new(dns.Msg)
	m.SetNotify("example.com.")
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	in, _, err := c.Exchange(m, udp)
	if err != nil {
		t.Fatal(err)
	}
	if in.Rcode != dns.RcodeRefused {
		t.Fatalf("NOTIFY without a receiver must be REFUSED, got %s", dns.RcodeToString[in.Rcode])
	}
}
