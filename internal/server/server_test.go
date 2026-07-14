package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

const testZone = `
zone: example.com
soa:
  mname: ns1.example.com.
  rname: hostmaster.example.com.
records:
  - {name: "@",  type: NS,  value: ns1.example.com.}
  - {name: ns1,  type: A,   value: 203.0.113.10}
  - {name: www,  type: A,   value: 203.0.113.10}
  - {name: big,  type: TXT, value: "` + "x" + `"}
`

// startServer boots a real server on loopback ephemeral ports and
// returns the resolved UDP and TCP addresses.
func startServer(t *testing.T, zoneYAML string) (udpAddr, tcpAddr string, s *Server) {
	t.Helper()
	return startServerGeo(t, zoneYAML, nil)
}

// startServerGeo is startServer with an injectable geo resolver.
func startServerGeo(t *testing.T, zoneYAML string, geo GeoResolver) (udpAddr, tcpAddr string, s *Server) {
	t.Helper()
	return startServerFull(t, zoneYAML, geo, "127.0.0.1:0")
}

// startServerListen is startServer on a specific listen address.
func startServerListen(t *testing.T, zoneYAML, listen string) (udpAddr, tcpAddr string, s *Server) {
	t.Helper()
	return startServerFull(t, zoneYAML, nil, listen)
}

func startServerFull(t *testing.T, zoneYAML string, geo GeoResolver, listen string) (udpAddr, tcpAddr string, s *Server) {
	t.Helper()
	return startServerOpts(t, zoneYAML, geo, nil, listen, "")
}

func startServerIdentity(t *testing.T, zoneYAML string, geo GeoResolver, listen, identity string) (udpAddr, tcpAddr string, s *Server) {
	t.Helper()
	return startServerOpts(t, zoneYAML, geo, nil, listen, identity)
}

// startServerOpts wires geo/view resolvers and NSID identity BEFORE
// Start, so the running server is never mutated while it serves
// (which would race under -race).
func startServerOpts(t *testing.T, zoneYAML string, geo GeoResolver, vr ViewResolver, listen, identity string) (udpAddr, tcpAddr string, s *Server) {
	t.Helper()
	dir := t.TempDir()

	cfgBody := "server:\n  listen: [\"" + listen + "\"]\n"
	if identity != "" {
		cfgBody += "  identity: \"" + identity + "\"\n"
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o640); err != nil {
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
	if err := os.WriteFile(filepath.Join(zonesDir, "example.com.yaml"), []byte(zoneYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	zones := zone.NewStore(zonesDir, filepath.Join(dir, "serials.json"), discard())
	zones.LoadAll()

	s = New(mgr, zones, geo, metrics.New(), discard(), discard(), discard())
	if vr != nil {
		s.SetViewResolver(vr)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s.Shutdown(ctx)
		cancel()
	})

	for _, b := range s.Bound() {
		proto, addr, _ := strings.Cut(b, " ")
		switch proto {
		case "udp":
			udpAddr = addr
		case "tcp":
			tcpAddr = addr
		}
	}
	if udpAddr == "" || tcpAddr == "" {
		t.Fatalf("bound addresses missing: %v", s.Bound())
	}
	return udpAddr, tcpAddr, s
}

func discard() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func query(t *testing.T, net, addr, qname string, qtype uint16, edns bool) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	if edns {
		m.SetEdns0(1232, false)
	}
	c := &dns.Client{Net: net, Timeout: 3 * time.Second}
	in, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s query %s %s: %v", net, qname, dns.TypeToString[qtype], err)
	}
	return in
}

func TestAuthoritativeAnswerUDPAndTCP(t *testing.T) {
	udp, tcp, _ := startServer(t, testZone)
	for _, net := range []string{"udp", "tcp"} {
		addr := udp
		if net == "tcp" {
			addr = tcp
		}
		in := query(t, net, addr, "www.example.com.", dns.TypeA, false)
		if in.Rcode != dns.RcodeSuccess || !in.Authoritative || len(in.Answer) != 1 {
			t.Fatalf("%s: authoritative answer broken: %v", net, in)
		}
		if a := in.Answer[0].(*dns.A); a.A.String() != "203.0.113.10" {
			t.Fatalf("%s: wrong answer: %v", net, a)
		}
	}
}

func TestRefusedOutsideZones(t *testing.T) {
	udp, _, _ := startServer(t, testZone)
	in := query(t, "udp", udp, "www.google.com.", dns.TypeA, false)
	if in.Rcode != dns.RcodeRefused {
		t.Fatalf("foreign zone must be REFUSED, got %s", dns.RcodeToString[in.Rcode])
	}
}

func TestNXDomainHasSOA(t *testing.T) {
	udp, _, _ := startServer(t, testZone)
	in := query(t, "udp", udp, "missing.example.com.", dns.TypeA, false)
	if in.Rcode != dns.RcodeNameError || len(in.Ns) != 1 {
		t.Fatalf("NXDOMAIN broken: %v", in)
	}
	if _, ok := in.Ns[0].(*dns.SOA); !ok {
		t.Fatalf("authority must carry the SOA: %v", in.Ns)
	}
}

func TestANYGetsRFC8482(t *testing.T) {
	udp, _, _ := startServer(t, testZone)
	in := query(t, "udp", udp, "www.example.com.", dns.TypeANY, false)
	if len(in.Answer) != 1 {
		t.Fatalf("ANY must get one minimal answer: %v", in)
	}
	if h, ok := in.Answer[0].(*dns.HINFO); !ok || h.Cpu != "RFC8482" {
		t.Fatalf("ANY must answer HINFO RFC8482: %v", in.Answer)
	}
}

func TestEDNSAdvertisedAndTruncationOverUDP(t *testing.T) {
	// A zone with many TXT records at one name: the answer exceeds
	// 512 bytes, so a plain-UDP client gets TC and a TCP retry works.
	big := strings.Repeat("a", 200)
	zoneYAML := `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS,  value: ns1.example.com.}
  - {name: ns1,  type: A,   value: 203.0.113.10}
  - {name: big, type: TXT, value: "` + big + `1"}
  - {name: big, type: TXT, value: "` + big + `2"}
  - {name: big, type: TXT, value: "` + big + `3"}
  - {name: big, type: TXT, value: "` + big + `4"}
`
	udp, tcp, _ := startServer(t, zoneYAML)

	// Plain UDP (no EDNS): 512-byte limit, must truncate.
	in := query(t, "udp", udp, "big.example.com.", dns.TypeTXT, false)
	if !in.Truncated {
		t.Fatalf("oversized plain-UDP answer must set TC: %d answers, len %d", len(in.Answer), in.Len())
	}

	// EDNS with a 1232 buffer: fits, no truncation, OPT advertised.
	in = query(t, "udp", udp, "big.example.com.", dns.TypeTXT, true)
	if in.Truncated || len(in.Answer) != 4 {
		t.Fatalf("EDNS answer must fit: tc=%v answers=%d", in.Truncated, len(in.Answer))
	}
	opt := in.IsEdns0()
	if opt == nil || opt.UDPSize() != 1232 {
		t.Fatalf("server must advertise its EDNS payload size: %v", opt)
	}

	// TCP: never truncated.
	in = query(t, "tcp", tcp, "big.example.com.", dns.TypeTXT, false)
	if in.Truncated || len(in.Answer) != 4 {
		t.Fatalf("TCP answer must be complete: tc=%v answers=%d", in.Truncated, len(in.Answer))
	}
}

func TestNonQueryOpcodeNotImplemented(t *testing.T) {
	udp, _, _ := startServer(t, testZone)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeSOA)
	m.Opcode = dns.OpcodeStatus
	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	in, _, err := c.Exchange(m, udp)
	if err != nil {
		t.Fatal(err)
	}
	if in.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("non-query opcode must be NOTIMP, got %s", dns.RcodeToString[in.Rcode])
	}
}
