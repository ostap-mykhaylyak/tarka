package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// startRRLServer boots a server with a tiny RRL cap (2 rps, no slip).
func startRRLServer(t *testing.T) (udp, tcp string) {
	t.Helper()
	dir := t.TempDir()
	cfgYAML := "server:\n  listen: [\"127.0.0.1:0\"]\n" +
		"rrl:\n  enabled: true\n  responses_per_second: 2\n  window: 15s\n  slip: 0\n" +
		"  ipv4_prefix: 24\n  ipv6_prefix: 56\n"
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o640); err != nil {
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
	if err := os.WriteFile(filepath.Join(zonesDir, "example.com.yaml"), []byte(testZone), 0o640); err != nil {
		t.Fatal(err)
	}
	zones := zone.NewStore(zonesDir, filepath.Join(dir, "serials.json"), discard())
	zones.LoadAll()

	s := New(mgr, zones, nil, metrics.New(), discard(), discard(), discard())
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(tContext(t)) })
	for _, b := range s.Bound() {
		switch b[:3] {
		case "udp":
			udp = b[4:]
		case "tcp":
			tcp = b[4:]
		}
	}
	return udp, tcp
}

func udpQuery(t *testing.T, addr string) (*dns.Msg, error) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	c := &dns.Client{Net: "udp", Timeout: time.Second}
	in, _, err := c.Exchange(m, addr)
	return in, err
}

func TestRRLDropsOverCapUDP(t *testing.T) {
	udp, tcp := startRRLServer(t)

	// The bucket starts full (2): first two pass.
	for i := 0; i < 2; i++ {
		if in, err := udpQuery(t, udp); err != nil || in.Rcode != dns.RcodeSuccess {
			t.Fatalf("query %d must pass: %v %v", i, in, err)
		}
	}
	// The next identical query is dropped: no response, client times out.
	if _, err := udpQuery(t, udp); err == nil {
		t.Fatal("over-cap UDP query must be dropped (timeout expected)")
	}

	// TCP is never rate-limited: same query answers fine.
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	in, _, err := c.Exchange(m, tcp)
	if err != nil || in.Rcode != dns.RcodeSuccess || len(in.Answer) != 1 {
		t.Fatalf("TCP must bypass RRL: %v %v", in, err)
	}
}
