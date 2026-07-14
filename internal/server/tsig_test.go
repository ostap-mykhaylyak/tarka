package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

const tsigKeyB64 = "c2VjcmV0LWtleS1mb3ItdGVzdGluZy0xMjM0NTY3OA==" // base64
const tsigZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: ns1,  type: A,  value: 203.0.113.10}
  - {name: www,  type: A,  value: 203.0.113.10}
transfer:
  allow: [127.0.0.1, "::1"]
`

// startTSIGServer boots a server that requires TSIG for transfers.
func startTSIGServer(t *testing.T) (tcpAddr string) {
	t.Helper()
	dir := t.TempDir()
	cfgYAML := "server:\n  listen: [\"127.0.0.1:0\"]\n" +
		"tsig:\n  name: xfer\n  algorithm: hmac-sha256\n  secret: " + tsigKeyB64 + "\n  require: true\n"
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
	if err := os.WriteFile(filepath.Join(zonesDir, "example.com.yaml"), []byte(tsigZone), 0o640); err != nil {
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
		if len(b) > 4 && b[:3] == "tcp" {
			tcpAddr = b[4:]
		}
	}
	return tcpAddr
}

func TestAXFRRequiresTSIG(t *testing.T) {
	tcp := startTSIGServer(t)
	secret := map[string]string{"xfer.": tsigKeyB64}

	// Unsigned AXFR against a require:true server is refused.
	if _, err := axfrIn(t, tcp, "example.com."); err == nil {
		t.Fatal("unsigned AXFR must fail when tsig.require is set")
	}

	// Correctly signed AXFR succeeds.
	m := new(dns.Msg)
	m.SetAxfr("example.com.")
	m.SetTsig("xfer.", dns.HmacSHA256, 300, time.Now().Unix())
	tr := &dns.Transfer{TsigSecret: secret}
	env, err := tr.In(m, tcp)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for e := range env {
		if e.Error != nil {
			t.Fatalf("signed AXFR envelope error: %v", e.Error)
		}
		n += len(e.RR)
	}
	if n < 4 {
		t.Fatalf("signed AXFR returned too few records: %d", n)
	}

	// A wrong key is rejected.
	m = new(dns.Msg)
	m.SetAxfr("example.com.")
	m.SetTsig("xfer.", dns.HmacSHA256, 300, time.Now().Unix())
	tr = &dns.Transfer{TsigSecret: map[string]string{"xfer.": "d3Jvbmcta2V5LXZhbHVlLTAwMDAwMDAw"}}
	if env, err := tr.In(m, tcp); err == nil {
		bad := false
		for e := range env {
			if e.Error != nil {
				bad = true
			}
		}
		if !bad {
			t.Fatal("AXFR with a wrong TSIG key must fail")
		}
	}
}

func tContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
