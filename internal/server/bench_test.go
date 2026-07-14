package server

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/logging"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// benchWriter is a no-op dns.ResponseWriter for measuring the handler
// without any socket.
type benchWriter struct{ udp *net.UDPAddr }

func (b *benchWriter) LocalAddr() net.Addr       { return b.udp }
func (b *benchWriter) RemoteAddr() net.Addr      { return b.udp }
func (b *benchWriter) WriteMsg(*dns.Msg) error   { return nil }
func (b *benchWriter) Write([]byte) (int, error) { return 0, nil }
func (b *benchWriter) Close() error              { return nil }
func (b *benchWriter) TsigStatus() error         { return nil }
func (b *benchWriter) TsigTimersOnly(bool)       {}
func (b *benchWriter) Hijack()                   {}

const benchZone = `
zone: example.com
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",   type: NS,   value: ns1.example.com.}
  - {name: ns1,   type: A,    value: 203.0.113.10}
  - {name: "@",   type: A,    value: 203.0.113.10}
  - {name: www,   type: A,    value: 203.0.113.10}
  - {name: www,   type: AAAA, value: "2001:db8::10"}
  - {name: mail,  type: A,    value: 203.0.113.20}
  - {name: "@",   type: MX,   value: mail.example.com., prio: 10}
`

// benchServer builds a server with the bench zone, using the given
// query logger (discard, or a real file to measure I/O + the mutex).
func benchServer(b *testing.B, qlog *slog.Logger) *Server {
	return benchServerCfg(b, qlog, "server:\n  listen: [\"127.0.0.1:0\"]\n")
}

func benchServerCfg(b *testing.B, qlog *slog.Logger, cfgBody string) *Server {
	b.Helper()
	dir := b.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o640); err != nil {
		b.Fatal(err)
	}
	mgr, err := config.NewManager(cfgPath)
	if err != nil {
		b.Fatal(err)
	}
	zonesDir := filepath.Join(dir, "zones")
	os.MkdirAll(zonesDir, 0o750)
	os.WriteFile(filepath.Join(zonesDir, "example.com.yaml"), []byte(benchZone), 0o640)
	zones := zone.NewStore(zonesDir, filepath.Join(dir, "serials.json"), discard())
	zones.LoadAll()
	d := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return New(mgr, zones, nil, metrics.New(), qlog, d, d)
}

func benchQuery(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(1232, false)
	return m
}

func BenchmarkServeDNS_Answer(b *testing.B) {
	s := benchServer(b, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
	r := benchQuery("www.example.com.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ServeDNS(w, r)
	}
}

func BenchmarkServeDNS_NXDOMAIN(b *testing.B) {
	s := benchServer(b, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
	r := benchQuery("nope.example.com.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ServeDNS(w, r)
	}
}

// BenchmarkServeDNS_RealLog measures with a real query.log file to
// include the marshal + write() cost paid on every query.
func BenchmarkServeDNS_RealLog(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), "query.log")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	qlog := slog.New(slog.NewJSONHandler(f, nil))
	s := benchServer(b, qlog)
	w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
	r := benchQuery("www.example.com.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ServeDNS(w, r)
	}
}

// BenchmarkServeDNS_Parallel exposes lock contention on the shared
// query-log file under concurrency (the real-world hot path).
func BenchmarkServeDNS_Parallel(b *testing.B) {
	f, _ := os.CreateTemp(b.TempDir(), "query.log")
	defer f.Close()
	s := benchServer(b, slog.New(slog.NewJSONHandler(f, nil)))
	r := benchQuery("www.example.com.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
		for pb.Next() {
			s.ServeDNS(w, r)
		}
	})
}

// BenchmarkServeDNS_LogBuffered uses the real buffered query.log (the
// production path): the per-query write is a memcpy into a buffer,
// flushed in the background — no write(2) on the hot path.
func BenchmarkServeDNS_LogBuffered(b *testing.B) {
	logs, err := logging.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer logs.Close()
	s := benchServer(b, logs.Query)
	w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
	r := benchQuery("www.example.com.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ServeDNS(w, r)
	}
}

// BenchmarkServeDNS_LogBufferedParallel is the same, concurrent: shows
// how the buffered log scales versus the unbuffered one.
func BenchmarkServeDNS_LogBufferedParallel(b *testing.B) {
	logs, err := logging.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer logs.Close()
	s := benchServer(b, logs.Query)
	r := benchQuery("www.example.com.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
		for pb.Next() {
			s.ServeDNS(w, r)
		}
	})
}

// BenchmarkServeDNS_LogOff measures the handler with query logging
// disabled (server.query_log: false) — the maximum-throughput mode.
func BenchmarkServeDNS_LogOff(b *testing.B) {
	s := benchServerCfg(b, slog.New(slog.NewJSONHandler(io.Discard, nil)),
		"server:\n  listen: [\"127.0.0.1:0\"]\n  query_log: false\n")
	r := benchQuery("www.example.com.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := &benchWriter{udp: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 200), Port: 5353}}
		for pb.Next() {
			s.ServeDNS(w, r)
		}
	})
}

func BenchmarkStoreFind(b *testing.B) {
	s := benchServer(b, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.zones.Find("www.example.com.")
	}
}
