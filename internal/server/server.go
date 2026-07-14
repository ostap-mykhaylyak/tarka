// Package server runs the authoritative DNS listeners (UDP + TCP on
// every configured address) and answers queries from the zone store.
//
// tarka is authoritative-only: no recursion, no forwarding. Queries
// for zones it does not host are answered with REFUSED.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/geoip"
	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/rrl"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// NotifyReceiver handles an incoming NOTIFY for apex from a source
// IP and returns the DNS rcode to answer with. Implemented by the
// xfr manager; nil means NOTIFY is refused.
type NotifyReceiver interface {
	HandleNotify(apex string, from netip.Addr) int
}

// GeoResolver locates a client IP for the geo-tagged records.
// Implemented by internal/geoip; nil (or not loaded) means geo
// records never match and the defaults answer.
type GeoResolver interface {
	Lookup(addr netip.Addr) geoip.Geo
	Loaded() bool
}

// ViewResolver maps a resolver's IP to the provider views it belongs
// to, for the view-tagged records. Implemented by internal/views;
// nil (or not loaded) means view records never match.
type ViewResolver interface {
	Lookup(addr netip.Addr) []string
	Loaded() bool
}

// Server owns the DNS listeners. Listen addresses, tcp_timeout, TSIG
// and RRL are read at Start: changing them requires a restart.
// udp_payload_size is read per-query and hot-reloads.
type Server struct {
	mgr      *config.Manager
	zones    *zone.Store
	geo      GeoResolver
	views    ViewResolver
	m        *metrics.Metrics
	qlog     *slog.Logger
	xlog     *slog.Logger
	slog     *slog.Logger
	notify   NotifyReceiver
	rrl      *rrl.Limiter
	tsig     map[string]string // key name -> secret; nil when disabled
	tsigReq  bool              // refuse unsigned AXFR
	identity string            // NSID payload (hostname or configured)
	servers  []*dns.Server
	bound    []string // "udp host:port", "tcp host:port" (resolved, for tests and logs)
}

// New wires the server; Start binds the sockets. geo may be nil.
func New(mgr *config.Manager, zones *zone.Store, geo GeoResolver, m *metrics.Metrics, qlog, xlog, service *slog.Logger) *Server {
	return &Server{mgr: mgr, zones: zones, geo: geo, m: m, qlog: qlog, xlog: xlog, slog: service}
}

// SetNotifyReceiver wires the NOTIFY handler (call before Start).
func (s *Server) SetNotifyReceiver(nr NotifyReceiver) { s.notify = nr }

// SetViewResolver wires the resolver-IP view table (call before
// Start). nil disables view matching.
func (s *Server) SetViewResolver(vr ViewResolver) { s.views = vr }

// Start binds UDP and TCP on every configured address and serves in
// background goroutines. Bind errors are synchronous and fatal.
func (s *Server) Start() error {
	cfg := s.mgr.Get()
	timeout := cfg.Server.TCPTimeout.Std()

	if cfg.RRL.Enabled {
		s.rrl = rrl.New(cfg.RRL.ResponsesPerSecond, cfg.RRL.Window.Std(),
			cfg.RRL.Slip, cfg.RRL.IPv4Prefix, cfg.RRL.IPv6Prefix)
		s.slog.Info("response rate limiting enabled",
			"responses_per_second", cfg.RRL.ResponsesPerSecond, "slip", cfg.RRL.Slip)
	}
	if cfg.TSIG.Enabled() {
		s.tsig = cfg.TSIG.SecretMap()
		s.tsigReq = cfg.TSIG.Require
		s.slog.Info("tsig enabled for transfers", "key", cfg.TSIG.KeyName(), "require", s.tsigReq)
	}
	s.identity = cfg.Server.Identity
	if s.identity == "" {
		if h, err := os.Hostname(); err == nil {
			s.identity = h
		}
	}

	for _, addr := range cfg.Server.Listen {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return bindError("udp", addr, err)
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close()
			return bindError("tcp", addr, err)
		}
		udp := &dns.Server{PacketConn: pc, Handler: s, TsigSecret: s.tsig}
		tcp := &dns.Server{Listener: l, Handler: s, ReadTimeout: timeout, WriteTimeout: timeout, TsigSecret: s.tsig}
		s.servers = append(s.servers, udp, tcp)
		s.bound = append(s.bound,
			"udp "+pc.LocalAddr().String(),
			"tcp "+l.Addr().String())
		go s.serve(udp, "udp", pc.LocalAddr().String())
		go s.serve(tcp, "tcp", l.Addr().String())
	}
	s.slog.Info("dns server started", "listen", cfg.Server.Listen)
	return nil
}

// Bound returns the resolved listener addresses ("udp 1.2.3.4:53").
func (s *Server) Bound() []string { return s.bound }

func (s *Server) serve(d *dns.Server, proto, addr string) {
	if err := d.ActivateAndServe(); err != nil {
		s.slog.Error("dns listener failed", "proto", proto, "addr", addr, "error", err)
	}
}

// Shutdown drains every listener.
func (s *Server) Shutdown(ctx context.Context) {
	for _, d := range s.servers {
		d.ShutdownContext(ctx)
	}
}

func bindError(proto, addr string, err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("listen %s %s: %w — port already in use: a local resolver "+
			"(e.g. systemd-resolved) may be bound to 53; list specific IPs in server.listen", proto, addr, err)
	}
	return fmt.Errorf("listen %s %s: %w", proto, addr, err)
}
