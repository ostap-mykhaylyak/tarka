// Package xfr implements zone transfers: AXFR out is served by
// internal/server (ACL-gated); this package owns the primary-side
// NOTIFY fan-out and the secondary-side refresh loops (SOA polling,
// AXFR in, refresh/retry/expire timers, NOTIFY-triggered refresh,
// persistence of the transferred copy).
package xfr

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/metrics"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// queryTimeout bounds one SOA query or transfer dial.
const queryTimeout = 5 * time.Second

// Manager reacts to zone (re)loads: primary zones fan out NOTIFY on
// serial changes, secondary zones get a refresh loop each.
type Manager struct {
	store *zone.Store
	m     *metrics.Metrics
	log   *slog.Logger
	dir   string // persisted secondary copies
	stop  <-chan struct{}

	mu       sync.Mutex
	loops    map[string]*secLoop
	notified map[string]uint32 // last NOTIFY-ed serial per primary zone
}

// NewManager wires the transfer manager. Hook ZoneLoaded/ZoneRemoved
// into the store BEFORE LoadAll so existing zones are picked up.
func NewManager(store *zone.Store, m *metrics.Metrics, log *slog.Logger, dir string, stop <-chan struct{}) *Manager {
	return &Manager{
		store:    store,
		m:        m,
		log:      log,
		dir:      dir,
		stop:     stop,
		loops:    map[string]*secLoop{},
		notified: map[string]uint32{},
	}
}

// ZoneLoaded is the store's OnLoad hook.
func (mg *Manager) ZoneLoaded(z *zone.Zone) {
	if z.Type == "primary" {
		mg.maybeNotify(z)
		return
	}
	mg.ensureLoop(z)
}

// ZoneRemoved is the store's OnRemove hook.
func (mg *Manager) ZoneRemoved(apex string) {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	if l, ok := mg.loops[apex]; ok {
		close(l.quit)
		delete(mg.loops, apex)
	}
	delete(mg.notified, apex)
}

// HandleNotify implements server.NotifyReceiver: a NOTIFY for a
// secondary zone coming from one of its primaries triggers an
// immediate refresh; anything else is refused (RFC 1996).
func (mg *Manager) HandleNotify(apex string, from netip.Addr) int {
	mg.mu.Lock()
	l, ok := mg.loops[apex]
	mg.mu.Unlock()
	if !ok {
		return dns.RcodeRefused
	}
	if !l.fromPrimary(from) {
		mg.log.Warn("notify refused", "zone", apex, "client", from.String())
		return dns.RcodeRefused
	}
	mg.m.NotifyReceived()
	mg.log.Info("notify received", "zone", apex, "client", from.String())
	l.wake()
	return dns.RcodeSuccess
}

// maybeNotify fans out NOTIFY to the zone's transfer.notify targets
// when the serial changed since the last fan-out (first load counts:
// the daemon may have been down while the zone changed).
func (mg *Manager) maybeNotify(z *zone.Zone) {
	if len(z.Transfer.Notify) == 0 {
		return
	}
	mg.mu.Lock()
	last, seen := mg.notified[z.Name]
	mg.notified[z.Name] = z.Serial
	mg.mu.Unlock()
	if seen && last == z.Serial {
		return
	}

	msg := new(dns.Msg)
	msg.SetNotify(z.Name)
	msg.Answer = []dns.RR{z.SOARR()} // current SOA hint (RFC 1996 §3.7)
	for _, target := range z.Transfer.Notify {
		go mg.sendNotify(z.Name, z.Serial, msg.Copy(), hostPort(target))
	}
}

func (mg *Manager) sendNotify(apex string, serial uint32, msg *dns.Msg, addr string) {
	c := &dns.Client{Net: "udp", Timeout: queryTimeout}
	in, _, err := c.Exchange(msg, addr)
	if err != nil {
		mg.log.Warn("notify send failed", "zone", apex, "target", addr, "error", err)
		return
	}
	mg.m.NotifySent()
	mg.log.Info("notify sent", "zone", apex, "target", addr,
		"serial", serial, "rcode", dns.RcodeToString[in.Rcode])
}

// hostPort appends the default DNS port when target has none.
func hostPort(target string) string {
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	return net.JoinHostPort(strings.Trim(target, "[]"), "53")
}

// serialNewer implements RFC 1982 serial arithmetic: true when a is
// newer than b, wraparound included.
func serialNewer(a, b uint32) bool { return int32(a-b) > 0 }
