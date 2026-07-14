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

	// Catalog subscription (secondary side): the catalog zone is a
	// dynamic secondary; every transferred copy is parsed and the
	// member zones are provisioned/removed accordingly.
	catalogApex      string
	catalogPrimaries []string

	// TSIG (shared cluster key) signs SOA polls, AXFR in and NOTIFY.
	tsig    map[string]string
	tsigKey string
	tsigAlg string

	mu       sync.Mutex
	loops    map[string]*secLoop
	notified map[string]uint32 // last NOTIFY-ed serial per primary zone
	lag      map[string]LagInfo
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
		lag:      map[string]LagInfo{},
	}
}

// SetTSIG installs the shared transaction key used to sign the
// secondary-side SOA polls, AXFR in and NOTIFY, and the master-side
// lag probes. Call before Start.
func (mg *Manager) SetTSIG(secret map[string]string, keyName, algFQDN string) {
	mg.tsig, mg.tsigKey, mg.tsigAlg = secret, keyName, algFQDN
}

// signTSIG stamps a message with the shared key when configured.
func (mg *Manager) signTSIG(msg *dns.Msg) {
	if mg.tsig != nil {
		msg.SetTsig(mg.tsigKey, mg.tsigAlg, 300, time.Now().Unix())
	}
}

// SubscribeCatalog provisions the catalog zone of the given masters
// as a dynamic secondary (no YAML file) and keeps the member zones in
// sync with every transferred copy. Call after the store hooks are in
// place.
func (mg *Manager) SubscribeCatalog(catalogZone string, primaries []string) {
	mg.catalogApex = strings.ToLower(dns.Fqdn(catalogZone))
	mg.catalogPrimaries = primaries
	mg.store.AddDynamicSecondary(mg.catalogApex, primaries)
}

// syncCatalog reconciles the provisioned member zones with a freshly
// transferred (or resumed) catalog copy.
func (mg *Manager) syncCatalog(rrs []dns.RR) {
	members, versionOK := zone.CatalogMembers(mg.catalogApex, rrs)
	if !versionOK {
		mg.log.Error("catalog version not supported, ignoring", "zone", mg.catalogApex)
		return
	}
	want := map[string]bool{}
	for _, member := range members {
		want[member] = true
		mg.store.AddDynamicSecondary(member, mg.catalogPrimaries)
	}
	for _, existing := range mg.store.DynamicSecondaries() {
		if existing != mg.catalogApex && !want[existing] {
			mg.store.RemoveDynamicSecondary(existing)
		}
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
	catLoop := mg.loops[mg.catalogApex]
	mg.mu.Unlock()
	if !ok {
		// A NOTIFY for a zone we do not know yet, from a catalog
		// master: the catalog is probably ahead of us — refresh it.
		if catLoop != nil && catLoop.fromPrimary(from) {
			mg.log.Info("notify for unknown zone, refreshing catalog", "zone", apex, "client", from.String())
			catLoop.wake()
		}
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

	for _, target := range z.Transfer.Notify {
		go mg.sendNotify(z.Name, z.Serial, z.SOARR(), hostPort(target))
	}
}

func (mg *Manager) sendNotify(apex string, serial uint32, soa dns.RR, addr string) {
	msg := new(dns.Msg)
	msg.SetNotify(apex)
	msg.Answer = []dns.RR{soa} // current SOA hint (RFC 1996 §3.7)
	mg.signTSIG(msg)           // sign per message: TSIG is not copyable
	c := &dns.Client{Net: "udp", Timeout: queryTimeout, TsigSecret: mg.tsig}
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
