// Package alias resolves ALIAS/ANAME targets to their A/AAAA records
// and feeds them into the zone store as a materialized overlay. It
// runs a background refresh loop: when a target's addresses change,
// the store bumps the zone serial and NOTIFYs the secondaries, so the
// flattened records propagate like any other change. The apex, where
// CNAME is forbidden, can thus point at an external hostname.
package alias

import (
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

const queryTimeout = 5 * time.Second

// Manager periodically resolves the ALIAS targets of every hosted
// zone and materializes their A/AAAA into the store.
type Manager struct {
	mgr   *config.Manager
	store *zone.Store
	log   *slog.Logger
}

// NewManager wires the alias manager.
func NewManager(mgr *config.Manager, store *zone.Store, log *slog.Logger) *Manager {
	return &Manager{mgr: mgr, store: store, log: log}
}

// Start runs the refresh loop until stop is closed. The interval and
// resolvers are read per-cycle, so a config reload is honored.
func (m *Manager) Start(stop <-chan struct{}) {
	go func() {
		for {
			m.refreshAll()
			select {
			case <-stop:
				return
			case <-time.After(m.mgr.Get().Alias.Refresh.Std()):
			}
		}
	}()
}

// refreshAll re-resolves every ALIAS owner and updates the store.
func (m *Manager) refreshAll() {
	cfg := m.mgr.Get().Alias
	ttl := uint32(cfg.TTL.Std() / time.Second)

	for apex, owners := range m.store.AliasZones() {
		var rrs []dns.RR
		ok := true
		for owner, target := range owners {
			v4, v6, err := m.resolve(cfg.Resolvers, target)
			if err != nil {
				// Keep the previous records on a transient failure:
				// don't blank a working apex because a resolver blipped.
				m.log.Warn("alias resolve failed, keeping last good",
					"zone", apex, "owner", owner, "target", target, "error", err)
				ok = false
				break
			}
			for _, ip := range v4 {
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip,
				})
			}
			for _, ip := range v6 {
				rrs = append(rrs, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: ip,
				})
			}
		}
		if ok {
			m.store.SetAliasRecords(apex, rrs)
		}
	}
}

// resolve looks up A and AAAA for target through the configured
// recursive resolvers, returning on the first that answers.
func (m *Manager) resolve(resolvers []string, target string) (v4, v6 []net.IP, err error) {
	for _, r := range resolvers {
		a, aaaa, e := queryBoth(r, target)
		if e != nil {
			err = e
			continue
		}
		sortIPs(a)
		sortIPs(aaaa)
		return a, aaaa, nil
	}
	if err == nil {
		err = &net.DNSError{Err: "no resolvers", Name: target}
	}
	return nil, nil, err
}

func queryBoth(resolver, target string) (v4, v6 []net.IP, err error) {
	c := &dns.Client{Net: "udp", Timeout: queryTimeout}
	for _, q := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(target), q)
		msg.RecursionDesired = true
		in, _, e := c.Exchange(msg, resolver)
		if e != nil {
			return nil, nil, e
		}
		if in.Truncated {
			tc := &dns.Client{Net: "tcp", Timeout: queryTimeout}
			if in, _, e = tc.Exchange(msg, resolver); e != nil {
				return nil, nil, e
			}
		}
		for _, rr := range in.Answer {
			switch a := rr.(type) {
			case *dns.A:
				v4 = append(v4, a.A)
			case *dns.AAAA:
				v6 = append(v6, a.AAAA)
			}
		}
	}
	return v4, v6, nil
}

func sortIPs(ips []net.IP) {
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
}
