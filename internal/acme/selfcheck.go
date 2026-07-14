package acme

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
)

// The delegation check answers one question before any CA is
// involved: does the public DNS tree actually route queries for this
// zone to us? A probe TXT is published in the zone (under a random,
// never-queried-before label, so resolver caches cannot lie) and
// looked up through public recursive resolvers — the exact path the
// CA's validator will follow. Visible probe = delegated; anything
// else = the zone is parked here and is silently skipped.

const (
	// delegationAttempts x delegationPause bounds the check; the
	// first attempt is immediate (secondaries get their NOTIFY-driven
	// transfer window in between).
	delegationAttempts = 4
	delegationPause    = 5 * time.Second
	resolverTimeout    = 5 * time.Second
)

// delegationCheck is the production implementation of
// Manager.delegated.
func (m *Manager) delegationCheck(ctx context.Context, cfg config.Acme, zoneName string) error {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	label := hex.EncodeToString(buf)
	token := "tarka-delegation-check-" + label

	// SetDNS01 prefixes _acme-challenge.: the probe lives at
	// _acme-challenge.<label>.<zone> — unique, in-zone, and swept
	// automatically even if we crash mid-check.
	probeDomain := label + "." + strings.TrimSuffix(zoneName, ".")
	if err := m.zones.SetDNS01(probeDomain, token); err != nil {
		return fmt.Errorf("probe publish: %w", err)
	}
	defer func() {
		if err := m.zones.ClearDNS01(probeDomain, token); err != nil {
			m.log.Warn("probe cleanup failed", "zone", zoneName, "error", err)
		}
	}()

	probeFQDN := "_acme-challenge." + probeDomain + "."
	for attempt := 0; attempt < delegationAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delegationPause):
			}
		}
		for _, resolver := range cfg.Resolvers {
			if hasTXT(probeFQDN, token, resolver) {
				return nil
			}
		}
	}
	return fmt.Errorf("probe %s not visible via %s: the zone's NS records do not seem to point at this server",
		probeFQDN, strings.Join(cfg.Resolvers, ", "))
}

// hasTXT asks one recursive resolver for the probe record.
func hasTXT(fqdn, token, resolver string) bool {
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, dns.TypeTXT) // RD bit set: recursive query
	c := &dns.Client{Net: "udp", Timeout: resolverTimeout}
	in, _, err := c.Exchange(msg, resolver)
	if err != nil || in.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range in.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, v := range txt.Txt {
				if v == token {
					return true
				}
			}
		}
	}
	return false
}
