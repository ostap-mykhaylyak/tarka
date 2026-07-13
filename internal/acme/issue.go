package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/ostap-mykhaylyak/tarka/internal/config"
)

// Directory presets; anything else is used as a URL verbatim.
var directories = map[string]string{
	"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
	"zerossl":             "https://acme.zerossl.com/v2/DV90",
}

func directoryURL(name string) string {
	if url, ok := directories[name]; ok {
		return url
	}
	return name
}

// client builds the ACME client: persistent account key plus a
// one-time registration (EAB included when the CA requires it).
func (m *Manager) client(ctx context.Context, cfg config.Acme) (*xacme.Client, error) {
	key, created, err := loadOrCreateAccountKey(accountKeyPath(cfg.CertDir))
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	if created {
		m.log.Info("acme account key created", "path", accountKeyPath(cfg.CertDir))
	}
	cl := &xacme.Client{
		Key:          key,
		DirectoryURL: directoryURL(cfg.Directory),
		UserAgent:    "tarka",
	}

	acct := &xacme.Account{Contact: []string{"mailto:" + cfg.Email}}
	if cfg.EAB.KID != "" {
		hmac, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(cfg.EAB.HMAC, "="))
		if err != nil {
			return nil, fmt.Errorf("eab.hmac: %w", err)
		}
		acct.ExternalAccountBinding = &xacme.ExternalAccountBinding{KID: cfg.EAB.KID, Key: hmac}
	}
	if _, err := cl.Register(ctx, acct, xacme.AcceptTOS); err != nil &&
		!errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("acme register: %w", err)
	}
	return cl, nil
}

// issue runs one full ACME order: authorize every domain via DNS-01
// (self-published), finalize with a fresh key and store the result.
func (m *Manager) issue(ctx context.Context, cfg config.Acme, c config.AcmeCert, name string) error {
	cl, err := m.client(ctx, cfg)
	if err != nil {
		return err
	}

	order, err := cl.AuthorizeOrder(ctx, xacme.DomainIDs(c.Domains...))
	if err != nil {
		return fmt.Errorf("authorize order: %w", err)
	}

	// Publish every challenge first, wait once for propagation, then
	// let the CA validate them all.
	type pending struct {
		authzURL string
		chal     *xacme.Challenge
		domain   string
		txt      string
	}
	var work []pending
	defer func() {
		// Always unpublish, also on failure; the sweeper is only the
		// net below a crash.
		for _, p := range work {
			if err := m.zones.ClearDNS01(p.domain, p.txt); err != nil {
				m.log.Warn("challenge cleanup failed", "domain", p.domain, "error", err)
			}
		}
	}()

	for _, aurl := range order.AuthzURLs {
		authz, err := cl.GetAuthorization(ctx, aurl)
		if err != nil {
			return fmt.Errorf("get authorization: %w", err)
		}
		if authz.Status == xacme.StatusValid {
			continue // still valid from a recent order
		}
		var chal *xacme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == "dns-01" {
				chal = ch
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("no dns-01 challenge offered for %s", authz.Identifier.Value)
		}
		txt, err := cl.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return fmt.Errorf("challenge record: %w", err)
		}
		domain := authz.Identifier.Value
		// The token lands in our own zone: serial bump + NOTIFY, so
		// the CA validates fine against the secondaries too.
		if err := m.zones.SetDNS01(domain, txt); err != nil {
			return fmt.Errorf("publish challenge for %s: %w", domain, err)
		}
		m.log.Info("challenge published", "cert", name, "domain", domain)
		work = append(work, pending{authzURL: aurl, chal: chal, domain: domain, txt: txt})
	}

	if len(work) > 0 && cfg.PropagationWait.Std() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.PropagationWait.Std()):
		}
	}

	for _, p := range work {
		if _, err := cl.Accept(ctx, p.chal); err != nil {
			return fmt.Errorf("accept challenge for %s: %w", p.domain, err)
		}
	}
	for _, p := range work {
		if _, err := cl.WaitAuthorization(ctx, p.authzURL); err != nil {
			return fmt.Errorf("authorization for %s: %w", p.domain, err)
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: c.Domains,
	}, certKey)
	if err != nil {
		return fmt.Errorf("csr: %w", err)
	}
	chain, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}

	dir := liveDir(cfg.CertDir, name)
	if err := writeCert(dir, certKey, chain); err != nil {
		return fmt.Errorf("store certificate: %w", err)
	}
	cert, err := readCert(dir)
	if err != nil {
		return fmt.Errorf("verify stored certificate: %w", err)
	}
	m.log.Info("certificate obtained", "cert", name, "domains", c.Domains,
		"not_after", cert.NotAfter.UTC().Format(time.RFC3339), "dir", dir)
	return nil
}
