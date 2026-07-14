// Package config loads and validates the GLOBAL tarka configuration
// (/etc/tarka/config.yaml) and provides hot-reload via fsnotify.
//
// Per-zone configuration (one file per zone under /etc/tarka/zones/)
// is handled by internal/zone, not here.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ostap-mykhaylyak/tarka/internal/paths"
)

// Duration wraps time.Duration to accept human-friendly YAML values
// such as "30m", "24h", "5s", plus a whole-days form ("7d") that
// time.ParseDuration lacks — DNS zone timers are naturally in days.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler via time.ParseDuration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid duration %q", s)
		}
		*d = Duration(time.Duration(n) * 24 * time.Hour)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML renders the duration back in its string form.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the global configuration. Every field has a production
// default (see Default), so the operator's config.yaml may be sparse.
type Config struct {
	Server  Server  `yaml:"server"`
	Zones   Zones   `yaml:"zones"`
	Catalog Catalog `yaml:"catalog"`
	TSIG    TSIG    `yaml:"tsig"`
	RRL     RRL     `yaml:"rrl"`
	Alias   Alias   `yaml:"alias"`
	GeoIP   GeoIP   `yaml:"geoip"`
	Acme    Acme    `yaml:"acme"`

	// Warnings collects non-fatal issues found by validate()
	// (e.g. invalid list entries that were skipped). Never fatal.
	Warnings []string `yaml:"-"`
}

// TSIG configures a shared transaction key (RFC 8945) authenticating
// zone transfers and NOTIFY across the cluster. One key for the whole
// deployment: distribute the same block to primary and secondaries.
type TSIG struct {
	// Name is the key name (any label, must match on both ends).
	Name string `yaml:"name"`
	// Algorithm: hmac-sha256 (default), hmac-sha512, hmac-sha1.
	Algorithm string `yaml:"algorithm"`
	// Secret is the base64 HMAC key.
	Secret string `yaml:"secret"`
	// Require refuses unsigned (or wrongly signed) AXFR even from an
	// allowed IP. Off by default so a mixed cluster still works.
	Require bool `yaml:"require"`
}

// Enabled reports whether a usable key is configured.
func (t TSIG) Enabled() bool { return t.Name != "" && t.Secret != "" }

// KeyName is the canonical (lowercase FQDN) TSIG key name.
func (t TSIG) KeyName() string {
	name := strings.ToLower(t.Name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// AlgorithmFQDN is the miekg/dns algorithm identifier (trailing dot).
func (t TSIG) AlgorithmFQDN() string { return t.Algorithm + "." }

// SecretMap is the {keyname: secret} map for dns.Server / dns.Client
// / dns.Transfer, or nil when no key is configured.
func (t TSIG) SecretMap() map[string]string {
	if !t.Enabled() {
		return nil
	}
	return map[string]string{t.KeyName(): t.Secret}
}

// RRL configures Response Rate Limiting (anti amplification). It only
// touches UDP: an authoritative server on UDP is a reflection vector,
// so identical responses to one client subnet are capped. TCP and
// zone transfers are never limited.
type RRL struct {
	Enabled bool `yaml:"enabled"`
	// ResponsesPerSecond is the sustained cap per client subnet +
	// response category.
	ResponsesPerSecond int `yaml:"responses_per_second"`
	// Window is how long a bucket accumulates its allowance.
	Window Duration `yaml:"window"`
	// Slip: every Nth throttled response is sent truncated (TC=1)
	// instead of dropped, so a legitimate client behind the subnet
	// retries over TCP. 0 drops everything, 1 truncates everything.
	Slip int `yaml:"slip"`
	// IPv4Prefix / IPv6Prefix aggregate clients into subnets: a whole
	// spoofed range shares one bucket.
	IPv4Prefix int `yaml:"ipv4_prefix"`
	IPv6Prefix int `yaml:"ipv6_prefix"`
}

// Alias configures ALIAS/ANAME flattening. An ALIAS record at a name
// (the zone apex, where CNAME is forbidden, or anywhere) is resolved
// to the target's A/AAAA and served as if they were local records —
// kept fresh in the background and re-transferred to the secondaries
// on change.
type Alias struct {
	// Resolvers are the recursive resolvers used to resolve targets.
	Resolvers []string `yaml:"resolvers"`
	// Refresh is how often the targets are re-resolved.
	Refresh Duration `yaml:"refresh"`
	// TTL is the TTL of the synthesized A/AAAA records.
	TTL Duration `yaml:"ttl"`
}

// Server holds the DNS listeners and wire-level behavior.
type Server struct {
	// Listen addresses; each one gets both a UDP and a TCP listener.
	Listen []string `yaml:"listen"`

	// UDPPayloadSize is the EDNS0 UDP payload size advertised to
	// clients (RFC 6891). Larger answers are truncated (TC bit) and
	// retried over TCP by the client.
	UDPPayloadSize int `yaml:"udp_payload_size"`

	// TCPTimeout is the read/write timeout for TCP connections
	// (queries and zone transfers).
	TCPTimeout Duration `yaml:"tcp_timeout"`
}

// Zones locates the per-zone YAML files.
type Zones struct {
	Dir string `yaml:"dir"`
}

// Catalog configures catalog zones (RFC 9432): the primary publishes
// a special zone listing every zone it hosts; a secondary subscribes
// to it and provisions the member zones automatically — no per-zone
// YAML files on the secondaries.
type Catalog struct {
	// Zone is the catalog zone name; primary and secondaries must
	// agree on it. It is never part of the public DNS tree.
	Zone string `yaml:"zone"`
	// AutoSecondaries derives the slaves from the zones themselves:
	// the glue IPs of every apex NS record (minus this machine's own
	// addresses) may transfer the zone and the catalog, and receive
	// NOTIFY. Two NS names pointing at this same server simply yield
	// no secondaries.
	AutoSecondaries bool `yaml:"auto_secondaries"`
	// Secondaries (PRIMARY side) declares extra slaves explicitly,
	// merged with the auto-derived ones. Entries are IP or IP:port.
	Secondaries []string `yaml:"secondaries"`
	// Primaries (SECONDARY side) subscribes to the catalog of these
	// masters and auto-provisions their zones. Entries are IP or
	// IP:port.
	Primaries []string `yaml:"primaries"`
}

// GeoIP configures MaxMind country lookups, consumed by the geo:
// field of zone records (GeoDNS). The database lives at the
// conventional Ubuntu path (kept fresh by geoipupdate) and is
// hot-swapped on change; a missing file is not fatal.
type GeoIP struct {
	Enabled   bool   `yaml:"enabled"`
	CountryDB string `yaml:"country_db"`
}

// Acme configures the built-in ACME client. Fully automatic: every
// hosted primary zone gets a certificate for <zone> + *.<zone>,
// issued and renewed only when the zone's delegation verifiably
// points at this server (checked through public resolvers, exactly
// the path the CA will follow). No domain lists, no certbot.
type Acme struct {
	Enabled bool   `yaml:"enabled"`
	Email   string `yaml:"email"`
	// Directory is a preset (letsencrypt, letsencrypt-staging,
	// zerossl) or a full RFC 8555 directory URL.
	Directory string  `yaml:"directory"`
	EAB       AcmeEAB `yaml:"eab"`
	// CertDir receives account.key and live/<zone>/{fullchain,privkey}.pem
	// (certbot-style layout: point a reverse proxy straight at it).
	CertDir string `yaml:"cert_dir"`
	// RenewBefore renews a certificate when less than this remains.
	RenewBefore Duration `yaml:"renew_before"`
	// PropagationWait is the pause between publishing the challenge
	// TXT (NOTIFY to the secondaries included) and telling the CA to
	// validate.
	PropagationWait Duration `yaml:"propagation_wait"`
	// Resolvers are the public recursive resolvers used to verify
	// that a zone's delegation actually reaches this server before
	// bothering the CA.
	Resolvers []string `yaml:"resolvers"`
}

// AcmeEAB is the External Account Binding some CAs require at
// registration (ZeroSSL: "EAB credentials" from the dashboard).
type AcmeEAB struct {
	KID  string `yaml:"kid"`
	HMAC string `yaml:"hmac"` // base64url-encoded key
}

// Default returns the configuration with ALL production defaults, so
// the operator's config.yaml may be sparse or even empty.
func Default() *Config {
	return &Config{
		Server: Server{
			// ":53" is the dual-stack wildcard: IPv4 and IPv6 on one
			// listener pair.
			Listen:         []string{":53"},
			UDPPayloadSize: 1232,
			TCPTimeout:     Duration(10 * time.Second),
		},
		Zones: Zones{
			Dir: paths.ZonesDir,
		},
		Catalog: Catalog{
			Zone:            "catalog.tarka.",
			AutoSecondaries: true,
		},
		TSIG: TSIG{
			Algorithm: "hmac-sha256",
		},
		RRL: RRL{
			Enabled:            false,
			ResponsesPerSecond: 15,
			Window:             Duration(15 * time.Second),
			Slip:               2,
			IPv4Prefix:         24,
			IPv6Prefix:         56,
		},
		Alias: Alias{
			Resolvers: []string{"1.1.1.1:53", "8.8.8.8:53"},
			Refresh:   Duration(5 * time.Minute),
			TTL:       Duration(5 * time.Minute),
		},
		GeoIP: GeoIP{
			Enabled:   false,
			CountryDB: "/usr/share/GeoIP/GeoLite2-Country.mmdb",
		},
		Acme: Acme{
			Enabled:         false,
			Directory:       "letsencrypt",
			CertDir:         paths.CertsDir,
			RenewBefore:     Duration(30 * 24 * time.Hour),
			PropagationWait: Duration(30 * time.Second),
			Resolvers:       []string{"1.1.1.1:53", "8.8.8.8:53"},
		},
	}
}

// Load reads the YAML file at path on top of Default() and validates
// the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate checks the minimal invariants. Invalid list entries are
// never fatal: they are skipped and collected in Warnings — but a
// server without a single valid listener cannot start.
func (c *Config) validate() error {
	valid := c.Server.Listen[:0]
	for _, e := range c.Server.Listen {
		if _, _, err := net.SplitHostPort(e); err != nil {
			c.Warnings = append(c.Warnings, fmt.Sprintf("server.listen: skipping invalid address %q", e))
			continue
		}
		valid = append(valid, e)
	}
	c.Server.Listen = valid
	if len(c.Server.Listen) == 0 {
		return fmt.Errorf("server.listen: at least one valid address is required")
	}

	// 512 is the pre-EDNS0 floor; 4096 the customary ceiling beyond
	// which UDP fragmentation makes answers unreliable.
	if c.Server.UDPPayloadSize < 512 || c.Server.UDPPayloadSize > 4096 {
		return fmt.Errorf("server.udp_payload_size must be between 512 and 4096, got %d", c.Server.UDPPayloadSize)
	}
	if c.Server.TCPTimeout.Std() <= 0 {
		return fmt.Errorf("server.tcp_timeout must be positive")
	}

	if c.Zones.Dir == "" {
		return fmt.Errorf("zones.dir is required")
	}

	if c.TSIG.Name != "" || c.TSIG.Secret != "" {
		if c.TSIG.Name == "" || c.TSIG.Secret == "" {
			return fmt.Errorf("tsig needs both name and secret")
		}
		switch c.TSIG.Algorithm {
		case "hmac-sha256", "hmac-sha512", "hmac-sha1":
		default:
			return fmt.Errorf("tsig.algorithm must be hmac-sha256, hmac-sha512 or hmac-sha1, got %q", c.TSIG.Algorithm)
		}
		if _, err := base64.StdEncoding.DecodeString(c.TSIG.Secret); err != nil {
			return fmt.Errorf("tsig.secret must be base64: %w", err)
		}
	} else if c.TSIG.Require {
		return fmt.Errorf("tsig.require needs a configured key")
	}

	if c.RRL.Enabled {
		if c.RRL.ResponsesPerSecond < 1 {
			return fmt.Errorf("rrl.responses_per_second must be >= 1")
		}
		if c.RRL.Window.Std() <= 0 {
			return fmt.Errorf("rrl.window must be positive")
		}
		if c.RRL.Slip < 0 {
			return fmt.Errorf("rrl.slip must be >= 0")
		}
		if c.RRL.IPv4Prefix < 1 || c.RRL.IPv4Prefix > 32 {
			return fmt.Errorf("rrl.ipv4_prefix must be between 1 and 32")
		}
		if c.RRL.IPv6Prefix < 1 || c.RRL.IPv6Prefix > 128 {
			return fmt.Errorf("rrl.ipv6_prefix must be between 1 and 128")
		}
	}

	// Alias resolvers: invalid entries skipped with a warning.
	aliasValid := c.Alias.Resolvers[:0]
	for _, r := range c.Alias.Resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			c.Warnings = append(c.Warnings, fmt.Sprintf("alias.resolvers: skipping invalid address %q", r))
			continue
		}
		aliasValid = append(aliasValid, r)
	}
	c.Alias.Resolvers = aliasValid
	if c.Alias.Refresh.Std() <= 0 {
		return fmt.Errorf("alias.refresh must be positive")
	}
	if c.Alias.TTL.Std() <= 0 {
		return fmt.Errorf("alias.ttl must be positive")
	}

	if c.GeoIP.Enabled && c.GeoIP.CountryDB == "" {
		return fmt.Errorf("geoip.country_db is required when geoip.enabled is true")
	}

	if c.Catalog.Zone == "" && (c.Catalog.AutoSecondaries || len(c.Catalog.Secondaries) > 0 || len(c.Catalog.Primaries) > 0) {
		return fmt.Errorf("catalog.zone is required when the catalog is in use")
	}
	if len(c.Catalog.Secondaries) > 0 {
		// Secondaries must carry a usable IP (it doubles as the
		// transfer ACL); invalid entries are skipped with a warning.
		valid := c.Catalog.Secondaries[:0]
		for _, e := range c.Catalog.Secondaries {
			host := e
			if h, _, err := net.SplitHostPort(e); err == nil {
				host = h
			}
			if net.ParseIP(host) == nil {
				c.Warnings = append(c.Warnings, fmt.Sprintf("catalog.secondaries: skipping invalid entry %q", e))
				continue
			}
			valid = append(valid, e)
		}
		c.Catalog.Secondaries = valid
	}

	if c.Acme.Enabled {
		if !strings.Contains(c.Acme.Email, "@") {
			return fmt.Errorf("acme.email is required when acme.enabled is true")
		}
		if c.Acme.CertDir == "" {
			return fmt.Errorf("acme.cert_dir is required")
		}
		if c.Acme.RenewBefore.Std() <= 0 {
			return fmt.Errorf("acme.renew_before must be positive")
		}
		if c.Acme.PropagationWait.Std() < 0 {
			return fmt.Errorf("acme.propagation_wait must be >= 0")
		}
		// Invalid resolver entries are skipped with a warning, but a
		// delegation check without any resolver cannot work.
		valid := c.Acme.Resolvers[:0]
		for _, r := range c.Acme.Resolvers {
			if _, _, err := net.SplitHostPort(r); err != nil {
				c.Warnings = append(c.Warnings, fmt.Sprintf("acme.resolvers: skipping invalid address %q", r))
				continue
			}
			valid = append(valid, r)
		}
		c.Acme.Resolvers = valid
		if len(c.Acme.Resolvers) == 0 {
			return fmt.Errorf("acme.resolvers: at least one valid resolver is required when acme.enabled is true")
		}
		if c.Acme.Directory == "zerossl" && (c.Acme.EAB.KID == "" || c.Acme.EAB.HMAC == "") {
			return fmt.Errorf("acme.eab (kid + hmac) is required for zerossl")
		}
		if c.Acme.EAB.HMAC != "" {
			if _, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c.Acme.EAB.HMAC, "=")); err != nil {
				return fmt.Errorf("acme.eab.hmac must be base64url: %w", err)
			}
		}
	}

	return nil
}

// watchDir resolves the directory to watch: editors replace the file
// atomically (rename), so watching the parent directory is the
// reliable pattern.
func watchDir(path string) string { return filepath.Dir(path) }
