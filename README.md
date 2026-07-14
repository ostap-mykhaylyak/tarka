# tarka

Authoritative DNS server in Go. A single static binary, YAML zone
files, no runtime dependencies, managed by systemd.

tarka is **authoritative-only**: no recursion, no forwarding, no
caching of other people's data. Queries for zones it does not host are
answered with REFUSED.

## Features

- Dual-stack UDP + TCP listeners (IPv4 + IPv6) with EDNS0 and correct
  truncation (TC + TCP retry)
- One YAML file per zone under `/etc/tarka/zones/`, hot-reloaded; an
  invalid file never unloads its last good version
- Automatic SOA serials: tarka bumps the serial on every zone change
  and persists it across restarts — never edit a serial by hand
- Primary mode: AXFR out to allow-listed secondaries, NOTIFY on change
- Secondary mode: AXFR in from external primaries with SOA
  refresh/retry/expire timers; the transferred copy is persisted so a
  restart resumes from the last good zone
- GeoDNS: tag records with `geo: [IT, EU, ...]` (MaxMind
  GeoLite2-Country, hot-swapped) and clients get the nearest variant;
  EDNS Client Subnet is honored and echoed (RFC 7871)
- Built-in ACME client, fully automatic: every hosted zone gets a
  `zone + *.zone` certificate from Let's Encrypt / ZeroSSL / any
  RFC 8555 CA, obtained **and renewed** by tarka itself via its own
  DNS-01 answers — no domain lists, no certbot, no hooks, no cron.
  Zones whose delegation does not point at the server are skipped
  automatically
- ACME DNS-01 hook surface for external clients too:
  `tarka --dns01-set <domain> <token>` / `--dns01-clear` publish the
  `_acme-challenge` TXT (serial bump + NOTIFY included, so
  secondaries validate too)
- JSON logs (`tarka.log`, `query.log`, `xfr.log`), rotation delegated
  to logrotate (SIGHUP reopens files)
- `tarka --status` / `--watch 2s` live status via a local Unix socket
  (Nagios-style exit codes, `--status-json` for machines)

## Install

Download a release bundle, then:

```sh
tar xzf tarka-*.tar.gz && cd tarka-*
sudo ./tarka --init
sudo systemctl daemon-reload
sudo systemctl enable --now tarka
tarka --status
```

The binary self-provisions its layout on first run: config in
`/etc/tarka/`, zones in `/etc/tarka/zones/`, logs and runtime state in
`/var/log/tarka/`.

Or from source: `make static && sudo make install`.

## Configure a zone

Copy `/etc/tarka/zones/example.com.yaml.example` to
`<your-zone>.yaml`, edit, done — the file is hot-reloaded, the serial
is bumped automatically and NOTIFY goes out to the configured
secondaries.

## Certificates (ACME DNS-01, fully automatic)

tarka is authoritative for your zones, so it can prove domain
ownership by itself. Enable the built-in ACME client and every hosted
zone gets a `zone.tld + *.zone.tld` certificate, obtained and renewed
with no external tooling and **no domain list to maintain**:

```yaml
acme:
  enabled: true
  email: hostmaster@example.com
  directory: letsencrypt        # or letsencrypt-staging / zerossl / URL
```

Add a zone file, get a certificate. Before contacting the CA, tarka
publishes a probe TXT in the zone and checks through public resolvers
(1.1.1.1 / 8.8.8.8) that the delegation actually reaches the server —
zones not (yet) pointed here are silently skipped, so parked zones
never fail or burn CA rate limits; the check re-runs at every cycle
and the certificate appears on its own once the NS records go live.

Certificates land in `/var/log/tarka/certs/live/<zone>/fullchain.pem`
+ `privkey.pem` (certbot-style layout): point your reverse proxy at
that directory and you are done. Renewal runs every 12 hours and
kicks in 30 days before expiry; the challenge TXT records bump the
zone serial and NOTIFY the secondaries, so validation passes against
them too. `tarka --status` shows every certificate and its expiry.

For ZeroSSL add the EAB credentials from its dashboard
(`eab: {kid: ..., hmac: ...}`).

An external ACME client can still drive tarka instead:
`--manual-auth-hook 'tarka --dns01-set "$CERTBOT_DOMAIN" "$CERTBOT_VALIDATION"'`
and `--manual-cleanup-hook 'tarka --dns01-clear "$CERTBOT_DOMAIN"'`.

## Build

```sh
make static   # CGO_ENABLED=0 linux binary in bin/tarka
make test     # race detector on
```

## License

MIT
