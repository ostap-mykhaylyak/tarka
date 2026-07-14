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
- Catalog zones (RFC 9432) with slave auto-discovery: the primary
  derives its secondaries from the NS glue of the zones themselves —
  no slave lists in the config, a secondary needs zero zone files,
  and new zones propagate on the spot
- GeoDNS: tag records with `geo: [IT, EU, ...]` (MaxMind
  GeoLite2-Country, hot-swapped) and clients get the nearest variant;
  EDNS Client Subnet is honored and echoed (RFC 7871)
- ALIAS/ANAME at the apex: point `@` at an external hostname; tarka
  resolves it and serves the flattened A/AAAA, refreshed in the
  background and re-transferred to the secondaries on change
- TSIG (RFC 8945) authenticating transfers and NOTIFY with a shared
  cluster key; Response Rate Limiting on UDP against amplification;
  master-side secondary-lag monitoring surfaced in `--status`
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

## Primary + secondary setup (master/slave)

Scenario: `ns1.example.com` (198.51.100.1) is the primary,
`ns2.example.com` (203.0.113.2) a secondary. Zone: `example.com`.
Everything is plain AXFR/NOTIFY, so the secondary can also be a
registrar's slave service or any other DNS server — and vice versa.

### 1. Install tarka on both machines

Same steps on each ([Install](#install)): unpack, `sudo ./tarka
--init`, `systemctl enable --now tarka`. Open **53/udp and 53/tcp**
inbound on both (the secondary reaches the primary's 53/tcp for the
transfers). If systemd-resolved or another resolver sits on port 53,
bind the public IPs explicitly in `/etc/tarka/config.yaml`
(`server.listen`, restart required).

### 2. On the PRIMARY — the full zone file

`/etc/tarka/zones/example.com.yaml`:

```yaml
zone: example.com
type: primary

soa:
  mname: ns1.example.com.
  rname: hostmaster.example.com.
  # no serial: tarka manages it

records:
  # the NS set: list EVERY nameserver, secondaries included
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: "@",  type: NS, value: ns2.example.com.}
  # glue for the in-zone nameserver names
  - {name: ns1,  type: A,  value: 198.51.100.1}
  - {name: ns2,  type: A,  value: 203.0.113.2}
  # ... the actual zone content
  - {name: "@",  type: A,  value: 198.51.100.10}
  - {name: www,  type: A,  value: 198.51.100.10}

transfer:
  allow:  [203.0.113.2]   # who may AXFR this zone
  notify: [203.0.113.2]   # who gets NOTIFY on every change
```

No restart needed: the file is hot-loaded on save.

### 3. On the SECONDARY — zero zone files (catalog)

The secondary needs no zone files at all. In
`/etc/tarka/config.yaml`:

```yaml
catalog:
  primaries: [198.51.100.1]
```

That's it — **the primary needs nothing**: it discovers its slaves
from the zones themselves. The glue IPs of the apex NS records
(`ns2 A 203.0.113.2` in step 2) may transfer every zone and receive
NOTIFY, automatically; the primary's own addresses never count, so
two NS names pointing at the same server just mean "no secondaries".
The primary also publishes a catalog zone (RFC 9432) listing every
zone it hosts; the secondary subscribes to it and provisions each
member automatically: add a zone file on the primary and the slave
picks it up on the spot (NOTIFY-driven), delete it and the slave
drops it.

A slave that is NOT in the NS records (e.g. a hidden backup) can
still be declared explicitly on the primary:

```yaml
catalog:
  secondaries: [192.0.2.9]
```

Alternatively, the manual per-zone way — a three-line file on the
secondary — still works, and is the way to slave zones from a
non-tarka master (BIND, PowerDNS, a registrar):

```yaml
zone: example.com
type: secondary
primaries: [198.51.100.1]
```

Either way, the zone body lives only on the primary. The secondary
transfers immediately, re-checks at the SOA `refresh` interval, on
every NOTIFY, and after the `retry`/`expire` timers on failures. The
transferred copies are persisted under `/var/log/tarka/secondary/`,
so a reboot serves instantly even if the primary is down.

### 4. Verify

```sh
# same serial on both?
dig +short SOA example.com @198.51.100.1
dig +short SOA example.com @203.0.113.2

# on each machine:
tarka --status        # primary: "zone example.com. primary serial N"
                      # secondary: "zone example.com. secondary serial N"
```

Transfers and NOTIFY are logged in `/var/log/tarka/xfr.log` on both
sides. Then edit the zone on the primary and watch the serial follow
on the secondary within seconds.

### 5. At the registrar

Point the domain's NS records at ALL the nameservers (`ns1` and
`ns2`), and register the glue/host records for the in-zone names
(`ns1.example.com → 198.51.100.1`, `ns2.example.com → 203.0.113.2`).

### 6. Adding another secondary (ns3, 192.0.2.3)

1. On **ns3**: install tarka, set `catalog.primaries:
   [198.51.100.1]` in its config — done, every zone arrives by
   itself.
2. On the **primary**: just add the NS + glue records to the zones
   (`{name: "@", type: NS, value: ns3.example.com.}`,
   `{name: ns3, type: A, value: 192.0.2.3}`) — hot-reloaded: the new
   glue makes ns3 a discovered slave, serial bumps, everyone gets
   NOTIFY.
3. At the registrar: add the `ns3` NS/host record.

The same works in reverse: a tarka instance can be the secondary of a
foreign primary (BIND, PowerDNS, a registrar's master) — only the
three-line file is needed.

### Authenticate the transfers (TSIG, recommended)

IP ACLs are enough on a trusted network, but a shared TSIG key
authenticates every AXFR and NOTIFY cryptographically. Put the **same**
block in `config.yaml` on the primary and every secondary:

```yaml
tsig:
  name: cluster
  algorithm: hmac-sha256
  secret: "PASTE-A-BASE64-SECRET"   # e.g. openssl rand -base64 32
  require: true                     # refuse unsigned AXFR
```

Restart all nodes. The lag monitor, NOTIFY and both transfer
directions sign automatically.

### Notes

- Edit zones **only on the primary**; on the secondaries the YAML file
  is just the subscription, its content is ignored beyond
  `zone`/`type`/`primaries`.
- On a public server, enable `rrl` (Response Rate Limiting) so tarka
  cannot be abused as an amplification reflector.
- `tarka --status` on the primary shows every secondary's serial and
  flags one that is unreachable or lagging.
- Enable ACME **on the primary only**: the challenge TXT records flow
  to the secondaries via the normal transfer (serial bump + NOTIFY),
  so the CA validates against any of the NS. The certificates are
  written on the primary.
- Each zone is independent: one machine can be primary for some zones
  and secondary for others, one YAML per zone.

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
