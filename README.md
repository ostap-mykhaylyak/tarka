# tarka

Authoritative DNS server in Go. A single static binary, YAML zone
files, no runtime dependencies, managed by systemd.

tarka is **authoritative-only**: no recursion, no forwarding, no
caching of other people's data. Queries for zones it does not host are
answered with REFUSED.

Every feature below comes with its configuration example. Two files
drive everything:

- **`/etc/tarka/config.yaml`** — the global config (this document's
  YAML blocks). Every field has a production default, so the file may
  be sparse. Hot-reloaded on save unless a block says "restart".
- **`/etc/tarka/zones/<zone>.yaml`** — one file per zone. Hot-reloaded;
  an invalid file keeps its last good version loaded.

---

## Contents

- [Install](#install)
- [Zone files](#zone-files)
- [Listeners (server)](#listeners-server)
- [Primary + secondary (transfers, NOTIFY)](#primary--secondary-transfers-notify)
- [Catalog zones — zero-config secondaries](#catalog-zones--zero-config-secondaries)
- [TSIG — authenticated transfers](#tsig--authenticated-transfers)
- [Response Rate Limiting (anti-amplification)](#response-rate-limiting-anti-amplification)
- [GeoDNS (geo + ECS)](#geodns-geo--ecs)
- [Resolver views (split by provider)](#resolver-views-split-by-provider)
- [ALIAS / ANAME at the apex](#alias--aname-at-the-apex)
- [Automatic certificates (ACME DNS-01)](#automatic-certificates-acme-dns-01)
- [NSID + Extended DNS Errors](#nsid--extended-dns-errors)
- [Status & observability](#status--observability)
- [CLI reference](#cli-reference)
- [Registrar checklist](#registrar-checklist)
- [Build](#build)

---

## Install

Download a release bundle, then:

```sh
tar xzf tarka-*.tar.gz && cd tarka-*
sudo ./tarka --init
sudo systemctl daemon-reload
sudo systemctl enable --now tarka
tarka --status
```

`--init` self-provisions the layout: `/etc/tarka/` (config + zones),
`/var/log/tarka/` (logs + runtime state), and the systemd unit. Open
**53/udp and 53/tcp** inbound. If a local resolver (systemd-resolved)
already holds port 53, bind specific IPs — see
[Listeners](#listeners-server).

From source: `make static && sudo make install`.

---

## Zone files

One file per zone under `/etc/tarka/zones/`. The SOA **serial is
managed by tarka** — never set it: it is bumped on every change and
persisted across restarts.

```yaml
# /etc/tarka/zones/example.com.yaml
zone: example.com
type: primary                    # primary | secondary

soa:
  mname: ns1.example.com.        # primary nameserver
  rname: hostmaster.example.com. # contact (first dot = @)
  refresh: 4h
  retry: 15m
  expire: 7d
  minimum: 1h                    # negative-answer TTL

ttl: 1h                          # default TTL for records without their own

records:
  - {name: "@",  type: NS,   value: ns1.example.com.}
  - {name: ns1,  type: A,    value: 203.0.113.10}
  - {name: "@",  type: A,    value: 203.0.113.10}
  - {name: "@",  type: AAAA, value: "2001:db8::10"}   # quote IPv6 in YAML
  - {name: www,  type: A,    value: 203.0.113.10}
  - {name: "@",  type: MX,   value: mail.example.com., prio: 10}
  - {name: "@",  type: TXT,  value: "v=spf1 mx -all"}
  - {name: "*",  type: A,    value: 203.0.113.10, ttl: 5m}
```

Record fields: `name` (`@` = apex, or relative/absolute), `type`,
`value` (presentation format), optional `ttl`, `prio` (MX/SRV), and
the `geo:` / `view:` tags described below. Any record type miekg/dns
knows works — A, AAAA, MX, TXT, SRV, CAA, NS, PTR, CNAME, … Save the
file and it is live: serial bumped, NOTIFY sent.

---

## Listeners (server)

```yaml
server:
  # Each address gets a UDP and a TCP listener. ":53" is the
  # dual-stack wildcard (IPv4 + IPv6). Bind specific IPs when port 53
  # is shared with a local resolver. Restart to change.
  listen: [":53"]
  # e.g. listen: ["203.0.113.10:53", "[2001:db8::10]:53"]

  udp_payload_size: 1232         # EDNS0 buffer; larger answers get TC + TCP retry
  tcp_timeout: 10s

  # NSID: the name reported on `dig +nsid` (see below). Empty = hostname.
  identity: "ns1.example.com"
```

---

## Primary + secondary (transfers, NOTIFY)

A **primary** serves the zone and feeds secondaries via AXFR, sending
NOTIFY on every change. A **secondary** pulls it and re-checks on
NOTIFY and on the SOA `refresh`/`retry`/`expire` timers.

### Who may transfer — three places, from global to per-zone

You almost never need to write this per zone. Pick the broadest that
fits:

| Where | Scope | Use it when |
|---|---|---|
| `catalog.auto_secondaries: true` (default) | every zone, automatically | the secondary is already an `NS` of the zone (with glue) — nothing to configure |
| `catalog.secondaries: [IP]` in `config.yaml` | every zone | a global slave that is **not** in the NS records (e.g. a hidden backup) |
| `transfer:` in a zone file | that one zone | an exception: a slave that should get only this zone |

Because the default `auto_secondaries` derives the allow-list and the
NOTIFY targets from each zone's own NS glue, a normal setup needs **no
`transfer:` block and no slave list at all** — listing the
nameservers in the zone is enough. See
[Catalog zones](#catalog-zones--zero-config-secondaries).

The explicit per-zone form is still there for exceptions:

```yaml
# /etc/tarka/zones/example.com.yaml (primary)
zone: example.com
type: primary
soa: {mname: ns1.example.com., rname: hostmaster.example.com.}
records:
  - {name: "@",  type: NS, value: ns1.example.com.}
  - {name: "@",  type: NS, value: ns2.example.com.}
  - {name: ns1,  type: A,  value: 198.51.100.1}   # this server
  - {name: ns2,  type: A,  value: 203.0.113.2}     # the secondary
  - {name: www,  type: A,  value: 198.51.100.10}

# Optional — only if you are NOT using the catalog for this zone:
transfer:
  allow:  [203.0.113.2]          # IPs/CIDRs allowed to AXFR this zone
  notify: [203.0.113.2]          # NOTIFY targets on change (optional :port)
```

The global equivalent, applied to **every** primary zone at once:

```yaml
# /etc/tarka/config.yaml — one line instead of a transfer: block per zone
catalog:
  secondaries: [203.0.113.2]
```

A **secondary** needs only a three-line file — the body comes over the
wire, and the transferred copy is persisted under
`/var/log/tarka/secondary/` (it serves instantly after a reboot even
if the primary is down):

```yaml
# /etc/tarka/zones/example.com.yaml (secondary)
zone: example.com
type: secondary
primaries: [198.51.100.1]
```

This is plain AXFR/NOTIFY, so tarka can slave from — or feed — BIND,
PowerDNS, or a registrar's DNS. But if both ends are tarka, prefer the
[catalog](#catalog-zones--zero-config-secondaries) and skip the
per-zone `transfer:` and secondary files entirely.

---

## Catalog zones — zero-config secondaries

With a tarka-to-tarka cluster the secondary needs **no zone files at
all**, and the primary needs **no slave list**: it discovers its
secondaries from the NS glue of the zones themselves (RFC 9432).

```yaml
# config.yaml — SECONDARY: just subscribe to the master's catalog
catalog:
  primaries: [198.51.100.1]
```

```yaml
# config.yaml — PRIMARY: nothing needed; auto_secondaries is on by
# default. The glue IPs of each zone's apex NS records become that
# zone's secondaries (this machine's own IPs never count).
catalog:
  auto_secondaries: true
  # secondaries: [192.0.2.9]   # add a hidden slave NOT in the NS set
```

Add a zone file on the primary → the slave provisions it on the spot
(NOTIFY-driven) and transfers it; delete it → the slave drops it.
Adding a fourth nameserver is just its NS + glue records in the zones,
plus `catalog.primaries` on the new box.

> A discovered slave may transfer the zones whose NS set it appears in
> (or any zone if listed in `secondaries`). Authenticate the cluster
> with TSIG below.

---

## TSIG — authenticated transfers

IP ACLs suffice on a trusted network; a shared TSIG key (RFC 8945)
authenticates every AXFR and NOTIFY cryptographically. Put the **same**
block on the primary and every secondary and restart:

```yaml
tsig:
  name: cluster                  # any label, identical on both ends
  algorithm: hmac-sha256         # hmac-sha256 | hmac-sha512 | hmac-sha1
  secret: "PASTE-A-BASE64-SECRET"   # e.g. openssl rand -base64 32
  require: true                  # refuse unsigned AXFR even from allowed IPs
```

Both transfer directions, NOTIFY, and the lag monitor sign
automatically.

---

## Response Rate Limiting (anti-amplification)

A public authoritative server on UDP is a reflection vector. RRL caps
identical responses per client subnet; over the cap a response is
dropped, or — every `slip`-th time — sent truncated so a real client
retries over TCP. UDP only (TCP is not spoofable). **Enable it on any
public server.**

```yaml
rrl:
  enabled: true
  responses_per_second: 15
  window: 15s
  slip: 2                        # 0 = drop all, 1 = truncate all, N = truncate every Nth
  ipv4_prefix: 24                # clients aggregated into subnets of this size
  ipv6_prefix: 56
```

Restart to change. Drops/truncations show up in `--status` and
`query.log`.

---

## GeoDNS (geo + ECS)

Answer with the nearest variant by the client's location. Enable the
MaxMind country database, then tag records with 2-letter **country**
(`IT`, `FR`) or **continent** (`EU`, `NA`, `AS`, `AF`, `SA`, `OC`,
`AN`) codes.

```yaml
# config.yaml
geoip:
  enabled: true
  country_db: /usr/share/GeoIP/GeoLite2-Country.mmdb   # keep fresh with geoipupdate
```

```yaml
# in the zone
- {name: www, type: A, value: 203.0.113.10}                # default for everyone else
- {name: www, type: A, value: 198.51.100.10, geo: [EU]}    # European clients
- {name: www, type: A, value: 192.0.2.10,    geo: [US, CA]}
```

A tagged record answers only matching clients; untagged records are
the fallback. EDNS Client Subnet is honored (the end user's network,
not the resolver's) and echoed back (RFC 7871). A missing database is
not fatal — geo records simply never match.

---

## Resolver views (split by provider)

Answer differently depending on **which resolver** the query comes
through (Fastweb here, TIM there). Unlike GeoDNS this keys on the
resolver's source IP, so it needs no ECS. Map providers to their
resolver ranges in a separate hot-reloaded file:

```yaml
# /etc/tarka/views.yaml — provider -> resolver IP ranges (CIDR or bare IP)
Fastweb: [85.18.0.0/16, 93.63.0.0/16]
TIM:     [212.216.0.0/16]
```

```yaml
# in the zone
- {name: www, type: A, value: 203.0.113.10}                 # everyone else
- {name: www, type: A, value: 198.51.100.10, view: [Fastweb]}
- {name: www, type: A, value: 192.0.2.10,    view: [TIM]}
```

> The ranges are yours to fill in — source each provider's resolver
> prefixes from its AS (bgp.he.net / RIPE). Wrong ranges = wrong
> answers.

**geo OR view.** A record answers if the client matches **either** its
`geo:` **or** its `view:` tag. So you can set `geo:` for ECS-capable
resolvers and `view:` as the fallback for the rest, on the same
record:

```yaml
- {name: www, type: A, value: 192.0.2.10, geo: [DE], view: [TIM]}
```

An unknown resolver with no geo match falls back to the untagged
defaults.

---

## ALIAS / ANAME at the apex

CNAME is forbidden at a zone apex. An `ALIAS` (a.k.a. `ANAME`) record
points `@` (or any name) at an external hostname; tarka resolves it in
the background and serves the flattened A/AAAA as if local — and, on
change, bumps the serial so the secondaries re-transfer.

```yaml
# in the zone
- {name: "@", type: ALIAS, value: my-lb.provider.net.}
```

```yaml
# config.yaml — resolvers, refresh cadence and the synthesized TTL
alias:
  resolvers: ["1.1.1.1:53", "8.8.8.8:53"]
  refresh: 5m
  ttl: 5m
```

---

## Automatic certificates (ACME DNS-01)

tarka is authoritative for your zones, so it proves ownership by
itself. Enable the client and **every hosted zone** gets a
`zone + *.zone` certificate, obtained **and renewed** with no external
tooling and no domain list:

```yaml
# config.yaml
acme:
  enabled: true
  email: hostmaster@example.com
  directory: letsencrypt         # letsencrypt-staging | zerossl | any directory URL
  # eab: {kid: "", hmac: ""}      # ZeroSSL et al. need EAB credentials
  cert_dir: /var/log/tarka/certs
  renew_before: 30d
  propagation_wait: 30s          # lets NOTIFY reach the secondaries before validating
  resolvers: ["1.1.1.1:53", "8.8.8.8:53"]   # used to verify the delegation points here
```

Add a zone file, get a certificate. Before contacting the CA, tarka
publishes a probe TXT and checks through the resolvers above that the
zone's delegation actually reaches this server — a zone that does not
(yet) point here is silently skipped (no failures, no rate-limit
burn), and the certificate appears on its own once the NS records go
live. Certificates land in
`<cert_dir>/live/<zone>/fullchain.pem` + `privkey.pem` (certbot-style
layout — point your reverse proxy there). Enable ACME **on the primary
only**; the challenge TXTs flow to the secondaries via NOTIFY so the
CA validates against any nameserver.

> Test with `directory: letsencrypt-staging` first — production has
> strict rate limits.

**External ACME clients** can drive tarka instead of the built-in one,
via the control socket:

```sh
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook    'tarka --dns01-set   "$CERTBOT_DOMAIN" "$CERTBOT_VALIDATION"' \
  --manual-cleanup-hook 'tarka --dns01-clear "$CERTBOT_DOMAIN"' \
  -d example.com -d '*.example.com'
```

---

## NSID + Extended DNS Errors

Two diagnostic niceties, always on (no config beyond `server.identity`
for NSID):

- **NSID (RFC 5001)** — `dig +nsid @your-server example.com` reports
  which node answered (the `server.identity`, or the hostname). Handy
  across a multi-server deployment.
- **Extended DNS Errors (RFC 8914)** — EDNS clients get a
  machine-readable reason on REFUSED ("not authoritative for this
  zone") and SERVFAIL ("secondary zone not yet transferred or
  expired").

```yaml
server:
  identity: "ns2.example.com"   # what dig +nsid reports
```

---

## Status & observability

No dashboard, no management API — observability is the local status
socket and the log files.

```sh
tarka --status          # one-line health, Nagios-style exit code
tarka --status --watch 2s   # live, top-style
tarka --status-json     # stable JSON for monitoring
```

`--status` shows loaded zones and serials, certificate expiries, RRL
counters, and — on a primary — every secondary's serial, flagging any
that is unreachable or lagging (the master-side lag monitor).

Logs are JSON under `/var/log/tarka/`, rotation delegated to logrotate
(SIGHUP reopens them): `tarka.log` (lifecycle), `query.log` (one line
per query), `xfr.log` (transfers + NOTIFY), `acme.log` (certificates).

### Throughput

Answers are served from an in-memory table (one atomic load + a label
walk, zero allocations to find the zone). The per-query log is
buffered so it does not put a `write(2)` on the hot path; at very high
QPS you can also turn it off:

```yaml
server:
  query_log: false   # drop per-query logging for maximum throughput
```

Rough single-box figures (12 cores, one small zone, loopback, no
network): ~540k queries/s with query logging on, ~2.5M/s with it off.
More than enough headroom for a public authoritative server; the
network and the kernel's UDP path are the real limits long before
tarka is.

---

## CLI reference

| Command | Purpose |
|---|---|
| `tarka` | run the daemon (what systemd does) |
| `tarka --init` | provision layout + install the unit, then exit |
| `tarka --purge [--yes]` | remove all config, data and logs |
| `tarka --status` | query the running daemon; `--status-json`, `--watch 2s` |
| `tarka --dns01-set <domain> <token>` | publish an ACME challenge TXT (external hook) |
| `tarka --dns01-clear <domain> [token]` | remove it |
| `tarka --version` | print version |

---

## Registrar checklist

For a domain served by your own in-zone nameservers
(`ns1.example.com`, …):

1. **Glue / host records** at the registrar: register each nameserver
   name with its IP (`ns1.example.com → 198.51.100.1`, …). Required
   because the nameservers live inside the zone they serve.
2. **Delegation**: set the domain's NS records to all your
   nameservers.
3. **DNSSEC / DS: leave empty.** tarka does not sign zones (yet); a
   stale DS record breaks resolution for validating clients. Remove it
   before switching if the old provider had it enabled.

Before pointing the registrar at tarka, copy **every** existing record
of the domain into the zone file — from the switch on, this zone is
the single source of truth.

---

## Build

```sh
make static   # CGO_ENABLED=0 static Linux binary in bin/tarka
make test     # race detector on
make install  # static + install unit, config and examples
```

Only dependencies: `miekg/dns` (wire protocol), `fsnotify`,
`yaml.v3`, `maxminddb-golang` (GeoIP), `x/crypto` (ACME). The binary
stays static.

## License

MIT
