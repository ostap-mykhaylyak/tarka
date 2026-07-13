# Security Policy

tarka is designed to serve DNS on the public internet: security
reports are taken seriously.

## Reporting a vulnerability

Please do NOT open a public issue. Report privately to
**ostap.mykhaylyak@gmail.com** with a description, reproduction steps
and the affected version (`tarka --version`). You will get an
acknowledgment as soon as possible.

## Scope notes

- tarka is authoritative-only: recursion and forwarding are refused by
  design; report any way to make it answer for a zone it does not host.
- Zone transfers (AXFR) are only served to the per-zone allow list;
  report any way to bypass it.
- The status Unix socket is local-only by design.
- The daemon is expected to run under the shipped systemd hardening.
