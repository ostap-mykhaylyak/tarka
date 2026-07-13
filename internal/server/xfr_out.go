package server

import (
	"time"

	"github.com/miekg/dns"
)

// answerTransfer handles an AXFR/IXFR question. It either fills m
// with a one-shot reply (refusals, the SOA-only UDP IXFR answer) and
// returns false so the caller's common path writes it, or streams the
// full transfer itself and returns true.
func (s *Server) answerTransfer(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg,
	qname string, qtype uint16, proto string, t0 time.Time, done func(int64, int)) bool {

	client := remoteIP(w)
	z := s.zones.Find(qname)

	switch {
	case z == nil || z.Name != qname:
		// Transfers are only served at the apex of a hosted zone.
		m.SetRcode(r, dns.RcodeRefused)
		return false
	case !z.TransferAllowed(client):
		s.xlog.Warn("transfer refused",
			"zone", qname, "client", client.String(), "qtype", dns.TypeToString[qtype])
		m.SetRcode(r, dns.RcodeRefused)
		return false
	case !z.Loaded():
		// Authorized, but a secondary with no valid data cannot feed
		// another secondary.
		m.SetRcode(r, dns.RcodeServerFailure)
		return false
	case proto == "udp":
		if qtype == dns.TypeAXFR {
			m.SetRcode(r, dns.RcodeRefused) // AXFR is TCP-only
			return false
		}
		// IXFR over UDP: answer with the current SOA alone; the
		// client compares serials and retries over TCP if behind.
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{z.SOARR()}
		return false
	}

	// Full zone over TCP. tarka keeps no incremental history, so an
	// IXFR is answered AXFR-style (RFC 1995 allows this fallback).
	rrs := z.TransferRecords()
	tr := new(dns.Transfer)
	ch := make(chan *dns.Envelope, 1)
	ch <- &dns.Envelope{RR: rrs}
	close(ch)
	err := tr.Out(w, r, ch)
	w.Hijack() // the transfer wrote the response; suppress the common path

	rcode := dns.RcodeSuccess
	if err != nil {
		rcode = dns.RcodeServerFailure
		s.xlog.Error("outbound transfer failed",
			"zone", qname, "client", client.String(), "error", err)
	} else {
		s.m.XfrOut()
		s.xlog.Info("outbound transfer served",
			"zone", qname, "client", client.String(),
			"qtype", dns.TypeToString[qtype], "serial", z.Serial,
			"records", len(rrs), "latency_ms", float64(time.Since(t0))/float64(time.Millisecond))
	}
	done(0, rcode)
	return true
}
