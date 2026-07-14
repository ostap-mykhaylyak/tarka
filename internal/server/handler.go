package server

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ostap-mykhaylyak/tarka/internal/rrl"
	"github.com/ostap-mykhaylyak/tarka/internal/zone"
)

// ServeDNS answers one query. Chain: opcode/format checks -> zone
// match (REFUSED when not hosted) -> authoritative lookup -> EDNS0
// negotiation and UDP truncation.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	done := s.m.QueryStart()
	t0 := time.Now()
	cfg := s.mgr.Get()

	proto := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		proto = "tcp"
	}

	m := new(dns.Msg)
	var qname string
	var qtype uint16
	var ede *dns.EDNS0_EDE // attached to the response for EDNS clients

	switch {
	case r.Opcode == dns.OpcodeNotify:
		rcode := dns.RcodeRefused
		if s.notify != nil && len(r.Question) == 1 {
			qname = strings.ToLower(r.Question[0].Name)
			qtype = r.Question[0].Qtype
			rcode = s.notify.HandleNotify(qname, remoteIP(w))
		}
		m.SetRcode(r, rcode)
	case r.Opcode != dns.OpcodeQuery:
		m.SetRcode(r, dns.RcodeNotImplemented)
	case len(r.Question) != 1:
		m.SetRcode(r, dns.RcodeFormatError)
	default:
		q := r.Question[0]
		qname, qtype = strings.ToLower(q.Name), q.Qtype
		switch {
		case q.Qclass != dns.ClassINET:
			m.SetRcode(r, dns.RcodeRefused)
		case qtype == dns.TypeAXFR || qtype == dns.TypeIXFR:
			if s.answerTransfer(w, r, m, qname, qtype, proto, t0, done) {
				return // full transfer already streamed and logged
			}
		default:
			z := s.zones.Find(qname)
			switch {
			case z == nil:
				// Not our zone: authoritative-only, no recursion.
				m.SetRcode(r, dns.RcodeRefused)
				ede = &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeNotAuthoritative,
					ExtraText: "not authoritative for this zone"}
			case qtype == dns.TypeANY:
				// Minimal ANY response (RFC 8482).
				m.SetReply(r)
				m.Authoritative = true
				m.Answer = []dns.RR{rfc8482(qname)}
			default:
				res := z.LookupGeo(qname, qtype, s.clientMatch(w, r, z))
				m.SetReply(r)
				m.Rcode = res.Rcode
				m.Authoritative = res.Authoritative
				m.Answer, m.Ns, m.Extra = res.Answer, res.Ns, res.Extra
				if res.Rcode == dns.RcodeServerFailure {
					// A secondary that is not (yet) transferred or has
					// expired: say so rather than a bare SERVFAIL.
					ede = &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeOther,
						ExtraText: "secondary zone not yet transferred or expired"}
				}
			}
		}
	}

	// EDNS0: advertise our payload size when the client spoke EDNS;
	// cap the UDP response at the smaller of the two buffers. An ECS
	// option is echoed back with the scope we honored (RFC 7871).
	size := dns.MinMsgSize
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(uint16(cfg.Server.UDPPayloadSize), false)
		s.echoECS(r, m, qname)
		s.addNSID(opt, m)
		if ede != nil {
			if ropt := m.IsEdns0(); ropt != nil {
				ropt.Option = append(ropt.Option, ede)
			}
		}
		size = int(opt.UDPSize())
		if size > cfg.Server.UDPPayloadSize {
			size = cfg.Server.UDPPayloadSize
		}
		if size < dns.MinMsgSize {
			size = dns.MinMsgSize
		}
	}
	if proto == "tcp" {
		size = dns.MaxMsgSize
	}
	m.Truncate(size)

	// Response Rate Limiting (UDP only): cap identical responses per
	// client subnet to defuse amplification. Opcode/NOTIFY replies are
	// unaffected; a flood of one answer to a spoofed range is dropped
	// (or, on the slip cycle, truncated so a real client retries over
	// TCP).
	if s.rrl != nil && proto == "udp" && r.Opcode == dns.OpcodeQuery {
		switch s.rrl.Check(remoteIP(w), rrlCategory(qname, qtype, m.Rcode)) {
		case rrl.Drop:
			s.m.RRLDropped()
			s.qlog.Info("rate limited", "client", remoteIP(w).String(),
				"qname", qname, "qtype", dns.TypeToString[qtype], "action", "dropped")
			done(0, m.Rcode)
			return // send nothing
		case rrl.Truncate:
			s.m.RRLTruncated()
			m.Answer, m.Ns, m.Extra = nil, nil, nil
			m.Truncated = true
		}
	}

	// Sign the response when the request carried a valid TSIG (zone
	// transfers, signed NOTIFY): use the same key it was signed with.
	if s.tsig != nil {
		if t := r.IsTsig(); t != nil && w.TsigStatus() == nil {
			m.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
		}
	}

	w.WriteMsg(m)
	done(int64(m.Len()), m.Rcode)

	client := w.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(client); err == nil {
		client = host
	}
	s.qlog.Info("query",
		"client", client,
		"proto", proto,
		"qname", qname,
		"qtype", dns.TypeToString[qtype],
		"rcode", dns.RcodeToString[m.Rcode],
		"answers", len(m.Answer),
		"tc", m.Truncated,
		"latency_ms", float64(time.Since(t0))/float64(time.Millisecond))
}

// rrlCategory groups equivalent responses so a flood of one answer is
// limited on its own account.
func rrlCategory(qname string, qtype uint16, rcode int) string {
	return qname + "|" + dns.TypeToString[qtype] + "|" + dns.RcodeToString[rcode]
}

// rfc8482 is the conventional minimal answer to ANY queries.
func rfc8482(qname string) dns.RR {
	return &dns.HINFO{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: 3600},
		Cpu: "RFC8482",
		Os:  "",
	}
}

// clientMatch resolves the querying client's matching context: its
// geo location (for geo-tagged records) and the provider views its
// resolver belongs to (for view-tagged records). Each dimension is
// computed only when the zone actually uses it. Geo prefers the EDNS
// Client Subnet (the end user) when present; view always uses the
// connection source — the resolver itself.
func (s *Server) clientMatch(w dns.ResponseWriter, r *dns.Msg, z *zone.Zone) zone.ClientGeo {
	var cm zone.ClientGeo
	src := remoteIP(w)

	if z.HasGeo() && s.geo != nil && s.geo.Loaded() {
		addr := src
		if ecs := findECS(r); ecs != nil {
			if a, ok := netip.AddrFromSlice(ecs.Address); ok {
				addr = a.Unmap()
			}
		}
		g := s.geo.Lookup(addr)
		cm.Country, cm.Continent = g.Country, g.Continent
	}
	if z.HasView() && s.views != nil && s.views.Loaded() {
		cm.Views = s.views.Lookup(src)
	}
	return cm
}

// echoECS mirrors the client's ECS option in the response. The scope
// says how specific the answer is: the full source prefix when geo
// records could differentiate it, zero (any client) otherwise.
func (s *Server) echoECS(r, m *dns.Msg, qname string) {
	ecs := findECS(r)
	if ecs == nil {
		return
	}
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	// Clamp the client-supplied netmask to its family maximum: never
	// reflect an out-of-range value from untrusted input.
	maxMask := uint8(32)
	if ecs.Family == 2 {
		maxMask = 128
	}
	mask := ecs.SourceNetmask
	if mask > maxMask {
		mask = maxMask
	}
	echo := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        ecs.Family,
		SourceNetmask: mask,
		SourceScope:   0,
		Address:       ecs.Address,
	}
	if z := s.zones.Find(qname); z != nil && z.HasGeo() && s.geo != nil && s.geo.Loaded() {
		echo.SourceScope = mask
	}
	opt.Option = append(opt.Option, echo)
}

// addNSID answers an NSID request (RFC 5001): a client that includes
// an empty NSID option gets our identity back. The payload is hex per
// the wire format.
func (s *Server) addNSID(reqOpt *dns.OPT, m *dns.Msg) {
	if s.identity == "" {
		return
	}
	requested := false
	for _, o := range reqOpt.Option {
		if _, ok := o.(*dns.EDNS0_NSID); ok {
			requested = true
			break
		}
	}
	if !requested {
		return
	}
	if ropt := m.IsEdns0(); ropt != nil {
		ropt.Option = append(ropt.Option, &dns.EDNS0_NSID{
			Code: dns.EDNS0NSID,
			Nsid: hex.EncodeToString([]byte(s.identity)),
		})
	}
}

// findECS returns the EDNS Client Subnet option of a query, if any.
func findECS(r *dns.Msg) *dns.EDNS0_SUBNET {
	opt := r.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_SUBNET); ok {
			return e
		}
	}
	return nil
}

// remoteIP extracts the client address from the connection.
func remoteIP(w dns.ResponseWriter) netip.Addr {
	var ip net.IP
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}
