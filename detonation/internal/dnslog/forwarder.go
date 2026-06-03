// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package dnslog is a tiny logging DNS forwarder. The detonation sandbox is
// pointed at it (`docker run --dns <forwarder>`), so every name the package
// resolves passes through here and we record resolved-IP -> hostname. The
// collector then tags each outbound connect with the *domain* it resolved,
// which is what lets us allow/deny by hostname (registry.npmjs.org allowed,
// callback.cyb3rsh4ykh.workers.dev flagged) instead of by raw CDN IP — Tetragon
// only ever sees the destination IP, and shared-CDN IPs (Cloudflare/Vercel) make
// IP-based allowlisting blind to abuse-hosting exfil.
//
// This is *observation only*: it forwards every query verbatim to an upstream
// resolver and never rewrites answers. Records expire so the map can't grow
// unbounded across a long-lived service.
package dnslog

import (
	"net"
	"sync"
	"time"
)

const recordTTL = 5 * time.Minute

type hostRecord struct {
	host string
	at   time.Time
}

// Forwarder forwards UDP DNS queries to an upstream and records the resolved
// IP -> hostname mapping for later connect correlation.
type Forwarder struct {
	upstream string
	conn     *net.UDPConn

	mu       sync.RWMutex
	ipToHost map[string]hostRecord
}

// New binds a UDP listener on listenAddr (e.g. "172.17.0.1:53") and forwards to
// upstreamAddr (e.g. "1.1.1.1:53").
func New(listenAddr, upstreamAddr string) (*Forwarder, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return &Forwarder{
		upstream: upstreamAddr,
		conn:     conn,
		ipToHost: make(map[string]hostRecord),
	}, nil
}

// Lookup returns the most-recently-resolved hostname for a destination IP, if a
// query within the TTL window produced it.
func (f *Forwarder) Lookup(ip string) (string, bool) {
	f.mu.RLock()
	rec, ok := f.ipToHost[ip]
	f.mu.RUnlock()
	if !ok || time.Since(rec.at) > recordTTL {
		return "", false
	}
	return rec.host, true
}

func (f *Forwarder) record(ip, host string) {
	f.mu.Lock()
	f.ipToHost[ip] = hostRecord{host: host, at: time.Now()}
	f.mu.Unlock()
}

// observe parses a query+response pair and records every answer IP -> qname.
// Exposed (unexported but called from tests) so the wire parsing is testable
// without real UDP sockets.
func (f *Forwarder) observe(query, response []byte) {
	host := parseQuestionName(query)
	if host == "" {
		return
	}
	for _, ip := range parseAnswerIPs(response) {
		f.record(ip, host)
	}
}

// Serve runs the forward loop until the connection is closed.
func (f *Forwarder) Serve() {
	buf := make([]byte, 1500)
	for {
		n, client, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return // listener closed
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go f.handle(query, client)
	}
}

func (f *Forwarder) handle(query []byte, client *net.UDPAddr) {
	up, err := net.DialTimeout("udp", f.upstream, 3*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := up.Write(query); err != nil {
		return
	}
	resp := make([]byte, 1500)
	rn, err := up.Read(resp)
	if err != nil {
		return
	}
	f.observe(query, resp[:rn])
	_, _ = f.conn.WriteToUDP(resp[:rn], client)
}

// Close stops the listener.
func (f *Forwarder) Close() error { return f.conn.Close() }

// --- DNS wire parsing (RFC 1035) --------------------------------------------

// parseQuestionName extracts the QNAME of the first question in a DNS message.
func parseQuestionName(msg []byte) string {
	if len(msg) < 13 {
		return ""
	}
	name, _, ok := readName(msg, 12)
	if !ok {
		return ""
	}
	return name
}

// parseAnswerIPs returns the A/AAAA record IPs in a DNS response.
func parseAnswerIPs(msg []byte) []string {
	if len(msg) < 12 {
		return nil
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	// skip questions
	for i := 0; i < qd; i++ {
		_, n, ok := readName(msg, off)
		if !ok || n+4 > len(msg) {
			return nil
		}
		off = n + 4 // QTYPE(2) + QCLASS(2)
	}
	var ips []string
	for i := 0; i < an && off < len(msg); i++ {
		_, n, ok := readName(msg, off)
		if !ok {
			return ips
		}
		off = n
		if off+10 > len(msg) {
			return ips
		}
		rrType := int(msg[off])<<8 | int(msg[off+1])
		rdLen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rdLen > len(msg) {
			return ips
		}
		if rrType == 1 && rdLen == 4 { // A
			ips = append(ips, net.IP(msg[off:off+4]).String())
		} else if rrType == 28 && rdLen == 16 { // AAAA
			ips = append(ips, net.IP(msg[off:off+16]).String())
		}
		off += rdLen
	}
	return ips
}

// readName reads a (possibly compressed) DNS name starting at off. Returns the
// dotted name, the offset just past the name in the *current* record (compression
// pointers do not advance past the 2-byte pointer), and ok.
func readName(msg []byte, off int) (string, int, bool) {
	var labels []byte
	jumped := false
	next := off
	steps := 0
	for {
		if off >= len(msg) || steps > 128 {
			return "", 0, false
		}
		steps++
		l := int(msg[off])
		if l == 0 {
			off++
			if !jumped {
				next = off
			}
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer
			if off+1 >= len(msg) {
				return "", 0, false
			}
			if !jumped {
				next = off + 2
			}
			off = (l&0x3F)<<8 | int(msg[off+1])
			jumped = true
			continue
		}
		off++
		if off+l > len(msg) {
			return "", 0, false
		}
		if len(labels) > 0 {
			labels = append(labels, '.')
		}
		labels = append(labels, msg[off:off+l]...)
		off += l
		if !jumped {
			next = off
		}
	}
	return string(labels), next, true
}
