// SPDX-License-Identifier: AGPL-3.0-or-later
package dnslog

import (
	"net"
	"strings"
	"testing"
)

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func buildQuery(name string) []byte {
	hdr := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	msg := append(hdr, encodeName(name)...)
	return append(msg, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
}

func TestParseQuestionName(t *testing.T) {
	for _, name := range []string{
		"callback.cyb3rsh4ykh.workers.dev",
		"registry.npmjs.org",
		"a.b.c.d.example.com",
	} {
		if got := parseQuestionName(buildQuery(name)); got != name {
			t.Errorf("parseQuestionName(%q) = %q", name, got)
		}
	}
}

func TestObserveAndLookupByDomain(t *testing.T) {
	f := &Forwarder{ipToHost: map[string]hostRecord{}}
	// build a response with one A record for the workers.dev callback
	q := buildQuery("callback.cyb3rsh4ykh.workers.dev")
	resp := append([]byte{}, q...)
	resp[7] = 0x01 // ANCOUNT=1
	resp = append(resp,
		0xc0, 0x0c, // name ptr -> question
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x3c, // TTL
		0x00, 0x04, // RDLENGTH
	)
	resp = append(resp, net.ParseIP("104.16.5.34").To4()...)

	f.observe(q, resp)

	if h, ok := f.Lookup("104.16.5.34"); !ok || h != "callback.cyb3rsh4ykh.workers.dev" {
		t.Fatalf("Lookup(104.16.5.34) = %q, %v", h, ok)
	}
	if _, ok := f.Lookup("8.8.8.8"); ok {
		t.Fatal("Lookup of an un-resolved IP should miss")
	}
}

func TestParseAnswerIPsMultiple(t *testing.T) {
	q := buildQuery("cdn.jsdelivr.net")
	resp := append([]byte{}, q...)
	resp[7] = 0x02 // two answers
	for _, ip := range []string{"151.101.1.229", "151.101.65.229"} {
		resp = append(resp, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04)
		resp = append(resp, net.ParseIP(ip).To4()...)
	}
	ips := parseAnswerIPs(resp)
	if len(ips) != 2 || ips[0] != "151.101.1.229" || ips[1] != "151.101.65.229" {
		t.Fatalf("parseAnswerIPs = %v", ips)
	}
}
