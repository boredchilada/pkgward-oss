// SPDX-License-Identifier: AGPL-3.0-or-later
package baseline

import (
	"testing"

	"detonation/internal/trace"
)

func connectEvt(host, addr string) trace.TraceEvent {
	d := map[string]interface{}{"addr": addr, "port": float64(443)}
	if host != "" {
		d["hostname"] = host
	}
	return trace.TraceEvent{Phase: "install", Category: "network", Operation: "connect", Detail: d}
}

func hasConnectTo(evs []trace.TraceEvent, addr string) bool {
	for _, e := range evs {
		if a, _ := e.Detail["addr"].(string); a == addr {
			return true
		}
	}
	return false
}

func TestFilterDNSAware(t *testing.T) {
	in := []trace.TraceEvent{
		connectEvt("registry.npmjs.org", "104.16.1.2"),                // allowlisted by domain -> drop
		connectEvt("callback.cyb3rsh4ykh.workers.dev", "104.16.5.34"), // abuse host -> keep + flag
		connectEvt("evil.example.com", "203.0.113.9"),                 // non-allowlisted -> keep
		connectEvt("", "104.16.9.9"),                                  // no hostname, Cloudflare CIDR -> drop (IP fallback)
		connectEvt("static.rust-lang.org", "151.101.2.137"),          // non-abuse host on allowlisted Fastly CIDR -> drop
	}
	out := Filter("npm", in)

	if hasConnectTo(out, "151.101.2.137") {
		t.Error("a non-abuse host resolving into an allowlisted CDN CIDR must be dropped (typos/static.rust-lang.org class), not FP'd")
	}

	if hasConnectTo(out, "104.16.1.2") {
		t.Error("registry.npmjs.org must be dropped by domain even on a Cloudflare IP")
	}
	if !hasConnectTo(out, "104.16.5.34") {
		t.Error("workers.dev must survive the filter (it shares Cloudflare IPs with the allowlist)")
	}
	if !hasConnectTo(out, "203.0.113.9") {
		t.Error("a non-allowlisted host must survive")
	}
	if hasConnectTo(out, "104.16.9.9") {
		t.Error("a no-hostname connect to a Cloudflare IP must fall back to the IP allowlist (no regression)")
	}
	for _, e := range out {
		if a, _ := e.Detail["addr"].(string); a == "104.16.5.34" {
			if ab, _ := e.Detail["abuse_host"].(bool); !ab {
				t.Error("the surviving workers.dev connect must be tagged abuse_host")
			}
		}
	}
}

func TestHostnameMatches(t *testing.T) {
	allow := []string{"registry.npmjs.org", "workers.dev"}
	cases := map[string]bool{
		"registry.npmjs.org":              true,
		"x.y.workers.dev":                 true,
		"workers.dev":                     true,
		"notworkers.dev":                  false, // must not match on substring
		"registry.npmjs.org.evil.com":     false,
		"":                                false,
	}
	for host, want := range cases {
		if got := hostnameMatches(host, allow); got != want {
			t.Errorf("hostnameMatches(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestHostnameMatchesExact(t *testing.T) {
	// "=" entry: bare host allowed, per-tenant bucket subdomains NOT (the GCS
	// dep-confusion exfil shape must stay flagged while path-style GCS is allowed).
	allow := []string{"=storage.googleapis.com", "cdn.playwright.dev"}
	cases := map[string]bool{
		"storage.googleapis.com":       true,  // exact path-style -> allowed
		"ltidi.storage.googleapis.com": false, // per-tenant bucket -> still flagged
		"cdn.playwright.dev":           true,  // normal suffix entry
		"x.cdn.playwright.dev":         true,  // subdomain of a normal entry
	}
	for host, want := range cases {
		if got := hostnameMatches(host, allow); got != want {
			t.Errorf("hostnameMatches(%q) = %v, want %v", host, got, want)
		}
	}
}
