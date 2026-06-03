// SPDX-License-Identifier: AGPL-3.0-or-later
package baseline

import (
	"net"
	"strings"

	"detonation/internal/intel"
	"detonation/internal/trace"
)

func isNoisyFile(path string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

func isNoisyExec(binary string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasSuffix(binary, p) || strings.Contains(binary, p) {
			return true
		}
	}
	return false
}

// runsLifecycleScriptJS reports whether a node/bun/deno exec is running a local
// JS *lifecycle script* (the malware-loader pattern `node ./x.js`) rather than a
// benign internal invocation (`node -e <probe>`, npm's own CLI, node-gyp). Such
// an exec must stay visible even though its binary matches the node/npm exec-noise
// filter: the binary is "noisy", but running a dropped script is the entire npm
// attack surface (logger-active/utils-terminal/faster-axios all do `node <file>`).
func runsLifecycleScriptJS(args string) bool {
	if args == "" {
		return false
	}
	if strings.Contains(args, " -e ") || strings.Contains(args, "--eval") ||
		strings.Contains(args, "-e require(") ||
		strings.Contains(args, "npm-cli.js") || strings.Contains(args, "npx-cli.js") ||
		strings.Contains(args, "/node_modules/npm/") || strings.Contains(args, "node-gyp") {
		return false
	}
	return strings.Contains(args, ".js") || strings.Contains(args, ".cjs") ||
		strings.Contains(args, ".mjs")
}

// allowSet is a resolved network allowlist: exact IP strings plus CIDR ranges.
// CIDRs cover CDN/registry fronts whose IPs rotate faster than per-detonation DNS
// resolution can track (Fastly/Cloudflare/Google/CloudFront), which was the
// dominant dyn_install_exfil false-positive source — a legit registry fetch
// landing on a CDN IP outside the freshly-resolved hostname set.
type allowSet struct {
	ips  map[string]struct{}
	nets []*net.IPNet
}

func (a *allowSet) contains(addr string) bool {
	if a == nil {
		return false
	}
	if _, ok := a.ips[addr]; ok {
		return true
	}
	if len(a.nets) == 0 {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveAllowedIPs expands an allowlist of hostnames / IPs / CIDRs. CIDR entries
// (e.g. "151.101.0.0/16") are kept as ranges; literal IPs pass through; hostnames
// are resolved via DNS at call time so the result tracks the registry/CDN IPs the
// sandbox reaches. Unresolvable entries are skipped (best-effort).
func resolveAllowedIPs(allow []string) *allowSet {
	out := &allowSet{ips: make(map[string]struct{})}
	for _, entry := range allow {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			out.nets = append(out.nets, ipnet)
			continue
		}
		if net.ParseIP(entry) != nil {
			out.ips[entry] = struct{}{}
			continue
		}
		addrs, err := net.LookupHost(entry)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			out.ips[a] = struct{}{}
		}
	}
	return out
}

// hostnameMatches reports whether host matches any entry in the list. A plain
// entry matches the host or any subdomain of it ("foo.com" matches "a.foo.com").
// An entry prefixed with "=" is EXACT-only ("=storage.googleapis.com" matches the
// path-style bare host but NOT "<bucket>.storage.googleapis.com") — used to allow a
// shared CDN's bare host while keeping per-tenant bucket subdomains (the exfil
// shape) flagged.
func hostnameMatches(host string, suffixes []string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	for _, d := range suffixes {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "=") {
			if host == d[1:] {
				return true
			}
			continue
		}
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func Filter(ecosystem string, events []trace.TraceEvent) []trace.TraceEvent {
	noise := intel.Current().Noise
	var fileNoise, execNoise, netAllow []string

	switch ecosystem {
	case "pypi":
		fileNoise = noise.PypiFileNoise
		execNoise = noise.PypiExecNoise
		netAllow = noise.PypiNetAllow
	case "npm":
		fileNoise = noise.NpmFileNoise
		execNoise = noise.NpmExecNoise
		netAllow = noise.NpmNetAllow
	case "crates":
		fileNoise = noise.CratesFileNoise
		execNoise = noise.CratesExecNoise
		netAllow = noise.CratesNetAllow
	case "gomod":
		fileNoise = noise.GomodFileNoise
		execNoise = noise.GomodExecNoise
		netAllow = noise.GomodNetAllow
	default:
		return events
	}

	// Resolve the network allowlist once per detonation (only if any network
	// connect events exist, to avoid needless DNS lookups).
	var allowedIPs *allowSet
	if len(netAllow) > 0 {
		for _, evt := range events {
			if evt.Category == "network" && evt.Operation == "connect" {
				allowedIPs = resolveAllowedIPs(netAllow)
				break
			}
		}
	}

	var out []trace.TraceEvent
	for _, evt := range events {
		if evt.Category == "file" {
			path, _ := evt.Detail["path"].(string)
			if isNoisyFile(path, fileNoise) {
				continue
			}
		}
		if evt.Category == "process" && evt.Operation == "exec" {
			binary, _ := evt.Detail["binary"].(string)
			if isNoisyExec(binary, execNoise) {
				// Keep a node/npm exec that runs a local JS lifecycle script — the
				// loader is the attack surface; only its binary is "noisy".
				args, _ := evt.Detail["arguments"].(string)
				if !runsLifecycleScriptJS(args) {
					continue
				}
			}
		}
		if evt.Category == "network" && evt.Operation == "connect" {
			host, _ := evt.Detail["hostname"].(string)
			if host != "" {
				// DNS-aware: judge by the resolved hostname, not the (shared-CDN) IP.
				if hostnameMatches(host, noise.AbuseHosts) {
					evt.Detail["abuse_host"] = true // -> dyn_abuse_hosting_callback
				} else if hostnameMatches(host, netAllow) {
					continue // allowlisted registry/CDN by domain
				} else if addr, _ := evt.Detail["addr"].(string); addr != "" && allowedIPs != nil && allowedIPs.contains(addr) {
					// A NON-abuse host that resolves into an allowlisted CDN range
					// (e.g. static.rust-lang.org on Fastly) — drop, same as pre-DNS-
					// aware. Abuse hosts were handled above, so this can't re-allow a
					// workers.dev beacon; it only restores the no-FP behaviour for
					// legit CDN-fronted hosts not named in net_allow.
					continue
				}
				// else: a non-allowlisted host — keep so the exfil rules fire.
			} else if allowedIPs != nil {
				// No hostname captured (direct-IP connect, or DNS not observed):
				// fall back to the resolved-IP allowlist — pre-DNS-aware behavior,
				// so this is a no-op regression until the DNS forwarder is wired.
				if addr, _ := evt.Detail["addr"].(string); addr != "" && allowedIPs.contains(addr) {
					continue
				}
			}
		}
		out = append(out, evt)
	}
	return out
}
