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

// resolveAllowedIPs expands an allowlist of hostnames/IPs into a set of IP
// strings. Hostnames are resolved via DNS at call time so the result tracks
// the registry/CDN IPs the sandbox is reaching the same way; literal IPs pass
// through. Unresolvable entries are skipped (best-effort).
func resolveAllowedIPs(allow []string) map[string]struct{} {
	ips := make(map[string]struct{})
	for _, entry := range allow {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if net.ParseIP(entry) != nil {
			ips[entry] = struct{}{}
			continue
		}
		addrs, err := net.LookupHost(entry)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ips[a] = struct{}{}
		}
	}
	return ips
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
	var allowedIPs map[string]struct{}
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
				continue
			}
		}
		if evt.Category == "network" && evt.Operation == "connect" && allowedIPs != nil {
			if addr, _ := evt.Detail["addr"].(string); addr != "" {
				if _, ok := allowedIPs[addr]; ok {
					continue
				}
			}
		}
		out = append(out, evt)
	}
	return out
}
