// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"fmt"
	"net"
	"strings"

	"detonation/internal/honeytokens"
	"detonation/internal/intel"
	"detonation/internal/trace"
)

type Rule struct {
	ID       string
	Evaluate func(evt trace.TraceEvent) *trace.DynFinding
}

// Rule data — sensitive path/env/shell lists — comes from the intel pack
// loader. Calls go through intel.Current() each invocation so the data
// stays in sync if Reset() is called between tests.
func sensitivePathPrefixes() []string {
	return intel.Current().Rules.SensitivePathPrefixes
}

func shellBinaries() []string {
	return intel.Current().Rules.ShellBinaries
}

func AllRules() []Rule {
	return []Rule{
		// installExfil() is active (high severity): the per-ecosystem net_allow
		// allowlist now drops legit registry/CDN/download-host connects before the
		// rule sees them, so a remaining install-phase connect is exfil-shaped. It's
		// HIGH (not critical) so a lone connect to an unlisted host corroborates
		// rather than solo-flipping to malicious — keeping FP low.
		installExfil(),
		importExfil(),
		abuseHostingCallback(),
		credentialRead(),
		honeytokenExfil(),
		screenCaptureProbe(),
		reverseShell(),
		procInject(),
		dnsExfil(),
		envHarvest(),
		suspiciousWrite(),
		filelessExec(),
	}
}

// honeytokenExfil is the canary tripwire: the sandbox seeds a broad spread of
// realistic decoy credentials (internal/honeytokens), and if any decoy VALUE ever
// surfaces in traced activity — an exec argument, a written path, a DNS label —
// then a worm harvested it and is staging/exfiltrating it. Because the values are
// unique fixed strings that never occur in real install traffic, this is near
// zero-FP regardless of the destination, so it needs no network allowlist (unlike
// the broad dyn_install_exfil, which leans on the network allowlist). It also names WHICH secret was taken, so
// we learn the worm's target list.
func honeytokenExfil() Rule {
	canaries := honeytokens.Canaries()
	return Rule{
		ID: "dyn_honeytoken_exfil",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			// Build a haystack from the stringy parts of the event: exec args,
			// file paths, dns names — wherever a stolen secret would appear.
			var hay strings.Builder
			for _, val := range evt.Detail {
				if s, ok := val.(string); ok {
					hay.WriteByte(' ')
					hay.WriteString(s)
				}
			}
			if hay.Len() == 0 {
				return nil
			}
			h := hay.String()
			for _, c := range canaries {
				if strings.Contains(h, c.Value) {
					return &trace.DynFinding{
						RuleID:     "dyn_honeytoken_exfil",
						Category:   "dynamic",
						Severity:   "critical",
						Confidence: "high",
						Evidence: fmt.Sprintf(
							"decoy credential %s surfaced in %s/%s during %s phase — harvested + staged for exfil",
							c.Label, evt.Category, evt.Operation, evt.Phase,
						),
					}
				}
			}
			return nil
		},
	}
}

// abuseHostingCallback fires when a connect resolves to an abuse-prone serverless
// / tunnel host (workers.dev, ngrok, …). The baseline filter tags such connects
// (it matches by HOSTNAME, so a shared-CDN IP can't hide them) — this is a runtime
// confirmation that the package actually beaconed to a known C2/exfil channel, so
// it's critical (a connect a legit install never makes).
func abuseHostingCallback() Rule {
	return Rule{
		ID: "dyn_abuse_hosting_callback",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "network" || evt.Operation != "connect" {
				return nil
			}
			if abuse, _ := evt.Detail["abuse_host"].(bool); !abuse {
				return nil
			}
			host, _ := evt.Detail["hostname"].(string)
			addr, _ := evt.Detail["addr"].(string)
			return &trace.DynFinding{
				RuleID:     "dyn_abuse_hosting_callback",
				Category:   "dynamic",
				Severity:   "critical",
				Confidence: "high",
				Evidence: fmt.Sprintf(
					"connect to abuse-prone hosting/tunnel host %q (%s) during %s phase — common C2/exfil channel",
					host, addr, evt.Phase),
			}
		},
	}
}

// destLabel renders a connect destination as "hostname (ip):port" when the DNS
// forwarder resolved the name, else "ip:port" — so the alert shows the *domain* a
// payload beaconed to (e.g. cdn.sheetjs.com, callback.workers.dev), not a bare IP.
func destLabel(evt trace.TraceEvent) string {
	addr, _ := evt.Detail["addr"].(string)
	port, _ := evt.Detail["port"].(float64)
	if host, _ := evt.Detail["hostname"].(string); host != "" {
		return fmt.Sprintf("%s (%s):%d", host, addr, int(port))
	}
	return fmt.Sprintf("%s:%d", addr, int(port))
}

// isExternalDest reports whether a connect leaves the sandbox for the public
// internet. A connect to a private/loopback/link-local address — most notably the
// DNS forwarder on the Docker bridge (172.17.x.x) the sandbox resolves through —
// is infrastructure, not egress, and must never read as exfil. Unknown/unparseable
// addresses are treated as external (conservative for detection).
func isExternalDest(evt trace.TraceEvent) bool {
	addr, _ := evt.Detail["addr"].(string)
	if addr == "" {
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	return true
}

// isSensitiveAccess reports whether an event is the package reading a secret —
// a credential/keystore file or another process's environment. This is the
// "touched secrets" half of the exfil chain: a network egress only convicts as
// exfil when one of these occurred in the same detonation. Mirrors the predicates
// of dyn_credential_read + dyn_env_harvest so the chain and the standalone signals
// stay consistent.
func isSensitiveAccess(evt trace.TraceEvent) bool {
	if evt.Category != "file" || evt.Operation != "open" {
		return false
	}
	path, _ := evt.Detail["path"].(string)
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/environ") &&
		path != "/proc/self/environ" {
		return true
	}
	for _, prefix := range sensitivePathPrefixes() {
		if strings.HasPrefix(path, prefix) || strings.Contains(path, prefix) {
			return true
		}
	}
	return false
}

// RunSensitiveAccess scans a detonation's events for any secret access, so the
// chain rules (install/import exfil) can require it alongside an external egress.
func RunSensitiveAccess(events []trace.TraceEvent) bool {
	for _, evt := range events {
		if isSensitiveAccess(evt) {
			return true
		}
	}
	return false
}

// installExfil is a CHAIN, not a lone-connect rule. A network egress during
// install is dual-use (fetching deps, prebuilt binaries, params, data lists, DNS),
// so a connect alone no longer convicts — it false-positived on every legit fetch
// (Zcash params, domain blocklists, JDK/LLM-SDK downloads, even the sandbox's own
// DNS forwarder). Exfil requires the data-theft shape: a secret was touched
// (`run_sensitive_access`, set by the engine when dyn_credential_read / dyn_env_harvest
// fired in this detonation) AND the connect leaves the sandbox for an external host.
// A lone external egress emits a low, non-convicting `dyn_install_egress` note for
// visibility. A honeytoken actually leaving the sandbox is handled standalone by
// dyn_honeytoken_exfil (proof of theft, no chain needed).
func installExfil() Rule {
	return exfilChain("install", "dyn_install_exfil", "dyn_install_egress")
}

func importExfil() Rule {
	return exfilChain("import", "dyn_import_exfil", "dyn_import_egress")
}

func exfilChain(phase, exfilID, egressID string) Rule {
	return Rule{
		ID: exfilID,
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Phase != phase || evt.Category != "network" || evt.Operation != "connect" {
				return nil
			}
			if !isExternalDest(evt) {
				return nil // sandbox infra (DNS forwarder, loopback, bridge) — not egress
			}
			sensitive, _ := evt.Detail["run_sensitive_access"].(bool)
			if sensitive {
				return &trace.DynFinding{
					RuleID:     exfilID,
					Category:   "dynamic",
					Severity:   "high",
					Confidence: "high",
					Evidence: fmt.Sprintf(
						"secret access + external egress during %s phase (exfil): %s",
						phase, destLabel(evt)),
				}
			}
			return &trace.DynFinding{
				RuleID:     egressID,
				Category:   "dynamic",
				Severity:   "low",
				Confidence: "low",
				Evidence: fmt.Sprintf(
					"external network egress during %s phase, no secret access observed: %s",
					phase, destLabel(evt)),
			}
		},
	}
}

func credentialRead() Rule {
	return Rule{
		ID: "dyn_credential_read",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "file" || evt.Operation != "open" {
				return nil
			}
			path, _ := evt.Detail["path"].(string)
			for _, prefix := range sensitivePathPrefixes() {
				if strings.HasPrefix(path, prefix) || strings.Contains(path, prefix) {
					return &trace.DynFinding{
						RuleID:     "dyn_credential_read",
						Category:   "dynamic",
						Severity:   "high",
						Confidence: "high",
						Evidence:   fmt.Sprintf("read sensitive file: %s during %s phase", path, evt.Phase),
					}
				}
			}
			return nil
		},
	}
}

// captureTools are screen-capture / screen-recording / input (keylog) utilities.
// A package that probes for these during install/import is staging desktop
// surveillance — near-zero legitimate use in a package lifecycle. Clipboard tools
// (xclip/xsel/wl-paste) are deliberately EXCLUDED: clipboard libraries legitimately
// probe for them, so they'd raise FP.
// Screenshot/screen-record + input-capture (keylog) utilities. `import`
// (ImageMagick) and `xdotool` (automation) are excluded — both have legitimate
// build/image uses, so they'd raise FP.
var captureTools = map[string]bool{
	"scrot": true, "maim": true, "grim": true, "spectacle": true,
	"gnome-screenshot": true, "ksnapshot": true, "flameshot": true,
	"xwd": true, "slurp": true, "xinput": true,
}

func screenCaptureProbe() Rule {
	return Rule{
		ID: "dyn_screen_capture_probe",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "process" || evt.Operation != "exec" {
				return nil
			}
			args, _ := evt.Detail["arguments"].(string)
			if args == "" {
				return nil
			}
			clean := func(s string) string {
				s = strings.Trim(s, "\"'`(),;")
				if i := strings.LastIndex(s, "/"); i >= 0 {
					s = s[i+1:]
				}
				return s
			}
			toks := strings.Fields(args)
			// A lookup probe: the `which`/`whereis` binary, or `command -v` / `type`.
			probe := clean(evt.Binary) == "which" || clean(evt.Binary) == "whereis" ||
				strings.Contains(args, "command -v") || strings.Contains(args, "type ")
			for _, t := range toks {
				if c := clean(t); c == "which" || c == "whereis" || c == "command" || c == "type" {
					probe = true
					break
				}
			}
			if !probe {
				return nil
			}
			for _, t := range toks {
				name := clean(t)
				if captureTools[name] {
					return &trace.DynFinding{
						RuleID:     "dyn_screen_capture_probe",
						Category:   "dynamic",
						Severity:   "high",
						Confidence: "high",
						Evidence: fmt.Sprintf(
							"install/import enumerated screen-capture/keylogger tool %q during %s phase — desktop-surveillance staging",
							name, evt.Phase,
						),
					}
				}
			}
			return nil
		},
	}
}

func reverseShell() Rule {
	return Rule{
		ID: "dyn_reverse_shell",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "process" || evt.Operation != "exec" {
				return nil
			}
			binary, _ := evt.Detail["binary"].(string)
			hasSocket, _ := evt.Detail["has_socket"].(bool)
			if !hasSocket {
				return nil
			}
			for _, sh := range shellBinaries() {
				if binary == sh {
					return &trace.DynFinding{
						RuleID:     "dyn_reverse_shell",
						Category:   "dynamic",
						Severity:   "critical",
						Confidence: "high",
						Evidence:   fmt.Sprintf("shell %s spawned with open socket during %s phase", binary, evt.Phase),
					}
				}
			}
			return nil
		},
	}
}

func procInject() Rule {
	return Rule{
		ID: "dyn_proc_inject",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "process" {
				return nil
			}
			if evt.Operation != "ptrace" && evt.Operation != "process_vm_writev" {
				return nil
			}
			return &trace.DynFinding{
				RuleID:     "dyn_proc_inject",
				Category:   "dynamic",
				Severity:   "critical",
				Confidence: "high",
				Evidence:   fmt.Sprintf("process injection via %s during %s phase", evt.Operation, evt.Phase),
			}
		},
	}
}

func dnsExfil() Rule {
	return Rule{
		ID: "dyn_dns_exfil",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "dns" || evt.Operation != "query" {
				return nil
			}
			entropy, _ := evt.Detail["subdomain_entropy"].(float64)
			if entropy < 4.0 {
				return nil
			}
			name, _ := evt.Detail["name"].(string)
			return &trace.DynFinding{
				RuleID:     "dyn_dns_exfil",
				Category:   "dynamic",
				Severity:   "high",
				Confidence: "medium",
				Evidence:   fmt.Sprintf("high-entropy DNS query: %s (entropy=%.1f)", name, entropy),
			}
		},
	}
}

func envHarvest() Rule {
	return Rule{
		ID: "dyn_env_harvest",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "file" || evt.Operation != "open" {
				return nil
			}
			path, _ := evt.Detail["path"].(string)
			// Reading /proc/<pid>/environ exposes another process's full
			// environment (tokens, keys, CI secrets). Tetragon surfaces the
			// file path, not individual variables, so we flag the act of
			// reading environ rather than matching specific var names.
			if !strings.HasPrefix(path, "/proc/") || !strings.HasSuffix(path, "/environ") {
				return nil
			}
			// Reading one's own environment is benign (many libs do it).
			if path == "/proc/self/environ" {
				return nil
			}
			return &trace.DynFinding{
				RuleID:     "dyn_env_harvest",
				Category:   "dynamic",
				Severity:   "high",
				Confidence: "high",
				Evidence:   fmt.Sprintf("read process environment via %s during %s phase", path, evt.Phase),
			}
		},
	}
}

func filelessExec() Rule {
	return Rule{
		ID: "dyn_fileless_exec",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "process" {
				return nil
			}
			switch evt.Operation {
			case "fileless_exec":
				return &trace.DynFinding{
					RuleID:     "dyn_fileless_exec",
					Category:   "dynamic",
					Severity:   "critical",
					Confidence: "high",
					Evidence:   fmt.Sprintf("execve from anonymous fd (AT_EMPTY_PATH) during %s phase", evt.Phase),
				}
			case "memfd_create":
				name, _ := evt.Detail["name"].(string)
				return &trace.DynFinding{
					RuleID:     "dyn_fileless_exec",
					Category:   "dynamic",
					Severity:   "medium",
					Confidence: "medium",
					Evidence:   fmt.Sprintf("anonymous executable memory created (memfd_create %q) during %s phase", name, evt.Phase),
				}
			}
			return nil
		},
	}
}

func suspiciousWrite() Rule {
	return Rule{
		ID: "dyn_suspicious_write",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Category != "file" || evt.Operation != "write" {
				return nil
			}
			path, _ := evt.Detail["path"].(string)
			// Hard persistence / backdoor sinks with no benign install reason — a
			// write here is conviction-grade on its own.
			hardPersistence := []string{
				"/etc/crontab", "/etc/cron.d/",
				"/etc/systemd/",      // systemd unit / timer persistence
				"/etc/init.d/",       // sysv init persistence
				"/etc/ld.so.preload", // global library injection
			}
			// Shell rc files are dual-use: a write is *usually* a benign PATH export
			// (nvm/cargo/deno/bun/pyenv and other native-CLI installers all append one),
			// but can also be command-injection persistence. Strong signal, not auto-
			// convicting on its own — high, so it must chain with a real payload signal
			// to reach malicious (score) rather than force it (critical).
			shellRC := []string{
				"/root/.bashrc", "/root/.profile", "/root/.bash_profile",
				"/root/.zshrc", "/root/.zshenv",
			}
			severity := ""
			for _, s := range hardPersistence {
				if strings.HasPrefix(path, s) {
					severity = "critical"
					break
				}
			}
			// authorized_keys is user-relative (/root/.ssh, /home/*/.ssh) so it
			// can't be prefix-matched — a write to one is an SSH backdoor-key install.
			if severity == "" && strings.Contains(path, ".ssh/authorized_keys") {
				severity = "critical"
			}
			if severity == "" {
				for _, s := range shellRC {
					if strings.HasPrefix(path, s) || strings.Contains(path, "/.config/fish/") {
						severity = "high"
						break
					}
				}
			}
			if severity != "" {
				return &trace.DynFinding{
					RuleID:     "dyn_suspicious_write",
					Category:   "dynamic",
					Severity:   severity,
					Confidence: "high",
					Evidence:   fmt.Sprintf("write to persistence path: %s during %s phase", path, evt.Phase),
				}
			}
			return nil
		},
	}
}
