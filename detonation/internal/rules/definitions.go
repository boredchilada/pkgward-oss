// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"fmt"
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

func installExfil() Rule {
	return Rule{
		ID: "dyn_install_exfil",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Phase != "install" || evt.Category != "network" || evt.Operation != "connect" {
				return nil
			}
			addr, _ := evt.Detail["addr"].(string)
			port, _ := evt.Detail["port"].(float64)
			return &trace.DynFinding{
				RuleID:     "dyn_install_exfil",
				Category:   "dynamic",
				Severity:   "high",
				Confidence: "high",
				Evidence:   fmt.Sprintf("connect(AF_INET, %s:%d) to a non-allowlisted host during install phase", addr, int(port)),
			}
		},
	}
}

func importExfil() Rule {
	return Rule{
		ID: "dyn_import_exfil",
		Evaluate: func(evt trace.TraceEvent) *trace.DynFinding {
			if evt.Phase != "import" || evt.Category != "network" || evt.Operation != "connect" {
				return nil
			}
			addr, _ := evt.Detail["addr"].(string)
			port, _ := evt.Detail["port"].(float64)
			return &trace.DynFinding{
				RuleID:     "dyn_import_exfil",
				Category:   "dynamic",
				Severity:   "high",
				Confidence: "high",
				Evidence:   fmt.Sprintf("connect(AF_INET, %s:%d) during import phase", addr, int(port)),
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
			suspicious := []string{
				"/etc/crontab", "/etc/cron.d/",
				"/root/.bashrc", "/root/.profile",
				"/root/.bash_profile",
				"/etc/systemd/",       // systemd unit / timer persistence
				"/etc/init.d/",        // sysv init persistence
				"/etc/ld.so.preload",  // global library injection
			}
			match := false
			for _, s := range suspicious {
				if strings.HasPrefix(path, s) {
					match = true
					break
				}
			}
			// authorized_keys is user-relative (/root/.ssh, /home/*/.ssh) so it
			// can't be prefix-matched — a write to one is an SSH backdoor-key install.
			if !match && strings.Contains(path, ".ssh/authorized_keys") {
				match = true
			}
			if match {
				return &trace.DynFinding{
					RuleID:     "dyn_suspicious_write",
					Category:   "dynamic",
					Severity:   "critical",
					Confidence: "high",
					Evidence:   fmt.Sprintf("write to persistence path: %s during %s phase", path, evt.Phase),
				}
			}
			return nil
		},
	}
}
