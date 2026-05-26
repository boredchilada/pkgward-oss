// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"fmt"
	"strings"

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

func sensitiveEnvPrefixes() []string {
	return intel.Current().Rules.SensitiveEnvPrefixes
}

func shellBinaries() []string {
	return intel.Current().Rules.ShellBinaries
}

func AllRules() []Rule {
	return []Rule{
		// installExfil() is intentionally NOT active: it fires on any
		// install-phase network connect, but sdists legitimately fetch build
		// deps from registries, so it would false-positive on most packages.
		// Deferred until it can distinguish registry traffic from real exfil
		// (offline install or destination allowlist). The rule + its tests are
		// retained so re-enabling is a one-line change.
		importExfil(),
		credentialRead(),
		reverseShell(),
		procInject(),
		dnsExfil(),
		envHarvest(),
		suspiciousWrite(),
		filelessExec(),
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
				Severity:   "critical",
				Confidence: "high",
				Evidence:   fmt.Sprintf("connect(AF_INET, %s:%d) during install phase", addr, int(port)),
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
			}
			for _, s := range suspicious {
				if strings.HasPrefix(path, s) {
					return &trace.DynFinding{
						RuleID:     "dyn_suspicious_write",
						Category:   "dynamic",
						Severity:   "critical",
						Confidence: "high",
						Evidence:   fmt.Sprintf("write to persistence path: %s during %s phase", path, evt.Phase),
					}
				}
			}
			return nil
		},
	}
}
