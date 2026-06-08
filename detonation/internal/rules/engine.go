// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"strings"

	"detonation/internal/trace"
)

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// isHarnessLaunch reports whether evt is OUR own `docker run …` command that launches
// the sandbox — not guest behavior. That host-side exec carries every planted
// `-e DECOY=…` env arg and every `-v …/.env:/root/.env` decoy mount by construction, so
// evaluating it self-matched the honeytoken canary (the long discord_webhook value) on
// EVERY detonation and looked like secret access — flipping legit packages to malicious
// (the 2026-06-08 FP cascade). A package inside the rootless sandbox can never invoke the
// container runtime, so any such exec is always ours. We drop it from rule evaluation
// (it stays persisted in trace_event for audit).
func isHarnessLaunch(evt trace.TraceEvent) bool {
	if evt.Category != "process" || evt.Operation != "exec" {
		return false
	}
	bin, _ := evt.Detail["binary"].(string)
	if i := strings.LastIndexByte(bin, '/'); i >= 0 {
		bin = bin[i+1:]
	}
	switch bin {
	case "docker", "podman", "runc", "nerdctl", "ctr":
		return true
	}
	return false
}

func (e *Engine) Evaluate(events []trace.TraceEvent) []trace.DynFinding {
	// Exclude the harness's own sandbox-launch command before ANY rule (and before
	// RunSensitiveAccess) sees it — see isHarnessLaunch.
	scoped := make([]trace.TraceEvent, 0, len(events))
	for _, evt := range events {
		if !isHarnessLaunch(evt) {
			scoped = append(scoped, evt)
		}
	}
	events = scoped

	seen := map[string]bool{}
	var findings []trace.DynFinding

	// Detonation-level fact for the exfil chain: did the package read a secret
	// anywhere in this run? install/import exfil require it alongside an external
	// egress, so a lone connect no longer convicts. Computed once, then surfaced to
	// the per-event rules via the connect events' detail.
	sensitive := RunSensitiveAccess(events)

	for _, evt := range events {
		if sensitive && evt.Category == "network" && evt.Operation == "connect" {
			// copy the detail so the run-level flag reaches the chain rules without
			// mutating the shared event slice.
			d := make(map[string]interface{}, len(evt.Detail)+1)
			for k, v := range evt.Detail {
				d[k] = v
			}
			d["run_sensitive_access"] = true
			evt.Detail = d
		}
		for _, r := range e.rules {
			if f := r.Evaluate(evt); f != nil {
				if seen[f.RuleID] {
					continue
				}
				seen[f.RuleID] = true
				findings = append(findings, *f)
			}
		}
	}
	return findings
}
