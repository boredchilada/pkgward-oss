// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"detonation/internal/trace"
)

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

func (e *Engine) Evaluate(events []trace.TraceEvent) []trace.DynFinding {
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
