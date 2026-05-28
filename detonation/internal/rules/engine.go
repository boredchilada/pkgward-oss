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

	for _, evt := range events {
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
