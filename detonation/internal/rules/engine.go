// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"fmt"
	"strings"

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

func (e *Engine) EvaluateWithDetails(events []trace.TraceEvent) ([]trace.DynFinding, []trace.TraceEvent) {
	seen := map[string]bool{}
	var findings []trace.DynFinding
	var matchedEvents []trace.TraceEvent

	for _, evt := range events {
		for _, r := range e.rules {
			if f := r.Evaluate(evt); f != nil {
				matched := evt
				matched.Detail["matched_rule"] = f.RuleID
				matchedEvents = append(matchedEvents, matched)
				if !seen[f.RuleID] {
					seen[f.RuleID] = true
					findings = append(findings, *f)
				}
			}
		}
	}
	return findings, matchedEvents
}

func FormatEvidence(findings []trace.DynFinding) string {
	if len(findings) == 0 {
		return "no behavioral findings"
	}
	var parts []string
	for _, f := range findings {
		parts = append(parts, fmt.Sprintf("[%s/%s] %s: %s", f.Severity, f.Confidence, f.RuleID, f.Evidence))
	}
	return strings.Join(parts, "; ")
}
