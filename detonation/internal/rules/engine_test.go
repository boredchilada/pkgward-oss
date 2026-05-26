// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"testing"

	"detonation/internal/trace"
)

func TestEngineNoEvents(t *testing.T) {
	eng := NewEngine(AllRules())
	findings := eng.Evaluate(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestEngineMultipleMatches(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "10.0.0.1", "port": float64(80)}},
		{Phase: "install", Category: "file", Operation: "open",
			Detail: map[string]interface{}{"path": "/root/.ssh/id_rsa"}},
		{Phase: "install", Category: "file", Operation: "open",
			Detail: map[string]interface{}{"path": "/usr/lib/python3.11/os.py"}},
	}

	eng := NewEngine(AllRules())
	findings := eng.Evaluate(events)

	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}

	if !ruleIDs["dyn_install_exfil"] {
		t.Error("expected dyn_install_exfil")
	}
	if !ruleIDs["dyn_credential_read"] {
		t.Error("expected dyn_credential_read")
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

func TestEngineDeduplicates(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "10.0.0.1", "port": float64(80)}},
		{Phase: "install", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "10.0.0.2", "port": float64(443)}},
	}

	eng := NewEngine(AllRules())
	findings := eng.Evaluate(events)

	exfilCount := 0
	for _, f := range findings {
		if f.RuleID == "dyn_install_exfil" {
			exfilCount++
		}
	}
	if exfilCount != 1 {
		t.Errorf("expected 1 deduplicated dyn_install_exfil finding, got %d", exfilCount)
	}
}
