// SPDX-License-Identifier: AGPL-3.0-or-later
package trace

import (
	"encoding/json"
	"testing"
)

func TestTraceEventJSON(t *testing.T) {
	raw := `{
		"phase": "install",
		"category": "network",
		"operation": "connect",
		"pid": 12345,
		"binary": "/usr/bin/python3",
		"detail": {"addr": "45.33.32.156", "port": 443, "family": "AF_INET"}
	}`

	var evt TraceEvent
	if err := json.Unmarshal([]byte(raw), &evt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if evt.Phase != "install" {
		t.Errorf("phase = %q, want install", evt.Phase)
	}
	if evt.Category != "network" {
		t.Errorf("category = %q, want network", evt.Category)
	}
	if evt.Detail["addr"] != "45.33.32.156" {
		t.Errorf("detail.addr = %v, want 45.33.32.156", evt.Detail["addr"])
	}
}

func TestFindingJSON(t *testing.T) {
	f := DynFinding{
		RuleID:     "dyn_install_exfil",
		Category:   "dynamic",
		Severity:   "critical",
		Confidence: "high",
		Evidence:   "connect(AF_INET, 45.33.32.156:443) during install phase",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded DynFinding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.RuleID != "dyn_install_exfil" {
		t.Errorf("rule_id = %q, want dyn_install_exfil", decoded.RuleID)
	}
}
