// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"testing"

	"detonation/internal/trace"
)

func TestInstallExfil(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "network",
		Operation: "connect",
		Detail:    map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)},
	}

	rules := AllRules()
	var matched []trace.DynFinding
	for _, r := range rules {
		if f := r.Evaluate(evt); f != nil {
			matched = append(matched, *f)
		}
	}

	if len(matched) == 0 {
		t.Fatal("expected dyn_install_exfil to match")
	}
	if matched[0].RuleID != "dyn_install_exfil" {
		t.Errorf("rule_id = %q, want dyn_install_exfil", matched[0].RuleID)
	}
	if matched[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", matched[0].Severity)
	}
}

func TestInstallExfilSkipsImport(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "import",
		Category:  "network",
		Operation: "connect",
		Detail:    map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)},
	}

	rules := AllRules()
	for _, r := range rules {
		if r.ID == "dyn_install_exfil" {
			if f := r.Evaluate(evt); f != nil {
				t.Error("dyn_install_exfil should NOT match import phase")
			}
		}
	}
}

func TestImportExfil(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "import",
		Category:  "network",
		Operation: "connect",
		Detail:    map[string]interface{}{"addr": "192.168.1.1", "port": float64(8080)},
	}

	rules := AllRules()
	var matched bool
	for _, r := range rules {
		if r.ID == "dyn_import_exfil" {
			if f := r.Evaluate(evt); f != nil {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("expected dyn_import_exfil to match")
	}
}

func TestCredentialRead(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "file",
		Operation: "open",
		Detail:    map[string]interface{}{"path": "/root/.ssh/id_rsa"},
	}

	rules := AllRules()
	var matched bool
	for _, r := range rules {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_credential_read" {
			matched = true
		}
	}
	if !matched {
		t.Fatal("expected dyn_credential_read to match")
	}
}

func TestCredentialReadSkipsNormal(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "file",
		Operation: "open",
		Detail:    map[string]interface{}{"path": "/usr/lib/python3.11/os.py"},
	}

	rules := AllRules()
	for _, r := range rules {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_credential_read" {
			t.Error("dyn_credential_read should not match normal Python files")
		}
	}
}

func TestReverseShell(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "process",
		Operation: "exec",
		Detail:    map[string]interface{}{"binary": "/bin/bash", "has_socket": true},
	}

	rules := AllRules()
	var matched bool
	for _, r := range rules {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_reverse_shell" {
			matched = true
		}
	}
	if !matched {
		t.Fatal("expected dyn_reverse_shell to match")
	}
}

func TestProcInject(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "process",
		Operation: "ptrace",
		Detail:    map[string]interface{}{},
	}

	rules := AllRules()
	var matched bool
	for _, r := range rules {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_proc_inject" {
			matched = true
		}
	}
	if !matched {
		t.Fatal("expected dyn_proc_inject to match")
	}
}

func TestDNSExfil(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "dns",
		Operation: "query",
		Detail: map[string]interface{}{
			"name":               "a3f8b2c1d4e5f678.evil.tk",
			"subdomain_entropy":  float64(4.5),
		},
	}

	rules := AllRules()
	var matched bool
	for _, r := range rules {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_dns_exfil" {
			matched = true
		}
	}
	if !matched {
		t.Fatal("expected dyn_dns_exfil to match")
	}
}

func TestEnvHarvest(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "process",
		Operation: "readenv",
		Detail:    map[string]interface{}{"name": "AWS_SECRET_ACCESS_KEY"},
	}

	rules := AllRules()
	var matched bool
	for _, r := range rules {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_env_harvest" {
			matched = true
		}
	}
	if !matched {
		t.Fatal("expected dyn_env_harvest to match")
	}
}
