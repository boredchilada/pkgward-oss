// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"testing"

	"detonation/internal/trace"
)

// installExfil is intentionally excluded from AllRules() (see definitions.go),
// so these tests exercise the rule function directly to keep its logic covered
// for when it is re-enabled with a better design.
func TestInstallExfil(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "network",
		Operation: "connect",
		Detail:    map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)},
	}

	f := installExfil().Evaluate(evt)
	if f == nil {
		t.Fatal("expected dyn_install_exfil to match")
	}
	if f.RuleID != "dyn_install_exfil" {
		t.Errorf("rule_id = %q, want dyn_install_exfil", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
}

func TestInstallExfilSkipsImport(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "import",
		Category:  "network",
		Operation: "connect",
		Detail:    map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)},
	}

	if f := installExfil().Evaluate(evt); f != nil {
		t.Error("dyn_install_exfil should NOT match import phase")
	}
}

func TestInstallExfilNotInActiveSet(t *testing.T) {
	for _, r := range AllRules() {
		if r.ID == "dyn_install_exfil" {
			t.Error("dyn_install_exfil must not be in AllRules() — deferred pending redesign")
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
			"name":              "a3f8b2c1d4e5f678.evil.tk",
			"subdomain_entropy": float64(4.5),
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
		Category:  "file",
		Operation: "open",
		Detail:    map[string]interface{}{"path": "/proc/1234/environ"},
	}

	if f := envHarvest().Evaluate(evt); f == nil || f.RuleID != "dyn_env_harvest" {
		t.Fatal("expected dyn_env_harvest to match /proc/<pid>/environ read")
	}
}

func TestEnvHarvestSkipsOrdinaryOpen(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "file",
		Operation: "open",
		Detail:    map[string]interface{}{"path": "/app/config.json"},
	}
	if f := envHarvest().Evaluate(evt); f != nil {
		t.Errorf("dyn_env_harvest should not match %v", evt.Detail["path"])
	}
}

func TestSuspiciousWrite(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "file",
		Operation: "write",
		Detail:    map[string]interface{}{"path": "/root/.bashrc"},
	}
	f := suspiciousWrite().Evaluate(evt)
	if f == nil || f.RuleID != "dyn_suspicious_write" {
		t.Fatal("expected dyn_suspicious_write to match persistence write")
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
}

func TestFilelessExec(t *testing.T) {
	crit := filelessExec().Evaluate(trace.TraceEvent{
		Phase: "import", Category: "process", Operation: "fileless_exec",
	})
	if crit == nil || crit.Severity != "critical" {
		t.Fatalf("expected critical dyn_fileless_exec for execveat, got %v", crit)
	}
	med := filelessExec().Evaluate(trace.TraceEvent{
		Phase: "install", Category: "process", Operation: "memfd_create",
		Detail: map[string]interface{}{"name": "x"},
	})
	if med == nil || med.Severity != "medium" {
		t.Fatalf("expected medium dyn_fileless_exec for memfd_create, got %v", med)
	}
	if f := filelessExec().Evaluate(trace.TraceEvent{Category: "process", Operation: "exec"}); f != nil {
		t.Error("dyn_fileless_exec should not match ordinary exec")
	}
}
