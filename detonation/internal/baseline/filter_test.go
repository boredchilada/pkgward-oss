// SPDX-License-Identifier: AGPL-3.0-or-later
package baseline

import (
	"testing"

	"detonation/internal/trace"
)

func TestFilterPipCache(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": "/root/.cache/pip/wheels/ab/cd/ef/pkg.whl"}},
		{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": "/root/.ssh/authorized_keys"}},
	}

	filtered := Filter("pypi", events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event after filter, got %d", len(filtered))
	}
	path, _ := filtered[0].Detail["path"].(string)
	if path != "/root/.ssh/authorized_keys" {
		t.Errorf("wrong event survived filter: %s", path)
	}
}

func TestFilterSitePackages(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": "/usr/local/lib/python3.11/site-packages/requests/__init__.py"}},
	}
	filtered := Filter("pypi", events)
	if len(filtered) != 0 {
		t.Errorf("expected 0 events (site-packages write is benign), got %d", len(filtered))
	}
}

func TestFilterPythonExec(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "process", Operation: "exec",
			Detail: map[string]interface{}{"binary": "/usr/local/bin/python3"}},
		{Phase: "install", Category: "process", Operation: "exec",
			Detail: map[string]interface{}{"binary": "/usr/bin/curl"}},
	}
	filtered := Filter("pypi", events)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 event, got %d", len(filtered))
	}
	binary, _ := filtered[0].Detail["binary"].(string)
	if binary != "/usr/bin/curl" {
		t.Errorf("wrong event: %s", binary)
	}
}

func TestFilterPycache(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": "/usr/local/lib/python3.11/__pycache__/os.cpython-311.pyc"}},
	}
	filtered := Filter("pypi", events)
	if len(filtered) != 0 {
		t.Errorf("expected 0 events (__pycache__ is benign), got %d", len(filtered))
	}
}

func TestFilterNpmCache(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": "/root/.npm/_cacache/tmp/0b838023"}},
	}
	filtered := Filter("npm", events)
	if len(filtered) != 0 {
		t.Errorf("expected 0 events (npm cache is benign), got %d", len(filtered))
	}
}

func TestFilterCargoRegistry(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": "/root/.cargo/registry/cache/crates.io-abc123/pkg-1.0.0.crate"}},
	}
	filtered := Filter("crates", events)
	if len(filtered) != 0 {
		t.Errorf("expected 0 events (cargo registry is benign), got %d", len(filtered))
	}
}

func TestFilterPassesSuspicious(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "45.33.32.156", "port": float64(443)}},
		{Phase: "install", Category: "file", Operation: "open",
			Detail: map[string]interface{}{"path": "/root/.aws/credentials"}},
		{Phase: "install", Category: "process", Operation: "exec",
			Detail: map[string]interface{}{"binary": "/bin/bash", "has_socket": true}},
	}
	filtered := Filter("pypi", events)
	if len(filtered) != 3 {
		t.Errorf("expected 3 suspicious events to pass, got %d", len(filtered))
	}
}

func TestFilterNpmNpmrc(t *testing.T) {
	// npm reads ~/.npmrc on every install — must be filtered so it doesn't
	// false-positive dyn_credential_read.
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "open",
			Detail: map[string]interface{}{"path": "/root/.npmrc"}},
	}
	filtered := Filter("npm", events)
	if len(filtered) != 0 {
		t.Errorf("expected 0 events (.npmrc read is benign for npm), got %d", len(filtered))
	}
}

func TestResolveAllowedIPsLiteral(t *testing.T) {
	got := resolveAllowedIPs([]string{"1.2.3.4", "  ", "2.3.4.5"})
	if _, ok := got["1.2.3.4"]; !ok {
		t.Error("literal IP 1.2.3.4 should resolve to itself")
	}
	if _, ok := got["2.3.4.5"]; !ok {
		t.Error("literal IP 2.3.4.5 should resolve to itself")
	}
}

func TestResolveAllowedIPsLocalhost(t *testing.T) {
	// localhost resolves from /etc/hosts (no network needed).
	got := resolveAllowedIPs([]string{"localhost"})
	if _, ok := got["127.0.0.1"]; !ok {
		t.Error("localhost should resolve to include 127.0.0.1")
	}
}

func TestFilterNonAllowedConnectPasses(t *testing.T) {
	// A connection to a non-registry destination must survive the net allowlist
	// (TEST-NET-3 address, never a real npm registry IP).
	events := []trace.TraceEvent{
		{Phase: "import", Category: "network", Operation: "connect",
			Detail: map[string]interface{}{"addr": "203.0.113.5", "port": float64(443)}},
	}
	filtered := Filter("npm", events)
	if len(filtered) != 1 {
		t.Errorf("expected suspicious non-registry connect to survive, got %d", len(filtered))
	}
}

func TestFilterUnknownEcosystem(t *testing.T) {
	events := []trace.TraceEvent{
		{Phase: "install", Category: "file", Operation: "write",
			Detail: map[string]interface{}{"path": "/tmp/something"}},
	}
	filtered := Filter("unknown", events)
	if len(filtered) != 1 {
		t.Errorf("unknown ecosystem should pass all events through, got %d", len(filtered))
	}
}
