package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// emittedDetailKeys is the set of Detail map keys the Tetragon collector actually
// populates (see internal/trace/collector.go). A behavioral rule that reads any
// other key can never fire on real traces — it only goes green on synthetic
// tests. Keep this in sync with collector.go when the collector emits a new key.
var emittedDetailKeys = map[string]bool{
	"binary":    true, // process/exec
	"arguments": true, // process/exec
	"addr":      true, // network/connect
	"port":      true, // network/connect
	"family":    true, // network/connect
	"path":      true, // file/open, file/write
	"name":      true, // process/memfd_create
	"hostname":   true, // network/connect — DNS annotation (server.go, when DNS capture is enabled)
	"abuse_host": true, // network/connect — set by the baseline filter on abuse-host connects
	"run_sensitive_access": true, // network/connect — set by the rules engine (detonation-level
	// secret-access fact) so the install/import exfil chain can require it. Not collector-emitted.
}

// knownDeadDetailKeys documents rules that read a key the collector does NOT emit
// — they are dead until the data source is wired (a Tetragon hook + collector
// enrichment). Listing them here keeps coverage HONEST: the gap is acknowledged,
// not hidden, and a NEW rule reading an un-emitted key still fails the test below.
//
//	has_socket        -> dyn_reverse_shell  (needs socket-fd -> PID correlation)
//	subdomain_entropy -> dyn_dns_exfil      (needs a DNS query hook + entropy calc)
var knownDeadDetailKeys = map[string]bool{
	"has_socket":        true,
	"subdomain_entropy": true,
}

// TestRuleDetailKeysAreEmittable fails if any rule reads a Detail key that the
// collector never emits and that isn't explicitly waived as known-dead. This is
// the guard against shipping a rule that silently can never fire.
func TestRuleDetailKeysAreEmittable(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("definitions.go"))
	if err != nil {
		t.Fatalf("read definitions.go: %v", err)
	}
	re := regexp.MustCompile(`Detail\["([a-zA-Z0-9_]+)"\]`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("no Detail[\"...\"] reads found — regex or file layout changed")
	}
	var offenders []string
	for _, m := range matches {
		key := m[1]
		if emittedDetailKeys[key] || knownDeadDetailKeys[key] {
			continue
		}
		offenders = append(offenders, key)
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("rules read Detail keys the collector never emits and that aren't "+
			"waived as known-dead: %v\nWire the collector to emit them, or add to "+
			"knownDeadDetailKeys with a wiring note.", offenders)
	}
}
