// SPDX-License-Identifier: AGPL-3.0-or-later
//go:build linux

package honeytokens

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMaterializeHomeWritesDecoys materializes the shared decoy home to disk (as
// the sandbox does once at startup) and asserts every decoy file lands with its
// secret — this is what gets bind-mounted into every container.
func TestMaterializeHomeWritesDecoys(t *testing.T) {
	root := t.TempDir()
	if err := MaterializeHome(root); err != nil {
		t.Fatalf("MaterializeHome: %v", err)
	}
	want := map[string]string{
		".aws/credentials":        secretValues["aws_secret"],
		".aws/config":             "region=us-east-1",
		".npmrc":                  secretValues["npm_token"],
		".pypirc":                 secretValues["pypi_token"],
		".ssh/id_rsa":             "OPENSSH PRIVATE KEY",
		".ssh/id_ed25519":         "OPENSSH PRIVATE KEY",
		".config/gh/hosts.yml":    secretValues["github_pat"],
		".git-credentials":        secretValues["gitlab_token"],
		".netrc":                  secretValues["openai_key"],
		".docker/config.json":     "ghcr.io",
		".kube/config":            "k8s-prod.internal",
		".cargo/credentials.toml": secretValues["cargo_token"],
		".config/solana/id.json":  secretValues["solana_key"],
		".env":                    secretValues["openai_key"],
	}
	for rel, marker := range want {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("decoy %s not materialized: %v", rel, err)
			continue
		}
		if !strings.Contains(string(b), marker) {
			t.Errorf("decoy %s missing expected content %q", rel, marker)
		}
	}
	// idempotent: a second call (shared tree reused across detonations) must not error
	if err := MaterializeHome(root); err != nil {
		t.Errorf("MaterializeHome not idempotent: %v", err)
	}
}
