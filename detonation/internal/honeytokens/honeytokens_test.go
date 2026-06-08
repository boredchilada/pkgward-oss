// SPDX-License-Identifier: AGPL-3.0-or-later
package honeytokens

import (
	"strings"
	"testing"
)

// The whole point is that a worm cannot tell these are decoys. Guard against ever
// re-introducing a "decoy"/"honeypot"/"test"/"fake" tell into a planted value.
func TestNoSelfIdentifyingTells(t *testing.T) {
	tells := []string{"decoy", "honeypot", "honeytoken", "fake", "dummy", "notreal", "pkgward", "example"}
	for label, val := range secretValues {
		low := strings.ToLower(val)
		for _, tell := range tells {
			if strings.Contains(low, tell) {
				t.Errorf("secret %q value leaks a tell %q: %s", label, tell, val)
			}
		}
	}
}

func TestEnvArgsCoverProviders(t *testing.T) {
	joined := strings.Join(EnvArgs(), " ")
	for _, want := range []string{
		"OPENAI_API_KEY=sk-", "ANTHROPIC_API_KEY=sk-ant-", "AWS_SECRET_ACCESS_KEY=",
		"GITHUB_TOKEN=ghp_", "NPM_TOKEN=npm_", "STRIPE_SECRET_KEY=sk_live_",
		"DATABASE_URL=postgres://", "HF_TOKEN=hf_", "CI=true",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("env decoys missing %q", want)
		}
	}
}

func TestFileMountsCoverBroadSpread(t *testing.T) {
	mounts := strings.Join(FileMounts("/srv/decoy", "/sandbox"), " ")
	for _, want := range []string{
		":/root/.npmrc:ro", ":/root/.aws/credentials:ro", ":/root/.pypirc:ro",
		":/root/.config/gh/hosts.yml:ro", ":/root/.ssh/id_rsa:ro", ":/root/.ssh/id_ed25519:ro",
		":/root/.config/gcloud/application_default_credentials.json:ro", ":/root/.kube/config:ro",
		":/root/.cargo/credentials.toml:ro", ":/root/.config/solana/id.json:ro", ":/root/.env:ro",
		"/sandbox/.env:ro", // $PWD-scanning worms
	} {
		if !strings.Contains(mounts, want) {
			t.Errorf("file mounts missing %q", want)
		}
	}
	// host source paths must be under the shared decoy root
	if !strings.Contains(mounts, "/srv/decoy/.aws/credentials:") {
		t.Error("mount host path not rooted at the shared decoy home")
	}
}

func TestCanariesAreLongAndUnique(t *testing.T) {
	cs := Canaries()
	if len(cs) < 25 {
		t.Errorf("expected a broad canary set, got %d", len(cs))
	}
	seen := map[string]bool{}
	for _, c := range cs {
		if len(c.Value) < 12 {
			t.Errorf("canary %q too short to be low-FP: %q", c.Label, c.Value)
		}
		if seen[c.Value] {
			t.Errorf("duplicate canary value %q", c.Value)
		}
		seen[c.Value] = true
	}
	// longest-first ordering so the most specific value matches
	for i := 1; i < len(cs); i++ {
		if len(cs[i-1].Value) < len(cs[i].Value) {
			t.Error("canaries not sorted longest-first")
			break
		}
	}
}
