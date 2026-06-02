// SPDX-License-Identifier: AGPL-3.0-or-later
package sandbox

import (
	"strings"
	"testing"
)

func TestDockerRunArgsPlantsDecoyEnvAndMounts(t *testing.T) {
	cfg := NewSandboxConfig("npm", "/tmp/pkg.tgz")
	cfg.DecoyHome = "/srv/decoy-home"
	args := cfg.DockerRunArgs("node:20-slim", []string{"sh", "-c", "true"}, "")
	joined := strings.Join(args, " ")
	// env decoys (never appear in a guest argv, safe for the value-canary)
	for _, want := range []string{"GITHUB_TOKEN=", "OPENAI_API_KEY=", "AWS_SECRET_ACCESS_KEY="} {
		if !strings.Contains(joined, want) {
			t.Errorf("DockerRunArgs must plant decoy env %q", want)
		}
	}
	// file decoys bind-mounted read-only from the shared host home
	for _, want := range []string{
		"/srv/decoy-home/.aws/credentials:/root/.aws/credentials:ro",
		"/srv/decoy-home/.ssh/id_rsa:/root/.ssh/id_rsa:ro",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("DockerRunArgs must bind-mount decoy %q", want)
		}
	}
	// the real command must pass through unwrapped (no in-container seeding)
	if args[len(args)-1] != "true" || args[len(args)-3] != "sh" {
		t.Errorf("phase command must not be wrapped: %v", args[len(args)-3:])
	}
}

func TestDockerRunArgsNoMountsWithoutDecoyHome(t *testing.T) {
	cfg := NewSandboxConfig("npm", "/tmp/pkg.tgz") // DecoyHome unset
	args := cfg.DockerRunArgs("node:20-slim", []string{"sh", "-c", "true"}, "")
	if strings.Contains(strings.Join(args, " "), ":/root/.aws/credentials:ro") {
		t.Error("must not emit file mounts when DecoyHome is empty")
	}
}
