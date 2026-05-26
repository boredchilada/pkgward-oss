// SPDX-License-Identifier: AGPL-3.0-or-later
package sandbox

import (
	"testing"
)

func TestNewSandboxConfig(t *testing.T) {
	cfg := NewSandboxConfig("pypi", "/tmp/archive/pkg.tar.gz")
	if cfg.ID == "" {
		t.Error("sandbox ID must not be empty")
	}
	if cfg.Ecosystem != "pypi" {
		t.Errorf("ecosystem = %q, want pypi", cfg.Ecosystem)
	}
	if cfg.ArchivePath != "/tmp/archive/pkg.tar.gz" {
		t.Errorf("archive path = %q", cfg.ArchivePath)
	}
	if cfg.CPULimit <= 0 {
		t.Error("CPU limit must be positive")
	}
	if cfg.MemoryLimitMB <= 0 {
		t.Error("memory limit must be positive")
	}
	if cfg.NetworkMode != "bridge" {
		t.Errorf("network mode = %q, want bridge", cfg.NetworkMode)
	}
}

func TestSandboxIDUnique(t *testing.T) {
	a := NewSandboxConfig("pypi", "/tmp/a.tar.gz")
	b := NewSandboxConfig("pypi", "/tmp/b.tar.gz")
	if a.ID == b.ID {
		t.Error("sandbox IDs must be unique")
	}
}

func TestBuildDockerRunArgs(t *testing.T) {
	cfg := NewSandboxConfig("pypi", "/tmp/pkg.tar.gz")
	args := cfg.DockerRunArgs("python:3.11-slim", []string{"pip", "install", "--no-deps", "/sandbox/pkg.tar.gz"})

	if len(args) == 0 {
		t.Fatal("empty docker args")
	}
	if args[0] != "run" {
		t.Errorf("first arg = %q, want \"run\"", args[0])
	}

	hasNetworkBridge := false
	hasImage := false
	hasMount := false
	hasRm := false
	for _, a := range args {
		switch a {
		case "--network=bridge":
			hasNetworkBridge = true
		case "--rm":
			hasRm = true
		case "python:3.11-slim":
			hasImage = true
		case "/tmp/pkg.tar.gz:/sandbox/pkg.tar.gz:ro":
			hasMount = true
		}
	}
	if !hasNetworkBridge {
		t.Error("--network=bridge missing")
	}
	if !hasRm {
		t.Error("--rm missing")
	}
	if !hasImage {
		t.Error("base image not in args")
	}
	if !hasMount {
		t.Error("archive bind-mount not in args")
	}
}
