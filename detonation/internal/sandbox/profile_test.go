// SPDX-License-Identifier: AGPL-3.0-or-later
package sandbox

import (
	"strings"
	"testing"
)

func TestPyPIProfile(t *testing.T) {
	p := GetProfile("pypi")
	if p == nil {
		t.Fatal("pypi profile not found")
	}
	if p.BaseImage != "python:3.11-slim" {
		t.Errorf("base image = %q", p.BaseImage)
	}
	install := p.InstallCmd("evil-package", "1.0.0", "/sandbox/pkg.tar.gz")
	if len(install) == 0 {
		t.Fatal("empty install command")
	}
	if install[0] != "pip" {
		t.Errorf("install cmd[0] = %q, want pip", install[0])
	}
	imp := p.ImportCmd("evil-package")
	if imp[0] != "python" {
		t.Errorf("import cmd[0] = %q, want python", imp[0])
	}
}

func TestNpmProfile(t *testing.T) {
	p := GetProfile("npm")
	if p == nil {
		t.Fatal("npm profile not found")
	}
	if p.BaseImage != "node:20-slim" {
		t.Errorf("base image = %q", p.BaseImage)
	}
	install := p.InstallCmd("chalk", "5.6.2", "/sandbox/chalk-5.6.2.tgz")
	if install[0] != "npm" {
		t.Errorf("install cmd[0] = %q, want npm", install[0])
	}
}

func TestCratesProfile(t *testing.T) {
	p := GetProfile("crates")
	if p == nil {
		t.Fatal("crates profile not found")
	}
	install := p.InstallCmd("evil-crate", "1.0.0", "/sandbox/evil-crate-1.0.0.crate")
	if install[0] != "sh" {
		t.Errorf("install cmd[0] = %q, want sh", install[0])
	}
	joined := strings.Join(install, " ")
	if !strings.Contains(joined, "tar -xzf") {
		t.Error("crates install must extract .crate tarball")
	}
	if !strings.Contains(joined, "cargo build") {
		t.Error("crates install must run cargo build")
	}
	if !strings.Contains(joined, "evil-crate-1.0.0") {
		t.Error("crates install must cd into extracted crate dir")
	}
	imp := p.ImportCmd("evil-crate")
	if imp != nil {
		t.Error("crates should have no import phase")
	}
}

func TestGomodProfile(t *testing.T) {
	p := GetProfile("gomod")
	if p == nil {
		t.Fatal("gomod profile not found")
	}
	if p.BaseImage != "golang:1.22-alpine" {
		t.Errorf("base image = %q", p.BaseImage)
	}
	install := p.InstallCmd("github.com/foo/bar", "v1.0.0", "/sandbox/bar-v1.0.0.zip")
	if install[0] != "sh" {
		t.Errorf("install cmd[0] = %q, want sh", install[0])
	}
	joined := strings.Join(install, " ")
	if !strings.Contains(joined, "unzip") {
		t.Error("gomod install must extract zip")
	}
	if !strings.Contains(joined, "go build") {
		t.Error("gomod install must run go build")
	}

	imp := p.ImportCmd("github.com/foo/bar")
	if imp == nil {
		t.Fatal("gomod should have import phase")
	}
	impJoined := strings.Join(imp, " ")
	if !strings.Contains(impJoined, "go test") {
		t.Error("gomod import must run go test to trigger init()")
	}
}

func TestUnknownProfile(t *testing.T) {
	p := GetProfile("unknown_ecosystem")
	if p != nil {
		t.Error("expected nil for unknown ecosystem")
	}
}

func TestProfileTimeouts(t *testing.T) {
	p := GetProfile("pypi")
	if p.InstallTimeoutSec <= 0 {
		t.Error("install timeout must be positive")
	}
	if p.ImportTimeoutSec <= 0 {
		t.Error("import timeout must be positive")
	}
}
