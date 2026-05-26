// SPDX-License-Identifier: AGPL-3.0-or-later
package sandbox

import "fmt"

type Profile struct {
	Ecosystem         string
	BaseImage         string
	InstallTimeoutSec int
	ImportTimeoutSec  int
	InstallCmd        func(name, version, archivePath string) []string
	ImportCmd         func(name string) []string
	ExtraPackages     []string
}

var profiles = map[string]*Profile{
	"pypi": {
		Ecosystem:         "pypi",
		BaseImage:         "python:3.11-slim",
		InstallTimeoutSec: 120,
		ImportTimeoutSec:  30,
		InstallCmd: func(name, version, archivePath string) []string {
			return []string{"pip", "install", "--no-deps", "--no-cache-dir", archivePath}
		},
		ImportCmd: func(name string) []string {
			return []string{"python", "-c", "import " + name}
		},
		ExtraPackages: []string{"gcc", "libc6-dev", "make"},
	},
	"npm": {
		Ecosystem:         "npm",
		BaseImage:         "node:20-slim",
		InstallTimeoutSec: 120,
		ImportTimeoutSec:  30,
		InstallCmd: func(name, version, archivePath string) []string {
			return []string{"npm", "install", "--ignore-scripts=false", archivePath}
		},
		ImportCmd: func(name string) []string {
			return []string{"node", "-e", "require('" + name + "')"}
		},
		ExtraPackages: nil,
	},
	"crates": {
		Ecosystem:         "crates",
		BaseImage:         "rust:1-slim",
		InstallTimeoutSec: 180,
		ImportTimeoutSec:  0,
		InstallCmd: func(name, version, archivePath string) []string {
			return []string{"sh", "-c", fmt.Sprintf(
				"tar -xzf %s && cd %s-%s && cargo build 2>&1",
				archivePath, name, version)}
		},
		ImportCmd: func(name string) []string {
			return nil
		},
		ExtraPackages: []string{"gcc", "libc6-dev", "pkg-config"},
	},
	"gomod": {
		Ecosystem:         "gomod",
		BaseImage:         "golang:1.22-alpine",
		InstallTimeoutSec: 180,
		ImportTimeoutSec:  60,
		InstallCmd: func(name, version, archivePath string) []string {
			return []string{"sh", "-c", fmt.Sprintf(
				"mkdir -p /tmp/build && cd /tmp/build && unzip -qo %s && "+
					"cd \"$(ls -d */|head -1)\" && go mod init _sandbox 2>/dev/null; go build ./... 2>&1",
				archivePath)}
		},
		ImportCmd: func(name string) []string {
			return []string{"sh", "-c",
				"cd /tmp/build/$(ls -d */|head -1) && go test -run='^ -count=1 ./... 2>&1"}
		},
		ExtraPackages: []string{"gcc", "musl-dev", "unzip"},
	},
}

func GetProfile(ecosystem string) *Profile {
	return profiles[ecosystem]
}

func SupportedEcosystems() []string {
	keys := make([]string, 0, len(profiles))
	for k := range profiles {
		keys = append(keys, k)
	}
	return keys
}
