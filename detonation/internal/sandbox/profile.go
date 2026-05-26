// SPDX-License-Identifier: AGPL-3.0-or-later
package sandbox

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
			return []string{"cargo", "install", "--path", archivePath}
		},
		ImportCmd: func(name string) []string {
			return nil
		},
		ExtraPackages: []string{"gcc", "libc6-dev", "pkg-config"},
	},
	"gomod": {
		Ecosystem:         "gomod",
		BaseImage:         "golang:1.22-alpine",
		InstallTimeoutSec: 240,
		ImportTimeoutSec:  0,
		// Go has no install-time hook the way pip/npm do. Its dynamic attack
		// surface is `go:generate` directives (which run arbitrary commands)
		// plus any code that executes while the toolchain resolves/builds the
		// module. We extract the module zip and exercise download → generate →
		// build so Tetragon traces any embedded execution. The alpine image has
		// no gcc/git, so CGO builds and VCS-only deps fail — that is expected
		// and benign (CGO/#cgo directives stay covered by the static
		// go_directives analyzer); the install-time *behavior* is what we trace.
		// GOTOOLCHAIN=local stops go from auto-downloading a newer toolchain
		// (network noise + surprise exec); GOSUMDB=off avoids sum.golang.org
		// lookups; CGO_ENABLED=0 lets pure-Go packages build without gcc.
		InstallCmd: func(name, version, archivePath string) []string {
			// A Go module zip always nests its content under a top dir named
			// "<modulepath>@<version>" (the version component carries the '@'),
			// so the module root is the first directory containing '@'. Fall
			// back to the shallowest go.mod, and `go mod init` when the module
			// predates modules (no go.mod) so generate/build still have a
			// module context. All steps are best-effort (|| true).
			script := "set -e\n" +
				"mkdir -p /tmp/det && cd /tmp/det\n" +
				"unzip -q '" + archivePath + "'\n" +
				"root=$(find . -type d -name '*@*' | head -1)\n" +
				"if [ -z \"$root\" ]; then root=$(find . -name go.mod | awk '{print length, $0}' | sort -n | head -1 | sed 's#/go.mod##'); fi\n" +
				"cd \"${root:-.}\"\n" +
				"[ -f go.mod ] || go mod init '" + name + "' 2>/dev/null || go mod init detonate 2>/dev/null || true\n" +
				"export GOFLAGS=-mod=mod GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0\n" +
				"go mod download 2>&1 | tail -n 5 || true\n" +
				"go generate ./... 2>&1 | tail -n 40 || true\n" +
				"go build ./... 2>&1 | tail -n 40 || true\n"
			return []string{"sh", "-c", script}
		},
		ImportCmd: func(name string) []string {
			return nil
		},
		ExtraPackages: nil,
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
