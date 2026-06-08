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

// Image is the container image the sandbox actually runs. The derived
// `pkgward-det-<eco>` image (BaseImage + the broad runtime libs/tools real
// payloads need — see deploy/build-sandbox-images.sh) is preferred so native
// binaries execute and trace instead of dying at dlopen; we fall back to the raw
// BaseImage only if the derived image was never built.
func (p *Profile) Image() string {
	return "pkgward-det-" + p.Ecosystem
}

var profiles = map[string]*Profile{
	"pypi": {
		Ecosystem:         "pypi",
		BaseImage:         "python:3.13-slim-trixie",
		InstallTimeoutSec: 120,
		ImportTimeoutSec:  30,
		InstallCmd: func(name, version, archivePath string) []string {
			return []string{"pip", "install", "--no-deps", "--no-cache-dir", archivePath}
		},
		ImportCmd: func(name string) []string {
			// `import <dist-name>` is a SyntaxError for the (very common) hyphenated
			// names and simply wrong whenever the module != dist name (sklearn,
			// yaml, bs4), so the import-time payload never ran — ~91% of pypi
			// detonations failed import with exit 1 and saw nothing. Resolve the
			// distribution's ACTUAL top-level module(s) from top_level.txt (mangled
			// name as fallback) and import each, then settle so an import-time
			// background/daemon thread completes its network calls and is traced
			// (mirrors the npm settle window). PyPI names cannot contain quotes, so
			// embedding name in a double-quoted literal is safe.
			// The settle MUST be inside the python process: an import-time payload
			// typically runs in a daemon thread, which is killed the instant the
			// interpreter exits (right after import returns). A shell-level sleep
			// keeps the container alive but not the python process, so the thread
			// never gets to connect/exfil. Sleeping in-process keeps the daemon
			// thread running so Tetragon traces its network/file activity.
			py := "import importlib, os, time\n" +
				"try:\n" +
				"    from importlib.metadata import distribution\n" +
				"    tops=(distribution(\"" + name + "\").read_text(\"top_level.txt\") or \"\").split()\n" +
				"except Exception:\n" +
				"    tops=[]\n" +
				"if not tops:\n" +
				"    tops=[\"" + name + "\".replace(\"-\",\"_\").replace(\".\",\"_\")]\n" +
				"for t in tops:\n" +
				"    try: importlib.import_module(t)\n" +
				"    except Exception: pass\n" +
				"try: time.sleep(int(os.environ.get(\"DET_SETTLE_SEC\",\"10\")))\n" +
				"except Exception: pass\n"
			return []string{"python", "-c", py}
		},
		ExtraPackages: []string{"gcc", "libc6-dev", "make"},
	},
	"npm": {
		Ecosystem:         "npm",
		BaseImage:         "node:22-trixie-slim",
		InstallTimeoutSec: 120,
		ImportTimeoutSec:  30,
		InstallCmd: func(name, version, archivePath string) []string {
			// Run the package's OWN lifecycle hooks directly instead of
			// `npm install <tarball>`. The latter spends the install budget
			// resolving the dependency tree first, so a heavy/native dep (e.g.
			// `sharp` downloading prebuilt libvips) can run out the timeout
			// before the target's postinstall ever fires — shadowing an
			// install-hook payload from the tracer (exactly how baileys-mbuilder
			// evaded dynamic capture). Mirrors pypi's `--no-deps`: trace the
			// target's install behavior, not its dependencies'. Deps are placed
			// best-effort with scripts OFF and time-bounded, so a hook that needs
			// them still has them, but a slow dep can't hide the payload. Archive
			// path is single-quoted (npm names / our basenames never contain a
			// single quote); the loop reads each script body from package.json
			// and runs pre/install/post in order so Tetragon traces whatever
			// they exec/connect/write.
			script := "set +e\n" +
				"mkdir -p /sandbox/pkg && cd /sandbox/pkg\n" +
				"tar xzf '" + archivePath + "' --strip-components=1\n" +
				"timeout 60 npm install --ignore-scripts --no-audit --no-fund --no-package-lock >/dev/null 2>&1\n" +
				"for h in preinstall install postinstall; do\n" +
				"  s=$(node -e \"try{var x=(require('./package.json').scripts||{})['$h']||'';process.stdout.write(x)}catch(e){}\")\n" +
				"  if [ -n \"$s\" ]; then echo \"[det] $h: $s\"; sh -c \"$s\"; fi\n" +
				"done\n" +
				// Runtime entry + CLI bins fire at require/CLI time, NOT install. The
				// import phase runs in a fresh container where this package isn't
				// resolvable (only the archive is mounted), so `node -e require(name)`
				// MODULE_NOT_FOUNDs and a require-time payload — a self-decoding loader
				// shipped as `main`, or a downloader `bin` — never executes (turbo-dls
				// 1.3.5). Run them HERE where the package is extracted, as ENTRY modules
				// (node <file>, not require()) so payloads gated on require.main===module
				// fire. Backgrounded + time-boxed so a blocking/looping entry can't eat
				// the settle window; Tetragon traces whatever they exec/connect/write.
				"main=$(node -e \"try{var m=require('./package.json').main||'index.js';process.stdout.write(typeof m==='string'?m:'')}catch(e){}\")\n" +
				"for f in \"$main\" index.js; do\n" +
				"  if [ -n \"$f\" ] && [ -f \"$f\" ]; then echo \"[det] entry: $f\"; timeout 15 node \"$f\" >/dev/null 2>&1 & break; fi\n" +
				"done\n" +
				"node -e \"try{var b=require('./package.json').bin;if(typeof b==='string')console.log(b);else if(b)Object.keys(b).forEach(function(k){console.log(b[k])})}catch(e){}\" | while IFS= read -r bp; do\n" +
				"  if [ -n \"$bp\" ] && [ -f \"$bp\" ]; then echo \"[det] bin: $bp\"; timeout 15 node \"$bp\" >/dev/null 2>&1 & fi\n" +
				"done\n" +
				// Settle window: many loaders spawn the real payload DETACHED and
				// exit immediately (logger-active: `node utils.js` -> detached
				// --bg agent that does the credential sweep). Without this the
				// container is torn down before the payload acts, so we stay alive
				// to keep tracing it. Bounded well under InstallTimeoutSec.
				"sleep \"${DET_SETTLE_SEC:-10}\"\n"
			return []string{"sh", "-c", script}
		},
		ImportCmd: func(name string) []string {
			return []string{"node", "-e", "require('" + name + "')"}
		},
		ExtraPackages: nil,
	},
	"crates": {
		Ecosystem:         "crates",
		BaseImage:         "rust:1-trixie",
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
		BaseImage:         "golang:1.24-trixie",
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
