# Ecosystem Reference — API & Attack Surface

Reference for implementing and maintaining ecosystem adapters.

## PyPI (Python) — ACTIVE

### Discovery (Real-time)
- **RSS feeds** (poll every 60s):
  - New packages: `https://pypi.org/rss/packages.xml`
  - Updates: `https://pypi.org/rss/updates.xml`
- **XML-RPC changelog** (cursor-based):
  - Endpoint: `https://pypi.org/pypi` (XML-RPC `changelog_since_serial()`)
  - Returns `(name, version, timestamp, action, serial)` tuples
  - Track position via serial number in `ScanCursor`

### Metadata & Download
- Metadata: `GET https://pypi.org/pypi/{name}/{version}/json`
  - Returns `info{}` (author, summary, requires_python, classifiers, etc.) + `urls[]` (download links)
- Download: URLs from the `urls[]` array, hosted on `files.pythonhosted.org`
  - sdist: `.tar.gz` (gzipped tarball)
  - wheel: `.whl` (ZIP with .dist-info)
- Integrity: SHA256 in `digests` field of each URL entry

### Watchlist (Top packages)
- Source: `https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json`
- Contains top ~8000 packages ranked by 30-day download count
- Refresh weekly

### Attack Surface
| Vector | File | Risk | Detection |
|--------|------|------|-----------|
| `setup.py` install scripts | `setup.py` | Critical — runs at `pip install` | AST parse for `urlopen`/`exec`/`subprocess` chains |
| Import-time code | `__init__.py` | High — runs on `import` | AST parse for network + subprocess at module level |
| Obfuscated payloads | Any `.py` | High | Base64 blob detection, encoded string patterns |
| Typosquatting | Package name | High | Levenshtein distance vs top-N packages |
| Dependency confusion | Package name | Medium | Name collision with internal package names |

### Behavioral Chain Rules
- `installer.urlopen_exec_chain` — network fetch + exec in setup.py
- `imports.network_subprocess_chain` — network + subprocess in __init__.py

---

## Crates.io (Rust) — ACTIVE

### Discovery (Real-time)
- **RSS feeds** (poll every 60s):
  - New crates: `https://static.crates.io/rss/crates.xml` (past 60min, min 50 entries)
  - Updates: `https://static.crates.io/rss/updates.xml` (past 60min, min 100 entries)
  - Per-crate: `https://static.crates.io/rss/crates/{name}.xml`
- **Sparse Index** (per-crate, pull-based):
  - Base: `https://index.crates.io/`
  - Path convention:
    - 1-char names: `1/{name}`
    - 2-char names: `2/{name}`
    - 3-char names: `3/{first_char}/{name}`
    - 4+ char names: `{first_two}/{next_two}/{name}`
  - Each line is NDJSON: `{"name","vers","deps","cksum","features","yanked",...}`
- **Database dump** (bulk, 24h): `https://static.crates.io/db-dump.tar.gz`

### Metadata & Download
- API base: `https://crates.io/api/v1`
- **Required header:** `User-Agent: pypi-scanner/1.0 (contact: email@example.com)`
- Crate info: `GET /crates/{name}`
- Version info: `GET /crates/{name}/{version}`
- Search: `GET /crates?q={query}&sort={sort}&per_page={n}&page={p}`
  - Sort: `downloads`, `recent-downloads`, `alphabetical`, `relevance`, `new`
- **Download (CDN, no rate limits):**
  - `https://static.crates.io/crates/{name}/{name}-{version}.crate`
  - `.crate` files are gzipped tarballs — extract with `tarfile`
- Integrity: SHA256 from sparse index `cksum` field
- OpenAPI spec: `https://crates.io/api/openapi.json`

### Archive Structure (.crate)
```
{name}-{version}/
  Cargo.toml
  Cargo.toml.orig
  src/
    lib.rs or main.rs
    ...
  build.rs (if present)
```

### Watchlist (Top crates)
- API: `GET https://crates.io/api/v1/crates?sort=downloads&per_page=100` (paginate)
- Also: `?sort=recent-downloads` for recent popularity
- Top crates: syn (1.69B), hashbrown (1.6B), getrandom (1.3B)
- Ecosystem: 270K+ crates, 310B+ total downloads
- Also: https://lib.rs/stats for ecosystem statistics

### Attack Surface
| Vector | File | Risk | Detection |
|--------|------|------|-----------|
| `build.rs` (build scripts) | `build.rs` | Critical — runs at compile time, full system access | Scan for `Command::new`, `std::net`, `reqwest`, `ureq`, env var reads |
| Proc macros | Any `.rs` in proc-macro crate | Critical — runs at compile time | Check `Cargo.toml` for `proc-macro = true`, scan for suspicious patterns |
| `unsafe` blocks | Any `.rs` | Medium — bypasses memory safety | Regex for `unsafe {`, flag excessive usage |
| Runtime malware | Any `.rs` | High — crypto key theft, payload download | Scan for HTTP calls, temp dir writes, env var exfil |
| Typosquatting | Crate name | High | Levenshtein distance vs top-N crates |
| `links` field | `Cargo.toml` | Low — influences downstream builds | Check for unusual `links` values |

### Behavioral Chain Rules
- `crates.build_rs_net_exec_chain` — network + command exec in build.rs

### Real-World Attacks
- `faster_log` / `async_println` (2025): Runtime crypto key theft, 8K+ downloads
- `evm-units` (2025): Cryptocurrency exfiltration, 7K+ downloads
- Typosquatting is heavily used in the Rust ecosystem

---

## Go Modules — ACTIVE

### Discovery (Real-time)
- **Module Index** (NDJSON feed, poll every 60s):
  - `https://index.golang.org/index?since={RFC3339_timestamp}&limit=2000`
  - Each line: `{"Path":"github.com/user/mod","Version":"v1.2.3","Timestamp":"2024-01-15T10:30:00.123456Z"}`
  - Track position via `Timestamp` of last entry in `ScanCursor`
  - `?include=all` for all versions ever served (including retracted)
- **Sum database** (`sum.golang.org`): Merkle tree for integrity verification, NOT for discovery

### Metadata & Download (GOPROXY protocol)
- Base: `https://proxy.golang.org`
- **Module path encoding:** uppercase → `!` + lowercase (e.g., `Azure` → `!azure`)
- Endpoints for module `{mod}`:
  - Version list: `GET /{mod}/@v/list` (plain text, one per line)
  - Version info: `GET /{mod}/@v/{version}.info` → `{"Version":"v1.2.3","Time":"..."}`
  - go.mod: `GET /{mod}/@v/{version}.mod` (plain text)
  - Source zip: `GET /{mod}/@v/{version}.zip`
  - Latest: `GET /{mod}/@latest`
- Archive: standard ZIP, all paths prefixed with `{mod}@{version}/`
- Size limits: max 500MB zip, max 16MB go.mod

### Watchlist
- **No official download counts.** Go's design is decentralized.
- Alternatives:
  - pkg.go.dev "Imported By" tab (no public API for bulk)
  - Snyk Advisor: `https://snyk.io/advisor/packages/golang/popularity/popular`
  - GitHub stars/forks as proxy
  - Crawl index.golang.org to count dependents via go.mod parsing

### Attack Surface
| Vector | File/Pattern | Risk | Detection |
|--------|-------------|------|-----------|
| `init()` functions | Any `.go` | Critical — auto-execute on import | Regex for `func init()`, scan body for exec/net |
| CGo | `.go` with `import "C"` | High — arbitrary C code execution | Scan for `import "C"` and `// #cgo` directives |
| `//go:generate` | Any `.go` | Medium — runs arbitrary commands | Regex for `//go:generate`, extract command |
| `replace` directive | `go.mod` | High — dependency hijacking | Parse go.mod for `replace` pointing to unusual paths |
| Global var init | Any `.go` | Medium — runs at init time | Scan for global vars with function call initializers |
| Build constraints | `//go:build` tags | Low — hide code for specific OS/arch | Flag files with unusual build constraints |
| Typosquatting | Module path | High — `boltdb-go/bolt` vs `boltdb/bolt` | Path similarity matching |

### Behavioral Chain Rules
- `gomod.init_net_exec_chain` — network + exec in init()

### Real-World Attacks
- `github.com/boltdb-go/bolt` (2021-2025): Typosquat of BoltDB, cached indefinitely by module mirror
- Fake MongoDB Go drivers (2025): Detected by GitLab
- Disk-wiping malware via Go modules (May 2025)
- Key issue: Go Module Mirror caches **indefinitely** — deleted GitHub repos stay cached

### Why Go is harder
- Decentralized: modules are GitHub repos, not uploaded to a registry
- No popularity API for watchlist prioritization
- Module paths are URLs, not simple names — typosquat detection is more complex
- Volume is massive — every tagged version of every Go repo

## npm (JavaScript) — ACTIVE

Implemented in `pkgsentry/ecosystems/npm/` (diagram: `diagrams/npm-pipeline.drawio`).
Plugs into the same ingest → analyze → score → detonate → triage pipeline. Notes below
document the registry APIs the adapter uses.

**Implementation notes:** the `_changes` feed carries only the package name (not the
version), so `ingest/cursor.py` gates on the name first, then resolves `dist-tags.latest`
for gated packages before enqueuing (one registry call per gated package). The seq cursor
is stored in `ScanCursor.last_serial` and treated as opaque/forward-only; first boot
bootstraps from the current `update_seq` (no historical backfill — the feed isn't
time-addressable). Install analysis is a native `package.json` lifecycle-script analyzer
(`installer.py`) plus shadow-mode opengrep `opengrep/javascript/` rules. The watchlist
combines registry-search popularity + awesome-nodejs + a hardcoded `CRITICAL_INFRA` list.

### Discovery (Real-time)
- The npm registry is a CouchDB. New/changed packages stream from the public replica's
  changes feed: `https://replicate.npmjs.com/_changes?since={seq}&feed=continuous` (or
  `feed=longpoll`). Each row carries a `seq` and the package `id`.
- **Gotcha:** the `seq` sequence numbers are **not guaranteed monotonic** — they were reset
  during a past CouchDB upgrade. Treat the `since` cursor as an **opaque token**, not an
  ever-increasing integer (don't compare/order by it like the PyPI XML-RPC serial).
- Source: https://github.blog/changelog/2021-09-08-npm-couchdb-upgrade-will-reset-sequence-number/

### Metadata & Download
- Package metadata: `GET https://registry.npmjs.org/{pkg}` → `dist-tags`, `versions{}`,
  `time{}`, `maintainers`. (`docs/responses/package-metadata.md` in `npm/registry`.)
- Tarball: `https://registry.npmjs.org/{pkg}/-/{pkg}-{version}.tgz`; scoped:
  `https://registry.npmjs.org/@{scope}/{name}/-/{name}-{version}.tgz`. It's a gzip tarball
  with a `package/` prefix (strip it on extract).
- Integrity: the version's `dist` object has `integrity` (SRI, `sha512-<base64>`, since
  Apr 2017) and a legacy `shasum` (SHA-1). Verify SRI on download.

### Watchlist (Top packages)
- Download counts: `https://api.npmjs.org/downloads/point/{last-day|last-week|last-month|last-year}/{pkg}`
  (bulk via comma-separated names; scoped packages excluded from bulk; ~18-month history cap).
  Source: https://github.com/npm/download-counts

### Attack Surface
| Vector | Where | Risk | Detection |
|--------|-------|------|-----------|
| Lifecycle scripts | `package.json` `preinstall`/`install`/`postinstall`/`prepare` | Critical — arbitrary code runs automatically on `npm install` (`postinstall` most-abused) | Parse `package.json` scripts; detonation runs `npm install` with scripts ENABLED, Tetragon-traced |
| `bin` entries | `package.json` `bin` | Medium — installed onto PATH | Flag unexpected bin shims |
| Obfuscation | minified/encoded JS | High — hide payload | opengrep JS/TS + entropy + IOC extraction |
| Typosquatting | package name | High — `expres` vs `express` | name-similarity matching |
| Dependency confusion | scope/name vs internal pkgs | High — internal-name hijack | name + registry-source checks |

### Detonation angle
`npm install` (scripts enabled) inside the rootless-Docker sandbox executes the lifecycle
scripts; Tetragon traces the resulting process/file/network behavior (same model as the
other ecosystems — runc runtime, not gVisor).

### Notes / sources
- Registry API docs: https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md , https://api-docs.npmjs.com/
- Lifecycle-script abuse background: https://docs.npmjs.com/misc/scripts ; recent campaigns (e.g. 36-package postinstall campaign, 2026-04).

## Focus list — file syntax per ecosystem

Operator-supplied dependency lists (`pkgsentry focus load <file> -e <eco>`; see
`docs/operations.md`). One entry per line; `#` comments and blank lines ignored. Names are
stored verbatim (no normalization) and matched against the ingest feeds.

Entry syntax is lenient: a package **name** optionally followed by a version in any common
form (`==`, `>=`, `~=`, `^`, range, or gomod space-separated) — paste-compatible with
dependency files.

| Ecosystem | Line syntax | Matching |
|-----------|-------------|----------|
| pypi | `name`, `name==1.2.3`, `name>=1.2.3`, `name~=1.2`, … | exact name |
| crates | `name`, `name==1.2.3`, `name^1.0`, `name~1.2`, … | exact name |
| gomod | `name` or `name v1.2.3` (space-separated) | **case-insensitive** module path (matches `is_watchlist`) |

The **name** is monitored — every new release is scanned at high priority. Any version
present is scanned once at load (for a range, its lower bound); a wildcard like `2.*` is
treated as no concrete pin.
