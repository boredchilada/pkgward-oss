# Changelog

All notable changes to pkgsentry are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Reserved for 0.6.0
- **LLM integration overhaul** — multi-provider support (beyond the current OpenRouter path) and
  a review of where LLM triage sits in the pipeline and how it's gated (cost/verdict thresholds,
  when it runs, and how its verdict interacts with rule-based scoring).
- **Model comparison / benchmarking** — a way to evaluate triage models head-to-head (agreement
  with rule verdicts, false-positive/negative rate, cost, and latency) so the default model and
  per-provider choices are driven by measured results rather than guesswork.

### Coming in 0.5.1 (in testing)
- **Detection regression suite** — a labeled corpus of known-bad / known-good sample packages
  run through the real analyze→score path, so a change that starts missing malware or
  over-flagging clean packages fails the test suite instead of reaching production. Includes a
  rule-coverage check that flags any scored detection rule lacking a sample.
- **opengrep `--test` fixtures for Python/Rust/Go** — all four language rule sets become
  self-testing (previously JavaScript-only).
- **Frozen-sample vault** — optionally preserve the original archive of anything flagged
  malicious (stored inert), so a caught package remains a permanent regression anchor even after
  the registry removes it.

## [0.5.0] — 2026-05-26

### Added
- **npm (JavaScript) ecosystem** — full parity with the other ecosystems. Discovery via the
  npm registry changes feed (top-package watchlist + every brand-new package + focus list);
  `.tgz` download with Subresource-Integrity (`sha512`) / `shasum` verification;
  `package.json` lifecycle-script analysis (`preinstall`/`install`/`postinstall`/`prepare`)
  with a known-benign build-tool allowlist and following of referenced install scripts;
  shadow-mode opengrep JavaScript/TypeScript rules; and detonation (`npm install` with
  scripts enabled, traced in the sandbox). The watchlist is assembled from registry-search
  popularity + `awesome-nodejs` + a curated keystone list.
- **Focus packages** — operators can supply their own dependencies as focus packages,
  scanned at high priority. Easiest: one combined file with `[pypi]`/`[crates]`/`[gomod]`/`[npm]`
  sections + `pkgsentry run -f <file>` (focused/exclusive mode — scans ONLY focus packages,
  authoritatively synced from the file). Also `pkgsentry focus load <file>` (combined, no
  `-e`) / `... -e <eco>` (flat, additive) / `focus list` / `focus clear`. Every new release
  of a focus package is enqueued automatically; pinned `name==version` scanned once at load.
  Toggle `PKGSENTRY_FOCUS_EXCLUSIVE` (`run -f` sets it). New `FocusList` table (auto-created),
  `pkgsentry/focus.py`, and per-ecosystem `ingest/focus.py` pollers. Lenient entry syntax —
  a package name optionally followed by a version in any common form (`name`, `name==1.2.3`,
  `name>=1.2.3`, `name~=1.2`, `name^1.0`, gomod `name v1.2.3`), so requirements.txt / go.mod /
  Cargo lines can be pasted directly. The name is monitored (every new release scanned); any
  version present is scanned once (a range's lower bound).
- **Per-ecosystem detonation network allowlist** — known registry/CDN destinations
  (`{eco}_net_allow` in the detonation noise baseline; hostnames resolved to IPs at analysis
  time, plus literal IPs) are dropped from the trace before the network-exfil rules run, so
  normal dependency fetches don't false-positive as exfil. Tunable via the intel pack.
- **opengrep JavaScript rules + rule-test harness** — baseline JS/TS taint rules
  (`net→exec`, `base64-decode→exec`, `env→network`) and `tools/test_opengrep_rules.sh`, which
  runs opengrep's `--test` over the co-located rule fixtures.

### Changed
- **License: Apache-2.0 → AGPL-3.0-or-later.**
- Detonation can load a private intel overlay (`PKGSENTRY_INTEL_PATH`) to extend its noise
  filters and network allowlists without rebuilding the binary.

### Fixed
- **crates ingest resolves `latest` to a concrete version before enqueue** — a brand-new
  crate that also appears in the updates feed is no longer scanned twice (the duplicate
  produced a spurious zero-finding code-diff re-scan).
- npm registry polling backs off on HTTP 429 and bounds request concurrency.

## [0.4.0] — 2026-05-26

### Added
- **Detonation for all ecosystems** — dynamic analysis now runs for PyPI, Crates, and Go
  modules (previously PyPI-only); worker max-concurrent raised to 6.
- **Dynamic behavioral rules wired up** — events are tagged by install/import phase, enabling
  network-exfil detection per phase, ptrace / `process_vm_writev` injection,
  `/proc/<pid>/environ` credential-and-env harvesting, persistence writes via the
  `security_file_permission` LSM hook, and fileless execution (`memfd_create` /
  `execveat(AT_EMPTY_PATH)`). All non-base Tetragon hooks are namespace-filtered to the
  sandbox so host activity is never misattributed.

### Fixed
- **Detonation emitted zero trace events since initial deployment** — resolved a cascade of
  faults: the Tetragon TracingPolicy was never loaded (and could not mix kprobes+tracepoints);
  the scanner held a stale detonation-socket inode after service restarts; the Tetragon log
  was unreadable by the service and lost its permissions on every rotation; and the
  `trace_event` table was missing the `pid`/`binary` columns. Collector namespace filtering
  (`targetNS=0`) corrected.
- **Rootless-Docker sandbox `docker run` failure** — removed the `--cpus` flag (no CPU CFS
  controller under rootless Docker → "NanoCPUs can not be set").
- **`dyn_proc_inject` never matched ptrace** — collector emitted `sys_ptrace` while the rule
  checked `ptrace`; normalized.
- **Two false-positive detection rules** — `env_bulk_exfil` no longer fires on test
  `conftest.py`; `.pth` companion-module discovery fixed for LLM triage.

### Changed
- Tetragon daemon tuning for the detonation host (ring-buffer sizing, log rotation +
  world-readable export perms, `127.0.0.1:2112` metrics endpoint) and systemd memory limits.

### Deferred
- `dyn_install_exfil` retained but excluded from the active rule set — it fires on any
  install-phase network connect, but sdists legitimately fetch build deps from registries,
  so it needs a registry-aware design (offline install or destination allowlist).

## [0.3.0] — 2026-05-25

### Added
- **Multi-ecosystem coverage** — Crates.io and Go modules scan alongside PyPI.
  Same analysis pipeline (extract, hash, code-diff, static analyzers, YARA, LLM triage, scoring)
  for all three ecosystems; detonation remains PyPI-only.
- **Detonation sandbox** — Go service (`detonation/`) runs package installs inside Docker
  containers (runc + Tetragon eBPF). Eight behavioral rules: credential harvest, reverse shell,
  process injection, DNS exfil, exfiltration, suspicious write, env harvest, network beacon.
- **Intel-pack architecture** — detection content moved from hard-coded Python to a data-driven
  overlay system. Public baseline at `pkgsentry/intel/baseline/`; private operator overlays load
  via `PKGSENTRY_INTEL_PATH`. Fields are merged at startup (UNION for additive content, REPLACE for
  scalars). Startup emits a structured `intel_loaded` log line confirming which pack is active.
- **Go modules ecosystem** — watchlist of ~10K modules (GitHub top stars + awesome-go +
  critical infrastructure). Brand-new module detection via `Package` table lookup. Pseudo-version
  filtering (`GOMOD_SCAN_PSEUDO`). Go-specific rules: `go:generate` exec detection, `init()` body
  analysis (exec/net chains), CGO, replace directives, unsafe imports, encoded payloads.
- **Crates.io ecosystem** — watchlist of 10K crates by download count. New-crate detection via
  `crates.xml` RSS feed. `build.rs` static analysis. Watchlist gap-healing on boot.
- **Lure name detection** — multi-category keyword scoring catches social-engineering package
  names (crypto × credential combinations, AI × security-theater, etc.) while ignoring single
  legitimate categories.
- **Threat-intel hash matching** — three-tier lookup: exact SHA256, ssdeep fuzzy (≥70%), TLSH
  distance (≤120). TrapDoor campaign fingerprints seeded.
- **Code-diff scanning** — per-file SHA256 hashes stored across scans; only changed/new files are
  analyzed on version updates.
- **Fair cross-ecosystem queue scheduling** — `claim_next()` rotates ecosystems within each
  priority tier so a large crates backlog cannot starve PyPI scans.
- **Env-var migration** — all vars renamed `PKGSENTRY_*` with backward-compatibility fallback
  through `PKGWATCH_*` and `PYPI_SCANNER_*`.
- **User-Agent helper** — `pkgsentry/util/user_agent.py` driven by `PKGSENTRY_CONTACT_EMAIL`;
  applied to all outbound HTTP clients (PyPI, crates.io, Go proxy).
- **Pre-commit hooks** — gitleaks secret scanning + `tools/precommit_no_private_intel.py`
  blocks accidental commit of `intel/private/` overlay files.
- **Trace event persistence** — raw Tetragon trace events persisted to `trace_event` table,
  enabling historical behavioral analysis and forensic queries.
- **Standalone Docker Compose** — `docker-compose.standalone.yml` bundles PostgreSQL for
  self-contained deployments. Three commands from clone to scanning live traffic.
- **Rootless Docker isolation** — detonation sandbox uses rootless Docker (separate daemon
  and storage). Cannot see or affect system Docker containers or volumes.
- `LICENSE` (Apache 2.0), `NOTICE` (Neo23x0/DRL 1.1 attribution), `CONTRIBUTING.md` (DCO),
  `SECURITY.md` (responsible-disclosure policy).

### Changed
- Project renamed from `pkgwatch` / `pypi_scanner` to **pkgsentry**.
- All Python imports updated to `from pkgsentry.…`.
- README fully rewritten; describes both threat models (supply-chain watchlist + brand-new lures)
  and all three ecosystems.

### Fixed
- LLM triage: redundant `or` pattern and lowercase env-var prefix causing silent model fallback.
- PyPI brand-new package detection was silently broken (changelog serial comparison off-by-one).
- `init_exec_chain` false positive on `modernc.org/cc/v5` (rules now parse init() body, not
  just coexistence of imports).

## [0.1.0] — 2026-01-15

### Added
- Initial PyPI-only scanner: watchlist (top 10K packages) + all new package uploads.
- Static analysis pipeline: import analysis, IOC extraction, metadata checks, setup.py AST,
  YARA scanning, scoring.
- Discord alerting for malicious verdicts.
- LLM triage via OpenRouter (cost-gated, rate-limited).

[Unreleased]: https://github.com/boredchilada/pkgsentry-oss/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/boredchilada/pkgsentry-oss/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/boredchilada/pkgsentry-oss/releases/tag/v0.1.0
