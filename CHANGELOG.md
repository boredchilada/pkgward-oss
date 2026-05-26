# Changelog

All notable changes to pkgsentry are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
