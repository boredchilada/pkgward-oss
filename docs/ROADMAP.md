# Roadmap

## Completed

- **8 malware pattern analyzers** — webhooks, .pth injection, .pyc hiding, credential access, deobfuscation chains, env exfil, whitespace payloads, download commands
- **Version-diff detection** — clean-to-critical escalation, new rule alerts, author change detection, dependency spike detection
- **Code-diff scanning** — per-file SHA256 hashes, only re-analyze changed/added files across versions
- **LLM triage** — OpenRouter integration with budget controls, Spotlighting anti-injection
- **Discord alerts** — IOC defanging, LLM reasoning summaries
- **Extraction hardening** — symlink skip, path traversal normalization, 500MB size cap, 10K file cap
- **New package scanning** — all brand-new PyPI/crates packages scanned on first publish, not just watchlist. Catches lure/social-engineering packages alongside supply-chain attacks
- **Threat intel fingerprints** — `ThreatIntelHash` table with three-tier matching (SHA256 exact, ssdeep ≥70%, TLSH ≤120). Seeded with TrapDoor campaign (2026-05-24)
- **Focus packages** — operator-supplied per-ecosystem dependency list (`pkgsentry focus load`, or `run -f <file>` for exclusive focused mode). Monitors your own deps for malicious new releases; lenient syntax accepts requirements.txt/go.mod/Cargo lines

## Multi-ecosystem expansion (complete)

### Crates.io (Rust) — ACTIVE

See `docs/ecosystems-reference.md` for full API and attack surface docs.

- Ingest via RSS feeds (`crates.xml` for new crates, `updates.xml` for watchlist version bumps)
- Download `.crate` files (gzipped tarballs) from CDN
- Detection: `build.rs` analysis (network + exec chains), proc macro scanning, unsafe block detection
- Watchlist: top 10K crates by download count via API
- Gap-healing: `seed_missing_watchlist()` on boot

### Go modules — ACTIVE

- Ingest via NDJSON index (`index.golang.org/index?since=`)
- Download via GOPROXY protocol (`proxy.golang.org`)
- Detection: `init()` body analysis (exec/net chains), CGo detection, `//go:generate` commands (benign tool whitelist), `replace` directive hijacking, unsafe imports, encoded payloads
- Watchlist: ~9K modules (GitHub stars + awesome-go + critical infrastructure)
- Brand-new module detection via `Package` table lookup
- Pseudo-version filtering (`GOMOD_SCAN_PSEUDO=0` by default)

### npm (JavaScript) — ACTIVE

Plugs into the same ingest → analyze → score → detonate → triage pipeline as the
other ecosystems.

- Ingest via the CouchDB `_changes` replication feed (`replicate.npmjs.com`); the feed
  carries only the package name, so the seq-cursor resolves `dist-tags.latest` for gated
  packages before enqueuing. Brand-new detection via the `Package`/`ScanQueue` tables.
- Download `.tgz` tarballs from `registry.npmjs.org`, SRI (`sha512`) / `shasum` verified
- Detection: native `package.json` lifecycle-script analyzer (`preinstall`/`install`/
  `postinstall`/`prepare`) with benign-tool suppression and referenced-JS following, plus
  shadow-mode opengrep `javascript/` rules; IOC/YARA/entropy generic layers; detonation
  runs `npm install` with scripts enabled under Tetragon
- Watchlist: top-N combined from registry-search popularity + awesome-nodejs + a
  hardcoded critical-infra keystone list

## Detonation sandbox (complete)

Go service (`detonation/`) runs package install + import inside isolated containers
(rootless Docker, runc runtime) while monitoring with Tetragon eBPF. Runs for PyPI,
crates, and Go modules (crates/Go sandbox builds are best-effort; install-time
behavior is traced even when a build fails).

- Behavioral rules: network exfil (per install/import phase), credential reads,
  reverse shell, process injection (ptrace / process_vm_writev), env harvest
  (`/proc/<pid>/environ`), persistence writes, fileless exec (memfd/execveat).
  `dyn_install_exfil` is deferred (fires on any install-phase connect; sdists fetch
  build deps from registries)
- Events are phase-tagged (install vs import) and trace events persisted to DB
- Rootless Docker isolation — detonation cannot see or touch system Docker containers/volumes
- See `docs/detonation.md` for deployment guide

## Frontend & API (future)

- REST API for querying scan results, package history, rule hit stats
- Dashboard for real-time monitoring, verdict breakdowns, trend analysis
- Package comparison tools and historical risk scoring
