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

## Detonation sandbox (complete)

Go service (`detonation/`) runs package installs inside isolated Docker containers
(rootless Docker, runc runtime) while monitoring with Tetragon eBPF. Currently PyPI-only.

- 8 behavioral rules: exfil, credential access, reverse shell, process injection, DNS exfil, env harvest, suspicious write, network beacon
- Trace events persisted to DB for historical analysis
- Rootless Docker isolation — detonation cannot see or touch system Docker containers/volumes
- See `docs/detonation.md` for deployment guide

## Frontend & API (future)

- REST API for querying scan results, package history, rule hit stats
- Dashboard for real-time monitoring, verdict breakdowns, trend analysis
- Package comparison tools and historical risk scoring
