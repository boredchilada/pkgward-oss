# pkgsentry

Multi-ecosystem malware scanner for package registries. Watches PyPI, crates.io, the Go module proxy, and npm for both supply-chain compromises on popular packages and lure / social-engineering attacks on brand-new names.

> **Status: alpha.** Runs in the maintainer's production setup against the live PyPI / crates.io / Go module / npm feeds. The engine API and intel-pack schema may shift before v1.0. Verdicts are correct for the maintainer's data; your mileage will vary until you tune your own intel pack.

## What it catches

Two threat models, both in scope:

- **Supply-chain attacks on popular packages** — a hijacked or malicious release of a top-N package (e.g. typosquats of `requests`, hijacked publish-credential on a real maintainer's account, dependency-confusion on internal names). Covered by watchlist scanning of the top 10K packages per ecosystem.
- **Lure / social-engineering on brand-new names** — fresh uploads with names like `wallet-security-checker` or `crypto-credential-scanner` designed to bait specific victim profiles. Covered by scanning every first-publish to each registry.

Existing-non-watchlist version updates are skipped on purpose — that's where the false-positive cost is highest and the real-attack signal is lowest.

## How it works

```
RSS / XML-RPC / NDJSON feeds          watchlist
        |                                |
        +---------- ingest ---------+----+
                                    |
                            cross-ecosystem queue
                                    |
                              async workers
                                    |
                 download archive  -> SHA-256 verify
                 extract           -> per-file SHA-256 / entropy / ssdeep
                 code-diff vs prev -> only analyze changed files
                 static analyzers  -> findings
                 detonate (all)    -> rootless Docker + Tetragon dynamic trace
                 score             -> rule + chain + watchlist verdict
                 LLM triage        -> cost-gated, only on suspicious / malicious
                 alert             -> Discord webhook
```

A dozen static-analysis layers (AST imports, IOC extraction, install-time malware patterns, sdist/wheel diff, ecosystem-specific install scripts incl. npm `package.json` lifecycle scripts, YARA, opengrep taint rules, version diff, threat-intel fingerprint matching) plus an optional rootless-Docker + Tetragon detonation sandbox across all four ecosystems. See `docs/detection-rules.md` for the rule catalog.

**Focus mode** — point the scanner at your own dependencies instead of (or in addition to) the live feeds: `pkgsentry focus load <file>`, or `pkgsentry run -f <file>` to scan *only* your dependency list. See `docs/operations.md`.

## Engine + intel pack

The engine is open-source (this repo, AGPL-3.0). The detection content — YARA rules, hash fingerprints, scoring thresholds, LLM prompt text, behavioral chain definitions — is loaded at runtime from an **intel pack**. A minimal **baseline pack** ships in-tree and is enough to demonstrate the engine works against obviously malicious test inputs. Operators with their own tuned threat intel can plug in a **private overlay pack** via the `PKGSENTRY_INTEL_PATH` env var.

Overlay semantics:

- Additive content (YARA rules, hash seeds, IOC whitelists, behavioral chain IDs, keyword lists) → **UNION** with baseline. Your overlay adds to baseline; baseline rules keep running.
- Scalar tuning (scoring thresholds, severity weights, prompt text) → **REPLACE** if overlay provides, else inherit baseline.

This means a private operator's deployment continuously exercises the public baseline, which prevents baseline rot. The model is borrowed from ClamAV: the engine is open, the signatures are configurable.

## Quickstart

Requires Docker + Docker Compose.

```bash
git clone https://github.com/boredchilada/pkgsentry-oss
cd pkgsentry-oss
cp .env.example .env
# .env defaults to no Discord alerts; no editing required for a first run

# Standalone (includes PostgreSQL — nothing else needed)
docker compose -f docker-compose.standalone.yml up -d

# Or, if you have your own Postgres: edit .env, then
# docker compose up -d

# Watch the scanner pick up live PyPI / crates.io / Go module traffic
docker logs pkgsentry -f
```

For dynamic analysis (rootless Docker + Tetragon sandbox, all ecosystems) you need a Linux host with kernel 5.8+ BTF support. See `docs/detonation.md`.

## Documentation

| Guide | Content |
|-------|---------|
| [Operations](docs/operations.md) | Running in production, logs, queue stats, debugging |
| [Intel pack](docs/intel-pack.md) | Building and loading private detection overlays |
| [Detonation](docs/detonation.md) | Deploying the rootless-Docker + Tetragon sandbox |
| [Detection rules](docs/detection-rules.md) | Full rule catalog across 12 detection layers |
| [Ecosystems](docs/ecosystems-reference.md) | API reference and attack surface per ecosystem |
| [Roadmap](docs/ROADMAP.md) | Completed and planned features |

## Ecosystem coverage

| Ecosystem | Watchlist | New-package coverage | Incremental ingest | Detonation |
|---|---|---|---|---|
| PyPI | top-10K (hugovk/top-pypi-packages) + every brand-new package | RSS `packages.xml` + XML-RPC changelog | XML-RPC serial cursor | yes (rootless Docker + Tetragon) |
| crates.io | top-10K by download count | RSS `crates.xml` | RSS `updates.xml` | yes |
| Go modules | ~9K (GitHub stars + awesome-go + critical infra) | NDJSON index, brand-new detection via DB | NDJSON cursor | yes |
| npm | top-N (registry-search popularity + awesome-nodejs + critical infra) | CouchDB `_changes` feed, brand-new detection via DB | `_changes` seq cursor | yes |

> All four ecosystems share the same ingest → analyze → score → detonate → triage flow. npm install-time analysis parses `package.json` lifecycle scripts (`preinstall`/`install`/`postinstall`/`prepare`) and detonation runs `npm install` with scripts enabled under Tetragon tracing.

## Comparison

Several established tools address adjacent problems, and pkgsentry is not a drop-in replacement for all of them:

- **Socket, Phylum, Endor Labs** — commercial platforms with large proprietary detection corpora, IDE and CI integrations, and dependency-graph analysis. Best suited to teams that want a managed, supported product.
- **Bumblebee** (Phylum, open source) — a mature command-line scanner focused on PyPI and npm.
- **OSV-Scanner** — matches dependencies against known-vulnerability databases (CVEs), which is a distinct problem from classifying previously-unknown malicious packages.

pkgsentry is self-hosted and deliberately focused: a single engine covering four ecosystems (PyPI, crates.io, Go, and npm), with first-publish scanning of brand-new packages, a rootless-Docker + Tetragon detonation sandbox across all four, focus-mode monitoring of your own dependencies, and plugin-loaded intel so you retain control of your detection content. It is intended for operators who prefer to run their own scanner against the live registries rather than rely on a hosted service.

## Known limitations

- **No Alembic migrations.** Schema is managed by SQLAlchemy `create_all()` (new tables auto-created, idempotent); new *columns* on an already-populated DB need a manual `ALTER TABLE`.
- **No reproducible-builds verification** — the engine doesn't compare your scan output against another scanner. Tier-1 parity test scripts ship in `tools/`; tier-2 (re-fetch + re-analyze) requires network access to PyPI.
- **crates.io / Go detonation builds are best-effort** — install/import behavior is observed for all ecosystems, but some crates/modules fail to build inside the sandbox (the malicious install-time code still executes and is traced).
- **The baseline intel pack is intentionally minimal.** It catches obviously-bad inputs (the kind any decent static scanner would). The maintainer's private overlay is what produces the operationally-useful detection rate.

## Contributing

DCO required — sign your commits with `git commit -s`. See `CONTRIBUTING.md`.

Security disclosures: see `SECURITY.md`. Please do not file a public issue for an active vulnerability.

## Acknowledgments

- **[t0asts](https://github.com/t0asts)** — for information and guidance on the opengrep static-analysis integration.

## License

AGPL-3.0 — see `LICENSE` and `NOTICE`.
