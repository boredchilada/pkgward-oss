# pkgsentry

Multi-ecosystem malware scanner for package registries. Watches PyPI, crates.io, and the Go module proxy for both supply-chain compromises on popular packages and lure / social-engineering attacks on brand-new names.

> **Status: alpha.** Runs in the maintainer's production setup against the live PyPI / crates.io / Go module feeds. The engine API and intel-pack schema may shift before v1.0. Verdicts are correct for the maintainer's data; your mileage will vary until you tune your own intel pack.

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
                 detonate          -> Docker + Tetragon dynamic trace
                 score             -> rule + chain + watchlist verdict
                 LLM triage        -> cost-gated, only on suspicious / malicious
                 alert             -> Discord webhook
```

Twelve analysis layers (AST imports, IOC extraction, install-time malware patterns, sdist/wheel diff, ecosystem-specific install scripts, YARA, version diff, threat-intel fingerprint matching, opengrep static taint tracking) plus a Docker + Tetragon detonation sandbox for all three ecosystems. See `docs/detection-rules.md` for the rule catalog.

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

For dynamic analysis (Docker + Tetragon sandbox, all ecosystems) you need a Linux host with kernel 5.8+ BTF support. See `docs/detonation.md`.

## Documentation

| Guide | Content |
|-------|---------|
| [Operations](docs/operations.md) | Running in production, logs, queue stats, debugging |
| [Intel pack](docs/intel-pack.md) | Building and loading private detection overlays |
| [Detonation](docs/detonation.md) | Deploying the Docker + Tetragon sandbox |
| [Detection rules](docs/detection-rules.md) | Full rule catalog (~104 rules across 12 layers) |
| [Ecosystems](docs/ecosystems-reference.md) | API reference and attack surface per ecosystem |
| [Roadmap](docs/ROADMAP.md) | Completed and planned features |

## Ecosystem coverage

| Ecosystem | Watchlist | New-package coverage | Incremental ingest | Detonation |
|---|---|---|---|---|
| PyPI | top-10K (hugovk/top-pypi-packages) + every brand-new package | RSS `packages.xml` + XML-RPC changelog | XML-RPC serial cursor | yes (gVisor + Tetragon, optional) |
| crates.io | top-10K by download count | RSS `crates.xml` | RSS `updates.xml` | yes (Docker + Tetragon) |
| Go modules | ~9K (GitHub stars + awesome-go + critical infra) | NDJSON index, brand-new detection via DB | NDJSON cursor | yes (Docker + Tetragon) |

## Comparison

pkgsentry overlaps with several existing scanners:

- **Socket / Phylum / Endor Labs** — commercial, much larger detection corpora, IDE integrations, dependency-graph features. If you need a managed product, use them.
- **Bumblebee** (Phylum OSS) — focused on PyPI and npm, mature CLI workflow.
- **OSV-Scanner** — vulnerability database matching (known-CVE coverage), not malicious-package classification.
- **pkgsentry** — three ecosystems in one engine, brand-new-package scanning explicitly in scope, Docker + Tetragon sandbox for all ecosystems, plugin-loaded intel so you own your detection content. Geared toward operators who want to run their own scanner against the live feeds rather than consume a hosted product.

## Known limitations

- **No Alembic migrations yet.** Wipe and re-init the DB when upgrading minor versions until v1.0.
- **No reproducible-builds verification** — the engine doesn't compare your scan output against another scanner. Tier-1 parity test scripts ship in `tools/`; tier-2 (re-fetch + re-analyze) requires network access to PyPI.
- **The baseline intel pack is intentionally minimal.** It catches obviously-bad inputs (the kind any decent static scanner would). The maintainer's private overlay is what produces the operationally-useful detection rate.

## Contributing

DCO required — sign your commits with `git commit -s`. See `CONTRIBUTING.md`.

Security disclosures: see `SECURITY.md`. Please do not file a public issue for an active vulnerability.

## License

AGPL-3.0 — see `LICENSE` and `NOTICE`.
