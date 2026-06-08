# pkgward

Multi-ecosystem malware scanner for package registries. Watches PyPI, crates.io, the Go module proxy, and npm for both supply-chain compromises on popular packages and lure / social-engineering attacks on brand-new names.

When someone publishes a malicious package to one of these registries — a typosquat of a popular library, a hijacked release, or a fresh `wallet-checker`-style lure — pkgward aims to catch it shortly after it goes live. For each new release it downloads the package, runs a stack of static checks over the code, optionally executes it in an isolated sandbox to see what it actually does, and flags anything that looks like credential theft, a backdoor, or a dropper.

> **Status: beta.** It runs continuously against the live feeds today, but it is maintained by one person and the open-source detection content is deliberately minimal. The baseline that ships here catches obviously-malicious inputs; the strongest, tuned detection lives in a separate **private intel pack** you supply (see [Engine + intel pack](#engine--intel-pack)). Think of this repo as a capable scanning *engine* you bring your own detection signatures to — much like ClamAV — rather than a turnkey product.

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
                 detonate          -> isolated sandbox (optional), trace behaviour
                 score             -> rule + chain + watchlist verdict
                 LLM triage        -> second opinion, only on suspicious / malicious
                 alert             -> Discord webhook
```

A dozen static-analysis layers (AST import analysis, IOC extraction, install-time malware patterns, sdist/wheel diff, ecosystem-specific install scripts including npm `package.json` lifecycle scripts, YARA signatures, opengrep taint rules — which run in shadow / non-scoring mode by default, version diff, and threat-intel fingerprint matching by fuzzy hash) plus an optional **detonation** sandbox across all four ecosystems.

*Detonation* means installing or importing the package inside a locked-down, rootless-Docker container and recording the system calls it makes (via Tetragon eBPF tracing) — so a payload that only reveals itself at runtime still gets caught. It is **off in the default quickstart** and needs a separately-deployed service on a Linux host (see [Detonation](docs/detonation.md)). See `docs/detection-rules.md` for the full rule catalog.

**Focus mode** — point the scanner at your own dependencies instead of (or in addition to) the live feeds: `pkgward focus load <file>`, or `pkgward run -f <file>` to scan *only* your dependency list. See `docs/operations.md`.

## Engine + intel pack

The engine is open-source (this repo, **AGPL-3.0**). The detection content — YARA rules, hash fingerprints, scoring thresholds, LLM prompt text, behavioral chain definitions — is loaded at runtime from an **intel pack**. A minimal **baseline pack** ships in-tree, licensed more permissively under **Apache-2.0** so its signatures can be freely reused (third-party YARA rules keep their own licenses — see `NOTICE`), and is enough to demonstrate the engine works against obviously malicious test inputs. Operators with their own tuned threat intel can plug in a **private overlay pack** via the `PKGWARD_INTEL_PATH` env var.

Overlay semantics:

- Additive content (YARA rules, hash seeds, IOC whitelists, behavioral chain IDs, keyword lists) → **UNION** with baseline. Your overlay adds to baseline; baseline rules keep running.
- Scalar tuning (scoring thresholds, severity weights, prompt text) → **REPLACE** if overlay provides, else inherit baseline.

This means a private operator's deployment continuously exercises the public baseline, which prevents baseline rot. The model is borrowed from ClamAV: the engine is open, the signatures are configurable.

## Quickstart

Requires Docker + Docker Compose.

```bash
git clone https://github.com/boredchilada/pkgward-oss
cd pkgward-oss
cp .env.example .env
# .env defaults to no Discord alerts; no editing required for a first run

# Standalone (includes PostgreSQL — nothing else needed)
docker compose -f docker-compose.standalone.yml up -d

# Or, if you have your own Postgres: edit .env, then
# docker compose up -d

# Watch the scanner pick up live PyPI / crates.io / Go module traffic
docker logs pkgward -f
```

For dynamic analysis (rootless Docker + Tetragon sandbox, all ecosystems) you need a Linux host with kernel 5.8+ BTF support. See `docs/detonation.md`.

## Documentation

| Guide | Content |
|-------|---------|
| [Operations](docs/operations.md) | Running in production, logs, queue stats, debugging |
| [Intel pack](docs/intel-pack.md) | Building and loading private detection overlays |
| [Detonation](docs/detonation.md) | Deploying the rootless-Docker + Tetragon sandbox |
| [Detection rules](docs/detection-rules.md) | Full rule catalog (~120 baseline rule IDs across the detection layers) |
| [Regression testing](docs/regression-testing.md) | Known-bad/known-good corpus suite to catch detection regressions |
| [Ecosystems](docs/ecosystems-reference.md) | API reference and attack surface per ecosystem |

## Ecosystem coverage

| Ecosystem | Watchlist | New-package coverage | Incremental ingest | Detonation |
|---|---|---|---|---|
| PyPI | top-10K (hugovk/top-pypi-packages) + every brand-new package | RSS `packages.xml` + XML-RPC changelog | XML-RPC serial cursor | yes (rootless Docker + Tetragon) |
| crates.io | top-10K by download count | RSS `crates.xml` | RSS `updates.xml` | yes |
| Go modules | ~9K (GitHub stars + awesome-go + critical infra) | NDJSON index, brand-new detection via DB | NDJSON cursor | yes |
| npm | top-N (registry-search popularity + awesome-nodejs + critical infra) | CouchDB `_changes` feed, brand-new detection via DB | `_changes` seq cursor | yes |

> All four ecosystems share the same ingest → analyze → score → detonate → triage flow. The **Detonation** column above marks ecosystems the sandbox *supports* — detonation itself is optional, requires the separately-deployed sandbox service on a BTF-enabled Linux host, and is off in the standalone quickstart (see [Detonation](docs/detonation.md)). npm install-time analysis parses `package.json` lifecycle scripts (`preinstall`/`install`/`postinstall`/`prepare`); when detonation is enabled it runs `npm install` with scripts under Tetragon tracing.

## Comparison

Several established tools address adjacent problems, and pkgward is not a drop-in replacement for all of them:

- **Socket, Phylum, Endor Labs** — commercial platforms with large proprietary detection corpora, IDE and CI integrations, and dependency-graph analysis. Best suited to teams that want a managed, supported product.
- **Bumblebee** (Phylum, open source) — a mature command-line scanner focused on PyPI and npm.
- **OSV-Scanner** — matches dependencies against known-vulnerability databases (CVEs), which is a distinct problem from classifying previously-unknown malicious packages.

pkgward is self-hosted and deliberately focused: a single engine covering four ecosystems (PyPI, crates.io, Go, and npm), with first-publish scanning of brand-new packages, a rootless-Docker + Tetragon detonation sandbox across all four, focus-mode monitoring of your own dependencies, and plugin-loaded intel so you retain control of your detection content. It is intended for operators who prefer to run their own scanner against the live registries rather than rely on a hosted service.

## Known limitations

- **No Alembic migrations.** Schema is managed by SQLAlchemy `create_all()` (new tables auto-created, idempotent); new *columns* on an already-populated DB need a manual `ALTER TABLE`.
- **No reproducible-builds verification** — the engine doesn't compare your scan output against another scanner. Tier-1 parity test scripts ship in `tools/`; tier-2 (re-fetch + re-analyze) requires network access to PyPI.
- **crates.io / Go detonation builds are best-effort** — install/import behavior is observed for all ecosystems, but some crates/modules fail to build inside the sandbox (the malicious install-time code still executes and is traced).
- **The baseline intel pack is intentionally minimal.** It catches obviously-bad inputs (the kind any decent static scanner would). The maintainer's private overlay is what produces the operationally-useful detection rate.

## Security

Disclosures: see `SECURITY.md`. Please do not file a public issue for an active vulnerability.

## Acknowledgments

- **[t0asts](https://github.com/t0asts)** — for information and guidance on the opengrep static-analysis integration.
- **[Cyb3rjerry](https://github.com/cyb3rjerry)** — for the idea behind the known-malicious **dependency** gate: tracking packages that take a new dependency on a confirmed-malicious package (supply-chain propagation along the dependency edge).

## License

The engine (this repo) is **AGPL-3.0** — see `LICENSE`. The baseline intel pack (`pkgward/intel/baseline/`) is licensed permissively under **Apache-2.0** so its detection signatures can be freely reused; see `NOTICE`.
