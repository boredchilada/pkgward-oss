# pkgsentry

Multi-ecosystem package malware scanner. Monitors PyPI, Crates.io, and Go modules for malicious packages — both supply-chain attacks on popular packages (top-10K watchlist) and lure/social-engineering packages (all new uploads).

## Quick reference

- **Module:** `pkgsentry` (all imports: `from pkgsentry.…`)
- **Runtime:** Python 3.11, Docker container `pkgsentry`
- **DB:** PostgreSQL (configurable via `PKGSENTRY_DB_URL`; defaults to local SQLite)
- **Detonation service:** Go binary at `detonation/`, runs on Linux via systemd (see `docs/detonation.md`)
- **Secrets:** `.env` file (gitignored) — see `.env.example`

## Running

```bash
# Standalone (includes PostgreSQL)
docker compose -f docker-compose.standalone.yml up -d

# Or, BYO Postgres
docker compose up -d

# Logs
docker logs pkgsentry --tail 50 -f

# Queue/scan stats
docker exec pkgsentry python -c "
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue, Scan
from sqlalchemy import select, func
sess.init_db()
with sess.session_scope() as s:
    for eco in ('pypi', 'crates', 'gomod'):
        pending = s.scalar(select(func.count()).where(ScanQueue.status == 'pending', ScanQueue.ecosystem == eco))
        done = s.scalar(select(func.count()).where(ScanQueue.status == 'done', ScanQueue.ecosystem == eco))
        print(f'{eco}: {pending} pending, {done} done')
    total = s.scalar(select(func.count()).select_from(Scan))
    mal = s.scalar(select(func.count()).where(Scan.verdict == 'malicious'))
    print(f'Scans: {total} total, {mal} malicious')
"
```

## Tests

```bash
python -m pytest tests/ -x -q        # Python (306 tests)
cd detonation && go test ./... -v     # Go
```

## Key env vars

| Var | Purpose | Default |
|-----|---------|---------|
| `SCANNER_INGEST` | `0` = don't enqueue new packages, `1` = poll feeds/cursor | `1` |
| `OPENROUTER_API_KEY` | LLM triage API key | — |
| `DISCORD_WEBHOOK_URL` | Malicious package alerts | — |
| `PKGSENTRY_DB_URL` | DB connection URL | `sqlite:///pkgsentry.db` |
| `PKGSENTRY_CONTACT_EMAIL` | Surfaced in outbound User-Agent | project URL |
| `PKGSENTRY_LLM_MODEL` | LLM model ID | `z-ai/glm-5.1` |
| `PKGSENTRY_LLM_MAX_USD` | Per-process budget cap | `20.0` |
| `PKGSENTRY_LLM_MAX_CALLS_PER_HOUR` | Rate limit on triage calls | `1000` |
| `PKGSENTRY_INTEL_PATH` | Path to private intel pack overlay | unset (baseline only) |
| `DETONATION_SOCKET` | Detonation service UNIX socket | — |
| `DETONATION_URL` | TCP fallback for detonation service | — |
| `GOMOD_SCAN_PSEUDO` | `1` = scan Go pseudo-versions, `0` = skip | `0` |
| `GITHUB_TOKEN` | GitHub API token for Go watchlist (optional) | — |
| `OPENGREP_ENABLED` | Master switch for the opengrep layer | `1` |
| `OPENGREP_SHADOW` | `1` = shadow mode (findings excluded from scoring); `0` = cutover (replaces legacy install-time analyzers) | `1` |
| `OPENGREP_TIMEOUT_SEC` | Per-package wall-clock timeout for the opengrep subprocess | `60` |
| `OPENGREP_BIN` | Override the opengrep binary path / PATH name | `opengrep` |

## Architecture

**Ingest** (watchlist + all new packages, per-ecosystem feeds/cursor) → **Queue** (fair cross-ecosystem scheduling) → **Workers** → **Download** + SHA256 verify → **Extract** + hash (SHA256 + entropy + ssdeep) → **Code-diff** vs previous version → **Analyze** → **Score** → **Detonate** → **Re-score** → **LLM triage** (cost-gated) → **Discord alert**

### Intel pack

All tunable detection data is loaded from an intel pack at process start (`pkgsentry.intel.load()` in `runtime.py`). See `docs/intel-pack.md` for full reference.

```
pkgsentry/intel/baseline/        # ships in tree, Apache 2.0
  intel_pack.toml                # manifest
  yara/                          # community + baseline YARA rules
  hashes/known_malicious.jsonl   # empty in baseline
  prompts/                       # LLM prompt templates
  thresholds.toml                # scoring thresholds
  scoring_weights.toml           # severity points
  behavioral_chains.toml         # chain rule IDs
  lure_keywords.toml             # lure name categories
  ioc_whitelist.toml             # benign domains
  malware_patterns.toml          # install-time file lists
  gomod_benign_tools.toml        # known-benign go:generate tools
  opengrep/                      # opengrep rule directories (python/, rust/, go/)
  detonation/                    # behavioral rule data + noise filters
```

Operators supply a private overlay via `PKGSENTRY_INTEL_PATH`. Merge semantics: UNION for additive content (YARA dirs, hashes, keywords, whitelists), REPLACE for scalars (thresholds, weights, prompts). Startup logs `intel_loaded source=… yara_n=… …`.

### Ecosystems

| Ecosystem | Watchlist | Incremental | Detonation |
|-----------|-----------|-------------|------------|
| PyPI | 10K + all new packages | RSS + XML-RPC cursor | Yes |
| Crates.io | 10K + all new crates | RSS feeds | Yes |
| Go modules | ~9K + all brand-new modules | NDJSON index cursor | Yes |

All ecosystems share the same analysis pipeline, including detonation.

### Ingest gates

A package is enqueued if it meets **either** condition:

| Condition | Priority | Purpose |
|-----------|----------|---------|
| **On watchlist** (top 10K per ecosystem) | `high` | Protect high-blast-radius packages |
| **Brand new package** (first-ever publish) | `normal` | Catch lure/social-engineering packages |

Existing non-watchlist version updates are skipped.

### Detection layers

~104 rules across 12 layers. Full catalog: `docs/detection-rules.md`.

1. `analyze/imports.py` — AST import analysis
2. `analyze/iocs.py` — URLs, IPs, onion, base64 (with benign domain whitelist)
3. `analyze/malware_patterns.py` — install-time file patterns
4. `analyze/metadata.py` — typosquatting, sdist/wheel mismatch, lure name detection
5. `ecosystems/pypi/installer.py` — setup.py AST parse (PyPI) — *being replaced by opengrep, see layer 12*
6. `ecosystems/crates/build_rs.py` — build.rs analysis (Crates) — *being replaced by opengrep, see layer 12*
7. `ecosystems/gomod/go_directives.py` — go:generate, init() body, CGO, replace, unsafe (Go)
8. `analyze/yara_scan.py` — YARA rule matching
9. `analyze/version_diff.py` — clean→critical transitions, author changes, dep spikes
10. `analyze/threat_intel.py` — known-malicious fingerprints (SHA256, ssdeep, TLSH)
11. `detonate/` — Docker sandbox + Tetragon eBPF dynamic analysis (all ecosystems)
12. `analyze/opengrep_scan.py` — opengrep static analysis with intrafile taint tracking (all ecosystems). Shadow mode default-on via `OPENGREP_SHADOW=1`.

### Scoring

`detect/score.py` — severity points (low=1, med=8, high=25, crit=60), per-category cap 30, suspicious ≥ 20, malicious ≥ 61. Behavioral chains in `detect/rules.py` auto-escalate.

### Queue scheduling

`queue.py` `claim_next()` uses fair cross-ecosystem scheduling: for each priority tier (high → normal → low), discovers which ecosystems have pending items, shuffles randomly, then picks the oldest item within the chosen ecosystem.

## Detonation service (Go)

Separate Go module at `detonation/`. Uses **rootless Docker** — the detonation user has its own isolated Docker daemon and cannot see or affect system Docker containers/volumes.

```bash
cd detonation && go test ./... -v     # Tests
cd detonation && make build           # Cross-compile for Linux
```

**Components:**
- `internal/trace/` — TraceEvent types + Tetragon JSON collector (PID namespace filtering)
- `internal/rules/` — 8 behavioral rules + dedup engine
- `internal/baseline/` — noise filter for known-benign behaviors
- `internal/sandbox/` — Docker container orchestration + per-ecosystem profiles
- `internal/api/` — HTTP server (`/api/v1/health`, `/api/v1/detonate`)
- `cmd/detonation-svc/` — main entry point
- `deploy/` — systemd unit, cgroup slice, Tetragon policy, setup.sh

**Isolation:** Detonation user is NOT in the `docker` group. Uses rootless Docker (separate daemon at `/run/user/<UID>/docker.sock`, separate storage). `DOCKER_HOST` env var set via `/etc/default/detonation-svc` (generated by `setup.sh`).

## Code conventions

- `from __future__ import annotations` in every file
- structlog for logging (`from pkgsentry.logging_setup import get_logger`)
- SQLAlchemy ORM models in `store/models.py`
- Async pipeline (`pipeline.py`), sync analyzers
- Findings use the `Finding` dataclass from `adapter.py`
- No comments unless the why is non-obvious

## Pipeline threading model

`pipeline.py` uses `asyncio.to_thread()` to keep the event loop unblocked:
- `_extract_and_hash()` — extraction + SHA256/entropy/ssdeep hashing (CPU-bound)
- `_run_analyzers()` — all static analyzers (CPU-bound)
- `_persist_and_finalize()` — scoring, DB writes, detonation, LLM triage, mark_done
- `_bump_rulehits_deferred()` — uses its own `session_scope()` to avoid row-lock deadlocks

Never call sync DB operations or CPU-heavy code directly from `process_one()`. Wrap in `asyncio.to_thread()`.

Workers have a 15-min per-package timeout. Extraction allows up to 25K files per archive.

## Diagrams

Architecture and flow diagrams live in `docs/diagrams/` (draw.io format):

| File | Content |
|------|---------|
| `architecture-overview.drawio` | High-level multi-ecosystem system architecture |
| `scan-pipeline.drawio` | process_one() detailed flowchart |
| `pypi-pipeline.drawio` | PyPI end-to-end pipeline |
| `crates-pipeline.drawio` | Crates.io end-to-end pipeline |
| `go-pipeline.drawio` | Go modules pipeline |
| `detection-layers.drawio` | Detection layers, color-coded by ecosystem |
| `code-diff-flow.drawio` | Code-diff scanning flow |
| `queue-state-machine.drawio` | Queue states + fair scheduling |
| `ecosystem-lifecycle.drawio` | Seed → Baseline → Incremental lifecycle |

## Debugging a frozen scanner

```bash
# Thread dump
docker exec --privileged pkgsentry py-spy dump --pid 1

# Reset stuck claimed items
docker exec pkgsentry python -c "
from pkgsentry.store.session import get_engine
from sqlalchemy import text
e = get_engine()
with e.begin() as c:
    n = c.execute(text(\"UPDATE scan_queue SET status='pending', claimed_at=NULL, claim_token=NULL WHERE status='claimed'\")).rowcount
    print(f'Reset {n} claimed items')
"
```
