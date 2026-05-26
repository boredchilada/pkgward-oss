# Operations Guide

Operator-facing reference for running pkgsentry in production.

## Prerequisites

- Docker + Docker Compose
- A populated `.env` file (copy `.env.example`, fill in values)

## Deployment options

### Standalone (batteries-included)

Includes PostgreSQL in the stack — no external database needed. Good for evaluation,
small deployments, or running everything on one machine.

```bash
cp .env.example .env
# Edit .env — at minimum set OPENROUTER_API_KEY if you want LLM triage

docker compose -f docker-compose.standalone.yml up -d
```

The standalone compose file sets `PKGSENTRY_DB_URL` automatically — you don't need to
configure it in `.env`. Data is persisted in a Docker volume (`pkgsentry-pgdata`).
Tables are created automatically on first start — no separate init step required.

### Production (BYO Postgres)

Point `PKGSENTRY_DB_URL` in `.env` at your own PostgreSQL instance and use the standard
compose file:

```bash
cp .env.example .env
# Edit .env — set PKGSENTRY_DB_URL, OPENROUTER_API_KEY, etc.

docker compose up -d
```

The scanner also supports SQLite (`PKGSENTRY_DB_URL=sqlite:///pkgsentry.db`) for local
development, but PostgreSQL is recommended for production.

Set `SCANNER_INGEST=0` to start workers without enqueueing new packages (useful for
draining an existing queue before a maintenance window).

## Logs

```bash
docker logs pkgsentry --tail 50 -f
```

Every scan emits a `scan_done` structured log line. Key fields:

| Field | Meaning |
|-------|---------|
| `verdict` | `clean`, `suspicious`, or `malicious` |
| `score` | Numeric score (≥20 suspicious, ≥61 malicious) |
| `n_findings` | Number of rule hits |
| `duration_s` | Scan wall time |
| `sid` | 8-char trace ID — grep this to see the full scan timeline |

Grep one scan end-to-end:

```bash
docker logs pkgsentry 2>&1 | grep '"sid":"<sid-value>"'
```

Confirm which intel pack loaded on startup:

```bash
docker logs pkgsentry 2>&1 | grep intel_loaded
```

## Queue and scan stats

```bash
docker exec pkgsentry python -c "
from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue, Scan
from sqlalchemy import select, func
sess.init_db()
with sess.session_scope() as s:
    for eco in ('pypi', 'crates', 'gomod'):
        pending = s.scalar(select(func.count()).where(ScanQueue.status == 'pending', ScanQueue.ecosystem == eco))
        done    = s.scalar(select(func.count()).where(ScanQueue.status == 'done',    ScanQueue.ecosystem == eco))
        print(f'{eco}: {pending} pending, {done} done')
    total = s.scalar(select(func.count()).select_from(Scan))
    mal   = s.scalar(select(func.count()).where(Scan.verdict == 'malicious'))
    print(f'Scans: {total} total, {mal} malicious')
"
```

## Intel pack

pkgsentry loads detection content from an intel pack at startup.

**Baseline only** (default, no config needed):

```
pkgsentry/intel/baseline/   — ships in-tree, Apache 2.0
```

**Private overlay** (operator-supplied):

```bash
# Mount your overlay directory and set the env var:
PKGSENTRY_INTEL_PATH=/path/to/intel/private
```

The overlay merges over the baseline at process start:
- Additive fields (YARA dirs, hashes, keywords, whitelists): **union**
- Scalars (thresholds, scoring weights, prompt text): **replace**

Startup log confirms the active pack:

```
intel_loaded source=baseline+overlay yara_n=… hash_seeds_n=… …
```

## Debugging a frozen scanner

```bash
# Thread dump — shows where each worker is stuck
docker exec --privileged pkgsentry py-spy dump --pid 1
```

Reset items stuck in `claimed` state after a crash or freeze:

```bash
docker exec pkgsentry python -c "
from pkgsentry.store.session import get_engine
from sqlalchemy import text
e = get_engine()
with e.begin() as c:
    n = c.execute(text(\"UPDATE scan_queue SET status='pending', claimed_at=NULL, claim_token=NULL WHERE status='claimed'\")).rowcount
    print(f'Reset {n} claimed items')
"
```

## Seeding threat-intel fingerprints

```bash
docker exec pkgsentry python -m pkgsentry.store.seed_intel
```

This populates the `ThreatIntelHash` table from `hashes/known_malicious.jsonl` in the loaded
intel pack(s). Safe to re-run — inserts are upserted by SHA256.

## Key environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PKGSENTRY_DB_URL` | PostgreSQL connection string | `sqlite:///pkgsentry.db` |
| `PKGSENTRY_INTEL_PATH` | Path to private intel overlay directory | unset (baseline only) |
| `PKGSENTRY_CONTACT_EMAIL` | Shown in outbound HTTP User-Agent | project URL |
| `PKGSENTRY_LLM_MODEL` | LLM model ID for triage | `z-ai/glm-5.1` |
| `PKGSENTRY_LLM_MAX_USD` | Per-process LLM spend cap | `20.0` |
| `PKGSENTRY_LLM_MAX_CALLS_PER_HOUR` | LLM triage rate limit | `1000` |
| `OPENROUTER_API_KEY` | OpenRouter API key | required for LLM triage |
| `DISCORD_WEBHOOK_URL` | Webhook for malicious package alerts | optional |
| `DETONATION_SOCKET` | UNIX socket path for detonation service | unset |
| `SCANNER_INGEST` | `0` = workers only, `1` = poll feeds | `1` |
| `GOMOD_SCAN_PSEUDO` | `1` = scan Go pseudo-versions | `0` |

Legacy prefixes `PKGWATCH_*` and `PYPI_SCANNER_*` are accepted as fallbacks for all
`PKGSENTRY_*` vars.

## Updating the scanner

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

Migrations run automatically at startup via `init_db()`. There is no separate migration command.
