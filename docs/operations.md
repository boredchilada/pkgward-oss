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

## Focus packages

Monitor a specific set of dependencies (your own) instead of, or in addition to,
the top-10K watchlist and all brand-new uploads.

### One combined file (recommended)

Write a single file with per-ecosystem sections — `#` comments and blanks ignored:

```
[pypi]
requests==2.31.0
cryptography
[crates]
serde
[gomod]
# name [version], whitespace-separated, matched case-insensitively
github.com/gin-gonic/gin v1.9.1
```

The easiest way to use it — **drop the file and run focused**:

```bash
pkgsentry run -f /config/focus.txt          # focused mode: scan ONLY these
```

`-f/--focus` runs the scanner in **exclusive** mode against the file: it authoritatively
syncs the focus list (each `[section]` replaces that ecosystem's entries), enqueues any
pinned `name==version` immediately, and skips the watchlist + brand-new gates entirely.
Without `-f`, `pkgsentry run` does the usual watchlist + brand-new ingest.

To load a combined file *without* switching to focused mode (additive — keep watching the
watchlist too), use the CLI and leave the scanner running normally:

```bash
docker exec pkgsentry pkgsentry focus load /config/focus.txt   # no -e: all sections
docker exec pkgsentry pkgsentry focus list                     # all ecosystems
docker exec pkgsentry pkgsentry focus clear                    # all (or -e <eco>)
```

### Single ecosystem (flat file)

`focus load <file> -e pypi` loads a flat list for one ecosystem, **additively** (upsert —
does not remove existing entries).

### Entry syntax (lenient)

Each line is a package **name** optionally followed by a version in any common form, so you
can paste lines straight from `requirements.txt` / `go.mod` / `Cargo.toml`:

```
requests                 # monitor every new release
requests==2.31.0         # also scan 2.31.0 once (the version you run)
requests>=2.31.0         # same — the version present is scanned once
flask~=3.0               # ~=, ^, and ranges accepted; lower bound used
github.com/gin/gin v1.9.1   # gomod: space-separated
```

The **name** is what's monitored — every new release of it is scanned at high priority.
Any version present is scanned once at load (for a range, its lower bound). Nothing is
rejected.

### Notes

- After loading, every new release of a focus package is enqueued at high priority
  automatically; pinned versions are scanned once at load.
- The underlying toggle is `PKGSENTRY_FOCUS_EXCLUSIVE` (`1` = exclusive, `0` = additive);
  `run -f` sets it to `1` for that process. In exclusive mode with an empty focus list the
  scanner logs `focus_exclusive_empty` and idles by design.

## Intel pack

pkgsentry loads detection content from an intel pack at startup.

**Baseline only** (default, no config needed):

```
pkgsentry/intel/baseline/   — ships in-tree, AGPL-3.0
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

## Tuning the detonation network allowlist

The detonation noise filter drops connections to known registry/CDN destinations
(`{eco}_net_allow` in `detonation/noise_baseline.toml`) so normal dependency fetches don't
false-positive as `dyn_import_exfil`. Before adding entries, **mine the data you already
have** — the recurring destinations on benign detonations are the FP candidates:

```bash
docker exec pkgsentry python -c "
from pkgsentry.store import session as sess
from sqlalchemy import text
sess.init_db()
with sess.session_scope() as s:
    rows = s.execute(text('''
      SELECT d.ecosystem, te.detail->>'addr' addr, sc.verdict,
             count(distinct d.scan_id) scans
      FROM trace_event te
      JOIN detonation d ON te.detonation_id=d.id
      JOIN scan sc ON d.scan_id=sc.id
      WHERE te.category='network' AND te.operation='connect' AND te.phase='import'
      GROUP BY 1,2,3 ORDER BY scans DESC LIMIT 30''')).all()
    for r in rows: print(r)
"
```

Reverse-resolve the IPs (`socket.gethostbyaddr`) to identify the owner (Fastly =
151.101/146.75/199.232; Cloudflare = 104.16–104.31; Google = 142.250/64.233 `1e100.net`;
CloudFront = `cloudfront.net`). Add **hostnames** (preferred — resolved per detonation,
self-updating) and/or the **observed registry /32s** to the per-ecosystem `*_net_allow` in
the private overlay. **Never** add broad CDN CIDRs (would mask real exfil) or internal infra.
Note: under SELinux the detonation service needs the overlay relabeled — `setup.sh` handles
this; see `docs/detonation.md`.

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
