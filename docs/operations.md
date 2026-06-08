# Operations Guide

Operator-facing reference for running pkgward in production.

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

The standalone compose file sets `PKGWARD_DB_URL` automatically — you don't need to
configure it in `.env`. Data is persisted in a Docker volume (`pkgward-pgdata`).
Tables are created automatically on first start — no separate init step required.

### Production (BYO Postgres)

Point `PKGWARD_DB_URL` in `.env` at your own PostgreSQL instance and use the standard
compose file:

```bash
cp .env.example .env
# Edit .env — set PKGWARD_DB_URL, OPENROUTER_API_KEY, etc.

docker compose up -d
```

The scanner also supports SQLite (`PKGWARD_DB_URL=sqlite:///pkgward.db`) for local
development, but PostgreSQL is recommended for production.

Set `SCANNER_INGEST=0` to start workers without enqueueing new packages (useful for
draining an existing queue before a maintenance window).

### Scaling horizontally (multiple worker hosts)

> See `docs/diagrams/deployment-topology.md` for the topology, code/intel deploy
> flow, and work-distribution diagrams.

The scan queue and the detonation queue are both DB-coordinated (claim-token
compare-and-set), so additional hosts can drain the same queues with no double-work.
To add a scan-worker host:

- Point it at the **same** `PKGWARD_DB_URL` as the primary.
- Set **`SCANNER_INGEST=0`** so only the primary polls feeds / advances cursors (no
  duplicate enqueues or cursor races); the new host purely drains the queue.
- If the cluster runs detonation but this host has no local detonation service, set
  **`DETONATION_ENABLED=1`** so its scans still enqueue detonation jobs for a host with
  a detonation service to drain. (A host with `DETONATION_SOCKET`/`DETONATION_URL`
  enqueues regardless.) The detonation worker pool only starts where a detonation
  service is actually reachable.

Give each host as many `--workers` as it has cores can carry. The work is heavily
I/O-bound (download, registry, DB) with CPU bursts (opengrep/YARA), so oversubscribe:
**~2.5 workers per core** is a sound default (memory is rarely the limit — a dozen
workers idle around a few hundred MB; giant packages are bounded by the giant-fastpath).
Throughput scales roughly linearly with total workers across hosts.

#### Code + intel deploys to worker hosts

The scanner image installs the package **editable** (`pip install -e .`), so a worker
host can bind-mount a git checkout over `/app` and pick up new **code** with a plain
`git pull` + `docker restart` — no image rebuild or transfer. The image only needs
re-shipping when **dependencies** change (`requirements.txt`). Two helpers drive this
(both read a gitignored `tools/worker-hosts.conf` listing `<ssh_key> <user@host>
<remote_intel_dir> <container> [<repo_dir>]`):

- **`tools/deploy-worker.sh`** — `git pull` + `docker restart` on each worker (ships code).
- **`tools/sync-worker.sh`** — `rsync` the private intel overlay + restart (ships rules/
  prompts/genes). The overlay is read once at process start, so a worker that isn't
  restarted keeps triaging with the **old** prompt/rules — this closes that drift.

Both verify the worker came back up via the `intel_loaded source=baseline+overlay` log line.

**Ordering when a change moves a YARA rule between tiers** (overlay → baseline, or back):
the baseline and overlay YARA dirs are UNION-merged, so a rule present in *both* is a
duplicate identifier — a hard `yara.compile` failure that disables the whole YARA layer.
Run **`sync-worker.sh` (the trimmed overlay) BEFORE `deploy-worker.sh` (the new baseline)**.
Baseline-first opens a window where the old overlay and the new baseline both contain the
rule → the worker's YARA compile fails on that restart. Validate before deploying by
compiling both baseline-only and the baseline+overlay union. (Pure-overlay or pure-code
changes: order doesn't matter.) On the prod host the overlay is a local bind-mount, so a
tier move there is just: edit overlay on disk → rebuild + recreate the scanner.

#### Reaching a private-network database

When the primary's Postgres is on a private VLAN the worker can't route to, run a
**reverse SSH tunnel from the primary out to the worker** (the primary can dial the
worker, not vice-versa), forwarding the DB onto the worker's loopback, and point the
worker's `PKGWARD_DB_URL` at `127.0.0.1:<port>`. Run the tunnel as a `restart: always`
container (e.g. an alpine + `openssh-client` loop) so it survives reboots — cleaner than
a host service if SELinux blocks an init-spawned `ssh`.

## Logs

```bash
docker logs pkgward --tail 50 -f
```

Every scan emits a `scan_done` structured log line. Key fields:

| Field | Meaning |
|-------|---------|
| `verdict` | `clean`, `suspicious`, `malicious`, or `inconclusive` (weak signal the LLM couldn't adjudicate → needs review) |
| `score` | Numeric score (≥20 suspicious, ≥61 malicious) |
| `n_findings` | Number of rule hits |
| `duration_s` | Scan wall time |

The `sid` field (an 8-char trace ID) is bound to every structured log line for a scan — grep it to follow one scan end-to-end:

```bash
docker logs pkgward 2>&1 | grep '"sid":"<sid-value>"'
```

Confirm which intel pack loaded on startup:

```bash
docker logs pkgward 2>&1 | grep intel_loaded
```

## Queue and scan stats

```bash
docker exec pkgward python -c "
from pkgward.store import session as sess
from pkgward.store.models import ScanQueue, Scan
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
pkgward run -f /config/focus.txt          # focused mode: scan ONLY these
```

`-f/--focus` runs the scanner in **exclusive** mode against the file: it authoritatively
syncs the focus list (each `[section]` replaces that ecosystem's entries), enqueues any
pinned `name==version` immediately, and skips the watchlist + brand-new gates entirely.
Without `-f`, `pkgward run` does the usual watchlist + brand-new ingest.

To load a combined file *without* switching to focused mode (additive — keep watching the
watchlist too), use the CLI and leave the scanner running normally:

```bash
docker exec pkgward pkgward focus load /config/focus.txt   # no -e: all sections
docker exec pkgward pkgward focus list                     # all ecosystems
docker exec pkgward pkgward focus clear                    # all (or -e <eco>)
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
- The underlying toggle is `PKGWARD_FOCUS_EXCLUSIVE` (`1` = exclusive, `0` = additive);
  `run -f` sets it to `1` for that process. In exclusive mode with an empty focus list the
  scanner logs `focus_exclusive_empty` and idles by design.

## Intel pack

pkgward loads detection content from an intel pack at startup.

**Baseline only** (default, no config needed):

```
pkgward/intel/baseline/   — ships in-tree, Apache-2.0
```

**Private overlay** (operator-supplied):

```bash
# Mount your overlay directory and set the env var:
PKGWARD_INTEL_PATH=/path/to/intel/private
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
docker exec pkgward python -c "
from pkgward.store import session as sess
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
docker exec --privileged pkgward py-spy dump --pid 1
```

Reset items stuck in `claimed` state after a crash or freeze:

```bash
docker exec pkgward python -c "
from pkgward.store.session import get_engine
from sqlalchemy import text
e = get_engine()
with e.begin() as c:
    n = c.execute(text(\"UPDATE scan_queue SET status='pending', claimed_at=NULL, claim_token=NULL WHERE status='claimed'\")).rowcount
    print(f'Reset {n} claimed items')
"
```

## Auto-watchlist (confirmed-malicious gate)

When a scan finishes with **both** the rule verdict and the LLM verdict at
`malicious`, pkgward inserts `(ecosystem, name)` into the `Watchlist` at a
sentinel rank (`9_999_999`) so every future release of that name is enqueued at
high priority. This closes the "brand-new gate fires once per name" gap — a
follow-up malicious release of an already-burned name would otherwise be
skipped by the brand-new ingest gate.

Auto-added rows are distinguishable by their rank: a popularity entry has
`rank ≤ ~10_000`; an auto-added one has `rank = 9_999_999`. The four ecosystem
`refresh_watchlist` jobs skip rows at the sentinel rank, so popularity refresh
never evicts an auto-added row.

For confirmed-malicious names the scanner *also* carries forward findings on
SHA-unchanged files from the most-recent prior scan (`PKGWARD_FINDING_REUSE_DAYS`,
default 7) — needed because a re-publish that only changes a handful of files
(common for many packages, malicious or not) would otherwise see the
`changed_files` optimization suppress analyzers on the unchanged majority, and
the new scan would surface only the deltas (e.g. 3 of 11 findings) to scoring
and the LLM.

### Inspecting and trimming auto-added entries

```bash
# list all auto-added entries (sentinel-rank rows)
docker exec pkgward pkgward watchlist auto list
docker exec pkgward pkgward watchlist auto list --ecosystem npm

# remove a single FP (e.g. an over-flagged build/fetch tool)
docker exec pkgward pkgward watchlist auto remove npm <name>

# bulk-prune: drop everything older than N days
docker exec pkgward pkgward watchlist auto purge --older-than-days 30

# one-shot backfill: walk scan history and add every package that ever produced
# a double-confirmed verdict in the last N days (default 30).
docker exec pkgward pkgward watchlist auto backfill --days 30
```

### Permanent FP blocklist
Set `WATCHLIST_AUTO_BLOCKLIST="npm:bad-name,pypi:other"` in `.env`. Names listed
there are **never** auto-added, even on double-confirm. Survives across restarts;
upgrade path is a private-intel TOML in a future release.

### Size-control layers (all env-tunable)

| Variable | Purpose | Default |
|---|---|---|
| `WATCHLIST_AUTO_MALICIOUS` | Master on/off | `1` |
| `WATCHLIST_AUTO_TTL_DAYS` | Auto-added entries pruned after no re-confirm | `180` |
| `WATCHLIST_AUTO_MAX_PER_ECO` | Hard cap per ecosystem; oldest evicted over | `5000` |
| `WATCHLIST_AUTO_MAX_ADDS_PER_HOUR` | Per-ecosystem add-rate ceiling (in-process) | `100` |
| `WATCHLIST_AUTO_BLOCKLIST` | `"eco:name,eco:name"` — never auto-add | unset |
| `PKGWARD_FINDING_REUSE_DAYS` | TTL window for carry-forward of prior findings | `7` |

The janitor (`watchlist_auto_janitor`, hourly) drops expired entries and
evicts oldest when over the cap. Logs `watchlist_auto_janitor` events.

## Seeding threat-intel fingerprints

```bash
docker exec pkgward python -m pkgward.store.seed_intel
```

This populates the `ThreatIntelHash` table from `hashes/known_malicious.jsonl` in the loaded
intel pack(s). Safe to re-run — inserts are upserted by SHA256.

## Key environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `PKGWARD_DB_URL` | PostgreSQL connection string | `sqlite:///pkgward.db` |
| `PKGWARD_INTEL_PATH` | Path to private intel overlay directory | unset (baseline only) |
| `PKGWARD_CONTACT_EMAIL` | Shown in outbound HTTP User-Agent | project URL |
| `PKGWARD_LLM_MODEL` | LLM model ID for triage | `deepseek/deepseek-v4-flash` |
| `PKGWARD_LLM_MAX_USD` | Per-process LLM spend cap | `20.0` |
| `PKGWARD_LLM_MAX_CALLS_PER_HOUR` | LLM triage rate limit | `1000` |
| `OPENROUTER_API_KEY` | OpenRouter API key | required for LLM triage |
| `DISCORD_WEBHOOK_URL` | Webhook for malicious package alerts | optional |
| `DETONATION_SOCKET` | UNIX socket path for detonation service | unset |
| `SCANNER_INGEST` | `0` = workers only, `1` = poll feeds | `1` |
| `GOMOD_SCAN_PSEUDO` | `1` = scan Go pseudo-versions | `0` |

Legacy prefixes `PKGWATCH_*` and `PYPI_SCANNER_*` are accepted as fallbacks only for the
LLM vars (`PKGWARD_LLM_MODEL`, `PKGWARD_LLM_BASE_URL`, `PKGWARD_LLM_MAX_USD`,
`PKGWARD_LLM_MAX_CALLS_PER_HOUR`) and `PKGWARD_DB_URL` — not for every `PKGWARD_*` var.

## Data retention and investigation

The scanner keeps full evidence for every scan it runs. This makes false-positive
analysis, rule-tuning, and threat-intel seeding tractable without re-fetching
upstream archives that may have been yanked.

### What's persisted

| Table | What it stores |
|---|---|
| `scan` | One row per scan: verdict, score, alert_tag, started_at, finished_at, duration |
| `finding` | One row per individual finding: rule_id, category, severity, file path, line number, **evidence text** (the substring or chain that triggered the rule) |
| `file_hash` | Per-file SHA-256 + ssdeep + entropy + archive_kind for every file extracted from every scanned archive |
| `detonation` | Per-detonation outcome: install/import exit codes, durations, timeouts, trace-event counts |
| `trace_event` | One row per Tetragon-captured behavior in the sandbox: phase, category, operation, detail, matched_rule, pid, binary |
| `watchlist` | Per-ecosystem watched names + rank (popularity rank for top-N, sentinel `9_999_999` for auto-watchlisted entries) |

LLM triage results are not a separate table — they're columns on the `scan` row
(`llm_verdict`, `llm_cost_usd`, `llm_latency_ms`, `llm_model`, `llm_reasoning`).

These rows are not garbage-collected by default. At ~10K scans/day on a
moderately-loaded host this produces ~5M `finding` rows and ~14M `file_hash`
rows per week of operation; plan disk accordingly. A future release may add an
opt-in retention policy (TTL-by-`finished_at` on `finding` and `file_hash`).

### Vault (frozen malicious archives)

When `PKGWARD_VAULT_PATH` is set, **double-confirmed** malicious archives (rules and
LLM both malicious) are auto-preserved (inert) under that directory. The naming convention is:

```
<eco>__<name>__<version>__<sha256-prefix>.zip
<eco>__<name>__<version>__<sha256-prefix>.manifest.toml
```

This means you can re-analyze, fingerprint, or seed threat-intel from real
samples even after the upstream registry has yanked them. The manifest carries
the verdict + rule hits at the time of capture.

### Investigating a finding after the fact

The persisted `evidence` column on `finding` carries the actual substring or
chain that triggered the rule, which is usually enough to verify a finding
without re-fetching the archive:

```sql
-- All findings for a scan you want to inspect
SELECT rule_id, severity, file, line, evidence
FROM finding
WHERE scan_id = <id>
ORDER BY CASE severity
  WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4
END;

-- Findings on a specific package across all versions
SELECT v.version, s.verdict, s.score, f.rule_id, f.severity, f.file
FROM scan s
JOIN version v ON s.version_id = v.id
JOIN package p ON v.package_id = p.id
LEFT JOIN finding f ON f.scan_id = s.id
WHERE p.ecosystem = 'pypi' AND p.name = '<name>'
ORDER BY s.finished_at DESC;

-- How often a given rule fires, and where (FP triage):
SELECT f.rule_id, COUNT(*) AS hits, AVG(s.score) AS avg_score
FROM finding f JOIN scan s ON f.scan_id = s.id
WHERE f.severity IN ('critical','high')
GROUP BY 1 ORDER BY 2 DESC;
```

When the `evidence` text isn't enough, the vault provides the actual archive.
When the vault doesn't have it either, `pip download <name>==<version>
--no-deps -d /tmp/x` (or `npm pack <name>@<version>` / `cargo pkgid ...`) will
fetch the upstream copy if it's still published.

### Turning a confirmed FP into a regression test

When you verify that a flagged package was actually benign, write the case
into the regression corpus so future rule changes can't re-introduce the FP:

1. Place the archive under your corpus directory (`PKGWARD_CORPUS_PATH` for
   private samples, or `tests/corpus/` for public).
2. Add a YAML manifest describing the expected outcome:
   ```yaml
   ecosystem: pypi
   name: example-tool
   version: 1.2.3
   expect:
     verdict_not: malicious
     # OR allowlist specific findings that are known-benign:
     allowed_findings:
       - rule_id: malware.credential_file_access
         file_substr: 'tests/'
   ```
3. The regression-corpus test (`tests/test_regression_corpus.py`) runs the
   full analyze → score path against every corpus sample on CI, so a future
   rule change that re-classifies the sample as malicious will fail the build.

See `docs/regression-testing.md` for the full corpus format.

### Auto-watchlist FP exit ramps

```bash
docker exec pkgward pkgward watchlist auto list
docker exec pkgward pkgward watchlist auto remove <ecosystem> <name>
```

Or set `WATCHLIST_AUTO_BLOCKLIST="<eco>:<name>,<eco>:<name>,…"` in `.env` to
keep names from ever being auto-added on a future backfill.

## Needs-review queue (LLM inconclusive)

When LLM triage can't decide from the evidence it was shown — the file a finding
points at wasn't in the source, or the only findings are metadata/name heuristics
with no behavioral code — it returns **`inconclusive`** rather than guessing. A
weak-signal inconclusive raises **no** malicious alarm; it's recorded with
`verdict='inconclusive'` (tagged `needs_review`), fires a distinct amber
"🔍 Needs Review" Discord alert, and lands in a queryable queue:

```bash
docker exec pkgward pkgward review            # newest inconclusive scans + missing evidence
docker exec pkgward pkgward review -e npm -n 100
```

Each row shows what the model was missing (the `MISSING EVIDENCE:` line) so you can
pull the package and adjudicate. A rule-malicious package the LLM merely couldn't
*confirm* still alarms (tagged `llm_unverified`) — inconclusive only softens weak signals.

## Updating the scanner

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

Migrations run automatically at startup via `init_db()`. There is no separate migration command.
