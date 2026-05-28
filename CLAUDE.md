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
python -m pytest tests/ -x -q          # Python (459 tests)
cd detonation && go test ./... -v       # Go
tools/test_opengrep_rules.sh            # opengrep rules via `--test` fixtures (all 4 langs)
python -m pytest tests/test_regression_corpus.py tests/test_rule_coverage.py -q  # detection regression suite
```

The regression corpus (`tests/corpus/`) runs labeled known-bad/known-good samples through the
real analyze→score path so detection regressions fail the build. See `docs/regression-testing.md`.
Private samples/vault load via `PKGSENTRY_CORPUS_PATH` / `PKGSENTRY_VAULT_PATH`.

opengrep/semgrep and (often) the Python deps aren't on dev hosts. Run against the scanner
image with the working tree mounted — clean, doesn't touch the running scanner:

```bash
docker run --rm --entrypoint python -v "$PWD:/src" -w /src pkgsentry-scanner -m pytest tests/ -q
docker run --rm --entrypoint bash   -v "$PWD:/src" -w /src pkgsentry-scanner tools/test_opengrep_rules.sh
```

## Key env vars

| Var | Purpose | Default |
|-----|---------|---------|
| `SCANNER_INGEST` | `0` = don't enqueue new packages, `1` = poll feeds/cursor | `1` |
| `PKGSENTRY_FOCUS_EXCLUSIVE` | `1` = scan ONLY focus-list packages (skip watchlist + brand-new gates and watchlist refresh); `0` = additive (focus packages scanned at high priority *plus* the normal gates) | `0` |
| `OPENROUTER_API_KEY` | LLM triage API key | — |
| `DISCORD_WEBHOOK_URL` | Malicious package alerts | — |
| `PKGSENTRY_DB_URL` | DB connection URL | `sqlite:///pkgsentry.db` |
| `PKGSENTRY_CONTACT_EMAIL` | Surfaced in outbound User-Agent | project URL |
| `PKGSENTRY_LLM_MODEL` | LLM model ID | `z-ai/glm-5.1` |
| `PKGSENTRY_LLM_MAX_USD` | Per-process budget cap | `20.0` |
| `PKGSENTRY_LLM_MAX_CALLS_PER_HOUR` | Rate limit on triage calls | `1000` |
| `PKGSENTRY_INTEL_PATH` | Path to private intel pack overlay | unset (baseline only) |
| `PKGSENTRY_CORPUS_PATH` | Path to a private regression-corpus dir (extra known-bad/good samples) | unset |
| `PKGSENTRY_VAULT_PATH` | Frozen-sample vault dir; when set, malicious archives are auto-preserved (inert) | unset (off) |
| `DETONATION_SOCKET` | Detonation service UNIX socket | — |
| `DETONATION_URL` | TCP fallback for detonation service | — |
| `DETONATION_WORKERS` | Async detonation worker pool size (drains `DetonationQueue`; match the service `--max-concurrent`) | `6` |
| `DETONATION_ENABLED` | Force detonation-enqueue even without a local detonation client — set on scan-only worker hosts so they enqueue into the shared `DetonationQueue` for a draining host (a host with `DETONATION_SOCKET` enqueues regardless) | `0` |
| `GOMOD_SCAN_PSEUDO` | `1` = scan Go pseudo-versions, `0` = skip | `0` |
| `GITHUB_TOKEN` | GitHub API token for Go watchlist (optional) | — |
| `OPENGREP_ENABLED` | Master switch for the opengrep layer | `1` |
| `OPENGREP_SHADOW` | `1` = shadow mode (findings excluded from scoring); `0` = cutover (replaces legacy install-time analyzers) | `1` |
| `OPENGREP_TIMEOUT_SEC` | Per-package wall-clock timeout for the opengrep subprocess | `60` |
| `OPENGREP_BIN` | Override the opengrep binary path / PATH name | `opengrep` |
| `PKGSENTRY_LLM_MAX_RETRIES` | Retries on bad/invalid JSON from the LLM (cost/tokens accumulate across attempts) | `2` |
| `PKGSENTRY_LLM_MAX_RESPONSE_TOKENS` | Cap on the LLM response (prevents `finish_reason=length` truncation that produces invalid JSON). On `finish_reason=length` the retry escalates by 1.5×, capped at `*_CEILING`. | `5000` |
| `PKGSENTRY_LLM_MAX_RESPONSE_TOKENS_CEILING` | Hard ceiling for the escalating retry on length-truncation. Beyond this the model is treated as rambling and the call bails. | `8000` |
| `PKGSENTRY_HASH_FULL_MAX_MB` | Files above this size get SHA-256 only (streamed); entropy/ssdeep/TLSH skipped. Big prebuilt native binaries are near-useless for those metrics. | `20` |
| `SCHED_RESERVED_FRACTION` | Fraction of claim-share split *equally* among non-empty ecosystems (the floor — guarantees no ecosystem starves). Set `1.0` for legacy uniform-fair behavior. | `0.4` |
| `SCHED_MAX_ECO_SHARE` | Upper cap on any single ecosystem's claim-share, so a surge can't fully dominate. | `0.7` |
| `WATCHLIST_AUTO_MALICIOUS` | Master switch for the auto-watchlist gate (double-confirmed malicious → add at sentinel rank). | `1` |
| `WATCHLIST_AUTO_TTL_DAYS` | Auto-added watchlist entries are pruned after this many days without a re-confirm. | `180` |
| `WATCHLIST_AUTO_MAX_PER_ECO` | Hard cap per ecosystem on auto-added entries; oldest evicted when over. | `5000` |
| `WATCHLIST_AUTO_MAX_ADDS_PER_HOUR` | Per-ecosystem add-rate ceiling (in-process, defense-in-depth). | `100` |
| `WATCHLIST_AUTO_BLOCKLIST` | `"eco:name,eco:name,…"` — names that are NEVER auto-added (operator FP exit ramp). | unset |
| `PKGSENTRY_FINDING_REUSE_DAYS` | For auto-watchlisted names, TTL window for carrying forward prior findings on SHA-unchanged files. Bounds rule-update staleness. | `7` |

## Architecture

**Ingest** (focus list + watchlist + all new packages, per-ecosystem feeds/cursor) → **Queue** (backlog-weighted cross-ecosystem scheduling, see "Queue scheduling" below) → **Workers** → **Download** + SHA256 verify → **Extract** + hash (streamed SHA-256 always; entropy + ssdeep + TLSH only on files ≤ `PKGSENTRY_HASH_FULL_MAX_MB`) → **Code-diff** vs previous version → **Analyze** → **Score** → **LLM triage** (cost-gated, on static-malicious, retried on bad JSON) → **Discord alert** (fail-open: rule-malicious alerts unless the LLM explicitly clears it; alerts where the LLM couldn't adjudicate are tagged `llm_unverified`); the scan finalizes on the static verdict and **enqueues** detonation (`DetonationQueue`) instead of running it inline.

**Detonation is async** (`pkgsentry/detonation_worker.py`, since 0.5.1): a separate worker pool drains `DetonationQueue` → **Detonate** (all ecosystems) → **Re-score** → **delayed Discord alert** if the verdict flips to malicious. This keeps the scan pipeline from blocking on the detonation service's concurrency cap. See `docs/internal/detonation-decouple-0.5.1.md` and `docs/diagrams/scan-pipeline.drawio`.

### Intel pack

All tunable detection data is loaded from an intel pack at process start (`pkgsentry.intel.load()` in `runtime.py`). See `docs/intel-pack.md` for full reference.

```
pkgsentry/intel/baseline/        # ships in tree, AGPL-3.0 (third-party YARA under their own licenses, see NOTICE)
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
  npm_benign_tools.toml          # known-benign package.json lifecycle-script tools
  opengrep/                      # opengrep rule directories (python/, rust/, go/, javascript/)
  detonation/                    # behavioral rule data + noise filters
```

Operators supply a private overlay via `PKGSENTRY_INTEL_PATH`. Merge semantics: UNION for additive content (YARA dirs, hashes, keywords, whitelists), REPLACE for scalars (thresholds, weights, prompts). Startup logs `intel_loaded source=… yara_n=… …`.

### Ecosystems

| Ecosystem | Watchlist | Incremental | Detonation |
|-----------|-----------|-------------|------------|
| PyPI | 10K + all new packages | RSS + XML-RPC cursor | Yes |
| Crates.io | 10K + all new crates | RSS feeds | Yes |
| Go modules | ~9K + all brand-new modules | NDJSON index cursor | Yes |
| npm | top-N + all brand-new packages | CouchDB `_changes` seq cursor | Yes |

All four ecosystems share the same analysis pipeline, including detonation (crates/Go
sandbox builds are best-effort — install-time behavior is still traced even when a
build fails). npm discovery uses the CouchDB `_changes` feed, which carries only the
package name (not the version), so the cursor resolves `dist-tags.latest` for gated
packages before enqueuing. npm install analysis parses `package.json` lifecycle scripts.

### Ingest gates

A package is enqueued if it meets **any** condition:

| Condition | Priority | Purpose |
|-----------|----------|---------|
| **On focus list** (operator-supplied per ecosystem) | `high` | Monitor the operator's own dependencies |
| **On watchlist** (top 10K per ecosystem) | `high` | Protect high-blast-radius packages |
| **Brand new package** (first-ever publish) | `normal` | Catch lure/social-engineering packages |

Existing non-watchlist/non-focus version updates are skipped.

**Focus list** (`FocusList` table; `pkgsentry/focus.py`): a per-ecosystem personal
watchlist. Easiest path is one combined file with `[pypi]`/`[crates]`/`[gomod]` sections
plus `pkgsentry run -f <file>` (focused/exclusive mode, authoritative sync). Also loadable
without switching modes via `pkgsentry focus load <file>` (combined, no `-e`, authoritative)
or `pkgsentry focus load <file> -e <eco>` (flat, additive). Entry syntax is lenient — a
package `name` optionally followed by a version in any common form (`name`, `name==1.2.3`,
`name>=1.2.3`, `name~=1.2`, `name^1.0`, gomod `name v1.2.3`) so operators can paste
requirements.txt / go.mod / Cargo lines. The NAME is monitored (every new release scanned);
any version present is scanned once at load (a range's lower bound). gomod matched
case-insensitively. Parsing lives in `focus.parse_focus_file` / `_floor_version`.
Every new release of a focus package is enqueued at `high`; a pinned version is scanned
once at load time. The gate check is centralized in `focus.gate_decision()` and applied
in the four gated ingest consumers. With `PKGSENTRY_FOCUS_EXCLUSIVE=1` the scanner ingests
**only** focus packages (watchlist + brand-new gates and the watchlist refresh/seed jobs
are skipped); an empty focus list in this mode logs `focus_exclusive_empty` and the
scanner idles by design. (Detonation trace events are attributed to the sandbox by the
Tetragon `docker` container id, not PID namespace — this host's Tetragon export emits no
`ns` data, so namespace-based filtering, in both the collector and the tracing policy, is
inert. See `docs/detonation.md` → "Event attribution".)

### Detection layers

~115 rules across 12 layers. Full catalog: `docs/detection-rules.md`.

1. `analyze/imports.py` — AST import analysis
2. `analyze/iocs.py` — URLs, IPs, onion, base64 (with benign domain whitelist)
3. `analyze/malware_patterns.py` — install-time file patterns
4. `analyze/metadata.py` — typosquatting, sdist/wheel mismatch, lure name detection
5. `ecosystems/pypi/installer.py` — setup.py AST parse (PyPI) — *being replaced by opengrep, see layer 12*
6. `ecosystems/crates/build_rs.py` — build.rs analysis (Crates) — *being replaced by opengrep, see layer 12*
7. `ecosystems/gomod/go_directives.py` — go:generate, init() body, CGO, replace, unsafe (Go)
7b. `ecosystems/npm/installer.py` — package.json lifecycle scripts + referenced-JS (npm)
8. `analyze/yara_scan.py` — YARA rule matching
9. `analyze/version_diff.py` — clean→critical transitions, author changes, dep spikes
10. `analyze/threat_intel.py` — known-malicious fingerprints (SHA256, ssdeep, TLSH)
11. `detonate/` — rootless-Docker sandbox + Tetragon eBPF dynamic analysis (all ecosystems)
12. `analyze/opengrep_scan.py` — opengrep static analysis with intrafile taint tracking (all ecosystems). Shadow mode default-on via `OPENGREP_SHADOW=1`.

### Scoring

`detect/score.py` — severity points (low=1, med=8, high=25, crit=60), per-category cap 30, suspicious ≥ 20, malicious ≥ 61. Behavioral chains in `detect/rules.py` auto-escalate.

### Queue scheduling

`queue.py` `claim_next()` uses **backlog-weighted** scheduling across ecosystems with a reserved floor. For each priority tier (high → normal → low) it counts pending items per ecosystem and picks one by weighted sampling: `SCHED_RESERVED_FRACTION` (default 0.4) of attention is split *equally* among non-empty ecosystems (the floor — guarantees nothing starves), the remainder is allocated *proportionally to backlog size*, and any single ecosystem is clamped at `SCHED_MAX_ECO_SHARE` (default 0.7) so a surge can't fully dominate. Within the chosen ecosystem the oldest pending item is claimed (CAS-on-status); on a CAS race the loop falls back to the next ecosystem in the weighted-sample order. `SCHED_RESERVED_FRACTION=1.0` reverts to the previous uniform-fair behavior. Priority tiers are strictly ordered (any high-priority item beats any backlog at lower tiers).

### Auto-watchlist + finding carry-forward (`pkgsentry/watchlist_auto.py`, `finding_reuse.py`)

When a scan completes with **both** `result.verdict == "malicious"` *and* `tri.verdict == "malicious"` (rules and LLM agree), the pipeline calls `watchlist_auto.add_confirmed_malicious(s, ecosystem, name)`. This inserts `(ecosystem, name)` into the `Watchlist` table at **sentinel rank `9_999_999`** so every future release of the name is enqueued at high priority — closes the gap where the brand-new ingest gate fires *once per name* (a follow-up malicious release after the initial catch would otherwise be skipped). Idempotent (`refreshed_at` updates on re-confirm). Size-controlled by a TTL janitor (default 180d), per-ecosystem hard cap, and in-process add-rate ceiling; FP exit via the `WATCHLIST_AUTO_BLOCKLIST` env or `pkgsentry watchlist auto remove`. The four `refresh_watchlist` paths filter `WHERE rank != AUTO_MALICIOUS_RANK` so popularity refresh never evicts auto-added rows.

For auto-watchlisted names *only*, the pipeline also runs **finding carry-forward**: after analyzers complete (still respecting `changed_files`), `finding_reuse.carry_forward_findings()` queries the most-recent prior scan of the same package within `PKGSENTRY_FINDING_REUSE_DAYS` (default 7) and appends every prior finding whose file's `(file_path, sha256)` is unchanged in the current scan's `FileHash` set. Scoring + the LLM see the full merged evidence; analyzers don't re-run on unchanged files. Scoped to known-bad names so a yara/opengrep rule update doesn't risk stale-cache false-negatives on clean packages.

CLI for inspection / FP trimming: `pkgsentry watchlist auto {list,remove,purge,backfill}`. The `backfill` subcommand walks scan history and adds every package that ever produced a double-confirmed verdict — useful as a one-shot after enabling the gate.

## Detonation service (Go)

Separate Go module at `detonation/`. Uses **rootless Docker** — the detonation user has its own isolated Docker daemon and cannot see or affect system Docker containers/volumes.

```bash
cd detonation && go test ./... -v     # Tests
cd detonation && make build           # Cross-compile for Linux
```

**Components:**
- `internal/trace/` — TraceEvent types + Tetragon JSON collector (PID namespace filtering)
- `internal/rules/` — 8 behavioral rules + dedup engine
- `internal/baseline/` — noise filter: per-ecosystem file/exec noise **+ network allowlist** (`{eco}_net_allow`). Hostnames resolved to IPs at filter time; connects to registry/CDN destinations are dropped so normal dependency fetches don't false-positive as `dyn_import_exfil`/`dyn_install_exfil`. Tune via the intel overlay (see below).
- `internal/sandbox/` — Docker container orchestration + per-ecosystem profiles
- `internal/api/` — HTTP server (`/api/v1/health`, `/api/v1/detonate`)
- `cmd/detonation-svc/` — main entry point
- `deploy/` — systemd unit, cgroup slice, Tetragon policy, setup.sh, `selinux/` policy

**Isolation:** Detonation user is NOT in the `docker` group. Uses rootless Docker (separate daemon at `/run/user/<UID>/docker.sock`, separate storage). `DOCKER_HOST` env var set via `/etc/default/detonation-svc` (generated by `setup.sh`).

**Intel overlay + SELinux:** the service reads a private overlay from `$PKGSENTRY_INTEL_PATH/detonation/{rules_data,noise_baseline}.toml` (set in `/etc/default/detonation-svc`), UNION-merged over the embedded baseline — operators pin extra noise filters + `{eco}_net_allow` domains/IPs there (mine FP destinations from the `trace_event` table). Under SELinux Enforcing, the service (`init_t`) cannot read `user_home_t` files, so `setup.sh` relabels the overlay to `public_content_t` and installs `deploy/selinux/detonation_intel_read.te`. Confirm with `intel_loaded source=baseline+overlay`. Build needs **Go 1.22+** (build-time only; not installed by `setup.sh`).

## Code conventions

- `from __future__ import annotations` in every file
- structlog for logging (`from pkgsentry.logging_setup import get_logger`)
- SQLAlchemy ORM models in `store/models.py`
- Async pipeline (`pipeline.py`), sync analyzers
- Findings use the `Finding` dataclass from `adapter.py`
- No comments unless the why is non-obvious

## Pipeline threading model

`pipeline.py` uses `asyncio.to_thread()` to keep the event loop unblocked:
- `_extract_and_hash()` — extraction + SHA256/entropy/ssdeep/TLSH hashing (CPU-bound)
- `_run_analyzers()` — all static analyzers (CPU-bound)
- `_persist_and_finalize()` — scoring, DB writes, LLM triage, detonation-**enqueue**, mark_done
- `_bump_rulehits_deferred()` — uses its own `session_scope()` to avoid row-lock deadlocks

Never call sync DB operations or CPU-heavy code directly from `process_one()`. Wrap in `asyncio.to_thread()`.

Workers have a 15-min per-package timeout. Extraction allows up to 25K files per archive.

**Detonation runs in a separate async pool** (`detonation_worker.py`, started by `runtime._async_run` when detonation is enabled, sized by `DETONATION_WORKERS`). It drains `DetonationQueue`, re-fetches the archive by `(ecosystem, name, version)`, detonates off the event loop, then in a **fresh short `session_scope`** persists `Detonation`/`TraceEvent`, re-scores, and fires `discord.send_dynamic_alert` only on a flip to malicious (the inline path already alerts on static-malicious). Same session discipline as the scan pipeline — never hold a session across the detonation HTTP call.

## Diagrams

Architecture and flow diagrams live in `docs/diagrams/` (draw.io format):

| File | Content |
|------|---------|
| `architecture-overview.drawio` | High-level multi-ecosystem system architecture |
| `scan-pipeline.drawio` | process_one() detailed flowchart |
| `pypi-pipeline.drawio` | PyPI end-to-end pipeline |
| `crates-pipeline.drawio` | Crates.io end-to-end pipeline |
| `go-pipeline.drawio` | Go modules pipeline |
| `npm-pipeline.drawio` | npm modules pipeline |
| `detection-layers.drawio` | Detection layers, color-coded by ecosystem |
| `code-diff-flow.drawio` | Code-diff scanning flow |
| `queue-state-machine.drawio` | Queue states + backlog-weighted scheduling |
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
