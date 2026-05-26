# Scan pipeline reference

End-to-end walk-through of what happens to a single package from "discovered in a feed" to "persisted finding + optional alert." Operators use this to understand log lines and debug pipeline behavior. Contributors use it to know where to plug in new functionality.

Top-level call: `pkgsentry/pipeline.py:process_one(queue_id)`.

## Phase map

```
ingest          feed pollers, watchlists, cursors (per-ecosystem)
   ↓
queue           fair cross-ecosystem scheduling (ScanQueue table)
   ↓
worker claim    claim_next() — exclusive lock on one row
   ↓
fetch           adapter.fetch() — download archive(s), SHA256 verify
   ↓
extract+hash    safe_extract + per-file SHA256/entropy/ssdeep
   ↓
code-diff       compare per-file hashes to previous scan, skip unchanged
   ↓
analyze         _run_analyzers — all static layers + adapter.analyze_install
   ↓
score           detect/score.py — severity points, behavioral chains, verdict
   ↓
detonate?       PyPI only, gated on verdict + watchlist rank + first-version
   ↓
re-score        dynamic findings folded back in
   ↓
LLM triage?     cost-gated, only when verdict already malicious
   ↓
persist         Scan, Finding, FileHash, Detonation, TraceEvent
   ↓
alert?          Discord webhook on malicious verdict
   ↓
mark_done       queue row → status=done
```

Every phase is logged with a structured event; grep by the 8-char `sid` to see all logs for one scan.

## Phase 1 — Ingest

Per-ecosystem adapters register scheduled jobs via `EcosystemAdapter.schedule_jobs()`:

| Ecosystem | Jobs | Cadence |
|-----------|------|---------|
| PyPI | RSS feed poll, XML-RPC cursor poll, watchlist refresh | 60s / 120s / 1w |
| crates.io | RSS feed poll, watchlist refresh | 60s / 1w |
| Go modules | NDJSON index cursor poll, watchlist refresh | 60s / 1w |

Each poll enqueues newly-discovered packages into `ScanQueue` with priority `high` (watchlist hit) or `normal` (brand-new package). Already-seen non-watchlist versions are skipped.

`SCANNER_INGEST=0` disables all ingest jobs — workers continue to drain whatever's already pending.

Log events: `feeds_poll`, `cursor_pull`, `watchlist_refresh`, `crates_feeds_polled`.

## Phase 2 — Queue

`pkgsentry/queue.py:claim_next()` is the fair cross-ecosystem scheduler. For each priority tier in order (`high` → `normal` → `low`):

1. Find all ecosystems with at least one pending item at that tier.
2. Shuffle the set randomly.
3. Pick the oldest item in the randomly-chosen ecosystem.

This means a 50K-item Go backlog cannot starve PyPI scans. The same scheduler also handles stale-claim sweeping (rows stuck in `claimed` longer than 15 minutes are reset to `pending`).

## Phase 3 — Worker claim

`pkgsentry/workers.py` runs a configurable number of async workers (`--workers` flag, default 4 in standalone / 6 in production). Each worker loops:

1. Claim one queue row (UPDATE with returning, advisory lock).
2. Bind a `sid` (8-char trace ID) into structlog contextvars.
3. Call `pipeline.process_one(queue_id, claim_token)`.
4. On completion, queue row is marked `done` (success), `failed_*` (recoverable), or `failed_permanently` (max retries).

Log event: `claim`, `scan_start`.

## Phase 4 — Fetch

`adapter.fetch(name, version)` returns a `FetchResult` containing `archives: list[ArchivePath]` and `metadata: dict`. Each `ArchivePath` carries:

- `path` — local download location
- `kind` — `sdist` / `wheel` / `crate` / `gomod_zip`
- `sha256` — expected hash (from registry metadata)

The downloader verifies the file's SHA256 against the registry-supplied value. Mismatch raises `IntegrityError` and emits a `fetch.sha256_mismatch` critical finding (no further analysis on that archive). Missing release files raise `NoFilesError` and emit `fetch.no_release_files`.

Log events: `downloaded`, `fetch_failed`, `sha256_mismatch`.

## Phase 5 — Extract + hash

`pipeline.py:_extract_and_hash()` (in `asyncio.to_thread()`):

1. `safe_extract()` — tarfile/zipfile with symlink-skip, path-traversal normalization, 500 MB size cap, 25K file cap.
2. Walk the extracted tree; for each file, compute SHA256, Shannon entropy, and ssdeep fuzzy hash (if `ppdeep` installed).
3. Normalize paths (strip top-level archive dir for sdist / crate / gomod_zip) so per-file diffs work across archive layouts.

Log events: `extracting`, `extracted`.

## Phase 6 — Code-diff

`pipeline.py:_get_prev_scan_hashes()` fetches the previous version's file hashes from the `file_hash` table. `_find_changed_files()` computes the set of files that are new or whose SHA256 changed.

If a previous scan exists and **no files changed**, the analyzers are skipped entirely for that archive — log line `no_code_changes`. If files changed, the `changed_files` set is passed to every analyzer that supports it; analyzers that walk the whole tree filter to just those paths. Massive efficiency win on point-release bumps that only change `setup.py` or one module.

First-ever scan of a package: `changed_files=None`, every file analyzed.

Log event: `code_diff` (with `changed=N total=M`).

**Operator note:** to maximize the code-diff benefit on a fresh deployment, see [operations.md — First-run baseline playbook](operations.md#first-run-baseline-playbook-recommended). The pattern is: let `boot()` seed the watchlist with `SCANNER_INGEST=1`, then flip to `SCANNER_INGEST=0` to drain it without new uploads competing for worker time, then flip back to `SCANNER_INGEST=1` once the baseline is established. After that, every watchlisted package's next release benefits from code-diff.

## Phase 7 — Analyze

`pipeline.py:_run_analyzers()` calls every static layer in this order, accumulating findings:

| # | Module | Scope | Notes |
|---|--------|-------|-------|
| 1 | `analyze/imports.py` | PyPI only | AST walk for module-top-level `urlopen`/`exec`/subprocess at import time |
| 2 | `analyze/iocs.py` | all | URLs, IPs, .onion, base64 blobs (with benign-domain whitelist from intel pack) |
| 3 | `analyze/malware_patterns.py` | PyPI install-time only | Discord/Slack/Telegram webhook exfil, `.pth` injection, `.pyc` hiding, credential file access, deobfuscation→exec chains, env exfil, whitespace-hidden payloads, download commands |
| 4 | `analyze/entropy.py` | all | Shannon entropy ≥ 7.2 = obfuscation; entropy delta ≥ 1.5 between versions = suspicious |
| 5 | `analyze/binary.py` | all | ELF/PE/Mach-O magic bytes in files with non-binary extensions |
| 6 | `analyze/yara_scan.py` | all | YARA rules from intel pack (baseline + overlay UNION) |
| 7 | `analyze/opengrep_scan.py` | all | opengrep static analysis with intrafile taint tracking (shadow-mode default-on) |
| 8 | `adapter.analyze_install()` | per ecosystem | PyPI: setup.py AST chain detection. Crates: build.rs regex chains. Go: see go_directives.py |

Steps 1–7 are wrapped in `asyncio.to_thread()` to keep the event loop unblocked. Step 8 is async at the adapter boundary but internally sync.

Three more analyzers run **after** static layers complete (inside `_persist_and_finalize`):

- `analyze/metadata.py` — typosquatting, sdist/wheel mismatch, lure name detection, rapid-release flagging
- `analyze/version_diff.py` — clean-to-critical transitions, author changes, dependency spikes
- `analyze/threat_intel.py` — SHA256 / ssdeep / TLSH lookup against `ThreatIntelHash` table

Log events: `analyzing`, `analyzed`.

## Phase 8 — Score

`detect/score.py:score_and_verdict(findings, watchlist_rank=…)`:

1. **Filter shadow findings.** Findings with `rule_id` starting `opengrep.shadow_*` are excluded from scoring (persisted for offline comparison only).
2. **Sum severity points per category.** Per-category cap of 30 prevents one noisy layer (e.g. low-confidence IOC matches) from driving the verdict.
3. **Verdict thresholds:** `< 20` clean, `≥ 20` suspicious, `≥ 61` malicious.
4. **Auto-escalation:**
   - Any `critical`-severity finding → verdict = malicious.
   - Any behavioral-chain rule (listed in `behavioral_chains.toml`) → verdict = malicious.
   - Watchlist top-100 package with any high/critical finding → verdict = malicious, `alert_tag=watchlist_top100`.
   - Watchlist (any rank) clean + any medium/high/critical finding → verdict = suspicious.

Returns a `ScoreResult(score, verdict, alert_tag)`.

## Phase 9 — Detonate (optional, PyPI only)

`detonate/gate.py:should_detonate()` returns True only when ALL of:

- Ecosystem is `pypi`
- `DETONATION_SOCKET` is set (detonation service is configured)
- Verdict is `suspicious` or `malicious`, OR it's a brand-new (first-version) package, OR watchlist rank ≤ 100

The package archive is sent to the Go detonation service via UNIX socket. The Go service runs `pip install` inside a rootless-Docker container with Tetragon eBPF tracing, evaluates 8 behavioral rules, and returns a `DetonationResult`. See [detonation.md](detonation.md) for the sandbox architecture.

If `DETONATION_URL` is set instead, the call goes over TCP (multi-host deployments).

Failures here are non-fatal — the rest of the scan continues. Log event: `detonation_start`, `detonation_done`, `detonation_skipped`.

## Phase 10 — Re-score

If detonation returned dynamic findings (`dyn_*` rule IDs), they're appended to the findings list and `score_and_verdict()` runs again. Dynamic findings include the behavioral chains (`dyn_install_exfil`, `dyn_reverse_shell`, `dyn_proc_inject`) that auto-escalate to malicious.

Log event: `detonation_rescored`.

## Phase 11 — LLM triage (optional)

`pkgsentry/llm/triage.py:is_enabled()` and `should_triage()` gate this phase. Triage runs ONLY when:

- `OPENROUTER_API_KEY` is set
- Verdict from scoring is already `malicious` (rule-confirmed)
- Per-process budget cap (`PKGSENTRY_LLM_MAX_USD`) not exceeded
- Hourly call rate (`PKGSENTRY_LLM_MAX_CALLS_PER_HOUR`) not exceeded

The LLM receives the package source (truncated with a clear marker if too large), the rule findings, and the system prompt from the intel pack's `prompts/triage_system.txt`. It returns a structured triage:

| Field | Type | Use |
|-------|------|-----|
| `verdict` | `malicious` / `suspicious` / `benign` | Final verdict (overrides rule verdict when LLM disagrees) |
| `confidence` | 0.0–1.0 | LLM's self-rated confidence |
| `reasoning` | text | Sent to Discord alert |
| `iocs` | list | Extracted indicators |
| `agrees_with_rules` | bool | Tracked for rule-tuning |
| `cost_usd`, `latency_ms`, `prompt_tokens`, `completion_tokens` | per-call accounting |

Failures here are non-fatal. Log events: `llm_triage_start`, `llm_triage_done`, `llm_triage_skipped`.

## Phase 12 — Persist

All findings, scan metadata, file hashes, detonation row, and trace events are written in a single transaction (`_persist_and_finalize`). Rule-hit counters are bumped in a separate short transaction (`_bump_rulehits_deferred`) to avoid row-lock deadlocks on the hot-path `RuleHit` table.

Tables written:
- `scan` — one row per `process_one` call
- `finding` — one row per detection (includes shadow findings)
- `file_hash` — per-file SHA256/entropy/ssdeep for next scan's code-diff
- `detonation` — sandbox run metadata (PyPI only)
- `trace_event` — every filtered Tetragon event from detonation
- `rule_hit` — counter per `rule_id`

## Phase 13 — Alert

If the final verdict is `malicious` AND `DISCORD_WEBHOOK_URL` is set, a structured Discord embed is sent containing: package name, version, ecosystem, verdict, rule findings (defanged URLs), LLM reasoning summary, and a link to the package on the registry.

Log event: `discord_alert_sent`, `discord_alert_skipped`.

## Phase 14 — Mark done

`queue.py:mark_done()` updates the queue row to `status=done`, clearing the claim. The worker loops back to claim the next item.

Log event: `scan_done` (the most important line for grepping — has `verdict`, `score`, `n_findings`, `duration_s`, `alert_tag`).

## Threading model

`pipeline.py` deliberately offloads CPU-bound work to `asyncio.to_thread()` to keep the event loop responsive for the workers' I/O (registry fetches, detonation socket calls, LLM API):

- `_extract_and_hash()` — extraction + per-file hashing (CPU-bound)
- `_run_analyzers()` — all static analyzers (CPU-bound)
- `_persist_and_finalize()` — DB writes, detonation client call, LLM triage (mostly I/O but called from sync context)
- `_bump_rulehits_deferred()` — uses its own `session_scope()` to avoid holding row locks across the whole pipeline

Workers have a 15-minute hard timeout per package — anything slower is killed and the row goes back to `pending` for retry on next claim sweep.

## Diagrams

draw.io diagrams under [`docs/diagrams/`](diagrams/) visualize:

- `architecture-overview.drawio` — overall multi-ecosystem architecture
- `scan-pipeline.drawio` — `process_one()` flowchart (this doc in picture form)
- `pypi-pipeline.drawio` / `crates-pipeline.drawio` / `go-pipeline.drawio` — per-ecosystem ingest+scan
- `detection-layers.drawio` — color-coded layer-per-ecosystem matrix
- `code-diff-flow.drawio` — code-diff hash compare flow
- `queue-state-machine.drawio` — ScanQueue states + claim/sweep transitions
- `ecosystem-lifecycle.drawio` — seed → baseline → incremental lifecycle

## Tracing one scan end-to-end

Every log line during a single scan shares the same `sid` (8-char trace ID, set in `process_one`). To dump a full scan timeline:

```bash
docker logs pkgsentry 2>&1 | grep '"sid":"abc12345"'
```

Replace `abc12345` with the `sid` from any log line you're investigating (typically the `scan_done` line for a flagged package).

## Where to plug in new functionality

| You want to | Add it here |
|---|---|
| Detect a new attack pattern (rule) | YARA rule → `intel/baseline/yara/` or overlay. Opengrep rule → `intel/baseline/opengrep/<lang>/` or overlay. See [opengrep-rules.md](opengrep-rules.md). |
| Add a whole new analyzer module | New file under `pkgsentry/analyze/`, function signature `analyze_xxx(extracted_root, changed_files=None) -> list[Finding]`. Add one line to `_run_analyzers()` in `pipeline.py`. |
| Add a new ecosystem | Implement `EcosystemAdapter` in `pkgsentry/ecosystems/<name>/adapter.py`, register in `pkgsentry/ecosystems/__init__.py`. Adapter contract: `discover()`, `fetch()`, `analyze_install()`, `schedule_jobs()`, `boot()`. |
| Change how findings score | `detect/score.py` and `intel/baseline/scoring_weights.toml` + `thresholds.toml`. |
| Add a new alerting channel | New module under `pkgsentry/notify/`, called from the alert phase in `_persist_and_finalize`. |
| Add new detonation behavioral rules | Go side: `detonation/internal/rules/definitions.go`. Rule data: `intel/baseline/detonation/rules_data.toml`. |
