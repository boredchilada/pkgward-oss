# Changelog

All notable changes to pkgsentry are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] — 2026-05-27

### Added
- **Auto-watchlist gate on double-confirmed malicious verdicts.** When a scan
  finishes with both the rule verdict and the LLM verdict at `malicious`, the
  `(ecosystem, name)` is inserted into the `Watchlist` at sentinel rank
  `9_999_999` so every future release of that name is scanned at high
  priority — closes the gap where the brand-new ingest gate fires *once* per
  name and a follow-up malicious release would otherwise slip past
  (e.g. `forge-jsxy 1.0.107 → 1.0.120`). Idempotent (re-confirms refresh
  `refreshed_at`), TTL-managed (default 180d via `WATCHLIST_AUTO_TTL_DAYS`,
  hourly janitor), per-ecosystem hard cap (`WATCHLIST_AUTO_MAX_PER_ECO` =
  5000), in-process add-rate ceiling (`WATCHLIST_AUTO_MAX_ADDS_PER_HOUR` =
  100). FP exit ramps: `WATCHLIST_AUTO_BLOCKLIST="eco:name,…"` env, plus
  `pkgsentry watchlist auto {list,remove,purge,backfill}` CLI. The four
  ecosystem `refresh_watchlist` paths now skip auto-rank rows so popularity
  refresh can't evict them. Disabled with `WATCHLIST_AUTO_MALICIOUS=0`. See
  `docs/operations.md` → "Auto-watchlist (confirmed-malicious gate)" and
  `docs/internal/detection-hardening-2026-05.md`.
- **Finding carry-forward for confirmed-malicious re-publishes.** When a
  package on the auto-watchlist publishes a new version that mostly re-uses
  files from the prior one (a version bump + a handful of changed files, as
  the `forge-jsxy 1.0.107 → 1.0.120` series did — 29 byte-identical RAT
  re-publishes), our `changed_files` optimization causes analyzers to skip
  the unchanged files → the new scan reports only the deltas (e.g. 3 of 11
  findings), thinning the LLM's evidence basis and leaving the verdict to
  ride entirely on the install-script chain rule. For *auto-watchlisted*
  names only, the pipeline now queries the most-recent prior scan within
  `PKGSENTRY_FINDING_REUSE_DAYS` (default 7) and **pulls forward** every
  prior finding whose file's `(path, sha256)` is unchanged. Scoring + the
  LLM see the full evidence; analyzers still don't re-run on unchanged
  files (no extra CPU). Scoped to known-bad names so a yara/opengrep rule
  update doesn't risk stale-cache false-negatives on clean packages.
- **YARA `forge_jsxy_rat_family`** in private intel — relay-protocol
  fingerprint (`RELAY_HF_CREDENTIALS_B64`, `fsShellExec`,
  `fsRemoteControlInput`, `fsWindowsScreenshotCapture`, `RELAY_DISCORD`,
  `.forge-jsxy/runtime`, `FORGE_JS_SKIP_INSTALL_AGENT`). Requires ≥3
  signatures to fire critical. Catches re-publishes of this RAT family
  under any package name as long as the operator's protocol is unchanged.
- **`tools/seed_forge_jsxy_hashes.py`** — one-shot script that fetches every
  published version of `forge-jsxy` from npm, computes SHA-256 / ssdeep /
  TLSH of the tarball and every RAT-bearing file inside, and appends entries
  to `intel/private/hashes/known_malicious.jsonl`. Closes the "operator
  copies these files into a renamed package" case at the exact-match tier
  and the "lightly reformatted clone" case at the fuzzy tiers.
- **Detection regression suite** — a labeled corpus of known-bad / known-good sample packages
  (`tests/corpus/`) run through the real analyze→score path, so a change that starts missing
  malware (false negative) or over-flagging clean packages (false-positive creep) fails the
  build. Verdict label is the primary gate; optional per-sample `expect_rules`/`forbid_rules`
  pin which rule should/shouldn't fire. A shared `pipeline.run_static_analyzers` seam keeps the
  harness from drifting from production. `tests/test_rule_coverage.py` enumerates every scored
  rule_id and asserts each is either sampled or explicitly waived, so new rules can't ship
  untested and renamed/removed rule_ids are caught. Operators can layer private samples via
  `PKGSENTRY_CORPUS_PATH`. See `docs/regression-testing.md`.
- **opengrep `--test` fixtures for Python/Rust/Go** — the python/rust/go rule directories now
  ship `--test` fixtures (previously JavaScript-only), so all four language rule sets self-test.
- **Frozen malicious-sample vault** — preserves the original archive of anything flagged
  `malicious` (inert, password-protected) before the registry yanks it, as a permanent
  regression anchor + forensic reference. Auto-captured by the pipeline when
  `PKGSENTRY_VAULT_PATH` is set (a no-op otherwise) and backfillable with `tools/vault_import.py`.
  Vault entries are only ever statically analyzed, never detonated.
- **Horizontal scan scaling.** Additional worker hosts can drain the same DB-coordinated scan
  queue (claim-token compare-and-set, no double-work). Run a second host with `SCANNER_INGEST=0`
  (only the primary polls feeds/cursors) and, if it has no local detonation service,
  `DETONATION_ENABLED=1` so its scans still enqueue detonation jobs for a draining host. See
  `docs/operations.md` → "Scaling horizontally".
- **`tools/stats.py` live snapshot.** One-shot view of scan-queue backlog + churn (ingest vs
  processed per ecosystem), the async detonation queue, verdicts, and detection-quality signals
  (LLM-triage source coverage per ecosystem, detonation-driven verdict flips). Baked into the
  image: `docker exec pkgsentry python tools/stats.py`.
- **Operations guide: data retention + FP investigation.** `docs/operations.md` gains a section
  documenting what the scanner persists (`scan`/`finding`/`file_hash`/`detonation`/`trace_event`
  rows with full evidence text), how the malicious-sample vault works, SQL queries for after-the-fact
  FP investigation, and the workflow for turning a confirmed FP into a regression-corpus sample.

### Changed
- **Detonation decoupled from the scan pipeline** — detonation no longer runs inline inside
  each scan worker (which blocked the whole pipeline on a small concurrency cap). It now runs
  as an asynchronous, prioritized job queue (`DetonationQueue`) drained by a separate worker
  pool: static analysis + scoring + alerting complete immediately, so the scan queue keeps up
  with high-volume ecosystems, and detonation follows best-effort — re-scoring and firing a
  delayed alert if a verdict flips to malicious. Statically-flagged and watchlist packages are
  detonated first; brand-new statically-clean packages are best-effort with a bounded backlog.
  The queue is shared-DB-coordinated, so a second detonation host can be added without redesign.
- **Detonation throughput** — the sandbox concurrency cap is now tunable via the
  `MAX_CONCURRENT` env var (`/etc/default/detonation-svc`) without editing the systemd unit,
  and the npm install step drops `--no-audit`/`--no-fund` registry roundtrips.
- **Intel-pack wiring visibility (anti-silent-failure).** The detonation service's
  `intel_loaded` log now reports every per-ecosystem noise-list size (file/exec/net for all
  four ecosystems) instead of just two, and a Go guardrail test asserts every populated
  noise list in the baseline is actually consumed by the filter — so a list can't ship
  unwired (the gomod gap above). The Python `intel_loaded` log surfaces the detonation
  noise/rules list names it loads (these are consumed by the Go service, not Python).
- **Backlog-weighted ecosystem scheduling.** `claim_next` used to pick a uniformly random
  ecosystem at each priority tier, so each ecosystem with pending work got ~1/N of claims
  *regardless* of how much was queued. With npm holding ~79% of the brand-new backlog and
  ~25% of claims, that was the real throttle (not worker count). The scheduler now does
  **backlog-weighted sampling with a reserved floor**: `SCHED_RESERVED_FRACTION` of attention
  (default 0.4) is split equally among non-empty ecosystems so none starves, the remainder is
  allocated proportionally to backlog size, and any single ecosystem is clamped to
  `SCHED_MAX_ECO_SHARE` (default 0.7) so a surge can't fully dominate. Priority tiers
  (high→normal→low) are unchanged. Surges and drainage adapt automatically — no thresholds or
  hysteresis. Setting `SCHED_RESERVED_FRACTION=1.0` restores the previous uniform behavior.

### Fixed
- **gomod detonations had no file/exec noise filtering** — the detonation noise filter was
  wired for pypi/npm/crates (file + exec + network) but gomod only had a network allowlist;
  its `NoiseFilters` struct fields didn't exist, so the Go toolchain's own build activity
  wasn't filtered and operators couldn't add gomod file/exec noise via the private overlay.
  Added `gomod_file_noise`/`gomod_exec_noise` (Go build/module cache, toolchain, unzip/tar)
  and wired them into the filter. Credential reads during a gomod build still surface.
- **Entropy false positive on certificate/keystore files** — `entropy.obfuscated_payload`
  fired on `.pfx`/`.p12`/`.cer`/`.der`/`.crt`/`.jks` files, which are encrypted by spec and
  always near-max entropy (e.g. a test-proxy dev cert in a legitimate package). These binary
  cert containers are now skipped. Text PEM (`.pem`/`.key`) is deliberately still scanned
  (base64 stays under threshold, so a payload disguised as PEM is still caught).
- **IOC false positives from documentation files** — `iocs.url_suspicious`/`iocs.ipv4`
  extracted doc and attribution links from README/NOTICE/LICENSE/CHANGELOG-style files,
  stacking low-severity hits up to the per-category cap (a large monorepo's docs alone could
  push a clean package toward "suspicious"). URL/IP extraction now skips those files — and the
  set is broadened to `SECURITY`/`SUPPORT`/`CONTRIBUTING`/`CODE_OF_CONDUCT`/`GOVERNANCE`/
  `MAINTAINERS` plus *any* `.md`/`.rst` file (prose). Placeholder URLs (`http://host:port`,
  RFC-2606 `example.com/.org/.net`) and textbook example IPs (`1.2.3.4`) are dropped in code
  too. Onion addresses and base64 blobs are still flagged anywhere.
- **Detonation trace events were not attributed to the sandbox container** — a fleet-wide
  false-positive source. The Tetragon collector filtered events by PID namespace
  (`ns.pid_for_children`), but the host's Tetragon export carries no `ns` field, so the filter
  matched everything: a detonation's trace was a blend of its own sandbox plus every concurrent
  sandbox and the scanner's own opengrep runs. A package could be flagged `dyn_credential_read`
  for a *different* container's `/root/.npmrc` read (observed: `azure-sdk-for-go` flipped to
  malicious for a concurrent npm sandbox's credential read). Events are now attributed by the
  Tetragon `docker` container id: each sandbox phase captures its container id via `--cidfile`,
  and the collector keeps only events from those ids (falling back to time-window-only, with a
  warning, if id capture fails). Guarded by a cross-container regression test.
- **False positive on native-binary wrapper packages** — `binary.hidden_executable` treated a
  *missing* file extension as a disguise, so packages shipping prebuilt platform binaries named
  `tool-<os>-<arch>` (the standard npm/esbuild convention) were flagged high and could score
  malicious. A missing extension now scores `binary.compiled_artifact` (low); "disguised" means
  a lying extension only (e.g. an ELF named `.py`/`.json`), which still scores high. Guarded by
  new regression-corpus samples (clean native wrapper + disguised-ELF).
- **LLM triage received no source for file-level findings.** gomod (`init()`/CGO chains flag a
  file with no specific line) and npm (which had no ecosystem config at all — it fell back to
  Python globs) often sent the model "(no source extracted)", capping confidence. Triage now
  includes the whole flagged file when a finding has a file but no line, ships a proper npm
  config (package.json priority + JS/TS extensions), and logs `llm_triage_no_source` when source
  files exist but none were gathered. Guarded by `tests/test_llm_triage_source.py`.
- **Threat-intel TLSH match tier was silently inactive.** The known-malicious fingerprint layer
  advertises three tiers (SHA256 exact / ssdeep ≥70% / TLSH distance ≤120) but TLSH never ran:
  the image had no C++ compiler so `py-tlsh` failed to build (and the failure was swallowed),
  and the scan path didn't compute a per-file TLSH to compare. Both fixed — the image now builds
  `py-tlsh` (g++, fail-loud), and `_compute_file_hashes` emits TLSH into the threat-intel batch —
  so all three tiers now run on every scanned file (incl. the existing fingerprint entries whose
  TLSH values were never being compared).
- **IOC layer was blind to non-Python source.** The URL / IPv4 / `.onion` / base64-blob scanner
  only inspected a fixed set of text/manifest extensions, so for npm, Crates, and Go modules it
  never read the actual package source (`.js`/`.ts`/`.go`/`.rs`/`.sh`/…) — only manifests and
  docs. Those source extensions are now scanned, closing the gap across all four ecosystems.
- **Silent detection-tier loss is now visible.** The `yara`, `ppdeep`, and `tlsh` native
  extensions each disabled their detection tier with no log if they failed to import (the same
  failure mode as the TLSH incident). Probing is centralized in `pkgsentry/util/capabilities.py`,
  the scanner emits one `detection_capabilities` line at startup (WARNING if any tier is missing),
  and the image build now asserts `import tlsh, yara, ppdeep` so a broken extension fails the
  build instead of shipping a dark tier.
- **Async detonation could drop a verdict-flip alert and orphan a Detonation row.** The worker
  wrapped the whole job — including the non-cancellable persist thread — in a wall-clock timeout,
  so a timeout firing mid-persist could commit the detonation result while discarding the
  malicious-flip Discord alert and requeueing the job (duplicate detonation). The timeout now
  covers only the network phase (re-fetch + detonate); persistence and alerting run outside it.
- **Yanked/deleted packages were re-fetched up to 3× by the detonation worker.** A permanent
  `NoFilesError` (404/yanked) was treated as a transient failure and requeued; it now fast-fails
  to `failed` on the first attempt.
- **Threat-intel re-seeding now backfills instead of skipping.** `seed_intel` skipped any
  fingerprint already present by SHA256, so an entry seeded before a hash field existed (e.g.
  TLSH, before py-tlsh built) never gained it on re-seed. It now upserts — backfilling missing
  `tlsh`/`ssdeep`/etc. without clobbering present values — and reports `added`/`updated` counts.
- **Threat-intel fingerprints now honor `file_pattern` and `label`.** A fingerprint's
  `file_pattern` (e.g. `*.js`) now scopes the fuzzy (ssdeep/TLSH) tiers to the intended file
  type, reducing false positives from a near-distance hit on an unrelated file; exact SHA256
  matches are unaffected. The `label` field now maps to the emitted severity
  (`malicious`→critical, `suspicious`→high, `pua`→medium) instead of always emitting critical.
- **Detonation queue stays bounded on scan-only hosts.** The queue-maintenance jobs
  (stale-claim sweep + clean-backlog expiry) were gated on a local detonation socket, so a
  scan-only host (`DETONATION_ENABLED=1`, no socket) enqueued jobs but never bounded the shared
  backlog if no draining host was up. They now run wherever detonation enqueue is enabled.
- **Detonation concurrency default aligned.** The service `--max-concurrent` default is now `6`
  (was `2`), matching the scanner's `DETONATION_WORKERS` default; `MAX_CONCURRENT` is documented
  in the systemd unit. (`setup.sh` already wrote `6`, so existing deploys were unaffected.)
- **LLM triage aborted on large repos, leaving a stale verdict.** Triage's source-gathering
  walked the extracted tree with `Path.rglob`, whose directory scan raises `FileNotFoundError`
  if a path disappears mid-walk — which happens on giant gomod monorepos, where the multi-minute
  walk races the per-scan temp-dir teardown. One vanished path aborted the *whole* triage
  (`llm_triage_skipped`), so the LLM never ran and a statically-flagged false `malicious` verdict
  stood (the LLM otherwise downgrades these to `benign`). More importantly, a genuinely malicious
  large package tripping the same crash would skip its triage too. The walk is now crash-tolerant
  (`os.walk` with `onerror`, skips vanished/unreadable dirs, doesn't follow symlinks) and bounded
  (the source-stats recon caps at 20K files instead of crawling a monorepo twice). Guarded by
  dangling-symlink regression tests in `tests/test_llm_triage_source.py`.
- **Huge native-binary packages stalled a worker for minutes.** Per-file hashing read the
  whole file into memory and computed entropy (a pure-Python byte histogram) + ssdeep + TLSH
  with no size cap, so a prebuilt platform binary (e.g. `@octopus-ai/*`, esbuild/turbo/swc —
  ~50–200 MB, often ~8 platform variants per release) took 5–14 minutes *each*, dominating npm
  worker-time and pressuring memory. SHA-256 is now **streamed** (bounded memory) and the
  expensive metrics (entropy/ssdeep/TLSH) are **skipped above a size cap**
  (`PKGSENTRY_HASH_FULL_MAX_MB`, default 20) — those metrics are near-useless on big binaries
  (always near-max entropy, rarely match a fuzzy fingerprint) and `binary.compiled_artifact`
  still flags them; exact SHA-256 threat-intel coverage is unchanged. Measured ~660× faster on
  a 60 MB file (34s → 0.05s). Same cap applied in `analyze_entropy`.
- **Real malware could go un-alerted when LLM triage errored.** The inline Discord alert
  fired only on a clean `llm_verdict == "malicious"`, so a rule-malicious package whose triage
  returned invalid JSON (`error`), was skipped, or ran without an LLM key produced **no alert**
  — silently. Triage now **retries** the call+parse (`PKGSENTRY_LLM_MAX_RETRIES`, default 2) and
  caps the response (`PKGSENTRY_LLM_MAX_RESPONSE_TOKENS`, default 1500) so a truncated reply
  (`finish_reason=length`, the usual bad-JSON cause) doesn't error; failed attempts log
  `llm_triage_retry`/`llm_triage_error` with the raw model output. And the alert path now **fails
  open**: a rule-`malicious` verdict alerts unless the LLM *explicitly* cleared it
  (`benign`/`suspicious`); if the LLM couldn't adjudicate (disabled/error/crash) the alert still
  fires, tagged `llm_unverified` (grey embed, "LLM could not verify"). LLM-less deployments now
  alert on rule-malicious instead of staying silent.
- **Go pseudo-versions of popular modules were scanned despite `GOMOD_SCAN_PSEUDO=0`.** The
  pseudo-version detector only matched the `v0.0.0-…` form; Go's other two forms
  (`vX.Y.Z-0.<ts>-<hash>`, `vX.Y.Z-pre.0.<ts>-<hash>`, used by any module with a prior tag) slipped
  past the skip gate. So every new commit of a watchlisted popular repo (dolt, aistore, zarf, …)
  was downloaded and scanned as a full monorepo snapshot — a large, low-signal, FP-heavy surface
  consuming the majority of worker time. The detector now matches all three forms (the
  `<14-digit-timestamp>-<12-char-hash>` signature), and the watchlist seed paths
  (`seed_watchlist_queue`/`seed_missing_watchlist`) drop pseudo-versions resolved from `@latest`
  unless `GOMOD_SCAN_PSEUDO=1`. Frees substantial worker capacity for higher-volume ecosystems.

## [0.5.0] — 2026-05-26

### Added
- **npm (JavaScript) ecosystem** — full parity with the other ecosystems. Discovery via the
  npm registry changes feed (top-package watchlist + every brand-new package + focus list);
  `.tgz` download with Subresource-Integrity (`sha512`) / `shasum` verification;
  `package.json` lifecycle-script analysis (`preinstall`/`install`/`postinstall`/`prepare`)
  with a known-benign build-tool allowlist and following of referenced install scripts;
  shadow-mode opengrep JavaScript/TypeScript rules; and detonation (`npm install` with
  scripts enabled, traced in the sandbox). The watchlist is assembled from registry-search
  popularity + `awesome-nodejs` + a curated keystone list.
- **Focus packages** — operators can supply their own dependencies as focus packages,
  scanned at high priority. Easiest: one combined file with `[pypi]`/`[crates]`/`[gomod]`/`[npm]`
  sections + `pkgsentry run -f <file>` (focused/exclusive mode — scans ONLY focus packages,
  authoritatively synced from the file). Also `pkgsentry focus load <file>` (combined, no
  `-e`) / `... -e <eco>` (flat, additive) / `focus list` / `focus clear`. Every new release
  of a focus package is enqueued automatically; pinned `name==version` scanned once at load.
  Toggle `PKGSENTRY_FOCUS_EXCLUSIVE` (`run -f` sets it). New `FocusList` table (auto-created),
  `pkgsentry/focus.py`, and per-ecosystem `ingest/focus.py` pollers. Lenient entry syntax —
  a package name optionally followed by a version in any common form (`name`, `name==1.2.3`,
  `name>=1.2.3`, `name~=1.2`, `name^1.0`, gomod `name v1.2.3`), so requirements.txt / go.mod /
  Cargo lines can be pasted directly. The name is monitored (every new release scanned); any
  version present is scanned once (a range's lower bound).
- **Per-ecosystem detonation network allowlist** — known registry/CDN destinations
  (`{eco}_net_allow` in the detonation noise baseline; hostnames resolved to IPs at analysis
  time, plus literal IPs) are dropped from the trace before the network-exfil rules run, so
  normal dependency fetches don't false-positive as exfil. Tunable via the intel pack.
- **opengrep JavaScript rules + rule-test harness** — baseline JS/TS taint rules
  (`net→exec`, `base64-decode→exec`, `env→network`) and `tools/test_opengrep_rules.sh`, which
  runs opengrep's `--test` over the co-located rule fixtures.

### Changed
- **License: Apache-2.0 → AGPL-3.0-or-later.**
- Detonation can load a private intel overlay (`PKGSENTRY_INTEL_PATH`) to extend its noise
  filters and network allowlists without rebuilding the binary.

### Fixed
- **crates ingest resolves `latest` to a concrete version before enqueue** — a brand-new
  crate that also appears in the updates feed is no longer scanned twice (the duplicate
  produced a spurious zero-finding code-diff re-scan).
- npm registry polling backs off on HTTP 429 and bounds request concurrency.

## [0.4.0] — 2026-05-26

### Added
- **Detonation for all ecosystems** — dynamic analysis now runs for PyPI, Crates, and Go
  modules (previously PyPI-only); worker max-concurrent raised to 6.
- **Dynamic behavioral rules wired up** — events are tagged by install/import phase, enabling
  network-exfil detection per phase, ptrace / `process_vm_writev` injection,
  `/proc/<pid>/environ` credential-and-env harvesting, persistence writes via the
  `security_file_permission` LSM hook, and fileless execution (`memfd_create` /
  `execveat(AT_EMPTY_PATH)`). All non-base Tetragon hooks are namespace-filtered to the
  sandbox so host activity is never misattributed.

### Fixed
- **Detonation emitted zero trace events since initial deployment** — resolved a cascade of
  faults: the Tetragon TracingPolicy was never loaded (and could not mix kprobes+tracepoints);
  the scanner held a stale detonation-socket inode after service restarts; the Tetragon log
  was unreadable by the service and lost its permissions on every rotation; and the
  `trace_event` table was missing the `pid`/`binary` columns. Collector namespace filtering
  (`targetNS=0`) corrected.
- **Rootless-Docker sandbox `docker run` failure** — removed the `--cpus` flag (no CPU CFS
  controller under rootless Docker → "NanoCPUs can not be set").
- **`dyn_proc_inject` never matched ptrace** — collector emitted `sys_ptrace` while the rule
  checked `ptrace`; normalized.
- **Two false-positive detection rules** — `env_bulk_exfil` no longer fires on test
  `conftest.py`; `.pth` companion-module discovery fixed for LLM triage.

### Changed
- Tetragon daemon tuning for the detonation host (ring-buffer sizing, log rotation +
  world-readable export perms, `127.0.0.1:2112` metrics endpoint) and systemd memory limits.

### Deferred
- `dyn_install_exfil` retained but excluded from the active rule set — it fires on any
  install-phase network connect, but sdists legitimately fetch build deps from registries,
  so it needs a registry-aware design (offline install or destination allowlist).

## [0.3.0] — 2026-05-25

### Added
- **Multi-ecosystem coverage** — Crates.io and Go modules scan alongside PyPI.
  Same analysis pipeline (extract, hash, code-diff, static analyzers, YARA, LLM triage, scoring)
  for all three ecosystems; detonation remains PyPI-only.
- **Detonation sandbox** — Go service (`detonation/`) runs package installs inside Docker
  containers (runc + Tetragon eBPF). Eight behavioral rules: credential harvest, reverse shell,
  process injection, DNS exfil, exfiltration, suspicious write, env harvest, network beacon.
- **Intel-pack architecture** — detection content moved from hard-coded Python to a data-driven
  overlay system. Public baseline at `pkgsentry/intel/baseline/`; private operator overlays load
  via `PKGSENTRY_INTEL_PATH`. Fields are merged at startup (UNION for additive content, REPLACE for
  scalars). Startup emits a structured `intel_loaded` log line confirming which pack is active.
- **Go modules ecosystem** — watchlist of ~10K modules (GitHub top stars + awesome-go +
  critical infrastructure). Brand-new module detection via `Package` table lookup. Pseudo-version
  filtering (`GOMOD_SCAN_PSEUDO`). Go-specific rules: `go:generate` exec detection, `init()` body
  analysis (exec/net chains), CGO, replace directives, unsafe imports, encoded payloads.
- **Crates.io ecosystem** — watchlist of 10K crates by download count. New-crate detection via
  `crates.xml` RSS feed. `build.rs` static analysis. Watchlist gap-healing on boot.
- **Lure name detection** — multi-category keyword scoring catches social-engineering package
  names (crypto × credential combinations, AI × security-theater, etc.) while ignoring single
  legitimate categories.
- **Threat-intel hash matching** — three-tier lookup: exact SHA256, ssdeep fuzzy (≥70%), TLSH
  distance (≤120). TrapDoor campaign fingerprints seeded.
- **Code-diff scanning** — per-file SHA256 hashes stored across scans; only changed/new files are
  analyzed on version updates.
- **Fair cross-ecosystem queue scheduling** — `claim_next()` rotates ecosystems within each
  priority tier so a large crates backlog cannot starve PyPI scans.
- **Env-var migration** — all vars renamed `PKGSENTRY_*` with backward-compatibility fallback
  through `PKGWATCH_*` and `PYPI_SCANNER_*`.
- **User-Agent helper** — `pkgsentry/util/user_agent.py` driven by `PKGSENTRY_CONTACT_EMAIL`;
  applied to all outbound HTTP clients (PyPI, crates.io, Go proxy).
- **Pre-commit hooks** — gitleaks secret scanning + `tools/precommit_no_private_intel.py`
  blocks accidental commit of `intel/private/` overlay files.
- **Trace event persistence** — raw Tetragon trace events persisted to `trace_event` table,
  enabling historical behavioral analysis and forensic queries.
- **Standalone Docker Compose** — `docker-compose.standalone.yml` bundles PostgreSQL for
  self-contained deployments. Three commands from clone to scanning live traffic.
- **Rootless Docker isolation** — detonation sandbox uses rootless Docker (separate daemon
  and storage). Cannot see or affect system Docker containers or volumes.
- `LICENSE` (Apache 2.0), `NOTICE` (Neo23x0/DRL 1.1 attribution), `CONTRIBUTING.md` (DCO),
  `SECURITY.md` (responsible-disclosure policy).

### Changed
- Project renamed from `pkgwatch` / `pypi_scanner` to **pkgsentry**.
- All Python imports updated to `from pkgsentry.…`.
- README fully rewritten; describes both threat models (supply-chain watchlist + brand-new lures)
  and all three ecosystems.

### Fixed
- LLM triage: redundant `or` pattern and lowercase env-var prefix causing silent model fallback.
- PyPI brand-new package detection was silently broken (changelog serial comparison off-by-one).
- `init_exec_chain` false positive on `modernc.org/cc/v5` (rules now parse init() body, not
  just coexistence of imports).

## [0.1.0] — 2026-01-15

### Added
- Initial PyPI-only scanner: watchlist (top 10K packages) + all new package uploads.
- Static analysis pipeline: import analysis, IOC extraction, metadata checks, setup.py AST,
  YARA scanning, scoring.
- Discord alerting for malicious verdicts.
- LLM triage via OpenRouter (cost-gated, rate-limited).

[Unreleased]: https://github.com/boredchilada/pkgsentry-oss/compare/v0.3.0...HEAD
[0.5.1]: https://github.com/boredchilada/pkgsentry-oss/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/boredchilada/pkgsentry-oss/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/boredchilada/pkgsentry-oss/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/boredchilada/pkgsentry-oss/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/boredchilada/pkgsentry-oss/releases/tag/v0.1.0
