# Changelog

All notable changes to pkgward are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.3] — Unreleased

### Changed
- **Outward-facing name → pkgward.** Discord alert footers and the outbound HTTP
  User-Agent now read `pkgward` (project URL `github.com/boredchilada/pkgward-oss`).
  Internal module, env-var prefixes, container and database names are unchanged.
- **Triage system prompt: escalation discipline.** Promoted the `tools/llm_eval` candidate
  prompt over the baseline after the A/B on the labeled set: explicit escalation rules +
  common-FP discriminators. With `gemini-3.1-flash-lite` it suppresses the low-confidence
  "malicious" escalations behind the 2026-06-07 FP surge (0–1/9 vs deepseek's 3/9) without
  losing a malware conviction.

### Added
- **Staged-loader detection: `imports.marshalled_bytecode_loader` + `obfuscation.remote_fetch_eval`
  (both critical, behavioral).** Two live misses shipped only a small loader stub with the real
  payload staged elsewhere — at scan time the dangerous code isn't in the package, so the old
  rules scored the loader soft and LLM triage cleared both. A module that `marshal.load()`s and
  `exec()`s at import is a compiled-payload dropper (the mps-xtrap shape; alias-aware;
  marshal-feeds-exec is ~zero in legit packages), and a base64-hidden fetch URL feeding a nearby
  `eval` is a remote-payload loader (the trojanized `buffer`-clone shape; proximity-gated like
  `charcode_eval`, with FP guards for marshal-without-exec and fetch/eval far apart). Both are
  anchored in the regression corpus (`pypi/marshalled_loader_dropper`,
  `npm/remote_fetch_eval_loader`) and convict on rules alone — staged loaders are exactly the
  class where model triage can't be trusted. `analyze/imports.py`, `analyze/obfuscation.py`.
- **`tools/llm_eval` two-axis triage prompt candidate.** `triage_system.risk_axis.txt` makes the
  call structural instead of holistic: the model rates `behavior_risk` and `malicious_intent`
  independently, and the verdict is hard-bound — "malicious" only with a cited hostile mechanism;
  dangerous-but-unproven (dual-use, pentest tooling, minified bundles) routes to suspicious /
  needs-review. Eval-harness candidate only, not the shipped default prompt.
- **Version-anomaly absolute-delta size trigger (crates+pypi).** `detect_anomaly` now
  fires `size_jump` when the absolute byte delta between a version and its predecessor
  clears `PKGWARD_ANOMALY_SIZE_ABS_BYTES` (default 50 KB) **and** the baseline clears
  `PKGWARD_ANOMALY_ABS_MIN_BASE_BYTES` (default 256 KB), OR'd with the existing ratio
  gate. A small malicious payload hidden behind a large benign decoy keeps the size
  *ratio* near 1.0× (the nhmpy class — a 17.7 MB package with a small bump), so the
  3×-ratio gate never fires while the absolute delta reveals the added code. The
  base-size floor is **data-driven** (vault replay of 542 frozen real catches): of
  pypi+crates malware large enough to carry a ≥50 KB delta, a 256 KB floor covers 91%
  — and 100% of the ≥1 MB decoy class — while excluding the small-package firehose that
  would otherwise flood the queue with benign minor-release scans. Same flag → unchanged
  downstream priority/adjudication; `=0` on either knob reverts that half of the gate.
- **Maintainer-pivot sweep — the THIRD sibling defense (force-scan only).** When a
  package is double-confirmed malicious, three orthogonal "the wave is spreading"
  defenses now fire: same NAME → `watchlist_auto`, same ORG/SCOPE → `scope_watchlist`,
  and **same MAINTAINER → `maintainer_pivot`** (new). The 2026-06-07 compromised-PyPI-
  account incident pushed malware across ~19 of one account's unrelated scientific-
  Python packages; we caught every artifact we ingested but missed 10 siblings whose
  payload never tripped the size-anomaly ingest gate (which force-scans only ~0.5% of
  version-updates). The pivot resolves the convicted package's maintainer, enumerates
  that account's catalog, and **force-scans it at high priority** — each sibling earns
  its own verdict through the full detection+LLM+conf-floor pipeline. Crucially it
  **never watchlists and never marks known-bad**: the worst case of a false-positive
  trigger is wasted scans on an innocent author's catalog (pure throughput cost), not
  watchlist pollution or a self-reinforcing FP cascade. Trigger gate is far stricter
  than the alert bar — it requires EITHER ≥ 2 of the maintainer's packages double-
  confirmed within the correlation window (the campaign signal), OR a single high-
  fidelity conviction (exact threat-intel hash match, a behavioral-chain rule, or LLM
  confidence ≥ 0.95) — atop the existing `_auto_watchlist_qualifies` primary-evidence +
  conf-floor bar. **Shadow-first** (`PKGWARD_MAINTAINER_PIVOT_SHADOW=1`, default): it
  logs the would-sweep set and enqueues nothing until a week of shadow data confirms
  triggers are real campaigns, mirroring the `OPENGREP_SHADOW` rollout. SSRF-guarded +
  bounded catalog fetch (pypi profile scrape / npm packument+search), per-maintainer
  TTL dedup (a 27-package wave sweeps ~once), catalog-size cap, and the shared
  `WATCHLIST_AUTO_BLOCKLIST` FP exit ramp. crates/gomod are out of scope (gated, never
  crash). pypi + npm only. `pkgward maintainer {sweep,list}`;
  `PKGWARD_MAINTAINER_PIVOT*`. `pkgward/maintainer_pivot.py`.
- **Bounded maintainer watch (closes the pivot's temporal hole).** The one-shot
  pivot only catches siblings *already* poisoned at sweep time; an account that rolls
  its payload out over several releases would slip back into the "established-package
  update → skipped at ingest" blind spot. So an active sweep now also registers the
  caught maintainer's **clean** siblings (catalog minus the trigger minus any already-
  malicious sibling) in a `MaintainerWatch` table, and the pypi/npm ingest gates
  force-scan their next releases at high priority. **Force-scan only — never a known-
  bad mark** (scored with `watchlist_rank=None`, so it can't manufacture an FP).
  Bounded two ways so it can't grow without limit: a release count
  (`PKGWARD_MAINTAINER_WATCH_RELEASES`, default 3 — derived from scan history, no
  mutable counter) and a safety TTL (`PKGWARD_MAINTAINER_WATCH_TTL_DAYS`, default
  180) for a package that never releases again. Shadow-gated with the pivot; hourly
  janitor prunes exhausted/expired/over-cap entries. `pkgward maintainer watch
  {list,remove}` (FP exit ramp). `pkgward/maintainer_watch.py`.
- **Conviction-precision harness.** `tools/conviction_precision.py` measures the FP
  rate of every rule allowed to drive the maintainer-pivot trigger, against both the
  regression corpus (ground-truth labels) and recent prod scans (read-only DB replay,
  LLM verdict as adjudicator proxy). Outputs per-rule precision and a suggested
  `PKGWARD_MAINTAINER_PIVOT_TRIGGER_DENY` set so a flaky rule can be kept from ever
  driving a sweep — the empirical input for choosing the trigger threshold.
- **LLM malicious-confidence floor.** Every observed FP escalation (the 2026-06-07 alert
  surge; 8/8 across 5 models on the `tools/llm_eval` labeled set) came with the LLM saying
  "malicious" at confidence 0.2–0.55, while real malware convicts at ≥ 0.95. An LLM-malicious
  below `PKGWARD_LLM_MALICIOUS_CONF_FLOOR` (default `0.7`) no longer escalates a
  non-malicious rule verdict, no longer fires the escalation alert, and no longer counts as
  corroboration for auto-watchlist promotion. Clearing, fail-open alerting on rule-malicious,
  and vault collection are unaffected — the floor only blocks an *unsure* model from
  convicting on its own.
- **Multi-provider LLM endpoint.** The OpenRouter-specific `usage` cost-accounting request
  extension is now sent only when the base URL is OpenRouter — other OpenAI-compatible
  providers (e.g. Google's `generativelanguage.googleapis.com/v1beta/openai/`) reject unknown
  request fields with a 400, which previously broke every triage call against a direct
  endpoint. Cost on such providers falls back to the existing token-price estimator
  (`PKGWARD_LLM_EST_*`).
- **CI dependency audit.** `.github/workflows/audit-deps.yml` runs the self-dependency audit
  (piptastic → pip-audit's CVE database) on a weekly schedule, on manual dispatch, and on PRs
  touching `pyproject.toml`/`requirements.txt` — so a newly-disclosed CVE in a pinned dependency
  is caught even without a code change. **Non-blocking**: findings land in the run summary, never
  failing a PR or the branch. Runs piptastic directly on the runner (the scanner image isn't
  built in CI), mirroring `tools/audit-deps.sh`.
- **Per-node alert identification.** With a local scanner + a cloud worker both draining the
  same queue and posting to Discord, alerts now carry which node fired them and its code
  version in the footer (`pkgward | <node> @ <sha> | …`) — essential for tracing an incident
  (e.g. a FP flood) to a node still on old code. `PKGWARD_NODE_NAME` labels the node
  (e.g. `prod` / `cloud`); version is the live git short-SHA where available (the worker
  bind-mounts a git checkout), else the SHA baked at image build (`PKGWARD_BUILD_SHA`,
  passed via the compose build arg), else the package version. `node_id.py`.
- **webcrack JS deobfuscation pre-pass (npm only).** Before the static analyzers run, npm
  packages now go through [webcrack](https://github.com/j4k0xb/webcrack), which unminifies,
  decodes string arrays, reverses obfuscator.io, and unpacks webpack/browserify bundles. The
  deobfuscated output is written into a `.webcrack/` subdir of the extracted tree, so YARA /
  opengrep / iocs / obfuscation all run on **readable code** (decoded URLs, real call sites)
  instead of an opaque minified blob — webcrack does the heavy lifting, our rules do the
  catching. Modeled on the UPX `unpack.py` transform→re-analyze pass: off the event loop,
  fail-soft, gated to npm + non-giant packages, and bounded (per-file timeout, file-count +
  size caps, only files that look obfuscated/minified). webcrack evaluates some decoder
  snippets in `isolated-vm` (a hardened V8 isolate, no fs/net); it runs as a bounded scanner
  subprocess. New image layer (Node 22 + `webcrack`). `analyze/webcrack_deobf.py`;
  `PKGWARD_WEBCRACK_ENABLED` / `_BIN` / `_TIMEOUT` / `_MAX_FILES` / `_MAX_MB`.
- **Recursive multi-layer decode engine wired into detection.** `analyze/decode_engine.py`
  (`recover()`) was built + fully unit-tested but had **zero production callers** — it was never
  invoked, so only the single-layer base64/hex/`\xNN` URL/IP pass actually ran. Now wired into
  `analyze/iocs.py`: it recovers nested chains (b64→gzip→b64, bz2/xz/base32/base85/charcode/…)
  and surfaces what the single-layer pass can't — `iocs.decoded_executable` (critical: a hidden
  PE/ELF/Mach-O or shebang decoded through a chain — dropper shape), `iocs.decoded_code` (high:
  code behind a ≥2-layer chain), and multi-layer `encoded_url`/`encoded_ip`. It returns ONLY
  layers carrying a URL/code-token/executable (benign printable data is dropped), so it does not
  fire on benign serialized base64 (the fazzgram class). Bounded per-file
  (`PKGWARD_DECODE_RECOVER_MAX_MB`, default 2) plus the engine's own node/byte budgets.
- **ROT/Caesar-cipher decode + `obfuscation.rot_cipher_eval` rule.** The decode engine gained a
  URI (`%XX`) decoder and a brute-force ROT-1..25 pass (gated to letter-heavy input; a recurse-gate
  surfaces ROT-ciphered code that carries no recognizable token yet), so a payload hidden behind a
  letter-rotation cipher is recovered for the IOC/decoded-code rules. The `obfuscation.py` analyzer
  also fires `obfuscation.rot_cipher_eval` (high) on the runtime wrapper itself —
  `.replace(/[a-zA-Z]/, …charCodeAt…%26…)` feeding `eval` (the Mini Shai-Hulud letter-rotation
  loader). Corpus-pinned by `tests/corpus/npm/rot_cipher_eval`.
- **Discord Top Rule Hits deduped + aggregated.** Identical (rule, evidence) findings across
  files rendered as repeated verbatim lines (deepalpha v1.1.0: the same URL hit three times),
  and a finding with a file but no line showed `` `N/A` `` instead of the file. One line per
  distinct (rule, evidence) now, with a ×N occurrence count, the first file plus
  `(+N more files)`, and a `+N more distinct hits` overflow note; file-only findings show the
  file. Shared `_render_top_findings` replaces the three duplicated render loops
  (static / detonation / needs-review alerts). `notify/discord.py`.
- **Triage source blocks annotate which rules fired on them.** Each file block's header now
  carries compact `rule_id@Lnn` tags (`--- FILE: x.py (regions around findings:
  malware.env_bulk_exfil@L41) ---`), so the model reads code with the accusation attached
  instead of joining file+line back against the findings JSON itself — the join is exactly what
  weaker models do sloppily on finding-heavy packages. Structure is unchanged (findings JSON
  outside, source inside the one spotlighting delimiter; one deduped block per file).
  `llm/triage.py` (`_finding_notes`).

### Added
- **Baseline detection content expanded: crates.io/Rust + Python supply-chain technique rules.**
  Promoted technique-level YARA rules from the private overlay into the public baseline so the
  shipped ruleset covers all four ecosystems (crates had **zero** baseline coverage before). New
  `rust_baseline.yar` — `rust_buildrs_network_exec`, `rust_buildrs_env_harvest`,
  `rust_buildrs_outdir_escape`, `rust_obfuscated_include_bytes`, `rust_encoded_payload_buildrs`,
  `rust_typosquat_indicator` (the `build.rs` install-time surface). Added to `python_baseline.yar`:
  `staged_subprocess_shell`, `reverse_shell_pattern`, `ssh_key_exfiltration`, `dns_exfiltration`.
  These are publicly-documented techniques; campaign/family-specific rules (`behav_*`,
  `forge_jsxy_rat_family`, `w4sp_stealer_*`, stealers) remain in the operator overlay.
- **`installer.npm_runtime_obfuscated_entrypoint` — convicts self-decoding loaders shipped as
  the package entry point.** The existing `installer.npm_install_obfuscated_entrypoint` only
  inspects files referenced by lifecycle hooks; a package whose **`main`/`bin`** is itself an
  opaque self-decoding eval loader (char-code or runtime-crypto reconstruction → `eval`/`Function`)
  has no install hook to catch and runs at `require()`/CLI time instead. `turbo-dls` 1.3.5
  (`main: gifted.js`, a self-referential `eval(transform(self.toString()))` VM with an anti-tamper
  guard, no lifecycle scripts) scored only `suspicious` (charcode_eval ×4, category-capped at 30)
  and the LLM went `inconclusive` because the payload is still encoded — webcrack only
  pretty-prints a custom VM packer and the decode engine only peels standard codec chains, so no
  static layer could reveal the payload. The new rule fires `critical` and is a behavioral chain
  (→ malicious), reusing the obfuscation analyzer's proximity + build-bundle discriminators so a
  legitimately minified `dist` bundle declared as `main` does not FP. `ecosystems/npm/installer.py`,
  `intel/baseline/behavioral_chains.toml`.

### Changed
- **npm detonation runs the package's runtime entry + CLI bins, not just install hooks.** Each
  detonation phase is a separate `docker run` with only the archive mounted, so the import phase's
  `node -e require(<name>)` ran in a fresh container where the package was never installed →
  `MODULE_NOT_FOUND`, exit 1 in ~1s — a require-time payload (a self-decoding loader shipped as
  `main`, or a downloader `bin`) never fired (turbo-dls 1.3.5: detonation produced only harness
  trace events and added nothing to the verdict). The install-phase script now also runs the
  resolved `main` **as an entry module** (`node <main>`, so payloads gated on
  `require.main === module` trigger) and each `bin` target, inside the container where the package
  is extracted, backgrounded + time-boxed into the existing settle window so Tetragon traces their
  network/file/exec activity. `detonation/internal/sandbox/profile.go`.
- **YARA rules are now one-rule-per-file** (file name == rule name) across the baseline and the
  private overlay. The multi-rule files (`community_sigbase.yar` 11, `python_baseline.yar` 5,
  `rust_baseline.yar` 6, `behavioral_evasion.yar` 3 + overlay `python_malware.yar` 6,
  `behavioral_campaigns.yar` 5, `npm_malware.yar` 2) were split into 38 single-rule `.yar` files.
  The loader globs every `*.yar`, so `rule_id`s, detections, and scoring are unchanged — this is
  purely organizational and makes the per-file compile pre-validation isolate a typo to **one rule**
  instead of dropping every rule in that file. Third-party attribution headers (Neo23x0 DRL-1.1,
  Yara-Rules GPLv2) re-applied per file; `NOTICE` updated to the per-file convention (and now also
  attributes the previously-undocumented GPLv2 `community_*` rules). `tests/test_evasion_yara.py`
  recompiles the split `evasion_*.yar` set.

### Fixed
- **Honeytoken canary self-matched the sandbox-launch command — every detonation fired
  `dyn_honeytoken_exfil` (critical).** Decoys are planted via
  `docker run -e DECOY=… -v …/.env:/root/.env`; Tetragon traces that HOST-side launch exec and
  attributes it to the detonation, so its argv carries every planted decoy by construction — the
  rule substring-matched our own launch command on every run, flipping high-profile legit
  packages (microsoft-kiota, golang/dep, gopherjs, neon, value-trait, go-task, …) to malicious,
  and the `-v …/.env` mounts tripped `RunSensitiveAccess` the same way. The rules engine now
  drops the harness-launch exec (binary = docker/podman/runc/nerdctl/ctr) before sensitive-access
  tracking and the rule loop; a package invoking those binaries *inside* the sandbox is still
  evaluated. `detonation/internal/rules/engine.go`.
- **Two opengrep rules were silently broken (caught by running `--validate`/`--test` in the Linux
  scanner image).** `js_env_to_net.yaml` used YAML anchors/aliases, which opengrep's rule parser
  rejects — the whole env-secret→network-call taint rule silently failed to load. Regex inlined
  in both blocks. `pth_import_injection.yaml`'s `pattern-not-regex` exclusion filtered on a span
  covering only `import <name>`, so the coverage.py exclusion tokens later on the line were never
  in range — FP-ing on coverage.py's bundled `.pth`; the match now spans the whole import line.
- **`js_env_to_net` was the noisiest opengrep rule: 2.0% precision over 2360 shadow-mode scans.**
  The taint source was a bare `process.env`, so every package reading any env var
  (PORT/NODE_ENV/LOG_LEVEL/npm_package_*) and making any network call matched — ordinary config
  plumbing, ~98% of hits. The source is now restricted via metavariable-regex to
  credential-named env reads (token/secret/password/api_key/private_key/aws_*/github_token/
  database_url/…).
- **`malware.credential_store_sweep` + `yara.aes_gcm_hardcoded_eval` fired on a security
  module's credential-file DENYLIST (octocode-mcp 15.0.0 FP class).** A security/redaction
  registry that enumerates credential files as regex literals (`[/^\.npmrc$/, /^Login Data$/, …]`)
  so an agent can refuse to read them tripped the sweep on surface tokens, and at-rest
  AES-256-GCM encryption of the user's own token (key = `randomBytes(32)`, decrypt feeding
  `JSON.parse`, not `eval`) tripped the "hardcoded key" YARA rule, which only checked
  `Buffer.from(x,'hex')`. Both now match the mechanism, not the tokens: a store counts toward
  the sweep only when it occurs OUTSIDE a run of ≥ 3 comma-separated regex literals (a real
  stealer must pass the path as a STRING to a read call, so the discriminator can't be
  disarmed by pasting decoy regexes beside a live harvest — `etc_shadow_read` shares the
  span set), and the YARA rule now requires an actual hardcoded hex literal (≥ 16 bytes
  quoted), which random/derived keys never produce. Synthetic denylist corpus anchor pinned
  clean. `analyze/secret_access.py`, `intel/baseline/yara/aes_gcm_hardcoded_eval.yar`.
- **Worker-timeout cancel deleted the extract tree under the still-running persist/triage
  thread → LLM triaged with NO source.** The 900s `asyncio.wait_for` timeout cancels only the
  `process_one` coroutine; `_persist_and_finalize` runs in a thread (`asyncio.to_thread`) and
  keeps going. The coroutine's `finally` ran `rmtree(tmp_extract)` immediately, so when the
  orphaned thread reached LLM triage it walked a deleted tree — `_safe_rglob` yields nothing on
  a missing dir — and the model adjudicated hundreds of findings with `(no source extracted)`
  (openprogram 0.5.0, scan 181813: 16-min scan, alert reasoning literally "No source code was
  extracted"). The extract-tree cleanup is now owned by whoever needs it last: once the persist
  phase starts, the thread cleans up at its own end; the coroutine's `finally` cleans only if
  the scan died before persist. Also explains the `timeout_after_900s`-but-`done` queue rows.
  `pipeline.py` (`_cleanup_extract`, `_persist_thread`).
- **Flagged binary files burned the triage source budget as mojibake.** File-level findings
  (entropy/YARA, no line) on media or compiled binaries (`.wav`, `Assets.car`, `.icns`) were fed
  whole via `read_text(errors="replace")` — up to `PER_FILE_CAP` (12KB) of replacement-char soup
  *each* (three such files ate 36KB of breaktimer-app's 48KB budget) while readable source was
  truncated out. A flagged binary now renders as a compact stub: size, type-identifying magic
  bytes (hex), and the embedded printable strings (deduped, ≥6 chars, ~1KB cap) — the part of a
  binary that actually convicts (URLs/IPs/commands). The sniff keys on NUL bytes / UTF-8
  decode-failure ratio, NOT non-ASCII: CJK-identifier source (the `nonascii_identifiers`
  surface) is still fed as readable text. `llm/triage.py` (`_is_binary_file`,
  `_binary_stub_block`).
- **DB connection pool exhausted under the new threaded concurrency (`QueuePool limit ... timed out`).**
  Since the event-loop fix (`97b3f4f`) the per-scan DB bursts run via `asyncio.to_thread` instead of
  serialized on the loop, so up to (scan workers + detonation workers + scheduler jobs) check out a
  connection at once — the old hardcoded `pool_size=8, max_overflow=4` (12) timed out under load,
  surfacing as `claim_error` / `pipeline_failed` (TimeoutError). Pool is now env-sized
  (`PKGWARD_DB_POOL_SIZE` / `PKGWARD_DB_MAX_OVERFLOW`, default 16+8); the 24-worker cloud node is
  set to 30+10. Self-recovering before the fix (claims retried, items re-listed) but lost throughput.
  `store/session.py`.
- **Discord alerts silently dropped on oversized embeds (HTTP 400).** The IOCs field
  (and any long field) had no length clamp; a package with many/long IOCs produced a
  >1024-char field, which Discord rejects with `400 {"embeds": ["0"]}` — losing the whole
  alert (observed on `@barefootjs/xslate`, a needs-review verdict, 2026-06-06; explains
  sparse alerts from the cloud node). Added `_sanitize_embed` at the single `_post_embed`
  choke point: clamps every field value to 1024 / name 256 / title 256 / description 4096 /
  footer 2048, caps at 25 fields and a 6000-char embed budget, and placeholders empty values
  (Discord rejects those too). Covers all alert builders (malicious, unverified, needs-review,
  dynamic). `notify/discord.py`.
- **Event loop froze on giant-package cleanup → whole scanner stalled.** `process_one`'s
  `finally` block ran `shutil.rmtree` on the extracted tree (up to 25K files) *synchronously
  on the event loop*; for a giant package the recursive delete blocked the loop for minutes,
  stalling every other worker and missing scheduler jobs (prod observed wedged 15+ min, zero
  throughput, APScheduler "job missed by 0:11:00"). Cleanup now runs via `asyncio.to_thread`;
  the detonation worker's archive cleanup was wrapped the same way. `pipeline.py`,
  `detonation_worker.py`.
- **Remote-DB workers: sync DB bursts froze the event loop → mass `ConnectTimeout`.** The
  worker claim loop, the scan head/failure-path queue updates, the prev-scan-hash fetch, and
  the detonation-worker claim/requeue paths all opened synchronous DB sessions **on the event
  loop**. With a local Postgres each is sub-millisecond; on a scan-only node reaching the DB
  over a tunnel (~wire-RTT per query) every one froze the loop for all coroutines, so
  in-flight registry connects blew their timeouts (~73% of scans failed `ConnectTimeout`/
  `ConnectError` on an otherwise idle node with a provably healthy network — py-spy caught the
  loop inside `do_execute`). All of these now run via `asyncio.to_thread` like
  `_persist_and_finalize` already did, and the loop's default executor is sized to
  `max(32, workers + detonation workers + 16)` so threaded DB waits can't starve
  `getaddrinfo` (which shares that pool). `workers.py`, `pipeline.py`,
  `detonation_worker.py`, `runtime.py`.
- **`obfuscation.charcode_eval` proximity gate (my-olly FP).** The rule fired when `eval`/
  `Function` and a `fromCharCode`/charCodeAt decode merely both appeared in a file — in a
  multi-MB minified bundle there's an `eval` somewhere and a UTF-16 surrogate codec
  (`fromCharCode`) elsewhere, megabytes apart and unrelated (the `my-olly` AI-CLI FP, whose
  `bin/olly.js` also dodged the bundle-name downgrade). Now requires the decode to sit within
  `PKGWARD_CHARCODE_EVAL_PROXIMITY` (600) chars of an eval sink — a real packer evals the
  decoded string inline; a bundle's are far apart. `analyze/obfuscation.py`.
- **fazzgram-class FP — npm triage now sees the package's real code.** The triage entry pass fed
  package.json + lifecycle scripts but not the runtime `main` entry or the package's readable
  source, so a legit framework convicted because only its obfuscated/base64-heavy file (the rule
  hit) reached the model. The reserved entry pass now resolves npm `main` (e.g. `src/index.js`)
  and fills the remaining entry budget with the package's own non-flagged source — so the model
  sees `ApiClient.js`/`Context.js`/etc. and can clear a benign package. `llm/triage.py`.
- **Two false-positive sources flooding the needs-review queue.** (1) `gomod.replace_local_path`
  dropped **high → low**: Go *ignores* `replace` directives in any module consumed as a
  dependency (they apply only in the main module), so a local-path replace in a *published*
  module is structurally inert — a monorepo/dev artifact, not a supply-chain vector. It was
  pushing every Go monorepo sub-module to `suspicious` → triage → review. Now informational;
  still escalates if paired with a real chain (init exec/net). (2) **LLM-triage entry-file
  starvation:** the convicting-evidence pass could consume the whole budget before the manifest
  / install scripts were fed, so the model adjudicated `@shareai-lab/kode` without its
  `postinstall.js` (a benign GitHub-release binary download) and `googleapis` without its
  `package.json` — both went `inconclusive`. Added a **reserved entry-file budget**
  (`PKGWARD_LLM_ENTRY_BYTES`, default 16 KB): manifests + resolved npm lifecycle scripts +
  gomod `*.go` are fed first and can't be starved by a flood of findings (nor starve the
  convicting pass — the arkclaw guard stays green). `ecosystems/gomod/go_directives.py`,
  `llm/triage.py`.

### Security
- **Cleared the two dev-tool CVEs piptastic flagged in our own tree.** `pytest` 8.3.3 → 9.0.3
  (CVE-2025-71176) and `black` 24.8.0 → 26.3.1 (CVE-2026-32274). pytest 9 cascaded a coordinated
  bump — `pytest-asyncio` 0.24 → 1.4.0 and `pytest-httpx` 0.32 → 0.36.2 (which requires httpx
  ≥0.28), so `httpx` (runtime) moved 0.27.2 → 0.28.1. The httpx bump is verified safe: our client
  construction uses none of httpx 0.28's removed args (`proxies=`/`app=`), and the full 838-test
  suite passes under the coordinated set. `tools/audit-deps.sh` now reports zero CVEs. (The runtime
  httpx bump lands in built images and rides normal prod soak; the dev CVEs are not in the
  production runtime path.)

### Added
- **Self-dependency audit via piptastic (`tools/audit-deps.sh`).** The scanner now audits its
  own Python dependency tree for drift + known CVEs (pip-audit) using piptastic, run in a
  throwaway scanner-image container against the tree mounted read-only — installs nothing on
  the host. `--format sarif` doubles as a CI gate. Baseline at adoption: zero runtime CVEs;
  two dev-tool CVEs flagged (pytest → 9.0.3 / CVE-2025-71176, black → 26.3.1 / CVE-2026-32274).
- **LLM triage `inconclusive` verdict + needs-review surface.** The schema forced
  malicious/suspicious/benign, so when the model lacked evidence it confabulated a
  confident verdict (yail-class: a lone typosquat-distance flag escalated to malicious by
  inventing behavior from a `Cargo.toml` feature list). New 4th verdict **`inconclusive`**
  is the model's honest "I can't decide from what I was shown", paired with a required
  **`missing_evidence`** field (what it couldn't see + what would resolve it). Routing is
  safe by construction: inconclusive can only downgrade a *weak* rule signal — `_enforce_no_downgrade`
  still pins behavioral chains and exact-intel matches at malicious, and a rule-malicious the
  LLM can't confirm still alarms (tagged `llm_unverified`). A weak-signal inconclusive
  (yail) becomes `scan.verdict='inconclusive'` (tagged `needs_review`), **no false-malicious
  alarm**, and fires a distinct amber "🔍 Needs Review" Discord alert leading with the
  missing evidence. Queryable surface: `pkgward review` (newest inconclusive scans + what
  each was missing). Prompt evidence-discipline reinforced (overlay + baseline): convict only
  on code you can see; capabilities/deps/API-surface/file-names ≠ behavior; don't assert
  unobserved facts. `llm/triage.py`, `pipeline.py`, `notify/discord.py`, `cli.py`.

### Fixed
- **LLM triage starvation on file-level findings (arkclaw-sdk FP class).** The convicting-
  evidence pass in `_gather_source` only prioritized *line-anchored* findings, so YARA /
  threat-intel / binary hits — which are file-level (no line) yet routinely critical — were
  collected dead last, *after* the generic priority-entry-files pass. A package with many
  entry files (tests, submodules) exhausted the 48 KB budget first, and the file the critical
  YARA rule actually fired on never reached the model — which then adjudicated from the rule
  *name* alone and confabulated a malicious verdict (`arkclaw-sdk@0.1.1`: a real OAuth SDK
  flagged on a proximity-only env-harvest rule). Now every finding-bearing file is ranked by
  its highest severity — line-anchored *or* file-level — and the convicting code is fed
  **before** the priority pass (whole file for line-less hits). `llm/triage.py`. Paired with
  a prompt evidence-discipline block (overlay) that forbids convicting on a rule name when its
  file isn't in the provided source, and forbids asserting unobserved facts (typosquat / file
  absence). See `docs/internal/` notes; same root cause as the graphifyy context-starvation FP.

### Added
- **Known-malicious dependency intel — supply-chain propagation along the dependency edge.**
  When a package is double-confirmed malicious it's already auto-watchlisted; a *different*
  package that declares a dependency on one of those confirmed-bad names is itself suspect
  (compromised, complicit, or a victim). New `dep_intel.depends_on_known_malicious` finding
  (critical when the bad-dep edge is **newly added** in this version, high when pre-existing),
  scoped per-ecosystem (an npm known-bad never matches a pypi dep) and covering npm + pypi at
  scan time. On **npm ingest** the same signal force-scans a normally-skipped version-update at
  high priority the instant it adds a bad-dep edge, so the catch doesn't die in the npm backlog.
  A scan **trigger + weighted evidence, not a verdict** — a single critical caps at 30 points
  (suspicious → LLM adjudicates), never auto-malicious, deliberately avoiding a self-confirming
  convict loop. `known_bad_deps.py` (cached confirmed-bad set, fail-soft), `analyze/dep_intel.py`,
  `ecosystems/npm/ingest/{anomaly.py,cursor.py}`. `KNOWN_BAD_DEPS_GATE=0` disables;
  `KNOWN_BAD_DEPS_CACHE_TTL` (300s) tunes the in-process set cache. Idea by **Cyb3rjerry**.
- **npm `binding.gyp` / node-gyp command-expansion detection (Phantom Gyp / Miasma).** node-gyp
  runs a package's `binding.gyp` for any package with native components — with **no preinstall/
  postinstall** entry — and GYP's `<!(...)` command-expansion executes a shell command at configure
  time, so `<!(node index.js …)` is arbitrary code execution during `npm install` that lifecycle-
  script tooling (and `--ignore-scripts`) never sees. `installer.npm_binding_gyp_command_exec`
  (critical) flags a `binding.gyp` whose `<!(...)`/`<!@(...)` runs a script file, fetches, or chains
  shell ops, while ignoring legit config reads (`<!(node -p "require('node-addon-api').include")`).
  `ecosystems/npm/installer.py`. Catches the June-2026 node-gyp supply-chain worm at install time.
- **`tools/genome.py` — manual malware fingerprinting for the threat-intel pack.** Turns a
  confirmed-malicious sample into pack-ready genes: `pull` (extract a vaulted sample, static),
  `inspect` (file hashes + its functions, so you choose), `gene` (emit the exact
  `known_malicious.jsonl` schema — SHA256/ssdeep/TLSH — for a file, plus the chosen function's
  hashes alongside). File-level genes match at scan time today; function-level matching is
  deferred (needs scan-time per-function hashing). Fully manual, never executes the sample.
  See `docs/threat-intel-genomes.md`.
- **`pkgward replay` — re-run vaulted known-bad samples through the real pipeline.** Sources the
  exact archive bytes from the vault (not the registry, whose malicious versions are usually yanked)
  and drives the genuine `process_one` path — analyze → score → LLM triage → Discord alert — so a
  frozen sample fires real alerts on demand for testing/validation. `replay --all` or filter with
  `--package/--version/--ecosystem`. Vault-sourcing is a per-call seam (`process_one(replay_from_vault=True)`)
  used only by this command; the live firehose always fetches from the registry. `pkgward/{cli,pipeline,vault}.py`.
- **Cross-ecosystem version-update anomaly ingest gate (crates + pypi).** Extends the npm anomaly
  gate to the other two registries via a shared core (`ecosystems/version_anomaly.py`): a non-
  watchlisted package's version bump is diffed against its predecessor from registry metadata (no
  tarball) and force-scanned if anomalous — **crates** flags a size jump or **publisher change**
  (`published_by` from the API), **pypi** flags a size jump (per-release file sizes from the JSON
  API). A scan trigger, not a verdict; bounded + flagged (`CRATES_ANOMALY_GATE`/`PYPI_ANOMALY_GATE`).
  gomod is excluded (no install-hook/publisher surface — its anomaly is git-registry drift, backlogged).
- **Rich detonation sandbox images (`pkgward-det-<eco>`).** The minimal base images made native
  payloads die at dlopen/exec before tracing (IronWorm's Rust ELF needed `libbpf.so.1`). A derived
  image per ecosystem now ships the broad runtime set real payloads link/invoke — libbpf, libssl,
  libsqlite3 (browser cred DBs), libpcap, libnss3/libsecret (keyrings), gnupg, git, curl/wget,
  python3/perl, gcc/make + recon tools — so they execute and trace. Safety unchanged: rootless user-ns
  + `unprivileged_bpf_disabled=2` + kernel lockdown still EPERM the eBPF rootkit; honeytokens catch the
  theft. The service auto-falls-back to the raw base if the derived image isn't built. gomod moved off
  alpine → `golang:1.22-bookworm` (gains gcc/git/CGO). `detonation/deploy/{sandbox.Dockerfile,build-sandbox-images.sh}`,
  `internal/sandbox/{profile,gvisor}.go`, `deploy/setup.sh`.

### Added
- **npm version-update anomaly ingest gate — closes the "compromised version of an established
  package" blind spot (the IronWorm miss).** A new version of a known, non-watchlisted package was
  *skipped* outright (ingested only brand-new/watchlist/scope/focus), so the asteroiddao campaign's
  malicious version bumps (`weavedb-sdk@0.45.3` + 35 siblings) were never even downloaded. The npm
  cursor now diffs a would-be-skipped update against its predecessor **from the packument alone (no
  tarball)** and force-scans it when it newly looks like a compromise: an added/changed install hook,
  a hook that **directly executes a bundled path** (the dropper signature — `./tools/setup`), a size
  jump (≥3× and ≥256 KB), or a **publisher change** (account takeover). It is a SCAN trigger, not a
  verdict — the package enters the queue at *normal* priority (the bundled-exec dropper signal → *high*)
  and the full pipeline adjudicates, so an FP only costs a wasted scan, never a false alert. Bounded
  for the npm firehose: a dedicated limiter + per-poll cap (`NPM_ANOMALY_MAX_CHECKS`, default 200) with
  **overflow logged, never silently dropped**; toggle via `NPM_ANOMALY_GATE`. Validated against the real
  IronWorm packument (all four flags fire on 0.45.3; the attacker's 0.45.4 cleanup revert correctly does
  not). `ecosystems/npm/ingest/{anomaly.py,cursor.py}`.
- **`installer.npm_install_runs_bundled_binary` (critical) — catches install-hook native-binary droppers.**
  A `preinstall`/`postinstall`/`install` hook that directly executes a file bundled in the package
  (`./tools/setup`, `./.github/scripts/precheck`) which is a native binary/ELF is the dropper/loader
  signature. Previously produced ZERO findings (the net/exec string heuristics never fire on a bare
  `./binary`), so `weavedb-sdk@0.45.3` / `zkjson@0.8.5` (the asteroiddao "IronWorm" campaign — a packed
  Rust infostealer + eBPF rootkit) scanned **clean**; both now convict. Legit native modules launch via
  a JS shim or node-gyp, never by exec-ing a prebuilt binary from a hook. `ecosystems/npm/installer.py`.
- **3 behavioral evasion YARA rules** for 2025-26 supply-chain TTPs: `evasion_workflow_secrets_exfil`
  (a shipped GitHub Actions workflow that serializes `${{ toJSON(secrets) }}` to an artifact/curl — the
  IronWorm/Shai-Hulud secret-exfil-via-CI second path), `evasion_anti_ci_payload_gate` (payload gated to
  run only OUTSIDE CI — `!process.env.CI` / `not GITHUB_ACTIONS` — chained to a net/exec/eval sink), and
  `evasion_media_stego_loader` (media-frame read + base64/XOR decode piped into an interpreter — the
  TeamPCP WAV-steganography harvester). Each requires the malicious *combination*, not the benign
  primitive, validated against benign lookalikes. `intel/baseline/yara/behavioral_evasion.yar`.

### Changed
- **npm version-update anomaly gate now catches *in time* (the IronWorm / Miasma ingest gap).**
  The gate already diffed the registry packument and had the signals, but two things defeated it:
  (1) only the bundled-exec dropper signature jumped the queue — `install_hook_added`, `size_jump`,
  `publisher_change` enqueued at **normal**, dying in the 80k npm backlog for days until the malicious
  version was yanked and a re-fetch got a clean release; (2) the per-poll cap silently **dropped**
  overflow candidates. Now: priority is **blast-radius aware** (`anomaly.py` `_anomaly_priority`) — an
  anomalous update of an *established* package (≥ `NPM_ANOMALY_ESTABLISHED_MIN_VERSIONS`, default 5)
  jumps to **high** for a size-jump (the binding.gyp/node-gyp class, whose scripts stay clean), a
  bundled-exec, or a publisher-change paired with a real content change; young packages stay normal so
  benign growth doesn't flood. And overflow candidates are **carried forward** across polls (bounded
  FIFO, `NPM_ANOMALY_CARRYOVER_MAX`, half the cap reserved to drain the backlog, half for fresh
  candidates) instead of dropped — so no established-package update goes permanently unchecked.
  `ecosystems/npm/ingest/{anomaly,cursor}.py`.
- **Vault preserve is double-confirm only; triage now runs on suspicious too.** The frozen-sample
  vault used to archive on the *rule* verdict alone, **before** the LLM ran — so every rule-only FP
  (kgateway/awscrt/notebook) got frozen even when the LLM later cleared it benign. The vault is now
  written **after** triage and only on a real malicious determination: the LLM says malicious (rules
  malicious *or* suspicious — the suspicious→malicious **escalation** case), or rules say malicious and
  the LLM was enabled-but-couldn't-adjudicate (a transient miss; a globally disabled LLM is excluded so
  it can't blanket-vault FPs). To enable the escalation case, LLM triage now also runs on rule-suspicious
  packages — which **catches malware the rules under-scored** (LLM escalates suspicious→malicious →
  alert *and* vault). Alerts unchanged for rule-malicious (fail-open unless LLM clears); rule-suspicious
  alerts only when the LLM convicts it. `pipeline.py`. Trade-off: more LLM calls (suspicious is common;
  budget-capped, cheap model).
- **Detonation exfil is now a chain (secret access + external egress), not a lone connect.** A
  network connect during install/import is dual-use — fetching deps, prebuilt binaries, Zcash Sapling
  params, disposable-email-domain blocklists, JDK/LLM-SDK downloads, or just resolving DNS all look
  identical to data theft. `dyn_install_exfil` / `dyn_import_exfil` fired on the bare connect and
  false-positived constantly, flipping *clean* packages to malicious — most egregiously on the
  sandbox's **own DNS forwarder** (`172.17.0.2:53`), which flooded the alert channel (@bwo-ui/vue+svelte,
  legalesign-ui, @oratis/lisa, actiondock, @blazediff/cli, @exodus/taquito-sapling, free-email-domains
  all clean/benign). Exfil now requires the data-theft *shape*: a secret was touched in the same
  detonation (`dyn_credential_read` / `dyn_env_harvest` — surfaced run-wide by the rules engine as
  `run_sensitive_access`) **and** the connect leaves the sandbox for an external host (private/loopback/
  bridge addresses — incl. the DNS forwarder — are infra, never egress). A lone external egress emits a
  new **low, non-convicting** `dyn_install_egress` / `dyn_import_egress` note for visibility. A
  honeytoken leaving the sandbox still convicts standalone (`dyn_honeytoken_exfil` — proof of theft, no
  chain needed). This is the first *dynamic* behavioral chain. `detonation/internal/rules/{definitions,engine}.go`.

### Fixed
- **IOC false positives on test/fixture files (the kgateway-class FP).** A large project's test suite
  is full of example URLs and hardcoded IP:port fixtures (`plugin_test.go` had `2.1.0.10:1234`), which
  fired `iocs.url_suspicious`/`iocs.ipv4` noise and — worse — two **high** `iocs.hardcoded_wan_ip_port`
  "C2-beacon shape" findings, persistently scoring popular repos `suspicious`. `analyze/iocs.py` now
  recognizes test files (`*_test.go`, `test_*.py`/`*_test.py`, `*.test|spec.[jt]s`, and `test/tests/
  testdata/fixtures/__tests__/spec` path components): the low/low url+ip noise is suppressed and the
  high `hardcoded_wan_ip_port` is down-weighted to **low** there. Production code is unchanged (full
  scrutiny); genuinely-notable IOCs (oast/abuse-hosting/cloud-metadata/onion/encoded) still fire in
  test files so malware can't hide under a `test/` path.
- **Vault re-detonation was silently failing (cross-uid staging permission drift).** The detonation
  worker stages a vaulted package's exact scanned bytes for re-detonation; `_stage_from_vault` created
  its staging dir via `mkdtemp` (mode `0700`) — but the scanner writes as root inside its container
  while the rootless detonation service reads as the unprivileged `detonation` uid, which can't
  traverse a `0700` dir, so every vault mount failed (`mkdir …: permission denied`) and fell back to a
  re-fetch (~20×/h in soak). For *yanked* malicious packages — the vault's whole reason to exist —
  the re-fetch gets a takedown placeholder, so the payload we actually scanned was never re-detonated.
  Root cause was deeper than one missing `chmod`: the cross-uid bind-mount permission contract was
  duplicated and implicit across all five staging paths (each ecosystem `fetch/download.py` widened
  its own dir and relied on the umask for the file mode), and the vault path drifted off it. New
  `pkgward/detonation_staging.py` is the single source of truth — explicit dir (`0755`) + file
  (`0644`) modes (umask-independent), documented contract, regression-tested (incl. under a restrictive
  umask); the vault path routes through it. `detonation_worker.py`, `detonation_staging.py`,
  `tests/test_detonation_staging.py`.
- **Native-CLI npm packages (esbuild/swc/cxpher pattern) no longer false-convict.** Two FP
  root causes, found via `cxpher 2.2.3` (a legit proprietary native-binary package manager
  that detonation flipped to malicious):
  - The obfuscation and entropy analyzers read a compiled binary that wears a *source*
    extension — `bin/cXpher.js` is actually an ELF — as text, turning its high-bit bytes into
    bogus `obfuscation.nonascii_identifiers` / `homoglyph_identifiers` and `entropy.obfuscated_payload`.
    Both now skip a file whose *content* is a compiled executable image (new
    `binary.looks_like_compiled_binary`, magic-byte match — strict, so an encrypted text-disguised
    payload is still scanned). `binary.py` still flags the artifact. `analyze/{binary,obfuscation,entropy}.py`.
  - The detonation `dyn_suspicious_write` rule treated a write to a shell rc (`.bashrc`/`.zshrc`/
    `.profile`) — the near-universal native-CLI **PATH-export** install convention (nvm, cargo,
    deno, bun, pyenv all do it) — as `critical`, which single-handedly forces a malicious verdict.
    Shell-rc writes are now `high` (strong signal that must *chain* with a real payload signal to
    convict, not force it); hard-persistence sinks (cron, systemd, init.d, ld.so.preload, ssh
    `authorized_keys`) stay `critical`. `detonation/internal/rules/definitions.go`. Regression:
    `tests/corpus/npm/native_wrapper_binary` extended with an ELF-named-`.js`.
- **Bundled test-virtualenv no longer false-convicts as `.pth` injection.** A package that
  sloppily ships its test venv into the sdist carries coverage.py's subprocess-measurement
  `.pth` (`coverage.process_startup` gated on `COVERAGE_PROCESS_START`/`_CONFIG`) — coverage's
  own documented file, present in every venv with subprocess coverage. Its `import sys; exec(...)`
  line tripped the critical `malware.pth_exec_injection` rule (and the opengrep
  `pth_import_injection` shadow), auto-flipping the whole package to malicious. Both now skip
  this content-anchored coverage signature; a real exec-payload `.pth` still convicts. Real-world:
  `portman-proxy 0.1.2` (a clean aiohttp reverse proxy, double-confirmed FP). `analyze/malware_patterns.py`,
  `intel/baseline/opengrep/python/pth_import_injection.yaml`; regression sample
  `tests/corpus/pypi/bundled_coverage_venv`.
- **gomod weak co-occurrence findings no longer flood large legit codebases.** The per-file
  `gomod.init_net_coexist` / `init_exec_coexist` / `unsafe_import` signals (init() co-located
  with a net/exec/unsafe import, but *not* used in init()) fired on dozens of files in a big
  networking project like `tailscale` — inflating the score to suspicious and bloating the LLM
  prompt. They're now capped per rule (keep 3 + one aggregate note); a high count is itself a
  benign indicator. The real in-`init()` threats (`init_exec_chain`/`init_net_chain`) are never
  capped. `ecosystems/gomod/go_directives.py`.
- **Detonation was blind for npm / crates / gomod — it traced an empty sandbox.**
  Those three ecosystems staged downloaded archives under `/tmp/pkgward_<eco>`, but
  only `/tmp/pkgward` is bind-mounted into both the scanner container and the
  detonation-service host. The service received an archive path it couldn't see, Docker
  auto-created it as an empty directory, and the sandbox detonated *nothing* — so every
  npm package produced the same ~15 install-harness trace events and zero payload
  behaviour (only pypi, which already staged to `/tmp/pkgward`, worked). Dynamic
  analysis is the generalizer that catches a payload the per-shape static rules miss, so
  this is why nearly every new npm/gomod sample needed fresh static tuning. All four
  ecosystems (and the vault-first restage) now stage to the shared `/tmp/pkgward`.
  Live npm detonations now show variable, payload-driven event counts.
  `ecosystems/{npm,crates,gomod}/fetch/download.py`, `detonation_worker.py`.
- **DNS-aware abuse-host detection could never fire.** Two bugs: (1) the detonation
  service runs as a confined systemd unit (`init_t`) that the host denies (`EACCES`)
  from connecting to the rootless-Docker–published loopback port the DNS forwarder's
  lookup API used — so the IP→hostname annotation silently no-op'd. Lookups now go over
  the rootless Docker socket via `docker exec det-dnslog /dns-forwarder lookup <ip>`
  (the same control channel the service already uses to run sandboxes), needing no host
  port. (2) `mergeNoise` unioned every noise field *except* `abuse_hosts`, so after the
  baseline+overlay merge the abuse-host list was always empty. Added a reflection-based
  regression test that fails if any `NoiseFilters` field is dropped from the merge.
- **Silent-detection-loss sweep (5 fixes).** A multi-agent audit (find → adversarially
  verify) surfaced detection paths that degraded to nothing without erroring:
  - **Behaviour-only convictions could never reach "malicious."** Every detonation
    finding carries `category="dynamic"`, so the per-category score cap (30) collapsed
    independent behavioural signals (credential read + DNS exfil + injection) under one
    ceiling. Scoring now buckets dynamic findings per `rule_id` — distinct behaviours
    accumulate, same-rule repeats still cap. `detect/score.py`.
  - **Env-exfil regex missed subscript reads.** `os.environ['AWS_SECRET']` (the canonical
    form) never matched — only `os.environ.get(...)` did. `analyze/malware_patterns.py`.
  - **Entropy-jump detector dead on giant packages.** The giant fast-path zeroed per-file
    entropy (while still computing the costlier ssdeep/TLSH), so `entropy.suspicious_jump`
    silently never fired on big packages. Entropy is now computed in lite mode too.
    `pipeline.py`, `analyze/entropy.py`.
  - **A service-side detonation `error` was finalized as a clean empty detonation** —
    losing any behaviour-only malicious flip. It now requeues within the bounded budget.
    `detonation_worker.py`.
  - **A package could suppress its own dynamic verdict with one NUL byte** in a traced
    exec path / syscall arg (failed the finalize txn). NUL is now stripped from
    package-controlled TraceEvent fields, like the static-scan path. `detonation_worker.py`.
- **Detonation false positives on prebuilt-binary CDNs.** With npm detonation now
  executing payloads, `dyn_install_exfil` fired on legitimate install-time downloads
  (Playwright browser CDNs). Added those CDNs to `npm_net_allow`, plus an **exact-match**
  allowlist entry form (`=host`) so path-style `storage.googleapis.com` (shared CDN) is
  allowed while per-tenant `<bucket>.storage.googleapis.com` — the dependency-confusion
  exfil shape (caught a live `corporate-front-vue@99.9.1`) — stays flagged.
- **LLM-triage hardening (two silent un-conviction paths).**
  - **Source starvation.** The convicting code is now gathered *first* — source windows
    around every line-anchored finding, highest-severity file first, per-file capped, with
    the budget raised 32→48KB — so a large priority/vendored file can no longer exhaust the
    budget before the line that drove the verdict is shown to the model. `llm/triage.py`.
  - **Exact-hash matches are non-downgradable.** The LLM could clear a byte-for-byte known
    malware match (`threat_intel` sha256 tier) to benign and suppress the alert. Those are
    now held malicious regardless of the LLM. Fuzzy ssdeep/TLSH matches stay downgradable
    (they were the self-seeded-FP source). `llm/triage.py`.
- **Intel-pack load robustness (3 silent-loss fixes).**
  - **One malformed overlay YARA file no longer disables the entire YARA layer.** Rules are
    compiled per-file first; a bad file (usually an overlay typo, the place operators add
    campaign rules) is dropped + logged and the rest still load. `analyze/yara_scan.py`.
  - **Malformed threat-intel hash lines are surfaced** (`intel_jsonl_malformed`, with
    skipped/loaded counts) instead of vanishing — a campaign fingerprint on a bad line no
    longer disappears silently. `intel/pack.py`.
  - **Non-numeric threshold/scoring-weight overrides are logged** (`intel_value_not_numeric`)
    rather than silently dropped + reverted to the hardcoded default, so a `malicious_min =
    "61"` typo in an overlay is visible. `intel/pack.py`.
- **Static-coverage false-negatives (silent-loss sweep, final batch).**
  - **IOC URL whitelist no longer over-matches** — a bare `^test` prefix silently
    whitelisted real C2 on any host starting with `test` (`test-c2.evil.com`,
    `testbench.workers.dev`). Anchored to actual test placeholders. `analyze/iocs.py`.
  - **Extensionless interpreter hooks are now followed** — `postinstall: node install`
    (or `tsx setup`) referenced no `.js`, so the install payload was never scanned;
    resolved via JS/TS module resolution now. `ecosystems/npm/installer.py`.
  - **Decode-and-rescan uses per-encoding budgets** — a base64-heavy file no longer
    exhausts a shared cap before the hex/`\xNN` passes, where concealed C2 hides.
    `analyze/iocs.py`.
  - **No-longer-silent skips/drops**: YARA logs files skipped for size
    (`yara_skipped_large_files`); a crates watchlist enqueue failure logs
    `crates_wl_enqueue_failed`; and a detonation host with DNS capture off now logs a
    loud `WARNING` that abuse-host detection is inert. `analyze/yara_scan.py`,
    `ecosystems/crates/ingest/feeds.py`, `detonation/internal/api/server.go`.

### Added
- **Richer Discord alerts.** Both the static-malicious and detonation-flip webhooks now show
  a **Publisher** field — author + email, the actual uploader, and maintainers, read from the
  `Version` row captured at scan time (no extra request; defanged). The publisher's email
  domain and uploader are first-order supply-chain triage signal. Finding evidence is also
  widened (80→240 chars) so a long exfil host/domain (e.g. a Cloud Run callback) is shown in
  full instead of cut off. `notify/discord.py`, `enrich/publisher.py`.
- **Publisher identity is now captured for every ecosystem (was pypi/npm-only and partial).**
  The Discord alert's Publisher field was empty for crates and gomod and missing the actual
  uploader on npm. Now: **npm** records `_npmUser` (the account that published the version — the
  first-order hijack signal) and the full `maintainers` set; **crates** reads `published_by`
  from the version (the inline `owners` it tried before is a separate endpoint, so it captured
  nothing — 0% in prod); **gomod** derives the VCS owner from the module path
  (`github.com/<owner>/...`, falling back to the host for vanity paths) since the Go proxy
  exposes no uploader; **pypi** falls back author→maintainer and now persists the uploader.
  `_apply_metadata` carries `upload_user` + a plural `maintainers` list end-to-end.
  `ecosystems/{npm,crates,gomod}/fetch/download.py`, `pipeline.py`.
- **Fetch + statically analyze second-stage deps from suspicious file hosters (npm).**
  npm lets a dependency be a raw tarball URL instead of a registry range; a
  dependency-confusion/staged-payload package points it at attacker infra (e.g.
  `corporate-front-vue@99.9.1 → https://<bucket>.storage.googleapis.com/depenconf/
  ltidisafe-*.tgz`, whose `preinstall` hex-exfils host/user to a Burp Collaborator
  callback). The scanner now (1) flags every URL-spec dependency
  (`installer.npm_url_dependency`, high on a suspicious host — cloud buckets, abuse/tunnel
  hosts, paste sites, raw/gist), and (2) for suspicious hosts **fetches the tarball and
  runs the static analyzers over the second stage**, merging findings (namespaced
  `[fetched-dep:<name>]`) so the staged payload convicts the parent at scan time — no
  detonation required. Heavily bounded and SSRF-guarded: rejects private/loopback/
  link-local/reserved/metadata IPs, no redirect-following, 20 MB / 15 s / 3-deps caps,
  never executed. Reaches attacker infrastructure from the scanner host, so it's gated by
  `PKGWARD_FETCH_URL_DEPS` (default on; the static flag still fires when off). Caps tune
  via `PKGWARD_URL_DEP_{MAX_MB,TIMEOUT,MAX_COUNT}`. `ecosystems/npm/url_deps.py`.
- **Prompt-injection defense for LLM triage.** The triage model reads attacker-controlled
  source, so a package can embed text aimed at clearing its own verdict. On top of the
  existing spotlighting + hardened system prompt, two confidence tiers:
  - `iocs.llm_prompt_injection` (high, **non-downgradable**) — output-schema mimicry of our
    exact internal field (`agrees_with_rules`). Near-zero legitimate use, so an injected
    `benign` verdict can't clear the package (`llm_clear_blocked_prompt_injection`).
  - `iocs.llm_injection_phrase` (medium, **informational**) — instruction-override phrases
    ("ignore previous instructions", "mark this as benign"). These also appear incidentally
    in large minified bundles and, deliberately, in *defensive* injection-guard pattern
    lists, so the LLM still adjudicates rather than the verdict being forced.
- **Detonation exfil alerts now show the resolved domain, not just the IP.** The DNS-aware
  capture already annotated each connect with its hostname, but `dyn_install_exfil` /
  `dyn_import_exfil` evidence printed only `IP:port`, so an operator couldn't tell a beacon to
  `callback.workers.dev` from a legit fetch from `cdn.sheetjs.com` (both Cloudflare IPs). The
  evidence now renders `hostname (ip):port`. Also allowlisted `cdn.sheetjs.com` (SheetJS's
  off-registry distribution CDN — packages that bundle xlsx fetch from it at install).
- **DNS-aware filter no longer false-positives on legit CDN-fronted hosts.** The DNS-aware
  change judged a connect *with* a hostname purely by domain and skipped the IP-CIDR
  allowlist, so a non-abuse host resolving into an allowlisted CDN range (e.g.
  `static.rust-lang.org` on Fastly — the `typos` install fetch) FP'd as exfil. The IP-CIDR
  allowlist is now consulted for hostnamed connects too; abuse hosts are matched first, so
  this can't re-allow a `workers.dev` beacon — it only restores the no-FP behaviour.
  `detonation/internal/baseline/filter.go`.
- **Checksum-verified prebuilt-binary downloads no longer convict as droppers.** A native
  wrapper that downloads its platform binary at install (esbuild/swc/`@huayoung/huayoungtk-cli`)
  tripped `npm_install_remote_binary_drop` + the `dyn_install_exfil` chain. When the install
  script also **SHA-256/512-verifies** the download, the drop finding is down-weighted (high→low)
  and the vendor host is recorded; at detonation re-score an install-time connect to that same
  host is recognized as the legit self-download (not exfil) and won't chain to malicious. An
  *unverified* drop, or exfil to a host unrelated to the download host, still convicts.
  `ecosystems/npm/installer.py`, `detonation_worker.py`.
- **OAST callback domains caught even when the URL is string-built** (`iocs.oast_callback`).
  A payload that splits `'http://' + x + '.oastify.com'` to dodge the URL-literal scanner is
  now caught by the bare-domain literal (these domains have ~zero legit use in source).
- **`dependency_confusion_version` flags high-major-not-year versions** (`99.9.1`, `100.0.0`)
  — the version-inflation pattern that wins a semver resolution race; calendar versions
  (`2024.1.1`) are excluded.
- **DNS-aware detonation network filtering + `dyn_abuse_hosting_callback` (critical).**
  A forwarder container on the detonation bridge captures every name a sandbox resolves
  (IP→hostname); outbound connects are then judged by *domain*, not by shared-CDN IP, so
  a runtime beacon to an abuse-prone host (`workers.dev`, `pages.dev`, `trycloudflare`,
  `ngrok`, `deno.dev`, …) is caught even though it inherits a big provider's trusted IPs.
  Closes the false-negative where `workers.dev` exfil hid inside the Cloudflare range the
  registry/CDN allowlist needs. CIDR allowlists are retained only as a no-hostname
  fallback (no FP regression on legit CDN fetches). Static counterpart
  `iocs.abuse_hosting_callback` flags the same hosts in source URLs.
- **Static install-time recon detectors (npm).** `installer.npm_install_{host_recon,
  network_recon,ci_secret_harvest}` and the `recon_exfil` chain — host/network
  fingerprinting and CI-secret harvest (`GITHUB_TOKEN`, `NPM_TOKEN`, CI env) in lifecycle
  scripts and referenced JS, the fast-path for the recon→exfil stealer class.
- **Vault-first detonation.** Async detonation now detonates the exact frozen bytes from
  the sample vault instead of re-fetching by name+version — a malicious release is often
  yanked before async detonation runs, so a re-fetch detonated a takedown placeholder
  (`0.0.1-security`) instead of the payload. Falls back to re-fetch only when unvaulted.

### Changed
- **Default LLM triage model → `deepseek/deepseek-v4-flash`** (was `z-ai/glm-5.1`). A benchmark
  over 9 labeled real samples (5 malware incl. a RAT + a basE91 backdoor + a dep-confusion
  second-stage, 4 distinct benign-FP classes) scored it perfect — 5/5 malware not suppressed,
  4/4 false positives cleared — at **~14× lower cost** than glm-5.1 (which left one FP
  un-cleared). Override with `PKGWARD_LLM_MODEL`; `moonshotai/kimi-k2.6:free` was an equally
  accurate free option. `openai/gpt-oss-20b` and `minimax/minimax-m2.5` cleared real malware in
  testing — do not use them.
- **Threat-intel auto-seeding now defaults OFF** (`PKGWARD_THREATINTEL_AUTOSEED=0`). A
  double-confirmed false positive self-seeds its own fingerprints and re-confirms on every
  later release (the graphifyy class). Re-enable explicitly once the defensive-module guard
  lands.

## [0.5.2] — 2026-06-02

### Known limitations
- **Static deobfuscation is shallow.** The encoded-payload decode pass handles single-layer
  base64/hex; multi-layer chains, compression codecs (gzip/zlib/lzma), XOR, and JavaScript
  AST-level deobfuscation (packed/minified bundles) are not yet unrolled statically. Heavily
  obfuscated payloads may slip the static layers — the detonation sandbox still observes their
  runtime behaviour.
- **LLM triage supplements the static rules; it isn't required for detection.** Triage runs only
  on rule-flagged packages and can clear a likely false positive, but an LLM error or absence
  never suppresses a rule-malicious alert (fail-open). The scanner functions without it.
- **npm throughput is host-bound.** npm ingests every new release and can out-pace a single
  worker host; horizontal scaling is the lever.

### Added
- **Weekly-download estimate in alerts + DB (blast-radius triage).** Every Discord
  alert now shows a `Downloads/week` field, and the count is cached on the `Package`
  row (`downloads_weekly` + `downloads_fetched_at`, additive migration). Lets an
  operator instantly separate a high-blast-radius compromise of a popular package
  from a zero-install lure — e.g. a false-positive on `google-adk` shows ~7.9M/week,
  while a malicious `@search-rank-bench/fixtures` shows `0 (no install base)`.
  Sources: npm + PyPI exact last-week (`api.npmjs.org`, `pypistats.org`), crates.io
  a ~90-day-derived weekly estimate, Go modules `n/a` (no public stats). Fetched at
  alert time (rare → low API volume) with a 7-day TTL; fully fail-soft (any
  network/parse error → `n/a`, never blocks an alert) and only definitive counts are
  cached (a transient 429/timeout retries rather than pinning `n/a`).
  `pkgward/enrich/downloads.py`. Toggle `PKGWARD_DOWNLOADS_ENABLED`.
- **Threat-intel auto-seeding — the campaign-recognition moat.** On a
  double-confirmed-malicious scan, the fingerprints (SHA-256 + ssdeep + TLSH) of
  the *implicated* files (those that drew a high/critical finding — the loader, the
  payload) are inserted into `threat_intel_hash` with `source="auto"`.
  `threat_intel.check_file` already matches every future file against that table, so
  the next package reusing the same (SHA-256) or a *tweaked* (ssdeep ≥70 / TLSH
  ≤120) payload is recognized **instantly, before the LLM** — turning a one-off
  catch into campaign-wide coverage (the meoo-* / rookie-security-test family
  rotates package names + the C2 subdomain but ships the same implant). Dedup is on
  SHA-256, so one payload across many names collapses to one fingerprint. `pkgward
  threatintel backfill` seeds from all historical confirmed-malicious scans in one
  shot; `pkgward threatintel stats`. **`FileHash` now persists `tlsh`** (was
  computed in-memory only) so backfill + matching get the full 3-tier fuzzy hash;
  an idempotent additive migration adds the column to existing DBs.

  **Now ships OFF by default** (`PKGWARD_THREATINTEL_AUTOSEED=1` to opt in). Shipping it
  *on* was, in hindsight, a mistake. A *double-confirmed* false positive — rules **and** LLM
  both fooled, e.g. a package's defensive `security.py` that lists the cloud-metadata IP
  `169.254.169.254` in a *blocklist* to **prevent** SSRF — gets its own SHA-256 auto-seeded,
  then re-matches and re-confirms itself on every subsequent release. The result is a
  self-perpetuating false positive that only a manual `threatintel remove` can put down. An
  automated moat that occasionally bricks a popular, legitimate package isn't a moat — it's a
  foot-gun with excellent aim. Disabled by default; `threatintel remove <campaign>` clears any
  seed that already snuck in.
- **`malware.credential_store_sweep` (critical) + `malware.etc_shadow_read` (high)
  — catch info-stealers by their harvest, not just their delivery.** A single source
  file that reaches into **≥3 distinct credential stores** (`/etc/shadow`,
  `/proc/<pid>/environ`, k8s service-account token, `~/.ssh` keys,
  `~/.aws/credentials`, `~/.npmrc`, browser/crypto cred files, bulk `process.env`
  harvest) is a stealer regardless of how it exfiltrates — a legit lib touches one
  store, an implant sweeps many (near-zero FP). The meoo-* / rookie-security-test
  campaign previously fired only the single install-time net+exec rule; now the
  `index.js` harvest (shadow + SSH + k8s SA + env) is flagged critical too.
  `analyze/secret_access.py`.
- **Detonation `dyn_install_exfil` re-enabled (high) + expanded `net_allow`.** Now
  that the per-ecosystem allowlist covers legit download hosts (registries + github /
  githubusercontent / jsdelivr / unpkg / nodejs.org / mirrors), an install-phase
  connect to a *remaining* (non-allowlisted) host is exfil-shaped and flagged —
  catching the stealer C2 connect (`115.190.132.46:8888`) that the noise-filter fix
  just made visible. Set to **high** (not critical) so a lone connect to an unlisted
  host corroborates rather than solo-flipping to malicious — FP-safe.
- **Hardcoded-C2 / SSRF IP detection + a decode-and-rescan pass.** Malware hardcodes
  C2 IPs (to dodge DNS/sinkholes) and hides IOCs behind simple encodings. New:
  `iocs.hardcoded_wan_ip_port` (high) — a **routable IP literal with an explicit
  port** (`195.201.194.107:8010`), excluding private/loopback/link-local/doc ranges
  and public DNS resolvers; `iocs.cloud_metadata_endpoint` (medium) — the cloud
  metadata SSRF / credential-theft endpoints `169.254.169.254` and `169.254.170.2`
  (kept despite the link-local skip). **Decode pass:** base64 / hex / `\xNN` blobs
  are decoded and re-scanned, so a URL or IP **hidden inside an encoded blob**
  surfaces as `iocs.encoded_url` (medium) / `iocs.encoded_ip` (high) — concealment
  is itself a signal. Benign/whitelisted domains and non-printable blobs are skipped.
- **Detonation: stop blinding on `node`/`npm` execs (the recurring npm gap).** The
  exec-noise filter dropped *every* `node`/`npm` exec by binary — which is npm's
  headline attack surface (a malicious `node <script>` lifecycle hook). 3+ live cases
  (RH worm, `logger-active`, `faster-axios` ×2) ran their loader invisibly. The filter
  is now argument-aware (`detonation/internal/baseline/filter.go`): a node exec running
  a **local `.js` lifecycle script** survives, while the benign internal invocations
  (`node -e` probes, npm's own CLI, `node-gyp`) stay filtered — un-blinding the loader
  without the npm-internal flood.
- **Scope-watchlist — watch a whole org, not single names (closes the
  `@redhat-cloud-services` ingest-blindness).** The ingest gate enqueues only
  brand-new names or top-N watchlist packages, so an *established* (non-top-N) org
  package's compromised version bump is skipped — exactly how 29/31 of the RH-worm
  versions were never ingested. A watched **scope** means every package + every
  release under an org is ingested at **high** priority. Cross-ecosystem, matched
  as a prefix-with-boundary: npm `@org`, gomod module-path prefix
  (`github.com/aws`, `golang.org/x`, `k8s.io`), pypi name prefix (`azure-`);
  crates is unsupported (flat namespace — would need owner-metadata). Seeded with a
  curated set of high-blast-radius vendor scopes per ecosystem (mega-prolific
  `@types`/`@babel` excluded by default, opt-in via
  `PKGWARD_SCOPE_WATCH_PROLIFIC=1`). **Auto-escalate:** when one package in a
  scope is double-confirmed malicious, the whole scope is watched automatically —
  catching a self-replicating worm's spread to the org's *other* packages within
  the same wave (the Shai-Hulud / RH-worm pattern). New `watchlist_scope` table;
  `pkgward scope {list,add,remove,seed}` CLI; toggle with
  `PKGWARD_SCOPE_WATCHLIST` (default on).
- **Resident-agent loader detection (npm) — catch infostealer loaders at the
  loader, not the payload signature.** The `logger-active`/`utils-terminal` stealer
  family (crypto-wallet theft + keylogger + screenshots, identical 836 KB
  `payload.js` republished under rotating lure names) previously fired only
  `yara.crypto_wallet_stealer` on the payload — one signature away from a miss. The
  `postinstall` loader (`utils.js`) is now caught structurally:
  `installer.npm_install_persistence_loader` (**critical**, behavioral-chain →
  malicious) fires when a lifecycle hook both **registers OS persistence** (systemd
  `--user` unit / launchd `.plist` / Windows Run-key·`.vbs` / XDG autostart / cron)
  **and** spawns a **detached, unref'd** background process — the resident-agent
  fingerprint, stable across payload variants. Each half alone scores high
  (`installer.npm_install_persistence`, `installer.npm_install_detached_spawn`).
- **Detonation honeytokens + canary tripwire — make environment-aware worms act,
  then catch them.** Many supply-chain worms only harvest when secrets are actually
  present; the `@redhat-cloud-services` worm decrypted its payload, found an empty
  sandbox, and exited in 1.3 s without touching the network — so detonation saw
  nothing. Every sandbox phase (all ecosystems, install + import) is now seeded with
  a broad, **realistic** decoy "developer/CI machine" (`internal/honeytokens`):
  **42 env vars** (AWS×3, GCP/Azure/DigitalOcean/Cloudflare, OpenAI/Anthropic/Gemini/
  HuggingFace/Groq/OpenRouter/Replicate/Perplexity/Mistral/Cohere/xAI, GitHub/GitLab/
  npm/Cargo, Stripe/SendGrid/Twilio, Slack/Discord/Telegram, Postgres/Redis,
  Vercel/Netlify, ETH key) + CI markers, and **16 on-disk files** (`~/.npmrc`,
  `~/.aws/{credentials,config}`, `~/.pypirc`, `~/.config/gh/hosts.yml`,
  `~/.git-credentials`, `~/.netrc`, `~/.docker/config.json`, `~/.ssh/id_rsa`+`id_ed25519`,
  gcloud ADC, `~/.kube/config`, `~/.cargo/credentials.toml`, solana key, an ethereum
  keystore, `~/.env`). Values are **generated at runtime (crypto/rand, per process),
  unique, and indistinguishable from real credentials — no "decoy"/"test" tell, and no
  literal secret in the source** (so an evasion-aware worm can't fetch the decoy list
  from the repo and skip-list it; one that spotted a tell would go dormant). Two tripwires catch the resulting theft: `dyn_credential_read` (now
  covering the new decoy paths) flags *reads* and names the file — the worm's target
  list; and the new **`dyn_honeytoken_exfil`** canary fires **critical** when any decoy
  *value* surfaces in traced activity (exec arg, written file, DNS label), naming which
  secret was taken — near-zero FP and no network allowlist needed (unlike the broad
  `dyn_install_exfil`, which leans on the network allowlist). The decoy home is **materialized once on the
  host and bind-mounted read-only** into every sandbox (`internal/honeytokens`,
  `SandboxConfig.DecoyHome`) — nothing is written inside the container, so no decoy
  value can land in a guest exec argv and false-trigger the canary on our own
  seeding. `.npmrc` stays noise-filtered (npm reads it legitimately) — its token is
  covered by the value-canary instead.
- **Detonation settle window — catch self-detaching payloads.** Many loaders spawn
  the real payload **detached** and exit immediately (e.g. `logger-active`'s
  `postinstall: node utils.js` → detached `--bg` agent), so the container was torn
  down before the payload acted and the trace was empty. The npm install phase now
  ends with a bounded `sleep ${DET_SETTLE_SEC:-10}` so the detached payload runs
  while Tetragon is still tracing. Validated: detonating `logger-active@3.2.0` now
  surfaces its live behavior (C2 beacon to `195.201.194.107:8010`, `/etc/passwd`
  read, screen-capture/keylog tool enumeration).
- **`dyn_screen_capture_probe` (high) — desktop-surveillance staging.** Fires when a
  package probes (`which`/`command -v`/`whereis`/`type`) for screenshot/screen-record
  or input-capture tools (`scrot`, `maim`, `grim`, `spectacle`, `gnome-screenshot`,
  `ksnapshot`, `flameshot`, `xwd`, `slurp`, `xinput`) during install/import — near-zero
  legitimate use in a package lifecycle. Clipboard tools (`xclip`/`xsel`/`wl-paste`)
  and dual-use `import`/`xdotool` are excluded to keep FP near zero. Caught
  `logger-active@3.2.0` dynamically.
- **Self-decoding-packer detection (JS) — closes the `@redhat-cloud-services`
  worm false-negative.** The June 2026 npm supply-chain worm (Shai-Hulud-class,
  31 `@redhat-cloud-services/*` packages) shipped a `preinstall: node index.js`
  whose 4 MB `index.js` layered **Caesar-cipher `eval(char-code array)` →
  AES-128-GCM `createDecipheriv` → eval** to hide a Bun-runtime downloader +
  token-harvest/self-replication worm. It scanned **clean (score 0)**: the
  obfuscation layer skipped the file (4.1 MB > the old 4 MB cap) and didn't know
  the char-code/crypto family; the install-script layer saw a bare `eval(` with
  no visible network/base64. Now caught by three new rules:
  `obfuscation.charcode_eval` (high — `String.fromCharCode`/`charCodeAt`/long
  decimal array feeding `eval`/`Function`), `obfuscation.decrypt_then_exec`
  (high — `createDecipheriv` feeding `eval`/`Function`), and
  `installer.npm_install_obfuscated_entrypoint` (**critical**, behavioral-chain →
  malicious — an npm lifecycle hook that runs a local script which self-decodes
  into `eval`/`Function`). The obfuscation alphabet/CJK cap is raised 4→10 MB
  (`PKGWARD_OBFUSCATION_MAX_MB`) and the cheap packer scan runs up to 32 MB
  (`PKGWARD_OBFUSCATION_PACKER_MAX_MB`) so a multi-MB hand-packed install file
  is no longer skipped. Validated: the live `tsc-transform-imports@1.2.2` /
  `frontend-components-advisor-components@3.8.2` samples now score **malicious**.
- **Run-time packer detection + UPX static unpacking.** Packed executables are a
  blind spot — opaque to every static analyzer *and* to the LLM (which reads
  source, not a compressed stub). The scanner now (1) detects packer signatures
  on shipped executables and (2) *attempts to unpack what is safely unpackable,
  statically, without ever executing the binary*: it bundles `upx` and runs
  `upx -d` (decompress-only, timeout + output-size-capped) on UPX-packed payloads,
  writing the recovered payload back into the extraction tree as
  `<name>.upx_unpacked` so every analyzer + threat-intel hashing sees the real
  payload. New `binary.packed_executable`, tiered: **critical** for commercial
  protectors (Themida/VMProtect/Enigma — no static unpacker exists, ~zero legit
  use in a source package), **high** for UPX that can't be unpacked
  (anti-unpack/unavailable), **medium** once UPX is unpacked and the payload
  re-analyzed (UPX has occasional legit use). Validated on the crates `eqr`
  package: its UPX-packed Rust CRC16 binary `cr16` previously drove a false
  `malicious` (73) + Discord alert; with unpacking the benign payload is read and
  the verdict drops to `suspicious`. Conversely, a real packed payload now has its
  IOCs/YARA surfaced instead of hidden. Knobs: `PKGWARD_UPX_BIN`,
  `PKGWARD_UNPACK_TIMEOUT`, `PKGWARD_UNPACK_MAX_MB`, `PKGWARD_UNPACK_MAX_FILES`.
- **`iocs.oast_callback` (high) — out-of-band-interaction callback domains.** A
  package whose source beacons to a known OOB-interaction / request-capture
  service (oastify.com, interact.sh, oast.*, burpcollaborator.net, webhook.site,
  requestbin, dnslog.cn, canarytokens, …) is near-certain exfil/C2 — these have
  no legitimate install-time use. Previously scored only as a generic
  `iocs.url_suspicious` (low, 1 pt); now `high`, mirroring `iocs.onion`. Caught
  live: `adminui-deps` (preinstall recon → `oastify.com`). Makes the malicious
  verdict robust without depending solely on the install-script net+exec rule.
  Dual-use dev tunnels (e.g. ngrok) are deliberately excluded.
- **`metadata.dependency_confusion_version` (low).** Flags all-nines / repeated-
  equal-component versions (`99.99.99`, `9.9.9`, `10.10.10`, `11.11.11`) as
  corroborating evidence of dependency-confusion semver inflation. Tighter than
  the npm-ingest priority check — excludes calendar versions (`2024.x`) so it
  won't false-fire. (Investigated promoting the `opengrep.shadow_js_*` taint
  rules out of shadow too, but measured only 12% / 0% malicious-precision on real
  traffic — too false-positive-prone, kept in shadow.)
- **npm install-attack packages jump the queue.** The npm backlog can run tens
  of thousands of items deep, so a brand-new package historically waited days at
  `normal` priority before being scanned — long enough for a live credential-
  stealer campaign to finish (e.g. the May 2026 `oob.moika.tech` / `99.99.99`
  dependency-confusion campaign: 164+ packages were ingested within minutes of
  publish but sat unscanned behind ~23K older `normal` items). The npm cursor
  already fetches `dist-tags.latest` to resolve a version; it now reads the same
  manifest's `scripts` and `version` and enqueues a brand-new package at `high`
  priority when it (a) declares an install lifecycle hook
  (`preinstall`/`install`/`postinstall`) — the on-install code-execution surface
  — or (b) carries a dependency-confusion version tell (`99.99.99`, `9.9.9`,
  `10.10.10`, `11.11.11`, absurd majors). Zero extra network cost; never
  downgrades watchlist/focus. The `changes_poll` log gains `promoted_high`.
- **`analyze/obfuscation.py` — custom-encoding + non-ASCII-identifier detection
  (all ecosystems).** The base64/entropy heuristics were blind to a whole
  obfuscation family: custom radix alphabets (base85 / basE91 / z85 and shuffled
  variants) decode through hand-rolled accumulator loops, not `atob`/`Buffer.from`,
  and their punctuation-heavy output has no long `[A-Za-z0-9+/]` run to trip the
  encoded-payload regex; identifier renaming into CJK (hiragana/katakana) defeats
  human review without raising file entropy. New layer flags two near-zero-FP
  tells in install-reachable source: `obfuscation.rotating_alphabet_codec` (**high**,
  ≥2 distinct ~85–91-char near-all-unique-printable alphabet literals = a packer),
  `obfuscation.custom_alphabet_codec` (**low**, exactly one — could be a codec lib),
  and `obfuscation.nonascii_identifiers` (**medium**, ≥8 distinct CJK identifiers
  after stripping strings/comments so CJK-authored libraries don't false-positive).
  Caught live: npm `baileys-mbuilder` (basE91 with 19 rotating alphabets + 50
  hiragana identifiers hiding an install-time GitHub remote-code fetcher) scored
  the obfuscation category to its cap on these tells alone — independent of the
  net+exec heuristic that was previously the only thing flagging it.
- **`obfuscation.homoglyph_identifiers` (medium) — confusable-script identifiers.**
  The CJK pass caught wholesale renaming but not the *homoglyph swap*: a Cyrillic `е`
  or Greek `ο` dropped into an otherwise-Latin token (`rеquests`) so malicious code
  reads as a call to a trusted symbol, or fullwidth-Latin forms. Flags a token that
  mixes ASCII Latin with Cyrillic/Greek, or contains fullwidth-Latin, after stripping
  strings/comments. The mix is *required* (or fullwidth) so legit pure-Cyrillic
  (Russian-authored) and pure-Greek (scientific `α`/`β`) identifiers don't
  false-positive. The homoglyph attack swaps only a few tokens, so this fires below
  the CJK threshold where the CJK rule wouldn't. `analyze/obfuscation.py`.
- **pypi install-time subprocess detection now resolves import aliases.**
  `from subprocess import run; run([...])` (bare name) and `import subprocess as sp;
  sp.run(...)` (module alias) were both missed — only `subprocess.X(...)` /
  bare `Popen(...)` fired. Now resolves how subprocess is bound in the file and
  flags aliased calls; gated on the actual import so a package's own local `run()`
  doesn't false-positive. `ecosystems/pypi/installer.py`.
- **`malware.credential_store_sweep` ssh-store widened** to `~/.ssh/authorized_keys`,
  `known_hosts`, and `~/.ssh/config` (backdoor-key install + lateral-movement recon),
  not just private-key filenames. `analyze/secret_access.py`.
- **Detonation `net_allow` now supports CIDR ranges (the dominant dyn_install_exfil
  FP fix).** The allowlist resolved hostnames to IPs per-detonation, but CDN fronts
  rotate IPs faster than that resolution tracks, so a legit registry fetch landing
  on an unresolved CDN IP false-fired as install-phase exfil. Mined `trace_event`
  (700+ install-phase connects to a single Fastly IP, etc.) and added the CDN ranges
  each registry actually sits behind — Fastly (`151.101.0.0/16` …) for PyPI/npm,
  Cloudflare (`104.16.0.0/13`) for npm/jsdelivr/crates, Google for the Go proxy, AWS
  CloudFront for S3-backed release assets. Scoped per-ecosystem, not blanket cloud
  allowlisting; the static IOC/opengrep layers still see any exfil URL in source, so
  a C2 hosted on a shared CDN isn't blind. `detonation/internal/baseline/filter.go`.
- **`dyn_suspicious_write` extended** to `/etc/systemd/` + `/etc/init.d/` (service
  persistence), `/etc/ld.so.preload` (global library injection), and
  `~/.ssh/authorized_keys` (SSH backdoor-key install, matched anywhere since it's
  user-relative). `detonation/internal/rules/definitions.go`.
- **Dynamic-rule key-coverage meta-test.** A Go test fails the build if any
  behavioral rule reads a `Detail` key the Tetragon collector never emits and that
  isn't explicitly waived as known-dead. Documents the two currently-dead rules
  (`dyn_reverse_shell` needs `has_socket`; `dyn_dns_exfil` needs `subdomain_entropy`
  — both pending a collector/Tetragon data source) so the coverage gap is honest
  rather than hidden behind synthetic-only green tests. `detonation/internal/rules/keycoverage_test.go`.
- **`dyn_credential_read` now fires on the full honeytoken decoy set.** The Tetragon
  openat selector only traced the original decoy paths (`~/.ssh`, `~/.aws`, `.npmrc`,
  `.cargo/credentials`, `.docker`, `.kube`), so the AI/cloud/crypto decoys added to
  the bind-mounted decoy home were inert — a worm could read them untraced. Extended
  the policy to trace `~/.pypirc`, `~/.netrc`, `~/.git-credentials`, `~/.config/gh`,
  `~/.config/gcloud`, `~/.config/solana`, `~/.ethereum`, `~/.env`, and added
  `/.git-credentials` to `sensitive_path_prefixes` (the others were already present).
  Now a credential sweep of any decoy fires `dyn_credential_read` (high).
  `detonation/deploy/tetragon-policy.yaml`, `rules_data.toml`.
- **`installer.npm_install_remote_binary_drop` (high) — remote-binary dropper with
  host/repo mismatch.** Detects the install-script chain *download → write-to-disk →
  chmod-executable* and scores it **high** when the download host is unrelated to the
  package's declared `repository`/`homepage` and isn't a known release host
  (GitHub/githubusercontent/npm registry/nodejs.org/…), **medium** when the URL is
  built dynamically (no literal host to check). A legitimate native wrapper drops its
  prebuilt binary from its own GitHub releases / the npm CDN, so those don't fire — the
  tell is a binary pulled from an *unrelated* host. Catches the stealth variant the
  net+exec rule misses: download in `postinstall` but defer the exec to the `bin`
  wrapper (no `child_process` in the install script). Caught live: the
  `veteran` / `veteran-proxy` twins (SOCKS5-proxy wrappers whose `repository` claims
  GitHub `veteran-cli/veteran` while `install.js` downloads + `chmod 0o755` + execs a
  binary from `laogou.us`, with a comment falsely claiming "GitHub Releases").

### Added
- **`metadata.gomod_impersonating_forge_host` (high) — Go-module namespace-hijack via
  fake forge domains.** A real attack class surfaced while triaging confirmed-malicious
  gomod samples: legit projects (telegraf, daytona, gitea, kraken) republished under
  module paths whose host *impersonates* GitHub/GitLab but isn't the real domain —
  `github.1485827954.workers.dev/...`, `gh.173371.xyz/...`, `git.832008.xyz/...`. So
  `go get` of the look-alike path pulls attacker-controlled content. Flags a git-prefix
  on a **numeric throwaway domain** (`gh.173371.xyz`/`git.832008.xyz`) or a forge name on
  a **Cloudflare ephemeral host** (`github.<rand>.workers.dev`) — the two host shapes that
  have no legitimate use. Deliberately does NOT flag a bare forge subdomain
  (`gitlab.arm.com`, `gitea.unbound.se`, `github.<company>.com`) — self-hosted GitLab/Gitea
  and GitHub Enterprise legitimately use `<forge>.<org>.<tld>`. Structurally gated to
  module-path names (npm/pypi/crates never match). Live impact: 154 packages across 8
  hijack hosts flagged, zero legit forges. `analyze/metadata.py`.
- **`pkgward threatintel remove <campaign>` — the FP exit-ramp for the fingerprint
  moat.** Deletes a campaign's auto/promoted fingerprints when a seed turns out to be a
  false positive that self-confirms on every rescan. Motivating case: the pre-fix
  `.pth` rule auto-seeded 7 *benign* packages (lovely-tensors, python-certifi-win32,
  cmeel, fortifyos-langchain, …) whose fingerprints then kept re-flagging them as
  malicious; with the rule since demoted, those seeds were pure noise. Removal doesn't
  blind detection — the package is re-evaluated by current rules on its next scan; add
  the name to `WATCHLIST_AUTO_BLOCKLIST` to stop re-seeding. `threat_intel_auto.remove`.

### Changed
- **PyPI detonation import phase actually imports the package now (major — ~91% were
  dead).** The import step ran `python -c "import <dist-name>"`, but the dist name is
  usually hyphenated (`quant-backtest-helpers`) — a Python **SyntaxError** — or simply
  differs from the importable module (`sklearn`/`yaml`/`bs4`). So **~91% of pypi
  detonations (6,583/7,158) failed import with exit 1 and the package's import-time
  code never ran** — detonation was contributing almost nothing for pypi. Now resolves
  the distribution's real top-level module(s) from `top_level.txt` (name-mangling
  fallback) and imports each. Additionally, the settle window is moved **into the
  python process** (`time.sleep`) rather than a shell-level sleep: an import-time
  payload runs in a daemon thread that is killed the instant the interpreter exits, so
  a shell sleep kept the container alive but not the thread. After the fix, post-deploy
  pypi detonations import 5/5 with trace events flowing (was near-zero).
  `detonation/internal/sandbox/profile.go`. (Known follow-up: import-phase **network**
  connects are still not captured by the tracer — a separate gap.)
- **`obfuscation.charcode_eval` downgraded to low in minified build bundles (FP fix).**
  Minified webpack/esbuild/vite/Angular output legitimately uses `String.fromCharCode`
  + `Function` and ships long numeric lookup arrays, so the rule false-fired `high` on
  bundled web UIs — confirmed flipping the legitimate `google-adk` (Google's ~7.9M/week
  Agent Dev Kit) to malicious via its bundled CLI browser `main-<hash>.js`. Now a
  recognized build artifact (output-dir segment like `dist/`/`browser/`, or a
  content-hashed/`.min.js` filename) downgrades the finding to `low` — still visible as
  a corroborator but no longer verdict-driving. `decrypt_then_exec` (`createDecipheriv`
  → eval) is unaffected — that's not a normal bundle pattern. `analyze/obfuscation.py`.
- **`.netrc` removed from the detonation credential-read trigger (FP fix).** pip /
  requests / urllib auto-read `~/.netrc` for HTTP auth during a normal install, so the
  new honeytoken `.netrc` decoy false-fired `dyn_credential_read` on ~9 benign AI/LLM
  packages (langchain / ollama / google-adk class) and helped flip google-adk to
  malicious. `/​.netrc` dropped from `sensitive_path_prefixes`; the decoy is still
  planted + Tetragon-traced, but a single `.netrc` read is no longer treated as theft.
  `detonation/.../rules_data.toml`.
- **`malware.env_bulk_exfil` is now taint-gated — co-occurrence no longer
  auto-malicious.** The rule fired `critical` + behavioral-chain on an `os.environ`
  read and an HTTP send merely *appearing in the same install file*, with no
  dataflow between them. That co-occurrence is the native-wrapper FP shape (read
  build-env for compiler flags, separately download a prebuilt binary) and it was
  pinning false `malicious` verdicts — which then poisoned the auto-watchlist and
  the fingerprint moat (confirmed on several native-wrapper packages). Split in
  two: **`malware.env_exfil_tainted`** (critical + chain) fires only when a light
  intrafile AST taint pass proves an `os.environ`-derived value *flows into* the
  send; **`malware.env_bulk_exfil`** is demoted to `medium` (de-chained) for the
  remaining co-occurrence-without-flow case — a low-weight corroborating signal, so
  it supports other findings but never single-handedly flags or
  pages. A real env-stealer (the value reaches the request body)
  still verdicts malicious; the build-env-read FP no longer does. `analyze/malware_patterns.py`.
- **`malware.pth_import_injection` is now chain-gated — APM `.pth` files no longer
  auto-malicious.** Any `.pth` containing an `import` line fired `critical` + chain,
  matching every legit auto-instrument bootstrap (Datadog / Sentry / OpenTelemetry /
  coverage.py) — confirmed FPs on legitimate auto-instrument packages. Split: a `.pth`
  *import line that runs a code-exec primitive at startup* (`import os; os.system(...)`,
  `exec`/`b64decode`/`__import__`/socket/…) is **`malware.pth_exec_injection`**
  (critical + chain — the real injection technique); a *bare* `import <module>` is
  flagged `high` as **`malware.pth_import_injection`** only when the module is
  neither shipped by the package nor stdlib (an at-startup sideload). A bare import
  of a shipped module is not flagged — that module is analyzed on its own, so no
  coverage is lost. `analyze/malware_patterns.py`.

### Fixed
- **NUL bytes in metadata/findings no longer fail the scan write.** Postgres
  `TEXT`/`JSONB` columns reject NUL bytes, so a single NUL anywhere in a scan's
  persisted strings — package metadata, a finding's evidence/path, an LLM field —
  raised `ValueError: A string literal cannot contain NUL (0x00) characters` and
  marked the whole scan failed. Observed on an npm package shipping a UTF-16
  `summary` (NUL between each character); also an evasion vector (a package could
  embed NUL to crash persistence and avoid being scanned). All persisted strings
  are now NUL-stripped at the persistence boundary (`_strip_nul`, recursing into
  the `metadata_json` audit blob and LLM JSON).
- **Queue enqueue survives Postgres deadlocks.** Concurrent ingest pollers
  (pypi/npm/gomod/crates feeds + watchlist refresh) all INSERT into `ScanQueue`
  and can deadlock on the `uq_scanqueue_ecosystem_name_version` unique index.
  `enqueue()` previously caught only `IntegrityError`, so a `DeadlockDetected`
  (an `OperationalError`) propagated uncaught and aborted the whole poll cycle
  with a raw traceback. It now retries the savepoint-scoped insert a bounded
  number of times (`PKGWARD_ENQUEUE_DEADLOCK_RETRIES`, default 3) — the
  deadlock victim's `ROLLBACK TO SAVEPOINT` recovers the transaction and a
  concurrent poller has committed by the retry — then skips the item (re-listed
  on the next poll) rather than crashing. No data loss either way; observed
  during the 0.5.2 soak at ~2/3h.
- **npm ingest no longer silently drops brand-new packages on a transient
  resolution failure.** Unlike the PyPI/Crates/Go feeds (which carry the
  version inline and enqueue in-transaction), the npm CouchDB `_changes` feed
  carries only the package *name*, so the cursor makes a second call to
  resolve `dist-tags.latest` before enqueuing. When that resolve failed for a
  transient reason (429/5xx past the built-in retries, or a network timeout),
  `_resolve_latest` returned `None` and the package was skipped — but the
  forward-only cursor had already advanced past it, so the brand-new package
  was *never re-examined and never scanned*, with nothing logged. The cursor
  now records each gated package's change-feed `seq` and advances only up to
  (not past) the earliest still-unresolved package, so the next poll re-fetches
  and retries it. A bounded per-name retry (`NPM_RESOLVE_MAX_ATTEMPTS`, default
  5) then gives up with an `npm_resolve_gave_up` warning, so a genuinely-deleted
  package (permanent 404) can't wedge the feed. Backfilled the npm cursor's
  previously-absent behavioral tests. Empirically the drop rate is ~0% under
  normal load, but the path was a real silent-miss vector for the brand-new
  lure-package gate (one-off network timeouts over time, npm incidents in bulk).
- **Metadata `maintainer_change` false positive when current author metadata is
  absent.** The detector compared the current release's maintainers against the
  previous release's; when the current release simply had no author field, the
  empty set read as "every maintainer was removed" and emitted a spurious
  medium-severity finding. It now requires both sides to be populated before
  comparing.
- **LLM triage no longer holds a DB transaction across its HTTP call.** `_persist_and_finalize`
  ran the whole scan in one `session_scope`, with the ~60–180s OpenRouter triage call
  *inside* it — pinning a pooled Postgres connection plus the claimed-row + Scan/Finding
  row locks for the duration. A burst of malicious packages could exhaust the connection
  pool and stall **every** worker behind triage latency, and the malicious scan record was
  contingent on triage completing (a crash mid-call rolled the whole scan back). The
  persistence path is now split: scan + findings + file-hashes + detonation-enqueue commit
  in one short transaction; the LLM call runs with **no session open**; a second short
  transaction writes the `llm_*` columns + verdict override + auto-watchlist. Clean/
  suspicious scans still finalize in a single transaction (only malicious scans triage).
  The Discord alert fires *before* the final `mark_done`, so a crash in that window
  re-scans and re-alerts rather than losing the alert. Mirrors the detonation-decouple
  pattern already in the codebase.
- **Queue claim drains a hot backlog under contention instead of idling.** On a claim
  CAS-race (another worker took the row), `claim_next` fell through to the next ecosystem
  and could return "nothing to do" even with thousands of pending rows — N workers
  colliding on the head of the npm backlog all went idle. It now retries the *same*
  ecosystem (the lost row is now `claimed`, so the next select returns the next-oldest),
  bounded by `_CLAIM_CAS_RETRIES`.
- **`scan_queue` is now pruned.** Terminal (`done`/`failed`) rows accumulated forever
  across "all new packages" on four ecosystems, degrading the per-claim pending-count
  aggregate and the unique-index dedup on every ingest INSERT over time. A 6-hour janitor
  (`prune_terminal`) deletes terminal rows older than `PKGWARD_QUEUE_RETENTION_DAYS`
  (default 14). Mirrors the existing detonation-queue cleanup.
- **Discord alerts retry transient failures instead of dropping them.** The webhook POST
  was single-shot — a 5xx, a 429, or a timeout silently lost the alert (the only signal an
  operator gets that a package is malicious). It now retries with backoff, honors a 429
  `retry_after`, and fails fast only on a non-retryable 4xx. The rate-limit throttle also
  no longer holds its lock across the inter-send sleep (which serialized all senders during
  a malware burst).
- **`enqueue` survives a statement/lock-timeout without crashing the poll cycle.** Only a
  Postgres *deadlock* was caught+retried; a `statement_timeout`/`lock_timeout` (also an
  `OperationalError`, and they spike together under load) hit the bare `raise` and aborted
  the whole ingest poll — the exact failure the deadlock retry was added to prevent. These
  are now treated as a bounded give-up (item re-listed next poll).
- **Obfuscation analyzer size-capped per file** (`PKGWARD_OBFUSCATION_MAX_MB`, 10 MB for the
  alphabet/CJK passes; `PKGWARD_OBFUSCATION_PACKER_MAX_MB`, 32 MB for the cheap packer scan).
  The regex passes cost ~5s on a 20MB minified blob, so a giant bundle can't burn worker CPU —
  while still covering the multi-MB hand-packed install scripts that motivated the higher caps.
- **Giant-package fast-path (`PKGWARD_GIANT_FASTPATH`, default on).** A handful of huge
  packages — Go monorepos (gitea, go-ethereum, …) and fat JS component libs — take tens of
  seconds of pure-Python CPU to fuzzy-hash + analyze; with many workers in one process sharing
  the GIL they blow the 15-min per-package timeout and burn a worker (observed: ~6 timeouts in
  the first 2h of soak, all giants). When a package exceeds `PKGWARD_GIANT_FILE_THRESHOLD`
  (5000 files) or `PKGWARD_GIANT_MAX_MB` (100 MB) extracted, the scanner skips the heaviest
  per-file work — ssdeep/TLSH fuzzy hashing, entropy, and the obfuscation analyzer — while
  keeping SHA-256 (exact threat-intel), opengrep, YARA, IOC, import, malware-pattern, binary,
  and metadata detection. Detection-critical signatures stay; only fuzzy-hash + entropy/
  obfuscation heuristics are dropped on giants (low risk — giants are legitimate large projects,
  not lures). Logs `giant_fastpath`. Toggle off with `PKGWARD_GIANT_FASTPATH=0`.
- **LLM triage: truncated-clearing-verdict suppression fixed + harder cost cap.** A response
  cut off by `finish_reason=length` that still parsed but *cleared* a rule-malicious package
  (benign/suspicious) was accepted as authoritative, silently suppressing the alert; it now
  escalates the token budget and retries, failing open if it can't get a complete answer.
  The budget is also re-checked before each retry (not once per package) and cost is recorded
  per attempt, so the `MAX_USD` cap is meaningfully hard under concurrency; failed upstream
  calls now count against the per-hour rate cap; and a token-based estimate
  (`PKGWARD_LLM_EST_*_USD_PER_1K`) is used when the provider doesn't report `usage.cost`,
  so the cap can't be defeated by a route that omits cost.
- **Async detonation: no duplicate work / alerts, transient archive misses retried.**
  `_finalize_detonation` now bails if a stale-claim sweep reassigned the job (was writing a
  duplicate `Detonation` row + re-scoring + firing a second flip-alert); a `NoFilesError`
  (archive temporarily unavailable) is retried within the bounded budget instead of being
  permanently failed; and the retry budget now counts real failures rather than every claim,
  so claim races / worker deaths don't burn it.
- **Extraction streams members + checks disk first.** Each archive member was read whole into
  memory (`src.read()`) — a single ~500MB member spiked RSS per worker; members are now copied
  in 1MB chunks. Extraction also refuses to start on a near-full disk (clear error instead of a
  partial write that dies on ENOSPC mid-extract).
- **npm resolve-attempt counter is hard-capped** so a name that vanishes mid-retry can't strand
  its entry and grow the dict without bound over a long uptime.
- **Crates ingest reconciliation backstop.** Crates discovery was a pure RSS snapshot
  with no cursor, so a failed/slow poll, a publish burst exceeding the feed window, or a
  restart spanning it silently dropped every crate in the gap — permanently, with no way
  to recover (unlike PyPI/npm/gomod, which resume from a saved position). A new 15-min
  `crates_reconcile` job re-derives the newest crates from the authoritative crates.io API
  (`sort=new`) and enqueues any the RSS feed missed. Additive — it only ever *adds*
  (enqueue dedups), so it can't drop a package. Tunable via `CRATES_RECONCILE_PAGES`.
- **gomod cursor no longer advances past a brand-new module it failed to enqueue.** The
  forward-only timestamp cursor advanced for every entry the moment it was read — so if a
  brand-new module's `enqueue` returned `None` (deadlock give-up / race), the cursor moved
  past it and it was never rescanned (the same silent-drop class the npm cursor's holdback
  fixed). The persisted cursor is now held just before the earliest unconfirmed brand-new
  entry; `already_known` gates it next poll so it can't dedup-wedge.
- **gomod poll can't hang on a same-timestamp page.** If a full 2000-entry page shared one
  timestamp at cursor resolution, `since=max_cursor` re-fetched the identical page forever.
  The loop now detects a non-advancing cursor and steps past it (a rare, bounded skip)
  rather than wedging the feed.
- **Hardening pass (queue/worker/ingest resilience).** A maintenance review of the
  failure paths fixed five further robustness issues, none changing happy-path behavior:
  - *Stale-claim sweep no longer races a still-running worker.* `STALE_CLAIM_TIMEOUT_SECONDS`
    equalled the worker `PROCESS_TIMEOUT_SECONDS` (both 900s), so a package processing
    at the boundary could be reclaimed by the sweeper at the same instant the worker's
    own timeout fired — two writers on one row, and a re-claim re-scanned the package
    (wasted work + duplicate detonation enqueue). Raised to 1800s (2×) for clear daylight.
  - *Failure handler can't be crashed by a NUL in the error text.* `mark_failed` wrote the
    raw error string (which can embed package-controlled bytes) to a Postgres `TEXT`
    column; a NUL would raise inside the failure handler itself and leave the row stuck
    `claimed` until the sweep. The error is now NUL-stripped.
  - *A transient DB error during claim no longer permanently kills a worker.* `claim_next`
    ran in an unguarded `session_scope`; an exception propagated out of the worker loop
    and `run_pool` never restarts a dead task, so capacity silently shrank one worker at
    a time. The claim is now wrapped — a hiccup logs and falls through to an empty poll.
  - *A malformed gomod feed timestamp no longer wedges the poll.* `_ts_to_cursor` parsed
    without a guard, so one bad upstream timestamp raised out of the page loop, rolled
    back the page's enqueues, and re-aborted every subsequent poll on the same row. The
    entry is now skipped-and-logged (like a bad NDJSON line); the cursor doesn't advance
    past a skipped row.
  - *Archive-listing failures are now observable.* `_archive_members` swallowed any error
    to an empty list, silently blinding the sdist/wheel-mismatch and lure-file metadata
    checks (they saw zero files). It now logs `archive_members_failed`.
- **npm detonation now runs the target's lifecycle hooks directly, so a heavy
  dependency can't shadow an install-hook payload.** The npm profile detonated
  via `npm install <tarball>`, which resolves and installs the full dependency
  tree *before* the target's `postinstall` runs. A package declaring a heavy /
  native dependency (e.g. `sharp`, which downloads prebuilt libvips at install)
  could run out the 120s install timeout before its own hook ever fired — so the
  payload never executed and the tracer saw nothing. Exactly how `baileys-mbuilder`
  (dep `sharp ^0.33.0`, postinstall `node index.js --install` fetching remote code
  from GitHub) evaded dynamic capture: the install exited non-zero with only the
  entrypoint exec traced. The profile now mirrors pypi's `--no-deps` intent — it
  extracts the tarball, places dependencies best-effort with **scripts off and
  time-bounded** (so a native dep's download script can't consume the budget),
  then runs the package's own `preinstall`/`install`/`postinstall` bodies directly
  so Tetragon traces whatever they exec/connect/write regardless of dependency-tree
  health. (Network egress was verified working — the sandbox reaches GitHub fine —
  so this was never a connectivity gap.) Detonation (Go) service change.
- **`pkgward.__version__` no longer reports a stale hardcoded value.** It was
  pinned to `"0.5.0"` and never bumped, so the outbound User-Agent advertised
  `pkgward/0.5.0` while the package was 0.5.2. It now derives from the installed
  package metadata (`importlib.metadata.version`) with the literal only as a
  source-tree fallback, so it can't drift from `pyproject.toml` again.

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
  `pkgward watchlist auto {list,remove,purge,backfill}` CLI. The four
  ecosystem `refresh_watchlist` paths now skip auto-rank rows so popularity
  refresh can't evict them. Disabled with `WATCHLIST_AUTO_MALICIOUS=0`. See
  `docs/operations.md` → "Auto-watchlist (confirmed-malicious gate)".
- **Finding carry-forward for confirmed-malicious re-publishes.** When a
  package on the auto-watchlist publishes a new version that mostly re-uses
  files from the prior one (a version bump + a handful of changed files, as
  the `forge-jsxy 1.0.107 → 1.0.120` series did — 29 byte-identical RAT
  re-publishes), our `changed_files` optimization causes analyzers to skip
  the unchanged files → the new scan reports only the deltas (e.g. 3 of 11
  findings), thinning the LLM's evidence basis and leaving the verdict to
  ride entirely on the install-script chain rule. For *auto-watchlisted*
  names only, the pipeline now queries the most-recent prior scan within
  `PKGWARD_FINDING_REUSE_DAYS` (default 7) and **pulls forward** every
  prior finding whose file's `(path, sha256)` is unchanged. Scoring + the
  LLM see the full evidence; analyzers still don't re-run on unchanged
  files (no extra CPU). Scoped to known-bad names so a yara/opengrep rule
  update doesn't risk stale-cache false-negatives on clean packages.
- **Detection regression suite** — a labeled corpus of known-bad / known-good sample packages
  (`tests/corpus/`) run through the real analyze→score path, so a change that starts missing
  malware (false negative) or over-flagging clean packages (false-positive creep) fails the
  build. Verdict label is the primary gate; optional per-sample `expect_rules`/`forbid_rules`
  pin which rule should/shouldn't fire. A shared `pipeline.run_static_analyzers` seam keeps the
  harness from drifting from production. `tests/test_rule_coverage.py` enumerates every scored
  rule_id and asserts each is either sampled or explicitly waived, so new rules can't ship
  untested and renamed/removed rule_ids are caught. Operators can layer private samples via
  `PKGWARD_CORPUS_PATH`. See `docs/regression-testing.md`.
- **opengrep `--test` fixtures for Python/Rust/Go** — the python/rust/go rule directories now
  ship `--test` fixtures (previously JavaScript-only), so all four language rule sets self-test.
- **Frozen malicious-sample vault** — preserves the original archive of anything flagged
  `malicious` (inert, password-protected) before the registry yanks it, as a permanent
  regression anchor + forensic reference. Auto-captured by the pipeline when
  `PKGWARD_VAULT_PATH` is set (a no-op otherwise) and backfillable with `tools/vault_import.py`.
  Vault entries are only ever statically analyzed, never detonated.
- **Horizontal scan scaling.** Additional worker hosts can drain the same DB-coordinated scan
  queue (claim-token compare-and-set, no double-work). Run a second host with `SCANNER_INGEST=0`
  (only the primary polls feeds/cursors) and, if it has no local detonation service,
  `DETONATION_ENABLED=1` so its scans still enqueue detonation jobs for a draining host. See
  `docs/operations.md` → "Scaling horizontally".
- **`tools/stats.py` live snapshot.** One-shot view of scan-queue backlog + churn (ingest vs
  processed per ecosystem), the async detonation queue, verdicts, and detection-quality signals
  (LLM-triage source coverage per ecosystem, detonation-driven verdict flips). Baked into the
  image: `docker exec pkgward python tools/stats.py`.
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
  failure mode as the TLSH incident). Probing is centralized in `pkgward/util/capabilities.py`,
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
  (`PKGWARD_HASH_FULL_MAX_MB`, default 20) — those metrics are near-useless on big binaries
  (always near-max entropy, rarely match a fuzzy fingerprint) and `binary.compiled_artifact`
  still flags them; exact SHA-256 threat-intel coverage is unchanged. Measured ~660× faster on
  a 60 MB file (34s → 0.05s). Same cap applied in `analyze_entropy`.
- **Real malware could go un-alerted when LLM triage errored.** The inline Discord alert
  fired only on a clean `llm_verdict == "malicious"`, so a rule-malicious package whose triage
  returned invalid JSON (`error`), was skipped, or ran without an LLM key produced **no alert**
  — silently. Triage now **retries** the call+parse (`PKGWARD_LLM_MAX_RETRIES`, default 2) and
  caps the response (`PKGWARD_LLM_MAX_RESPONSE_TOKENS`, default 1500) so a truncated reply
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
  sections + `pkgward run -f <file>` (focused/exclusive mode — scans ONLY focus packages,
  authoritatively synced from the file). Also `pkgward focus load <file>` (combined, no
  `-e`) / `... -e <eco>` (flat, additive) / `focus list` / `focus clear`. Every new release
  of a focus package is enqueued automatically; pinned `name==version` scanned once at load.
  Toggle `PKGWARD_FOCUS_EXCLUSIVE` (`run -f` sets it). New `FocusList` table (auto-created),
  `pkgward/focus.py`, and per-ecosystem `ingest/focus.py` pollers. Lenient entry syntax —
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
- Detonation can load a private intel overlay (`PKGWARD_INTEL_PATH`) to extend its noise
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
  overlay system. Public baseline at `pkgward/intel/baseline/`; private operator overlays load
  via `PKGWARD_INTEL_PATH`. Fields are merged at startup (UNION for additive content, REPLACE for
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
  distance (≤120). Campaign fingerprints load from the intel pack; the baseline ships none.
- **Code-diff scanning** — per-file SHA256 hashes stored across scans; only changed/new files are
  analyzed on version updates.
- **Fair cross-ecosystem queue scheduling** — `claim_next()` rotates ecosystems within each
  priority tier so a large crates backlog cannot starve PyPI scans.
- **Env-var migration** — all vars renamed `PKGWARD_*` with backward-compatibility fallback
  through `PKGWATCH_*` and `PYPI_SCANNER_*`.
- **User-Agent helper** — `pkgward/util/user_agent.py` driven by `PKGWARD_CONTACT_EMAIL`;
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
- Project renamed from `pkgwatch` / `pypi_scanner` to **pkgward**.
- All Python imports updated to `from pkgward.…`.
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

[Unreleased]: https://github.com/boredchilada/pkgward-oss/compare/v0.3.0...HEAD
[0.5.1]: https://github.com/boredchilada/pkgward-oss/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/boredchilada/pkgward-oss/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/boredchilada/pkgward-oss/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/boredchilada/pkgward-oss/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/boredchilada/pkgward-oss/releases/tag/v0.1.0
