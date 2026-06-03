# Changelog

All notable changes to pkgsentry are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  `pkgsentry/enrich/downloads.py`. Toggle `PKGSENTRY_DOWNLOADS_ENABLED`.
- **Threat-intel auto-seeding — the campaign-recognition moat.** On a
  double-confirmed-malicious scan, the fingerprints (SHA-256 + ssdeep + TLSH) of
  the *implicated* files (those that drew a high/critical finding — the loader, the
  payload) are inserted into `threat_intel_hash` with `source="auto"`.
  `threat_intel.check_file` already matches every future file against that table, so
  the next package reusing the same (SHA-256) or a *tweaked* (ssdeep ≥70 / TLSH
  ≤120) payload is recognized **instantly, before the LLM** — turning a one-off
  catch into campaign-wide coverage (the meoo-* / rookie-security-test family
  rotates package names + the C2 subdomain but ships the same implant). Dedup is on
  SHA-256, so one payload across many names collapses to one fingerprint. `pkgsentry
  threatintel backfill` seeds from all historical confirmed-malicious scans in one
  shot; `pkgsentry threatintel stats`. **`FileHash` now persists `tlsh`** (was
  computed in-memory only) so backfill + matching get the full 3-tier fuzzy hash;
  an idempotent additive migration adds the column to existing DBs.

  **Now ships OFF by default** (`PKGSENTRY_THREATINTEL_AUTOSEED=1` to opt in). Shipping it
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
  `PKGSENTRY_SCOPE_WATCH_PROLIFIC=1`). **Auto-escalate:** when one package in a
  scope is double-confirmed malicious, the whole scope is watched automatically —
  catching a self-replicating worm's spread to the org's *other* packages within
  the same wave (the Shai-Hulud / RH-worm pattern). New `watchlist_scope` table;
  `pkgsentry scope {list,add,remove,seed}` CLI; toggle with
  `PKGSENTRY_SCOPE_WATCHLIST` (default on).
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
  (`PKGSENTRY_OBFUSCATION_MAX_MB`) and the cheap packer scan runs up to 32 MB
  (`PKGSENTRY_OBFUSCATION_PACKER_MAX_MB`) so a multi-MB hand-packed install file
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
  IOCs/YARA surfaced instead of hidden. Knobs: `PKGSENTRY_UPX_BIN`,
  `PKGSENTRY_UNPACK_TIMEOUT`, `PKGSENTRY_UNPACK_MAX_MB`, `PKGSENTRY_UNPACK_MAX_FILES`.
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
- **`pkgsentry threatintel remove <campaign>` — the FP exit-ramp for the fingerprint
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
  number of times (`PKGSENTRY_ENQUEUE_DEADLOCK_RETRIES`, default 3) — the
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
  (`prune_terminal`) deletes terminal rows older than `PKGSENTRY_QUEUE_RETENTION_DAYS`
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
- **Obfuscation analyzer size-capped per file** (`PKGSENTRY_OBFUSCATION_MAX_MB`, 10 MB for the
  alphabet/CJK passes; `PKGSENTRY_OBFUSCATION_PACKER_MAX_MB`, 32 MB for the cheap packer scan).
  The regex passes cost ~5s on a 20MB minified blob, so a giant bundle can't burn worker CPU —
  while still covering the multi-MB hand-packed install scripts that motivated the higher caps.
- **Giant-package fast-path (`PKGSENTRY_GIANT_FASTPATH`, default on).** A handful of huge
  packages — Go monorepos (gitea, go-ethereum, …) and fat JS component libs — take tens of
  seconds of pure-Python CPU to fuzzy-hash + analyze; with many workers in one process sharing
  the GIL they blow the 15-min per-package timeout and burn a worker (observed: ~6 timeouts in
  the first 2h of soak, all giants). When a package exceeds `PKGSENTRY_GIANT_FILE_THRESHOLD`
  (5000 files) or `PKGSENTRY_GIANT_MAX_MB` (100 MB) extracted, the scanner skips the heaviest
  per-file work — ssdeep/TLSH fuzzy hashing, entropy, and the obfuscation analyzer — while
  keeping SHA-256 (exact threat-intel), opengrep, YARA, IOC, import, malware-pattern, binary,
  and metadata detection. Detection-critical signatures stay; only fuzzy-hash + entropy/
  obfuscation heuristics are dropped on giants (low risk — giants are legitimate large projects,
  not lures). Logs `giant_fastpath`. Toggle off with `PKGSENTRY_GIANT_FASTPATH=0`.
- **LLM triage: truncated-clearing-verdict suppression fixed + harder cost cap.** A response
  cut off by `finish_reason=length` that still parsed but *cleared* a rule-malicious package
  (benign/suspicious) was accepted as authoritative, silently suppressing the alert; it now
  escalates the token budget and retries, failing open if it can't get a complete answer.
  The budget is also re-checked before each retry (not once per package) and cost is recorded
  per attempt, so the `MAX_USD` cap is meaningfully hard under concurrency; failed upstream
  calls now count against the per-hour rate cap; and a token-based estimate
  (`PKGSENTRY_LLM_EST_*_USD_PER_1K`) is used when the provider doesn't report `usage.cost`,
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
- **`pkgsentry.__version__` no longer reports a stale hardcoded value.** It was
  pinned to `"0.5.0"` and never bumped, so the outbound User-Agent advertised
  `pkgsentry/0.5.0` while the package was 0.5.2. It now derives from the installed
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
  `pkgsentry watchlist auto {list,remove,purge,backfill}` CLI. The four
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
  `PKGSENTRY_FINDING_REUSE_DAYS` (default 7) and **pulls forward** every
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
  distance (≤120). Campaign fingerprints load from the intel pack; the baseline ships none.
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
