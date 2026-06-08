# pkgward Detection Rules Reference

Complete catalog of every detection rule, organized by layer. Each rule produces a `Finding` with a unique `rule_id`, severity, and confidence.

## Scoring quick reference

| Severity | Points | Notes |
|----------|--------|-------|
| low | 1 | Informational signal |
| medium | 8 | Moderate suspicion |
| high | 25 | Strong indicator |
| critical | 60 | Single finding can force malicious verdict |

**Verdicts:** clean (< 20pts), suspicious (>= 20pts or any high), malicious (>= 61pts or any critical or behavioral chain).
Per-category cap: 30pts. A noisy single category cannot alone drive malicious.

---

## Layer 1: Import-time analysis (PyPI only)

Source: `analyze/imports.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `imports.network_at_import` | high | medium | `urlopen`/`urlretrieve` call at module top level |
| `imports.exec_at_import` | high | high | Bare `exec`/`eval`/`compile` call at module top level |
| `imports.subprocess_at_import` | medium | low | `subprocess`/`os.system`/`os.popen` at module top level |
| `imports.subprocess_at_import_suspicious` | high | high | Subprocess with suspicious flags (shell=True, /tmp paths, python re-invoke) |
| `imports.network_subprocess_chain` | critical | high | Network + suspicious subprocess in same module. **Behavioral chain** |

## Layer 2: IOC extraction (all ecosystems)

Source: `analyze/iocs.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `iocs.url_suspicious` | low | low | Non-benign URL in source (benign domain whitelist applied) |
| `iocs.ipv4` | low | low | Non-private/non-reserved IPv4 literal |
| `iocs.hardcoded_wan_ip_port` | high | medium | A routable IPv4 literal with an explicit `:port` (C2-beacon shape) — excludes private/loopback/link-local/doc ranges and public DNS resolvers. Malware hardcodes IP+port to dodge DNS/sinkholes |
| `iocs.cloud_metadata_endpoint` | medium | high | Cloud metadata SSRF / credential-theft endpoint (`169.254.169.254` AWS IMDS, `169.254.170.2` ECS task-role) — flagged despite the link-local skip |
| `iocs.encoded_url` | medium | medium | A non-benign URL found inside a decoded blob — single-layer base64 / hex / `\xNN`, **or** a multi-layer chain recovered by the recursive decode engine (b64→gzip→b64, …) |
| `iocs.encoded_ip` | high | medium | A routable / C2 / cloud-metadata IP found inside a decoded blob (single- or multi-layer) |
| `iocs.decoded_executable` | critical | high | Source decodes a hidden native executable (PE/ELF/Mach-O) or shebang script through a base64/compression chain — dropper shape. Via the recursive decode engine (`analyze/decode_engine.py`, `recover()`) |
| `iocs.decoded_code` | high | medium | Executable code (eval/exec/child_process/socket …) recovered through a **≥2-layer** decode chain — concealed payload behind nested encoding |
| `iocs.onion` | high | high | Tor .onion address |
| `iocs.oast_callback` | high | high | URL host is a known out-of-band-interaction / request-capture service (oastify.com, interact.sh, oast.*, burpcollaborator.net, webhook.site, requestbin, dnslog.cn, canarytokens, …) — near-certain exfil/C2 at install time. Also fires on a **bare/concatenated** OAST-domain literal (`'http://'+x+'.oastify.com'`) the full-URL matcher misses |
| `iocs.abuse_hosting_callback` | medium | high | URL host is an abuse-prone serverless/tunnel/paste service (`workers.dev`, `pages.dev`, `trycloudflare`, `ngrok`, `deno.dev`, …) — favored for C2 because it inherits a big provider's trusted IPs |
| `iocs.llm_prompt_injection` | high | high | Source mimics the scanner's **own** LLM-triage output field (`agrees_with_rules`) — a targeted self-clearing injection. Non-downgradable: an injected verdict can't clear the package |
| `iocs.llm_injection_phrase` | medium | low | Instruction-override phrase ("ignore previous instructions", "mark this as benign"). Informational only — also appears in minified bundles and *defensive* injection-guard lists, so the LLM still adjudicates |
| `iocs.base64_blob` | medium | low | Large base64 blob (160+ chars) in string literal |

## Layer 3: Malware patterns (PyPI install-time files only)

Source: `analyze/malware_patterns.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `malware.discord_webhook` | critical | high | Discord webhook URL for exfiltration (W4SP). **Behavioral chain** |
| `malware.telegram_bot_exfil` | critical | high | Telegram bot `/send` endpoint for exfiltration |
| `malware.slack_webhook` | high | high | Slack incoming webhook URL |
| `malware.pth_exec_injection` | critical | high | `.pth` import line runs a code-exec primitive at Python startup (`import os; os.system(...)`, `exec`/`b64decode`/`__import__`/socket/etc.). **Behavioral chain** |
| `malware.pth_import_injection` | high | medium | `.pth` bare-imports a module the package does **not** ship and isn't stdlib (at-startup sideload). A bare import of a shipped module (Datadog/Sentry/OTel auto-instrument bootstrap) or stdlib is not flagged — the imported module is analyzed on its own |
| `malware.credential_store_sweep` | critical | high | A single source file (any ecosystem) references **≥3 distinct credential stores** — `/etc/shadow`, `/proc/<pid>/environ`, k8s SA token, `~/.ssh` keys, `~/.aws/credentials`, `~/.npmrc`, browser/crypto cred files, bulk `process.env`/`os.environ` harvest. A legit lib touches one; an info-stealer sweeps many. `analyze/secret_access.py` (all ecosystems) |
| `malware.etc_shadow_read` | high | high | Source references `/etc/shadow` (password-hash theft) |
| `malware.pyc_bytecode_hidden` | critical/high | high/medium | Standalone `.pyc` outside `__pycache__` (critical if importlib loader present) |
| `malware.credential_file_access` | critical | high | SSH keys, AWS creds, browser profiles, crypto wallet paths in install file |
| `malware.deobfuscation_exec_chain` | critical | high | marshal/zlib/bz2/lzma decompress piped to exec/eval. **Behavioral chain** |
| `malware.env_exfil_tainted` | critical | high | Intrafile taint proves an `os.environ`-derived value **flows into** an HTTP send in an install file. **Behavioral chain** |
| `malware.env_bulk_exfil` | medium | low | `os.environ` read + HTTP send **co-occur** in an install file with no provable flow between them (a low-weight corroborating signal that never flags on its own; native-wrapper build-env reads no longer auto-escalate) |
| `malware.env_sensitive_exfil` | high | medium | Sensitive env var access + HTTP send in install file (no provable flow) |
| `malware.whitespace_hidden_payload` | critical | high | Code hidden with 200+ leading whitespace |
| `malware.download_command` | critical | high | PowerShell/curl/wget/certutil/bitsadmin download in install script |

## Layer 4: Metadata analysis (all ecosystems)

Source: `analyze/metadata.py`, `analyze/lure_names.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `metadata.typosquat_candidate` | high | medium | Name within 1 edit distance of top package |
| `metadata.typosquat_separator` | high | high | Name matches top package after normalizing `-`/`_`/`.` |
| `metadata.typosquat_prefix` | medium | medium | Top package name with common prefix (python-, py-, lib, etc.) |
| `metadata.typosquat_suffix` | medium | medium | Top package name with common suffix (-python, -sdk, -api, etc.) |
| `metadata.sdist_wheel_mismatch` | low | low | Wheel contains Python files absent from sdist |
| `metadata.rapid_release` | medium | medium | New release < 24h after previous version |
| `metadata.maintainer_change` | medium | high | Maintainer list changed between versions (fires only when both current and previous releases carry author metadata — an absent current author is not read as a removal) |
| `metadata.dependency_confusion_version` | low | medium | Version is all-nines or repeated-equal components ≥9 (`99.99.99`/`9.9.9`/`10.10.10`/`11.11.11`) — semver inflation to win a dependency-confusion resolution race. Corroborating evidence; deliberately excludes calendar versions (`2024.x`) |
| `metadata.lure_name` | medium | medium | Name matches 2 social-engineering lure categories |
| `metadata.lure_name_combo` | high | medium | Name matches 3+ lure categories (crypto + security + creds, etc.) |
| `metadata.gomod_impersonating_forge_host` | high | high | Go-module path host impersonates a code forge but isn't the real domain — a forge name on a foreign domain (`github.<rand>.workers.dev`), a git-prefix on a numeric throwaway domain (`gh.173371.xyz`/`git.832008.xyz`), or a Cloudflare ephemeral host. Namespace-hijack / dependency-confusion that republishes a legit module under attacker infra. Structurally gated to module-path names (npm/pypi/crates never match) |

### Lure name categories

Lure detection (`analyze/lure_names.py`) scores package names against 5 keyword categories commonly used in social-engineering campaigns:

| Category | Example keywords |
|----------|-----------------|
| crypto/blockchain | wallet, token, defi, mnemonic, eth, solana, web3 |
| security theater | security, audit, scanner, sentinel, guard, verifier |
| dev environment | deploy, config, env, setup, runtime, debug |
| AI/LLM | ai, llm, gpt, model, neural, copilot |
| credential/secret | credential, secret, key, password, auth, api-key |

Single-category hits are ignored (too common in legitimate packages). Multi-category combos produce findings.

## Layer 5: PyPI install scripts

Source: `ecosystems/pypi/installer.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `installer.urlopen_exec_chain` | critical | high | Network-read result passed to exec/compile/eval in setup.py. **Behavioral chain** |
| `installer.subprocess_at_install` | high | medium | subprocess call in setup.py |
| `installer.os_system_at_install` | high | high | `os.system`/`os.popen` in setup.py |

## Layer 6: Crates.io build.rs

Source: `ecosystems/crates/build_rs.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `crates.build_rs_net_exec_chain` | critical | high | build.rs has both network + command execution |
| `crates.build_rs_network` | high | high | Network library in build.rs (reqwest, ureq, hyper, etc.) |
| `crates.build_rs_exec` | medium | medium | `Command::new` / `std::process::Command` in build.rs |
| `crates.build_rs_env_harvest` | high | high | build.rs reads 3+ sensitive env vars |
| `crates.build_rs_outdir_escape` | high | medium | build.rs writes outside OUT_DIR |
| `crates.build_rs_suspicious_include` | high | medium | `include_bytes!` of .exe/.dll/.so/.sh/.ps1 file |
| `crates.build_rs_encoded_payload` | medium | medium | Large encoded payload in build.rs |

## Layer 6b: Go module directives

Source: `ecosystems/gomod/go_directives.py`

Rules analyze Go source files and go.mod. The `init_*` rules extract the actual `init()` function body via brace-matching -- they only fire if the suspicious call is inside init(), not merely in the same file.

`go:generate` has zero confirmed real-world attacks (as of 2026-05). It requires explicit `go generate` invocation -- not part of `go build`. Known benign tools (stringer, mockgen, protoc, etc.) are whitelisted and produce no finding.

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `gomod.go_generate_exec` | critical | high | `//go:generate` runs curl/wget/bash/python/etc. |
| `gomod.go_generate` | low | medium | `//go:generate` with unrecognized tool (known-benign tools whitelisted, no finding) |
| `gomod.init_exec_chain` | critical | high | `init()` body calls `exec.Command`/`exec.CommandContext` |
| `gomod.init_net_chain` | high | high | `init()` body makes `http.Get`/`net.Dial`/etc. calls |
| `gomod.init_env_harvest` | high | high | `init()` body reads 3+ sensitive env vars via `os.Getenv` |
| `gomod.init_exec_coexist` | low | medium | `init()` exists + `os/exec` imported but exec not in init body (indirect call fallback) |
| `gomod.init_net_coexist` | low | medium | `init()` exists + network import but net calls not in init body (indirect call fallback) |
| `gomod.cgo_exec_chain` | high | high | CGO with dangerous C calls (system/exec/socket) |
| `gomod.cgo_import` | medium | medium | `import "C"` (compiles C code at build time) |
| `gomod.unsafe_import` | low | medium | `import "unsafe"` |
| `gomod.encoded_payload` | medium | medium | Large base64/hex payload in Go source |
| `gomod.replace_local_path` | low | high | `go.mod` replace pointing to a local path. Informational: Go ignores `replace` in dependency modules, so it's inert downstream (monorepo/dev artifact); escalates only when paired with a real behavioral chain |
| `gomod.replace_directive` | medium | high | `go.mod` replace pointing to remote target |

## Layer 6c: npm lifecycle scripts

Source: `ecosystems/npm/installer.py`

Parses the root `package.json` (never bundled `node_modules` manifests) and inspects the
lifecycle scripts that run automatically on `npm install` (`preinstall`/`install`/
`postinstall`/`prepare`). A script whose every command-chain segment leads with a
known-benign build tool (node-gyp, tsc, webpack, …; intel `npm_benign_tools.toml`)
produces no finding. Local `.js` files invoked by a script (e.g. `node scripts/x.js`) are
followed and scanned for network + `child_process`/eval.

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `installer.npm_lifecycle_net_exec` | critical | high | Lifecycle script chains a network fetch + shell/eval/decode |
| `installer.npm_lifecycle_network` | high | medium | Lifecycle script makes a network call (curl/wget/https/…) |
| `installer.npm_lifecycle_subprocess` | medium | medium | Lifecycle script runs a shell/eval/base64-decode |
| `installer.npm_install_script_net_exec` | critical | high | Referenced install `.js` has both network and child_process/eval |
| `installer.npm_install_script_network` | high | medium | Referenced install `.js` makes a network call |
| `installer.npm_install_script_decode_exec` | high | medium | Referenced install `.js` base64-decodes then executes |
| `installer.npm_install_script_encoded_payload` | medium | medium | Large encoded payload in referenced install `.js` |
| `installer.npm_install_remote_binary_drop` | high/low | high/medium | Install `.js` downloads → writes → chmod-executes a binary. **high** when the download host is unrelated to the package's declared repo/homepage and isn't a known release host (GitHub/githubusercontent/npm registry/nodejs.org/…); **medium** when the URL is built dynamically; **low** when the script also SHA-256/512-verifies the download (the legit prebuilt-binary pattern — esbuild/swc/native-wrapper). On the low/verified case, the detonation re-score also recognizes an install-time connect to that same vendor host as the legit self-download, so `dyn_install_exfil` to it won't chain to malicious |
| `installer.npm_url_dependency` | high/medium | high | A dependency spec is a raw tarball **URL** (not a registry range). high on a suspicious file host (cloud bucket / abuse host / paste site — the dependency-confusion delivery shape); medium otherwise. For suspicious hosts the second-stage tarball is fetched + statically analyzed (see `PKGWARD_FETCH_URL_DEPS`) |
| `installer.npm_install_host_recon` | medium | medium | Install script/JS gathers host info (`os.hostname`/`userInfo`, `whoami`/`uname`/`id -un`) |
| `installer.npm_install_network_recon` | medium | medium | Install script/JS enumerates network interfaces / internal IPs (`os.networkInterfaces`, `ifconfig`/`ipconfig`) |
| `installer.npm_install_ci_secret_harvest` | high | medium | Install script/JS reads CI/registry secrets (`GITHUB_TOKEN`/`ACTOR`/`REPOSITORY`, `NPM_TOKEN`, `CIRCLECI`/`JENKINS_URL`/`GITLAB_CI`) |
| `installer.npm_install_recon_exfil` | high | high | Recon (host/network/secret) co-occurs with a network send in an install hook — the recon→exfil chain |
| `installer.npm_install_obfuscated_entrypoint` | critical | high | A lifecycle hook runs a local script that self-decodes (char-code / runtime-crypto `createDecipheriv`) into `eval`/`Function`. Behavioral-chain → malicious. Catches the `@redhat-cloud-services` worm's `preinstall: node index.js` (Caesar→AES→eval), invisible to the net/base64 rules because the payload is encoded |
| `installer.npm_runtime_obfuscated_entrypoint` | critical | high | The package's own `main` or a `bin` entry **is** a self-decoding eval loader (char-code / runtime-crypto → `eval`/`Function`) — the runtime-time twin of the install-hook rule above, for payloads that fire at `require()`/CLI time rather than install. Behavioral-chain → malicious. Reuses the obfuscation analyzer's proximity + build-bundle discriminators so a minified `dist` bundle declared as `main` doesn't FP. Catches `turbo-dls` 1.3.5 (`main: gifted.js`), which has no lifecycle hooks at all |
| `installer.npm_install_persistence_loader` | critical | high | A lifecycle hook registers **OS persistence** (systemd `--user` unit / launchd `.plist` / Windows Run-key·`.vbs` / XDG autostart / cron) **and** spawns a **detached, unref'd** background process — the resident-agent loader fingerprint. Behavioral-chain → malicious. Catches the `logger-active`/`utils-terminal` stealer family at the loader, independent of the payload's YARA signature |
| `installer.npm_install_persistence` | high | high | Lifecycle hook registers OS persistence (above), without the detached-spawn half |
| `installer.npm_install_detached_spawn` | high | medium | Lifecycle hook spawns a detached, unref'd background process (keeps a dropped payload resident after install exits) |
| `installer.npm_suspicious_bin` | low | low | `bin` entry points to a `.sh`/`.ps1`/`.exe`/… script |

## Layer 7: YARA signature matching (all ecosystems)

Source: `analyze/yara_scan.py` + baseline rules in `pkgward/intel/baseline/yara/`.

Rule IDs are emitted as `yara.{rule_name}`; severity/confidence come from each rule's
YARA metadata. Rules are **one per `.yar` file** (the file name matches the rule name);
the loader globs every `*.yar` in each pack directory, so the groupings below are
logical, not per-file. The baseline ships community signatures (adapted from
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) under their own
licenses — see `NOTICE`) plus a first-party set of **technique-level** rules covering
all four ecosystems (self-decoding loaders, the crates.io `build.rs` surface, npm
install-time exfil, supply-chain mismatch patterns). Campaign- and family-specific
rules are not shipped here — operators add those via the private overlay
(`$PKGWARD_INTEL_PATH/yara/`), UNION-merged over the baseline at load.

### Community signatures — `sigbase_*` / `community_*` (11 rules)

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.sigbase_python_reverse_shell_b64` | critical | high | Base64-encoded Python reverse shell |
| `yara.sigbase_python_pty_backconnect` | critical | high | PTY reverse-connect shell (dup2 + pty.spawn) |
| `yara.sigbase_pyminifier_obfuscation` | high | high | pyminifier obfuscation (zlib + base64 + exec) |
| `yara.sigbase_python_encoded_adware` | high | high | Lambda XOR + base64 decoding payload |
| `yara.sigbase_python_ssh_backdoor` | critical | high | paramiko SSH backdoor |
| `yara.sigbase_evilosx_backdoor` | critical | high | EvilOSX macOS backdoor |
| `yara.sigbase_python_macos_persistence` | high | high | macOS LaunchAgent persistence |
| `yara.sigbase_double_b64_executable` | critical | high | Double base64-encoded PE/ELF binary |
| `yara.sigbase_reversed_b64_executable` | high | high | Reversed base64-encoded executable |
| `yara.community_dyndns_c2` | medium | medium | Dynamic DNS domain for C2 |
| `yara.community_ip_lookup_recon` | low | medium | External IP lookup service (recon) |

### Baseline Python rules (5 rules)

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.base64_exec_chain` | high | high | Base64 decode piped to `exec`/`eval` |
| `yara.staged_subprocess_shell` | high | medium | Downloads content then runs it via `subprocess(..., shell=True)` |
| `yara.reverse_shell_pattern` | critical | high | Python reverse shell — `socket.socket(`+`.connect(` with `dup2`+`fileno`, `pty.spawn`, or `subprocess`+`/bin/sh` |
| `yara.ssh_key_exfiltration` | critical | high | Reads SSH private keys (`.ssh/id_*`) and sends them to a network sink |
| `yara.dns_exfiltration` | high | medium | DNS-based data exfil — resolver/`getaddrinfo` + encode + sensitive-data source |

### Baseline Rust rules (6 rules — crates.io `build.rs` surface)

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.rust_buildrs_network_exec` | critical | high | `build.rs` has both a network crate (`reqwest`/`ureq`/`hyper`/`attohttpc`) and command execution |
| `yara.rust_buildrs_env_harvest` | high | high | `build.rs` reads 3+ sensitive env vars (SSH/AWS/GH/cargo-registry tokens, `PRIVATE_KEY`, `DATABASE_URL`) |
| `yara.rust_buildrs_outdir_escape` | high | medium | `build.rs` writes to paths outside `OUT_DIR` (`/`, `$HOME`, `/tmp`) |
| `yara.rust_obfuscated_include_bytes` | high | medium | `include_bytes!` of an `.exe`/`.dll`/`.so`/`.sh`/`.ps1` |
| `yara.rust_encoded_payload_buildrs` | medium | medium | Large base64/hex-encoded payload in `build.rs` |
| `yara.rust_typosquat_indicator` | medium | low | Crate name resembles a popular-crate typosquat (`serde_jsom`, `tokiio`, `reqwests`, …) |

### Self-decoding loader family (3 rules)

Char-code / crypto / self-referential reconstruction feeding `eval` — packers that hide
the payload until runtime. Companion to the static `obfuscation.charcode_eval` analyzer
and the `installer.npm_runtime_obfuscated_entrypoint` chain rule (Layer 6c).

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.caesar_charcode_eval` | critical | high | Charcode array decoded via ROT/Caesar then `eval` (TeamPCP `.pth` bun dropper `_index.js`) |
| `yara.xor_self_referencing_eval` | critical | high | XOR key derived from a function's own `toString()` feeding `eval` (turbo-btns anti-tamper packer) |
| `yara.aes_gcm_hardcoded_eval` | critical | high | AES-GCM decrypt with a hardcoded hex key/IV feeding `eval` (TeamPCP `.pth` stage-1) |

### Supply-chain pattern rules (4 rules)

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.npm_install_base64_domain_exfil` | critical | high | npm install hook base64-decodes a domain and sends recon data (fhirproxy-utils pattern) |
| `yara.pth_bun_dropper` | critical | high | Python `.pth` startup file downloads + executes the Bun JS runtime (TeamPCP / Mini Shai-Hulud) |
| `yara.cross_ecosystem_python_in_go` | high | medium | Go module shipping Python source + `setup.py` + a runtime exec framework — cross-ecosystem mismatch |
| `yara.pyarmor_suspicious_deps` | high | medium | `setup.py` bundles PyArmor's pytransform alongside stealer-associated deps (boto3/cryptography/requests/psutil) — flags for review |

### Behavioral evasion rules (3 rules)

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.evasion_workflow_secrets_exfil` | critical | high | GitHub Actions workflow serializes ALL repo secrets (`toJSON(secrets)`) and writes/uploads them — CI secret-exfil (IronWorm / Shai-Hulud second path) |
| `yara.evasion_anti_ci_payload_gate` | high | medium | Payload gated to run only *outside* CI/analysis (negated `if(!CI)` / `not GITHUB_ACTIONS`) around a live network/exec sink — sandbox-evasion gating |
| `yara.evasion_media_stego_loader` | high | high | Steganographic media loader: reads audio/image frame bytes, base64/XOR-decodes, pipes the result into an interpreter — media-parse + decode + exec chain |

## Layer 8: Version diff (all ecosystems)

Source: `analyze/version_diff.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `version_diff.clean_to_critical` | critical | high | Previous version clean, new version introduces critical rules |
| `version_diff.new_rules_fired` | medium | medium | Previously clean version now triggers new rules |
| `version_diff.author_changed` | high | high | Author/email changed between versions (possible account takeover) |
| `version_diff.dependency_spike` | medium | medium | 3+ new deps exceeding 50% of previous count |

## Layer 9: Threat intelligence (all ecosystems)

Source: `analyze/threat_intel.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `intel.{campaign}` | critical | high | File matches known-malicious fingerprint (SHA256 exact, ssdeep >= 70%, or TLSH distance <= 120). Campaign name is substituted dynamically. |

The baseline ships **no** fingerprints (`hashes/known_malicious.jsonl` is empty). Campaign rows appear under `intel.{campaign}` only when an intel pack that provides fingerprints is loaded; the campaign name is substituted from that pack.

## Layer 9b: Known-malicious dependency intel (npm + pypi)

Source: `analyze/dep_intel.py` (scan-time finding) + `known_bad_deps.py` (data) +
the npm ingest gate in `ecosystems/npm/ingest/{anomaly.py,cursor.py}`.

When a package is double-confirmed malicious it lands on the auto-watchlist (sentinel
rank). A *different* package that declares a dependency on one of those confirmed-bad
names is itself suspect — compromised, complicit, or a victim pulling the payload in.
This follows the malice along the dependency edge, a different axis than file
fingerprints (Layer 9), name re-catch (auto-watchlist), or namespace (scope-watch).

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `dep_intel.depends_on_known_malicious` | critical | high | A dependency on a confirmed-malicious same-ecosystem package that is **newly added** in this version (the inject moment) |
| `dep_intel.depends_on_known_malicious` | high | high | A pre-existing dependency on a confirmed-malicious same-ecosystem package |

The check is per-ecosystem (a known-bad npm name never matches a pypi dep — avoids
name-collision FPs) and covers npm + pypi at scan time (the ecosystems whose
`requires_dist` is populated). It is a **scan trigger + weighted evidence, not a
verdict** — a single critical caps at the per-category 30 points, landing *suspicious*
(LLM triage adjudicates), never auto-malicious; this deliberately avoids a
self-confirming convict loop. On **npm ingest**, the same signal force-scans a
normally-skipped version-update at high priority the moment it adds a bad-dep edge,
so the catch isn't lost in the npm backlog. `KNOWN_BAD_DEPS_GATE=0` disables.

## Layer 12: opengrep static analysis (all ecosystems)

Source: `analyze/opengrep_scan.py`

Runs the [opengrep](https://github.com/opengrep/opengrep) binary against the
extracted package tree. Restores cross-function (intrafile) taint tracking
that the regex-based `crates/build_rs.py` and AST-based
`ecosystems/pypi/installer.py` cannot perform.

**Modes:**

* `OPENGREP_SHADOW=1` (default) — findings emit as `opengrep.shadow_<id>`
  and are **excluded from scoring**. The legacy install-time analyzers
  continue to run. Findings are persisted for offline parity comparison.
* `OPENGREP_SHADOW=0` — findings emit as `opengrep.<id>` and enter scoring.
  The legacy install-time analyzers for PyPI and Crates are skipped.

Rules ship in `pkgward/intel/baseline/opengrep/{python,rust,go,javascript}/`. Operators
add private rules via `$PKGWARD_INTEL_PATH/opengrep/<lang>/*.yaml`. UNION
merge semantics, identical to YARA dirs. Each rule directory ships co-located
`opengrep --test` fixtures (`<id>.{py,rs,go,js}`); run `tools/test_opengrep_rules.sh`.

Baseline rule set (11 rules, deliberately small):

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `opengrep.setup_net_to_exec` | critical | high | Python: net response tainted into exec/eval/compile |
| `opengrep.setup_net_to_subprocess` | critical | high | Python: net response tainted into subprocess/os.system |
| `opengrep.pth_import_injection` | critical | high | `.pth` file with `import` statement (text match) |
| `opengrep.buildrs_net_to_exec` | critical | high | Rust: net response tainted into Command::new in build.rs |
| `opengrep.buildrs_env_to_net` | high | high | Rust: sensitive env var tainted into network body |
| `opengrep.buildrs_include_executable` | high | medium | Rust: `include_bytes!` of .exe/.dll/.so/.sh/.ps1/.bat |
| `opengrep.init_net_to_exec` | critical | high | Go: net response inside init() tainted into exec.Command |
| `opengrep.init_env_to_net` | high | high | Go: sensitive env var inside init() tainted into network |
| `opengrep.js_net_to_exec` | critical | high | JS/TS: net response tainted into child_process/eval/Function |
| `opengrep.js_decode_to_exec` | high | high | JS/TS: base64-decoded data tainted into eval/Function/exec |
| `opengrep.js_env_to_net` | high | medium | JS/TS: a **credential-named** `process.env` read (token/key/secret/…) tainted into a network call. Source is name-filtered to secrets — a bare `process.env` or non-secret var (PORT/NODE_ENV) is no longer a source (was a 2% precision firehose). |

## Layer 10: Dynamic analysis / detonation (all ecosystems)

Source: `detonation/internal/rules/definitions.go` (Go sandbox service)

Package is installed/imported in a rootless-Docker sandbox with Tetragon eBPF tracing on the host. The collector (`internal/trace/collector.go`) parses the Tetragon JSONL log into `TraceEvent`s, tags them with the install/import phase by time window (`AssignPhase`), and the Go rules engine evaluates them. Tetragon policy: `detonation/deploy/tetragon-policy.yaml`. Detonation now runs for PyPI, Crates, Go modules, and npm.

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `dyn_install_exfil` | high | high | **Chain:** a secret was read (`dyn_credential_read`/`dyn_env_harvest`, surfaced run-wide as `run_sensitive_access`) **and** the package connects out to an **external** host during install. A connect alone is dual-use (dep/param/data fetches, DNS) and no longer convicts — a private/loopback/bridge address (incl. the sandbox DNS forwarder) is infra, never egress. Evidence shows the resolved domain when DNS capture is on. **Behavioral chain.** |
| `dyn_install_egress` | low | low | A lone external network egress during install with **no** secret access observed — non-convicting visibility note (the dual-use half of the exfil chain). |
| `dyn_abuse_hosting_callback` | critical | high | Runtime connect to an abuse-prone host (`workers.dev`, `pages.dev`, `trycloudflare`, `ngrok`, …), judged by the **resolved domain** (DNS-aware), not the shared-CDN IP — catches a beacon hiding inside a trusted provider's IP range that the IP allowlist would otherwise drop |
| `dyn_import_exfil` | high | high | **Chain:** secret read + external egress during import phase (same model as `dyn_install_exfil`). |
| `dyn_import_egress` | low | low | Lone external egress during import, no secret access — non-convicting note. |
| `dyn_credential_read` | high | high | Read of sensitive file (SSH keys, cloud creds, /etc/shadow) via openat path-prefix hook |
| `dyn_reverse_shell` | critical | high | Shell spawned with open socket. **Behavioral chain.** Dormant — needs socket-fd tracking on exec (not yet wired) |
| `dyn_proc_inject` | critical | high | ptrace (PTRACE_ATTACH/SEIZE/POKE) or process_vm_writev injection. **Behavioral chain** |
| `dyn_dns_exfil` | high | medium | High-entropy DNS query. Dormant — needs UDP payload capture + DNS parsing (Tetragon gives only dest IP:port) |
| `dyn_env_harvest` | high | high | Read of another process's environment via `/proc/<pid>/environ` (excludes /proc/self) |
| `dyn_suspicious_write` | critical | high | Write to persistence path (crontab, /etc/systemd, .bashrc, authorized_keys) via `security_file_permission` MAY_WRITE hook |
| `dyn_fileless_exec` | critical / medium | high / medium | `execveat(AT_EMPTY_PATH)` fileless execution (critical); `memfd_create` anonymous executable memory (medium) |
| `dyn_honeytoken_exfil` | critical | high | A bind-mounted decoy credential (the honeytoken set planted in the sandbox home) is read **and** its value subsequently leaves the box — proof of credential theft, not just a read |
| `dyn_screen_capture_probe` | critical | high | Execution of a screen-capture utility (`screencapture`/`import`/`scrot`/…) during install/import — screenshot exfil probe |

Trace events are attributed to the detonation's own sandbox container by the Tetragon
`docker` container id (captured per phase via `docker run --cidfile`), so concurrent
detonations and host activity are not misattributed. The tracing policy also carries
`matchNamespaces Pid NotIn [host]` as best-effort defense-in-depth, but it is **not** relied
upon: this host's Tetragon export does not populate PID-namespace data, so that selector is
inert and host events still reach the log — the collector-side container-id filter is the
real boundary. Note: Tetragon `matchArgs` has no `In` operator — use `Equal` with multiple
values (OR-matched).

## Fetch-level findings

Source: `pipeline.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `fetch.sha256_mismatch` | critical | high | Downloaded archive SHA256 doesn't match registry metadata |
| `fetch.no_release_files` | medium | high | No release files found for version |

## Entropy analysis (all ecosystems)

Source: `analyze/entropy.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `entropy.obfuscated_payload` | high/medium | medium | Shannon entropy >= 7.2 bits/byte (high if install file) |
| `entropy.high_entropy_script` | low | low | Shannon entropy >= 6.0 in .py/.js/.sh script |
| `entropy.suspicious_jump` | high/medium | medium | Entropy jumped >= 1.5 bits/byte between versions |

## Binary artifact detection (all ecosystems)

Source: `analyze/binary.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `binary.hidden_executable` | high | high | ELF/PE/Mach-O binary with .py/.txt/.json extension |
| `binary.compiled_artifact` | medium | high | Compiled binary without expected extension |
| `binary.packed_executable` | critical/high/medium | high | Run-time-packed executable. critical = commercial protector (Themida/VMProtect/Enigma — no static unpacker); high = UPX that couldn't be unpacked; medium = UPX successfully unpacked + payload re-analyzed. Packed payloads are unpacked via `upx -d` (decompress-only, never executed) and written back as `<name>.upx_unpacked` so all analyzers see the real payload |

---

## Source obfuscation / custom encoding (all ecosystems)

Source: `analyze/obfuscation.py`. Catches the obfuscation family the base64/entropy
heuristics miss — custom radix alphabets (base85/basE91/z85 and shuffled variants
decode through hand-rolled loops, not `atob`, and emit punctuation-heavy output
with no long base64 run) and CJK identifier renaming (defeats human review without
raising file entropy). Scans install-reachable source (`.js/.mjs/.cjs/.ts/.py`…).

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `obfuscation.rotating_alphabet_codec` | high | high | >=2 distinct ~85–91-char, near-all-unique-printable string literals in one file = a base85/basE91 "rotating alphabets" packer |
| `obfuscation.custom_alphabet_codec` | low | medium | Exactly one such radix-alphabet literal (could be a legitimate codec library) |
| `obfuscation.nonascii_identifiers` | medium | medium | >=8 distinct non-ASCII (hiragana/katakana/CJK) identifiers after stripping strings + comments (so CJK-authored libraries don't false-positive) |
| `obfuscation.homoglyph_identifiers` | medium | medium | >=1 confusable identifier after stripping strings + comments: a token mixing ASCII Latin with Cyrillic/Greek (`rеquests` with a Cyrillic `е`) or containing fullwidth-Latin. Requires the *mix* (or fullwidth) so legit pure-Cyrillic (Russian) / pure-Greek (scientific `α`/`β`) identifiers don't false-positive |
| `obfuscation.charcode_eval` | high | high | A char-code decode (`String.fromCharCode` / `.charCodeAt` / a long decimal `[n,n,…]` array) feeding `eval`/`Function` (JS self-decoding packer — the `@redhat-cloud-services` worm layer 1) |
| `obfuscation.decrypt_then_exec` | high | high | A runtime crypto-decrypt (`createDecipheriv`) feeding `eval`/`Function` (staged self-decoding payload — the worm's AES-128-GCM stage) |
| `obfuscation.rot_cipher_eval` | high | high | A ROT/Caesar-cipher wrapper (`.replace(/[a-zA-Z]/, …charCodeAt…%26…)`) decoding its payload at runtime then feeding `eval` (the Mini Shai-Hulud letter-rotation loader) |

The alphabet/CJK passes scan files up to `PKGWARD_OBFUSCATION_MAX_MB` (10); the
cheap `eval`+charcode/crypto packer scan runs up to `PKGWARD_OBFUSCATION_PACKER_MAX_MB`
(32), so a multi-MB hand-packed install file isn't skipped.

---

## Behavioral chain rules

These rule IDs auto-escalate the verdict to malicious regardless of score. The
canonical list is `intel/baseline/behavioral_chains.toml` (overlay-extendable):

- `installer.urlopen_exec_chain`
- `installer.npm_install_obfuscated_entrypoint`
- `installer.npm_runtime_obfuscated_entrypoint`
- `installer.npm_install_persistence_loader`
- `imports.network_subprocess_chain`
- `malware.deobfuscation_exec_chain`
- `malware.discord_webhook`
- `malware.env_exfil_tainted`
- `malware.pth_exec_injection`
- `dyn_install_exfil`
- `dyn_reverse_shell`
- `dyn_proc_inject`

## Ecosystem coverage matrix

| Rule prefix | PyPI | Crates.io | Go modules | npm |
|-------------|------|-----------|------------|-----|
| `imports.*` | Yes | - | - | - |
| `iocs.*` | Yes | Yes | Yes | Yes |
| `malware.*` | Yes | - | - | - |
| `metadata.*` | Yes | Yes | Yes | Yes |
| `installer.*` | Yes | - | - | Yes (`installer.npm_*`, `package.json` lifecycle scripts) |
| `crates.*` | - | Yes | - | - |
| `gomod.*` | - | - | Yes | - |
| `yara.{python}` | Yes | - | - | - |
| `yara.{rust}` | - | Yes | - | - |
| `entropy.*` | Yes | Yes | Yes | Yes |
| `binary.*` | Yes | Yes | Yes | Yes |
| `obfuscation.*` | Yes | Yes | Yes | Yes |
| `version_diff.*` | Yes | Yes | Yes | Yes |
| `intel.*` | Yes | Yes | Yes | Yes |
| `dyn_*` | Yes | Yes | Yes | Yes |
| `opengrep.*` | Yes | Yes | Yes | Yes (`opengrep/javascript`) |
| `fetch.*` | Yes | Yes | Yes | Yes |

---

## Adding custom rules

**YARA rules:** Add `.yar` files to an intel pack's `yara/` directory — `pkgward/intel/baseline/yara/` for the shipped baseline, or your private overlay's `yara/` dir loaded via `PKGWARD_INTEL_PATH` (UNION-merged over baseline). Rules compile at process start. Use YARA metadata fields `severity` and `confidence` to control scoring. Rule name becomes `yara.{rule_name}`.

**Threat intel hashes:** Add entries to the `ThreatIntelHash` table via `python -m pkgward.store.seed_intel` or direct DB insert. Fields: `sha256`, `ssdeep`, `tlsh`, `campaign`, `source`.

## Counts

| Category | Count |
|----------|-------|
| Static rule IDs | ~77 |
| YARA rules (baseline, via `yara.{name}`) | 32 |
| Dynamic sandbox rules | 14 (2 dormant) |
| Threat intel (via `intel.{campaign}`) | 0 in baseline; added by a loaded intel pack |
| **Total distinct rule IDs (baseline)** | **~120** |
