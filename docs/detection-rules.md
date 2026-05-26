# pkgsentry Detection Rules Reference

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
| `iocs.onion` | high | high | Tor .onion address |
| `iocs.base64_blob` | medium | low | Large base64 blob (160+ chars) in string literal |

## Layer 3: Malware patterns (PyPI install-time files only)

Source: `analyze/malware_patterns.py`

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `malware.discord_webhook` | critical | high | Discord webhook URL for exfiltration (W4SP). **Behavioral chain** |
| `malware.telegram_bot_exfil` | critical | high | Telegram bot `/send` endpoint for exfiltration |
| `malware.slack_webhook` | high | high | Slack incoming webhook URL |
| `malware.pth_import_injection` | critical | high | `.pth` file with import (executes at Python startup). **Behavioral chain** |
| `malware.pyc_bytecode_hidden` | critical/high | high/medium | Standalone `.pyc` outside `__pycache__` (critical if importlib loader present) |
| `malware.credential_file_access` | critical | high | SSH keys, AWS creds, browser profiles, crypto wallet paths in install file |
| `malware.deobfuscation_exec_chain` | critical | high | marshal/zlib/bz2/lzma decompress piped to exec/eval. **Behavioral chain** |
| `malware.env_bulk_exfil` | critical | high | `os.environ` read + HTTP send in install file. **Behavioral chain** |
| `malware.env_sensitive_exfil` | high | medium | Sensitive env var access + HTTP send in install file |
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
| `metadata.maintainer_change` | medium | high | Maintainer list changed between versions |
| `metadata.lure_name` | medium | medium | Name matches 2 social-engineering lure categories |
| `metadata.lure_name_combo` | high | medium | Name matches 3+ lure categories (crypto + security + creds, etc.) |

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
| `gomod.replace_local_path` | high | high | `go.mod` replace pointing to local filesystem |
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
| `installer.npm_suspicious_bin` | low | low | `bin` entry points to a `.sh`/`.ps1`/`.exe`/… script |

## Layer 7: YARA signature matching (all ecosystems)

Source: `analyze/yara_scan.py` + rules in `yara_rules/`

Rule IDs are emitted as `yara.{rule_name}`. Severity/confidence are set per-rule via YARA metadata.

### python_malware.yar (11 rules)

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.w4sp_stealer_discord_harvest` | critical | high | W4SP/VVS Discord token harvesting |
| `yara.stealer_browser_credential_theft` | critical | high | Chrome/Firefox credential/cookie theft |
| `yara.crypto_wallet_stealer` | critical | high | Cryptocurrency wallet data theft |
| `yara.staged_payload_exec` | critical | high | Remote code download + exec/eval |
| `yara.staged_subprocess_shell` | high | medium | Remote download + subprocess shell=True |
| `yara.base64_exec_chain` | high | high | Base64 decode piped to exec/eval |
| `yara.reverse_shell_pattern` | critical | high | Reverse shell indicators |
| `yara.pyarmor_obfuscation` | medium | high | PyArmor obfuscated code (used by VVS Stealer) |
| `yara.ssh_key_exfiltration` | critical | high | SSH private key read + exfiltration |
| `yara.environment_credential_harvest` | critical | high | Bulk env var harvesting + HTTP exfil |
| `yara.dns_exfiltration` | high | medium | DNS-based data exfiltration pattern |

### rust_malware.yar (6 rules)

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `yara.rust_buildrs_network_exec` | critical | high | build.rs network + exec (YARA-level) |
| `yara.rust_buildrs_env_harvest` | high | high | build.rs sensitive env reads (YARA-level) |
| `yara.rust_buildrs_outdir_escape` | high | medium | build.rs OUT_DIR escape (YARA-level) |
| `yara.rust_obfuscated_include_bytes` | high | medium | include_bytes! of executable (YARA-level) |
| `yara.rust_encoded_payload_buildrs` | medium | medium | Encoded payload in build.rs (YARA-level) |
| `yara.rust_typosquat_indicator` | medium | low | Crate name resembles popular crate |

### community_sigbase.yar (11 rules)

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

Current campaigns: **TrapDoor** (Sui/Move/Aptos/Solana wallet stealer, 3 variant hashes covering 7 crates.io packages).

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

Rules ship in `pkgsentry/intel/baseline/opengrep/{python,rust,go,javascript}/`. Operators
add private rules via `$PKGSENTRY_INTEL_PATH/opengrep/<lang>/*.yaml`. UNION
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
| `opengrep.js_env_to_net` | high | medium | JS/TS: `process.env` secrets tainted into a network call |

## Layer 10: Dynamic analysis / detonation (all ecosystems)

Source: `detonation/internal/rules/definitions.go` (Go sandbox service)

Package is installed/imported in a rootless-Docker sandbox with Tetragon eBPF tracing on the host. The collector (`internal/trace/collector.go`) parses the Tetragon JSONL log into `TraceEvent`s, tags them with the install/import phase by time window (`AssignPhase`), and the Go rules engine evaluates them. Tetragon policy: `detonation/deploy/tetragon-policy.yaml`. Detonation now runs for PyPI, Crates, and Go modules.

| rule_id | Sev | Conf | What it detects |
|---------|-----|------|-----------------|
| `dyn_install_exfil` | critical | high | Network connect() during install phase. **DEFERRED — not in `AllRules()`**: fires on any install-phase connect, but sdists fetch build deps from registries → FPs. Re-enable with offline install or a destination allowlist. |
| `dyn_import_exfil` | high | high | Network connect() during import phase |
| `dyn_credential_read` | high | high | Read of sensitive file (SSH keys, cloud creds, /etc/shadow) via openat path-prefix hook |
| `dyn_reverse_shell` | critical | high | Shell spawned with open socket. **Behavioral chain.** Dormant — needs socket-fd tracking on exec (not yet wired) |
| `dyn_proc_inject` | critical | high | ptrace (PTRACE_ATTACH/SEIZE/POKE) or process_vm_writev injection. **Behavioral chain** |
| `dyn_dns_exfil` | high | medium | High-entropy DNS query. Dormant — needs UDP payload capture + DNS parsing (Tetragon gives only dest IP:port) |
| `dyn_env_harvest` | high | high | Read of another process's environment via `/proc/<pid>/environ` (excludes /proc/self) |
| `dyn_suspicious_write` | critical | high | Write to persistence path (crontab, /etc/systemd, .bashrc, authorized_keys) via `security_file_permission` MAY_WRITE hook |
| `dyn_fileless_exec` | critical / medium | high / medium | `execveat(AT_EMPTY_PATH)` fileless execution (critical); `memfd_create` anonymous executable memory (medium) |

All non-network kprobe hooks are namespace-filtered (`matchNamespaces Pid NotIn [host]`) so host activity is not misattributed to a detonation. Note: Tetragon `matchArgs` has no `In` operator — use `Equal` with multiple values (OR-matched).

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

---

## Behavioral chain rules

These rule IDs auto-escalate the verdict to malicious regardless of score. Defined in `detect/rules.py`:

- `installer.urlopen_exec_chain`
- `imports.network_subprocess_chain`
- `malware.deobfuscation_exec_chain`
- `malware.discord_webhook`
- `malware.env_bulk_exfil`
- `malware.pth_import_injection`
- `dyn_install_exfil`
- `dyn_reverse_shell`
- `dyn_proc_inject`

## Ecosystem coverage matrix

| Rule prefix | PyPI | Crates.io | Go modules |
|-------------|------|-----------|------------|
| `imports.*` | Yes | - | - |
| `iocs.*` | Yes | Yes | Yes |
| `malware.*` | Yes | - | - |
| `metadata.*` | Yes | Yes | Yes |
| `installer.*` | Yes | - | - |
| `crates.*` | - | Yes | - |
| `gomod.*` | - | - | Yes |
| `yara.{python}` | Yes | - | - |
| `yara.{rust}` | - | Yes | - |
| `entropy.*` | Yes | Yes | Yes |
| `binary.*` | Yes | Yes | Yes |
| `version_diff.*` | Yes | Yes | Yes |
| `intel.*` | Yes | Yes | Yes |
| `dyn_*` | Yes | Yes | Yes |
| `opengrep.*` | Yes | Yes | Yes |
| `fetch.*` | Yes | Yes | Yes |

---

## Adding custom rules

**YARA rules:** Drop `.yar` files into `pkgsentry/yara_rules/`. Rules compile at container startup. Use YARA metadata fields `severity` and `confidence` to control scoring. Rule name becomes `yara.{rule_name}`.

**Threat intel hashes:** Add entries to the `ThreatIntelHash` table via `python -m pkgsentry.store.seed_intel` or direct DB insert. Fields: `sha256`, `ssdeep`, `tlsh`, `campaign`, `source`.

## Counts

| Category | Count |
|----------|-------|
| Static rule IDs | 60 |
| YARA rules (via `yara.{name}`) | 28 |
| Dynamic sandbox rules | 8 |
| Threat intel (via `intel.{campaign}`) | 1+ per campaign |
| **Total distinct rule IDs** | **~96** |
