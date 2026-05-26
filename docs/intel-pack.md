# Intel Pack Reference

pkgsentry loads all detection content — YARA rules, threat-intel hashes, scoring thresholds,
LLM prompts, behavioral chains, and more — from an **intel pack** at process start. This
data-driven design lets operators tune detection without modifying engine code.

## How it works

On startup, `pkgsentry.intel.load()` loads the **baseline pack** (ships in-tree at
`pkgsentry/intel/baseline/`), then optionally merges a **private overlay** on top of it.
The overlay directory is set via:

```bash
PKGSENTRY_INTEL_PATH=/path/to/your/overlay
```

If unset, the engine runs with baseline only — generic, publicly-derivable detection content
sufficient for demonstrating the engine works.

After loading, a structured log line confirms what's active:

```
intel_loaded source=baseline+overlay yara_n=2 hash_seeds_n=3 ...
```

## Directory layout

A pack is a directory with this convention (every file is optional):

```
intel_pack.toml                     # Manifest (name, version, extends)
yara/                               # YARA rule files (*.yar)
  python_malware.yar
  rust_malware.yar
opengrep/                           # opengrep static-analysis rules (*.yaml)
  python/
  rust/
  go/
hashes/
  known_malicious.jsonl             # One threat-intel hash per line
prompts/
  triage_system.txt                 # LLM system prompt template
  truncation_warning.txt            # Injected when source is truncated
thresholds.toml                     # Verdict score thresholds
scoring_weights.toml                # Severity point values
behavioral_chains.toml              # Rule IDs that auto-escalate to malicious
lure_keywords.toml                  # Social-engineering keyword categories
ioc_whitelist.toml                  # Known-benign domains (IOC false-positive suppression)
malware_patterns.toml               # Install-time file target lists
gomod_benign_tools.toml             # go:generate tool whitelist
detonation/
  rules_data.toml                   # Sensitive paths, env vars, shell binaries
  noise_baseline.toml               # Per-ecosystem trace noise filters
```

Missing files leave the corresponding field empty (or whatever the baseline set). The engine
falls back to safe defaults if a field is empty.

## Merge semantics

When an overlay is loaded on top of the baseline, each field merges with specific semantics:

| File | Merge | Effect |
|------|-------|--------|
| `yara/*.yar` | UNION | Overlay rules are added alongside baseline rules. Namespaced by parent directory to prevent collisions. |
| `opengrep/<lang>/*.yaml` | UNION | opengrep rule directory paths are appended. opengrep itself walks each directory for `*.yaml` / `*.yml` rules. |
| `hashes/known_malicious.jsonl` | UNION | Overlay hashes are added. Deduplicated by SHA256. |
| `prompts/*.txt` | REPLACE | Overlay prompt text fully overrides the baseline version for that slot. |
| `thresholds.toml` | REPLACE | Overlay values fully override baseline thresholds. |
| `scoring_weights.toml` | REPLACE | Overlay values fully override baseline severity points. |
| `behavioral_chains.toml` | UNION | Overlay chain IDs are added to the set. |
| `lure_keywords.toml` | UNION | Overlay keywords are added per-category. New categories are created. |
| `ioc_whitelist.toml` | UNION | Overlay domains are added to the benign set. |
| `malware_patterns.toml` | UNION | Overlay file targets are added per-detector. |
| `gomod_benign_tools.toml` | UNION | Overlay tools are added to the whitelist. |
| `detonation/rules_data.toml` | UNION | Overlay entries are added per-list (paths, env prefixes, shell binaries). |
| `detonation/noise_baseline.toml` | UNION | Overlay noise patterns are added per-ecosystem. |

**UNION** = overlay entries are added to the baseline set. Duplicates are ignored.
**REPLACE** = overlay values fully override the baseline. Useful for tuning thresholds or
swapping prompts without inheriting baseline defaults.

## File format reference

### `intel_pack.toml`

Manifest identifying the pack.

```toml
name = "my-overlay"
version = "0.1.0"
extends = "baseline"
```

### `thresholds.toml`

Controls when a scan's total score graduates from clean to suspicious to malicious.

```toml
suspicious_min = 20          # Score >= this → suspicious
malicious_min = 61           # Score >= this → malicious
category_cap = 30            # Max points from a single finding category
whitespace_min_leading_spaces = 200  # Whitespace-hidden-payload detector threshold
```

### `scoring_weights.toml`

Points awarded per finding severity level. The total determines the verdict.

```toml
low = 1
medium = 8
high = 25
critical = 60
```

### `behavioral_chains.toml`

Rule IDs that, when fired, auto-escalate the verdict to malicious regardless of total score.
These represent high-confidence multi-signal correlations.

```toml
chain_ids = [
    "installer.urlopen_exec_chain",
    "imports.network_subprocess_chain",
    "malware.deobfuscation_exec_chain",
    "malware.discord_webhook",
    "malware.env_bulk_exfil",
    "malware.pth_import_injection",
    "dyn_install_exfil",
    "dyn_reverse_shell",
    "dyn_proc_inject",
]
```

### `lure_keywords.toml`

Keywords used to detect social-engineering package names. Organized by category.
Single-category hits are ignored (too common). Multi-category combinations produce findings:
2 categories = medium, 3+ = high.

```toml
[categories]
crypto = ["crypto", "blockchain", "wallet", "token", "defi"]
security_theater = ["security", "checker", "scanner", "audit"]
dev_environment = ["env", "config", "setup", "tool", "cli"]
ai_llm = ["ai", "gpt", "llm", "model", "neural"]
credential_secret = ["credential", "secret", "password", "key", "auth"]
```

### `ioc_whitelist.toml`

Domains that should not produce IOC findings. Suppresses false positives from legitimate
URLs in package source code.

```toml
benign_domains = [
    "pypi.org",
    "github.com",
    "stackoverflow.com",
    "docs.python.org",
    # ...
]
```

### `malware_patterns.toml`

File names targeted by install-time malware detectors. Each list scopes which files a
particular detector applies to.

```toml
[patterns]
install_time_all = ["setup.py", "setup.cfg", "install.py", "post_install.py", "conftest.py"]
credential_targets = ["setup.py", "setup.cfg", "install.py", "post_install.py"]
deobfuscation_targets = ["setup.py", "install.py", "post_install.py"]
download_targets = ["setup.py", "install.py", "post_install.py"]
```

### `gomod_benign_tools.toml`

Tools invoked by `//go:generate` directives that are known-benign. Packages using these
tools produce no finding. Unknown tools produce a low-severity finding. Dangerous commands
(curl, bash, etc.) remain critical regardless of this list.

```toml
tools = [
    "stringer",
    "mockgen",
    "protoc",
    "protoc-gen-go",
    "wire",
    "controller-gen",
    # ...
]
```

### `hashes/known_malicious.jsonl`

One JSON object per line. Each entry represents a known-malicious file fingerprint used by
the threat-intel matching layer (exact SHA256, ssdeep fuzzy >= 70%, TLSH distance <= 120).

```json
{"sha256": "abc123...", "ssdeep": "48:...", "tlsh": "T1...", "campaign": "TrapDoor", "note": "build.rs variant A"}
```

Seed fingerprints into the database:

```bash
python -m pkgsentry.store.seed_intel
```

### `prompts/triage_system.txt`

The LLM system prompt template for automated triage. Supports `{placeholders}` that the
engine fills at runtime: `{eco_name}`, `{source_desc}`, `{delim}`, `{truncation_warning}`.

### `prompts/truncation_warning.txt`

Injected into the system prompt when only a portion of the package source is provided to the
LLM. Instructs the model to lower confidence proportionally to missing source.

### `detonation/rules_data.toml`

Reference data for the detonation sandbox's behavioral rules. The rule logic is compiled
into the Go binary; this file defines what counts as "sensitive."

```toml
sensitive_path_prefixes = ["/root/.ssh/", "/home/", "/.aws/", ...]
sensitive_env_prefixes = ["AWS_SECRET", "GITHUB_TOKEN", "NPM_TOKEN", ...]
shell_binaries = ["/bin/sh", "/bin/bash", ...]
```

### `detonation/noise_baseline.toml`

Per-ecosystem patterns for trace events that are normal package-manager behavior (pip cache
writes, node_modules churn, rustc invocations). These are filtered out before behavioral
rules evaluate.

```toml
pypi_file_noise = ["/site-packages/", "/.cache/pip/", "/tmp/pip-", ...]
pypi_exec_noise = ["/python", "/pip"]
npm_file_noise = ["/.npm/_cacache/", "/node_modules/", ...]
crates_file_noise = ["/.cargo/registry/", "/target/", ...]
```

## Creating your own overlay

1. Create a directory with an `intel_pack.toml`:

   ```toml
   name = "my-org-overlay"
   version = "0.1.0"
   extends = "baseline"
   ```

2. Add only the files you want to customize. You don't need to copy every baseline file —
   only include what you're changing or adding.

3. Point the engine at it:

   ```bash
   export PKGSENTRY_INTEL_PATH=/path/to/my-overlay
   ```

4. Restart. Verify with the `intel_loaded` log line.

**For REPLACE fields** (thresholds, scoring weights, prompts): your file fully overrides
the baseline. Include all values you want, not just the ones you're changing.

**For UNION fields** (YARA, hashes, keywords, whitelists, patterns): your file adds to the
baseline. You only need to include new entries — baseline entries are always present.

## Example: adding a YARA rule

Create `my-overlay/yara/custom_rules.yar` with your rule(s). Set `PKGSENTRY_INTEL_PATH` to
`my-overlay/`. On next restart, the engine compiles your rules alongside the baseline rules.

YARA files are namespaced by parent directory name to prevent rule-name collisions between
baseline and overlay.

## Example: tuning thresholds

Create `my-overlay/thresholds.toml`:

```toml
suspicious_min = 15    # More sensitive than baseline (20)
malicious_min = 50     # More aggressive than baseline (61)
category_cap = 30
whitespace_min_leading_spaces = 200
```

This fully replaces the baseline thresholds.

## Example: adding threat-intel hashes

Create `my-overlay/hashes/known_malicious.jsonl` with one hash per line. These are merged
(UNION) with any baseline hashes. Then seed them into the database:

```bash
python -m pkgsentry.store.seed_intel
```

## Versioning your overlay

We recommend keeping your overlay in a separate git repository. This lets you:

- Version intel independently of the engine
- Push YARA rule updates without rebuilding the engine
- Keep private detection content out of the public engine repo
- Track changes to thresholds and scoring over time

On your deployment host, clone the overlay repo and set `PKGSENTRY_INTEL_PATH` to point at it.
Updates are `git pull` + container restart.
