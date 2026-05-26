# Authoring opengrep rules for pkgsentry

The opengrep layer (`pkgsentry/analyze/opengrep_scan.py`) runs the [opengrep](https://github.com/opengrep/opengrep) binary against every extracted package and converts each match into a pkgsentry `Finding`. This guide explains how to write new rules — both for the public baseline and for private overlays.

## Where rules live

| Tree | Path | Audience | License |
|------|------|----------|---------|
| Baseline (ships with the engine) | `pkgsentry/intel/baseline/opengrep/{python,rust,go}/*.yaml` | Public OSS users | Apache 2.0 |
| Private overlay (operator-supplied) | `$PKGSENTRY_INTEL_PATH/opengrep/{python,rust,go}/*.yaml` | Single deployment | Operator's choice |

The two directories are **UNION-merged** at process start — same semantics as the YARA dirs. Both sets of rules run on every scan; baseline rules are not replaced by overlay rules, they coexist. Rule IDs must be globally unique across both sets.

opengrep itself walks each rule directory recursively for `*.yaml` and `*.yml`. There is no manifest file — drop a YAML file in the right directory and it loads on the next container restart.

## Anatomy of a rule

Every pkgsentry opengrep rule is a YAML document with a `rules:` list. Most files ship a single rule; multi-rule files are allowed but harder to read.

```yaml
rules:
  - id: setup_net_to_exec                # becomes opengrep.setup_net_to_exec
    mode: taint                          # or omit for plain pattern matching
    message: >-
      Network response is tainted into exec/eval/compile at install time.
    languages: [python]                  # python | rust | go | generic
    severity: ERROR                      # opengrep's own scale: ERROR | WARNING | INFO
    metadata:
      severity: critical                 # pkgsentry scale: low | medium | high | critical
      confidence: high                   # pkgsentry scale: low | medium | high
      category: installer                # category label for grouping in scoring
      pkgsentry_layer: opengrep          # convention; lets you filter rules by source
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: urllib.request.urlopen(...)
              - pattern: requests.get(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: exec($X)
              - pattern: eval($X)
```

### Required fields

| Field | Why |
|-------|-----|
| `id` | Becomes the `rule_id` after pkgsentry prefixing (`opengrep.<id>` or `opengrep.shadow_<id>`). Use snake_case. Keep it descriptive — it shows up in alerts, DB rows, and Discord messages. |
| `message` | Becomes the `evidence` string on the Finding. Operator-facing. Be concrete about what the rule fires on. |
| `languages` | Single-element list (`[python]`, `[rust]`, `[go]`) or `[generic]` for textual/regex rules. pkgsentry's three ecosystems are Python / Rust / Go. |
| `severity` (top-level) | opengrep's required field. Use `ERROR` for the most serious findings; opengrep filters by this when run with `--severity` flags (we don't, but it's still required). |
| `metadata.severity` | **The pkgsentry-side severity.** Maps to scoring points: `low=1`, `medium=8`, `high=25`, `critical=60`. This is what actually drives the verdict. |
| `metadata.confidence` | `low`, `medium`, `high`. Currently surfaced for analyst triage; doesn't change scoring math. |

### Severity normalization (what happens if you omit `metadata.severity`)

`pkgsentry/analyze/opengrep_scan.py:_normalize_severity` falls back to opengrep's top-level `severity:` if `metadata.severity` is missing or invalid:

- `ERROR` → `high`
- `WARNING` → `medium`
- `INFO` → `low`

Anything unrecognized → `medium`. Always set `metadata.severity` explicitly — implicit defaults are an antipattern.

### Optional fields

| Field | When to use |
|-------|-------------|
| `metadata.category` | Set this to group the finding with related rules in scoring (`installer`, `gomod`, `malware`, etc.). Defaults to `opengrep` if omitted. |
| `paths.include` / `paths.exclude` | Restrict the rule to specific file globs. Critical for rules that only make sense in `build.rs` or `setup.py` — don't fire them on the entire package tree. |
| `pattern` / `patterns` / `pattern-either` / `pattern-not` | Plain (non-taint) matching modes. |
| `mode: taint` + `pattern-sources` + `pattern-sinks` | Intrafile taint tracking — the killer feature opengrep restored over Semgrep CE. |

## When to use taint mode

Use `mode: taint` when the rule is "X reaches Y" rather than "X exists and Y exists in the same file". The regex-based `crates/build_rs.py` was the cautionary tale: it could detect that build.rs contained both a network library AND a `Command::new` call, but couldn't tell whether the network response actually fed the exec. That produces noise (legit crates that use both for unrelated purposes) and misses real attacks where the source and sink are several function calls apart.

Taint mode in opengrep does cross-function intrafile analysis: if a value originating from a `pattern-sources` match flows — through assignments, helper function calls, struct fields — into a `pattern-sinks` match anywhere in the same file, the rule fires. The taint is invalidated if it passes through a `pattern-sanitizers` match (use this to suppress known-safe transformations).

Plain pattern matching (no `mode:`) is right for:
- Textual / regex rules (e.g. `pth_import_injection.yaml` matches lines in `.pth` files).
- Single-statement detections where one match is enough (e.g. `include_bytes!` of a `.exe`).
- Rules that act on file-level structure rather than data flow.

## Path scoping — extremely important for install-time rules

A Python rule that matches `exec($X)` calls without `paths.include` will fire on every `.py` file in the package — including legitimate library code that calls `exec` for valid reasons. That's a false-positive factory.

Install-time rules MUST be scoped to install-time files:

```yaml
paths:
  include:
    - "setup.py"
    - "**/setup.py"
```

For Rust build scripts:

```yaml
paths:
  include:
    - "**/build.rs"
```

For Go init() — opengrep doesn't have a path-level filter for "inside init()", but you can scope to files most likely to contain init blocks (typically root-level `.go` files) or use `pattern-inside: func init() { ... }` to gate the match.

The high-fidelity rules in the baseline all scope tightly. Mirror that pattern.

## How findings flow into scoring

Every match becomes one `Finding`:

```
Finding(
    rule_id="opengrep.<id>"            (or "opengrep.shadow_<id>" in shadow mode)
    category=metadata.category or "opengrep"
    severity=metadata.severity (validated against low/medium/high/critical)
    confidence=metadata.confidence (validated against low/medium/high)
    file=<path relative to extracted package root>
    line=<opengrep start.line>
    evidence=<metadata.message>
)
```

Scoring (`pkgsentry/detect/score.py`):
- Shadow findings (`opengrep.shadow_*`) are **excluded** from scoring entirely. They persist for offline comparison.
- Non-shadow findings score normally: severity-points (low=1, med=8, high=25, crit=60), per-category cap of 30 points, verdict thresholds `suspicious≥20` and `malicious≥61`.
- Critical-severity findings auto-promote verdict to malicious regardless of total score.
- A finding can be marked as a [behavioral chain](detection-rules.md#behavioral-chain-rules) by adding its ID to `behavioral_chains.toml`, which auto-promotes the verdict to malicious.

## Validating rules

### Local (requires opengrep binary)

```bash
opengrep scan --validate -f path/to/rule.yaml
```

Exits 0 if the YAML parses and the patterns compile, non-zero otherwise.

### Test suite

`tests/analyze/test_opengrep_rules_compile.py` runs `--validate` against every baseline rule. Tests skip cleanly when opengrep isn't on PATH (dev machines without the binary), and run in the Docker container / CI where the binary is installed. Drop a new rule into `pkgsentry/intel/baseline/opengrep/<lang>/` and the test picks it up automatically — no test changes required.

### Test the rule fires (recommended for non-trivial rules)

Write a small fixture package that should trigger the rule, run it through opengrep manually:

```bash
mkdir /tmp/fixture && echo '<minimal triggering source>' > /tmp/fixture/setup.py
opengrep scan --json --quiet -f pkgsentry/intel/baseline/opengrep/python/your_rule.yaml /tmp/fixture | jq .results
```

If `.results` is empty, the rule isn't matching what you think it is — iterate on the pattern.

## Shadow mode vs cutover

Every new rule lands under shadow mode (`OPENGREP_SHADOW=1`, the default). Findings emit as `opengrep.shadow_<id>` and do not affect scoring. The intent is to soak the rule against real traffic and compare its hit rate / FP rate to whatever existing analyzer covers the same ground.

After soak proves parity (or improvement), cutover for the whole opengrep layer happens via `OPENGREP_SHADOW=0`. There is no per-rule cutover — the flag is global. So when adding a rule to the baseline, write it with the assumption it will eventually contribute to verdict — set `metadata.severity` honestly.

## Public-baseline policy

The baseline is **demonstrative**, not operational. Two rules of thumb when proposing a new baseline rule:

1. **No proprietary intel.** If the rule encodes a campaign-specific IOC, a hash list, a customer-specific allowlist, or a tuned threshold that took months of incident data to derive, it belongs in the private overlay, not the baseline.
2. **Generic enough to publish.** A baseline rule should be one that any operator would benefit from. The bar is "this catches a textbook supply-chain attack pattern", not "this catches the specific malicious package my customer hit last Tuesday".

When in doubt, ship to the private overlay first. Promote to baseline later if it stays generic.

## Worked example: the `setup_net_to_exec` rule

```yaml
rules:
  - id: setup_net_to_exec
    mode: taint
    message: >-
      Network response is tainted into exec/eval/compile at install time —
      this is the canonical "fetch then run remote code" supply-chain attack.
    languages: [python]
    severity: ERROR
    metadata:
      severity: critical
      confidence: high
      category: installer
      pkgsentry_layer: opengrep
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: urllib.request.urlopen(...)
              - pattern: urllib.urlopen(...)
              - pattern: urllib.request.urlretrieve(...)
              - pattern: requests.get(...)
              - pattern: requests.post(...)
              - pattern: requests.request(...)
              - pattern: httpx.get(...)
              - pattern: httpx.post(...)
              - pattern: urllib3.PoolManager(...).request(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: exec($X)
              - pattern: eval($X)
              - pattern: compile($X, ...)
              - pattern: __import__($X)
```

Breaking it down:

- **Taint mode** because we care that the network result *reaches* exec, not just that both exist.
- **Sources** are the common Python HTTP libraries. The `pattern-either` block enumerates each because opengrep doesn't have a "any HTTP call" abstraction — you list them explicitly.
- **Sinks** are the bare-name builtins (`exec`, `eval`, `compile`, `__import__`). Bare names because attacker code rarely uses module-qualified forms here, and `re.compile` / `tabulate.compile` shouldn't trigger.
- **`metadata.severity: critical`** because this is the canonical fetch-then-execute pattern. Coupled with the high-confidence taint flow, a single hit should drive the verdict to malicious.
- No `paths.include` — the rule is reasonable to run on any Python source. (In practice, a more cautious variant scoped to `setup.py` would reduce FP risk further.)

## Iteration loop for a new rule

1. Write the rule in `pkgsentry/intel/baseline/opengrep/<lang>/` (or the private overlay).
2. `opengrep scan --validate -f <rule>` — parses cleanly.
3. Build a triggering fixture, `opengrep scan --json -f <rule> <fixture>` — confirm it matches.
4. Build a benign fixture that looks superficially similar (e.g. a setup.py that uses `urlopen` for a legitimate download but never feeds it to exec), confirm it does NOT match.
5. Commit + push to Gitea. Deploy to prod ([release-flow doc](maintainer-release-flow.md)). Soak under `OPENGREP_SHADOW=1`.
6. Watch the shadow-finding count for the new rule. If FP rate is acceptable, the rule earns its place when the global shadow→cutover happens.

## References

- opengrep rules syntax: https://github.com/opengrep/opengrep
- Semgrep rule registry (most syntax overlaps, useful for inspiration): https://semgrep.dev/r
- pkgsentry analyzer source: `pkgsentry/analyze/opengrep_scan.py`
- pkgsentry intel-pack loader: `pkgsentry/intel/pack.py` (look for `opengrep_dirs`)
- Layer overview: [detection-rules.md](detection-rules.md) (Layer 12)
