# LLM-triage evaluation harness

Measures whether an LLM model + system-prompt combination does the triage job
**without introducing detection gaps** — on a labeled set of real packages run
through the exact production path (`adapter.fetch` → `safe_extract` →
`run_static_analyzers` → `score_and_verdict` → `llm.triage.triage()`).

## Why this exists

The 2026-06 benchmark (`docs/internal/llm-model-benchmark-2026-06.md`) measured
only two outcomes: *don't clear malware* and *do clear benign FPs*. It had **no
over-escalation axis** — it never penalized the model for confidently calling a
benign FP `malicious`. That is exactly the failure that produced the 2026-06-07
FP alert surge: `deepseek-v4-flash` scored "perfect" on the old set while
escalating legitimate packages (stickcode, ainx, @expo/apple-utils,
quantum-core-engine, react-native-safe, …) to malicious in production.

This harness adds the missing axis and pins the adjudicated FPs so model/prompt
changes can be A/B'd against the real failure.

## Three axes

| Sample | Outcome | Meaning |
|---|---|---|
| `bad`  | **PASS** (verdict ≠ benign) / **SUPPRESSED** (benign) | SUPPRESSED is catastrophic — a hard CI fail |
| `good` | **CLEARED** (benign) | the value: FP removed |
| `good` | **ESCALATED** (malicious) | the production failure: fires an FP alert |
| `good` | **NEUTRAL** (suspicious/inconclusive) | safe — no malicious alert fires |

A `good` sample where **both** rules and LLM say malicious is additionally
flagged `AUTO-WATCHLIST FP` — the worst case, because it gets promoted onto the
watchlist (`watchlist_auto`).

## Running (inside the scanner image)

opengrep/yara/deps + network + `OPENROUTER_API_KEY` are required, so run against
the scanner image with the tree mounted (same pattern as the test suite):

```bash
docker build -t pkgward-scanner .     # once, or after a deps/Dockerfile change

# current shipped prompt:
docker run --rm --entrypoint python --env-file .env -v "$PWD:/src" -w /src \
    pkgward-scanner tools/llm_eval/run_eval.py --prompt baseline

# reinforced candidate prompt:
docker run --rm --entrypoint python --env-file .env -v "$PWD:/src" -w /src \
    pkgward-scanner tools/llm_eval/run_eval.py --prompt candidate
```

### A/B a prompt change in isolation

```bash
run_eval.py --prompt baseline  --json /tmp/base.json
run_eval.py --prompt candidate --json /tmp/cand.json
# compare the per-sample RESULT lines / the over-escalation counts
```

### Experiment: two-axis "risky vs malicious" prompt

`triage_system.risk_axis.txt` is a candidate that makes the malicious/benign call
*structural* instead of holistic. It forces the model to rate two INDEPENDENT axes
before the verdict — `behavior_risk` (none/low/medium/high — how dangerous the code
*does*) and `malicious_intent` (none/unclear/evident — is there a *cited* hostile
mechanism) — and **hard-binds** the verdict: `malicious` is only allowed when
`malicious_intent = evident`; high-`behavior_risk` with no proven intent (the dual-
use / pentest-tool / minified-bundle shape) routes to `suspicious` (the "risky"
tier → needs_review, not the alarm). Hypothesis: the explicit axis split cuts
over-escalation on `good` without suppressing `bad`. The `suspicious` verdict is the
existing "risky" bucket — no parser/pipeline change; `behavior_risk`/`malicious_intent`
are advisory JSON fields the parser ignores.

```bash
# baseline (current shipped reinforced prompt) vs the two-axis variant:
run_eval.py --prompt baseline                                  --json /tmp/base.json
run_eval.py --prompt tools/llm_eval/triage_system.risk_axis.txt --json /tmp/risk.json
diff <(grep RESULT /tmp/base.json) <(grep RESULT /tmp/risk.json)   # or compare the summary blocks
```

Win condition: `GOOD over-escalate` drops (dual-use FPs move ESCALATED→NEUTRAL via
`suspicious`) while `BAD no-suppress` stays at full (the two BAD samples — concrete
visible mechanisms — must keep `malicious_intent = evident`). If it holds across a
couple of models (gemini-3.1-flash-lite, deepseek-v4-flash), promote the two-axis
prompt the same way the reinforced one was promoted.

### Compare models (after the prompt is settled)

```bash
run_eval.py --prompt candidate --model deepseek/deepseek-v4-flash
run_eval.py --prompt candidate --model google/gemini-3.1-flash-lite
run_eval.py --prompt candidate --model z-ai/glm-4.6
```

Flags: `--model`, `--prompt baseline|candidate|<path>`, `--eco`, `--label`,
`--only <substr>`, `--json <path>`.

## Decision rule (don't introduce gaps)

1. **Hard gate, always:** `bad` no-suppress must stay 5/5 (or whatever the full
   bad set is). The harness exits non-zero if any malware is cleared. Never ship a
   model/prompt that suppresses a real catch.
2. **Tune down:** over-escalation rate on `good`. The reinforced prompt targets
   this; expect it to drop without touching the bad set.
3. **Only change the model** if `deepseek-v4-flash` + candidate prompt still
   over-escalates. Then re-score the both-correct alternatives (gemini-3.1-flash-lite,
   glm-4.6, kimi-k2.6:free) on this set with the bad-set hard gate enforced.

## Files

- `labeled_set.toml` — the adjudicated ground truth (FPs that exposed the gap +
  confirmed malware). Add new adjudications here as they come in.
- `triage_system.candidate.txt` — proposed reinforced system prompt (baseline +
  escalation discipline + the common-FP discriminators). Promote it over
  `pkgward/intel/baseline/prompts/triage_system.txt` once the A/B confirms it.
- `run_eval.py` — the harness.

## Notes / caveats

- Live fetch: samples are downloaded each run, so results depend on the package
  still being published (malware gets yanked). Per-sample failures are reported as
  `SKIP`, not crashes.
- `@hellyeah/cli-darwin-arm64` is a ~24 MB download (a `bun --compile` binary) —
  use `--only` to skip it for quick iterations.
- The harness mutates the in-process intel prompt only; it never writes the
  baseline. Promoting the candidate is a deliberate file move.
