#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""LLM-triage evaluation harness.

Runs the labeled set (``labeled_set.toml``) through the REAL production path —
``adapter.fetch`` -> ``safe_extract`` -> ``run_static_analyzers`` ->
``score_and_verdict`` -> ``llm.triage.triage()`` — for a chosen model and a chosen
system prompt, and scores three axes the old 2026-06 benchmark did not all cover:

  bad  sample : PASS if triage verdict != "benign"   (no-suppress; a "benign" here is CATASTROPHIC)
  good sample : CLEARED   if verdict == "benign"      (the value — removes the FP)
              : ESCALATED  if verdict == "malicious"   (the production failure: fires an FP alert)
              : NEUTRAL    otherwise (suspicious/inconclusive — no malicious alert fires)

The headline new number is OVER-ESCALATION RATE on the good set. A "good" sample
where BOTH rules and LLM say malicious is additionally flagged AUTO-WATCHLIST
(the worst case — it gets promoted to the watchlist).

Run INSIDE the scanner image (opengrep/yara/deps + network + OPENROUTER_API_KEY):

  docker run --rm --entrypoint python --env-file .env -v "$PWD:/src" -w /src \\
      pkgward-scanner tools/llm_eval/run_eval.py --prompt candidate

A/B the prompt change in isolation:

  ... run_eval.py --prompt baseline   > /tmp/base.txt
  ... run_eval.py --prompt candidate  > /tmp/cand.txt
  diff <(grep RESULT /tmp/base.txt) <(grep RESULT /tmp/cand.txt)

Flags: --model <id> (default: triage default), --prompt baseline|candidate|<path>,
--eco npm|pypi|gomod|crates, --label good|bad, --only <substr>, --json <path>.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

_HERE = Path(__file__).resolve().parent
LABELED_SET = _HERE / "labeled_set.toml"
CANDIDATE_PROMPT = _HERE / "triage_system.candidate.txt"


def _load_samples(args) -> list[dict]:
    with LABELED_SET.open("rb") as fh:
        data = tomllib.load(fh)
    samples = data.get("sample", [])
    out = []
    for s in samples:
        if args.eco and s["ecosystem"] != args.eco:
            continue
        if args.label and s["label"] != args.label:
            continue
        if args.only and args.only.lower() not in s["name"].lower():
            continue
        out.append(s)
    return out


def _install_prompt(which: str) -> str:
    """Swap the active system prompt in-process so the same triage() code runs
    against either the shipped baseline or the candidate. Returns a short label."""
    from pkgward import intel

    if which == "baseline":
        return "baseline"
    path = CANDIDATE_PROMPT if which == "candidate" else Path(which)
    text = path.read_text(encoding="utf-8")
    pack = intel.current()
    try:
        pack.prompts["triage_system"] = text
    except (TypeError, AttributeError) as e:
        raise SystemExit(
            f"could not swap triage_system prompt in-process ({e}); "
            f"as a fallback, copy {path} over the baseline or point "
            f"PKGWARD_INTEL_PATH at an overlay providing prompts/triage_system.txt"
        )
    return f"candidate:{path.name}"


async def _eval_one(sample: dict, model: str) -> dict:
    import pkgward.ecosystems  # noqa: F401  (registers adapters)
    from pkgward.adapter import adapter_registry
    from pkgward.detect.score import score_and_verdict
    from pkgward.llm import triage as triage_mod
    from pkgward.pipeline import run_static_analyzers
    from pkgward.util.extract import safe_extract

    eco = sample["ecosystem"]
    name = sample["name"]
    version = str(sample["version"])
    rec: dict = {"id": f"{eco}:{name}@{version}", "label": sample["label"], "ok": False}

    adapter = adapter_registry.get(eco)
    if adapter is None:
        rec["error"] = f"no adapter for {eco}"
        return rec

    work = Path(tempfile.mkdtemp(prefix="llmeval-"))
    try:
        fr = await adapter.fetch(name, version)
        if not fr.archives:
            rec["error"] = "no archives returned by fetch"
            return rec
        kind = adapter.install_archive_kind
        arc = next((a for a in fr.archives if a.kind == kind), fr.archives[0])
        root = work / arc.kind
        safe_extract(arc.path, root)

        findings = await run_static_analyzers(
            root, ecosystem=eco, adapter=adapter, arc_kind=arc.kind, changed=None,
        )
        result = score_and_verdict(findings, watchlist_rank=None)
        rec["rule_verdict"] = result.verdict
        rec["rule_score"] = result.score
        rec["n_findings"] = len(findings)

        if not triage_mod.is_enabled():
            rec["error"] = "triage disabled (OPENROUTER_API_KEY not set?)"
            return rec

        tri = triage_mod.triage(
            pkg_name=name, pkg_version=version, rule_verdict=result.verdict,
            findings=findings, extracted_root=root, model=model, ecosystem=eco,
        )
        rec.update(
            ok=True,
            llm_verdict=tri.verdict,
            llm_conf=round(tri.confidence, 2),
            cost=tri.cost_usd,
            latency_ms=tri.latency_ms,
            reasoning=(tri.reasoning or "").strip()[:300],
        )
    except Exception as e:  # fail-soft per sample (yanked pkg, fetch error, etc.)
        rec["error"] = f"{type(e).__name__}: {e}"
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return rec


def _classify(rec: dict) -> str:
    if not rec.get("ok"):
        return "SKIP"
    lv = rec["llm_verdict"]
    if rec["label"] == "bad":
        return "PASS" if lv != "benign" else "SUPPRESSED"   # SUPPRESSED = catastrophic
    # good
    if lv == "benign":
        return "CLEARED"
    if lv == "malicious":
        return "ESCALATED"                                   # the failure we are fixing
    return "NEUTRAL"


async def _amain() -> int:
    ap = argparse.ArgumentParser(description="LLM-triage evaluation harness")
    ap.add_argument("--model", default=None, help="model id (default: triage default)")
    ap.add_argument("--prompt", default="baseline",
                    help="baseline | candidate | <path to a prompt file>")
    ap.add_argument("--eco", default=None, choices=["npm", "pypi", "gomod", "crates"])
    ap.add_argument("--label", default=None, choices=["good", "bad"])
    ap.add_argument("--only", default=None, help="substring filter on package name")
    ap.add_argument("--json", default=None, help="write raw per-sample records to this path")
    args = ap.parse_args()

    from pkgward import intel
    from pkgward.llm import triage as triage_mod

    intel.reset()
    intel.load(use_env=True)           # baseline + operator overlay, matching prod
    prompt_label = _install_prompt(args.prompt)
    model = args.model or triage_mod.DEFAULT_MODEL

    samples = _load_samples(args)
    print(f"# model={model}  prompt={prompt_label}  samples={len(samples)}\n")

    records: list[dict] = []
    for s in samples:
        rec = await _eval_one(s, model)
        rec["outcome"] = _classify(rec)
        # auto-watchlist exposure: a "good" pkg both rules AND llm call malicious
        rec["autowatch_fp"] = (
            rec["label"] == "good"
            and rec.get("rule_verdict") == "malicious"
            and rec.get("llm_verdict") == "malicious"
        )
        records.append(rec)
        if rec.get("ok"):
            aw = " [AUTO-WATCHLIST FP]" if rec["autowatch_fp"] else ""
            print(f"RESULT {rec['outcome']:10} {rec['id']:64} "
                  f"rule={rec['rule_verdict']:10} llm={rec['llm_verdict']}@{rec['llm_conf']}"
                  f" ${rec['cost']:.4f}{aw}")
        else:
            print(f"RESULT {rec['outcome']:10} {rec['id']:64} -- {rec.get('error','')}")

    # ---- summary ----
    bad = [r for r in records if r["label"] == "bad" and r.get("ok")]
    good = [r for r in records if r["label"] == "good" and r.get("ok")]
    suppressed = [r for r in bad if r["outcome"] == "SUPPRESSED"]
    escalated = [r for r in good if r["outcome"] == "ESCALATED"]
    cleared = [r for r in good if r["outcome"] == "CLEARED"]
    autowatch = [r for r in good if r["autowatch_fp"]]
    skipped = [r for r in records if not r.get("ok")]
    total_cost = sum(r.get("cost", 0.0) for r in records if r.get("ok"))

    print("\n" + "=" * 72)
    print(f"BAD  (no-suppress) : {len(bad) - len(suppressed)}/{len(bad)} held"
          f"   {'<<< ' + str(len(suppressed)) + ' MALWARE CLEARED — HARD FAIL' if suppressed else 'OK'}")
    print(f"GOOD over-escalate : {len(escalated)}/{len(good)} escalated to malicious"
          f"   (FP alerts){' <<< incl ' + str(len(autowatch)) + ' AUTO-WATCHLISTED' if autowatch else ''}")
    print(f"GOOD cleared       : {len(cleared)}/{len(good)} cleared to benign")
    print(f"GOOD neutral       : {len(good) - len(escalated) - len(cleared)}/{len(good)} (suspicious/inconclusive — safe)")
    if skipped:
        print(f"SKIPPED            : {len(skipped)} (fetch/triage errors — see above)")
    print(f"cost (this run)    : ${total_cost:.4f}")
    print("=" * 72)
    if suppressed:
        print("HARD FAIL: a real malicious package was cleared to benign:")
        for r in suppressed:
            print(f"  - {r['id']}")

    if args.json:
        Path(args.json).write_text(json.dumps(records, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")

    # exit non-zero if any malware was suppressed (CI gate); over-escalation is
    # reported but not a hard gate (it is the metric we are tuning down).
    return 1 if suppressed else 0


def main() -> int:
    return asyncio.run(_amain())


if __name__ == "__main__":
    sys.exit(main())
