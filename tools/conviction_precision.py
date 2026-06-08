# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conviction-precision harness — measure the FP rate of the rules allowed to
drive a maintainer-pivot sweep.

The maintainer pivot (``pkgward/maintainer_pivot.py``) is only as trustworthy as
the convictions that trigger it. Before letting a rule force-scan a maintainer's
whole catalog, we want to KNOW its precision. This tool scores every
trigger-eligible rule (non-shadow, high/critical, PRIMARY-category — the exact set
``maintainer_pivot._trigger_eligible_findings`` admits) against two sources:

  * CORPUS — every labeled known-bad / known-good sample under ``tests/corpus``
    (+ private/vault via ``PKGWARD_CORPUS_PATH`` / ``PKGWARD_VAULT_PATH``), run
    through the real analyze→score path. Ground truth = the sample label.
        precision = fired_on_bad / (fired_on_bad + fired_on_good)

  * PROD — recent persisted scans (read-only DB replay, like tools/parity_tier1).
    No labels, so the LLM verdict is the adjudicator proxy: a rule that fires on a
    scan the LLM then CLEARED (benign) is a likely false positive.
        precision = llm_confirmed / (llm_confirmed + llm_cleared)

Rules whose measured precision is poor (with enough support) are printed as a
suggested ``PKGWARD_MAINTAINER_PIVOT_TRIGGER_DENY`` set — the empirical input for
which rules are safe to let drive the pivot.

Run:
    python tools/conviction_precision.py                  # corpus + prod
    python tools/conviction_precision.py --source corpus  # offline, no DB
    python tools/conviction_precision.py --source prod --limit 5000
    python tools/conviction_precision.py --min-precision 0.9 --min-support 5
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select

from pkgward import intel
from pkgward.adapter import Finding as FindingDC
from pkgward.maintainer_pivot import _high_fidelity, _trigger_eligible_findings
from pkgward.store import session as sess
from pkgward.store.models import Finding, Package, Scan, Version


@dataclass
class RuleStat:
    rule_id: str
    # corpus
    bad: int = 0
    good: int = 0
    # prod
    confirmed: int = 0
    cleared: int = 0
    ambiguous: int = 0
    high_fidelity: bool = False

    @property
    def corpus_support(self) -> int:
        return self.bad + self.good

    @property
    def corpus_precision(self) -> Optional[float]:
        return self.bad / self.corpus_support if self.corpus_support else None

    @property
    def prod_support(self) -> int:
        return self.confirmed + self.cleared

    @property
    def prod_precision(self) -> Optional[float]:
        return self.confirmed / self.prod_support if self.prod_support else None


def _ensure(stats: dict[str, RuleStat], rule_id: str) -> RuleStat:
    st = stats.get(rule_id)
    if st is None:
        st = RuleStat(rule_id=rule_id)
        stats[rule_id] = st
    return st


async def _corpus_findings(sample, work_dir) -> tuple[str, list[FindingDC]]:
    """Run a sample and return (label, full Finding list) — the analyze path with
    objects, so we can apply the real trigger-eligibility filter."""
    import pkgward.ecosystems  # noqa: F401  (adapter_registry)
    from pkgward.adapter import adapter_registry
    from pkgward.analyze.metadata import MetadataContext, analyze_metadata
    from pkgward.analyze.version_diff import PreviousVersion, analyze_version_diff
    from pkgward.pipeline import run_static_analyzers
    from tests import corpus_harness as ch

    ch._pin_intel(sample.tier)
    root = ch.materialize(sample, work_dir)
    adapter = adapter_registry[sample.ecosystem]
    findings = await run_static_analyzers(
        root, ecosystem=sample.ecosystem, adapter=adapter,
        arc_kind=adapter.install_archive_kind, changed=None,
    )
    meta_dict: dict = {}
    if sample.metadata is not None:
        md = sample.metadata
        findings.extend(analyze_metadata(MetadataContext(
            name=sample.name, version=sample.version,
            previous_release_at=md.get("previous_release_at"),
            maintainers_now=list(md.get("maintainers_now", [])),
            maintainers_prev=list(md.get("maintainers_prev", [])),
            watchlist_top_names=list(md.get("watchlist_top_names", [])),
            sdist_files=list(md.get("sdist_files", [])),
            wheel_files=list(md.get("wheel_files", [])),
        )))
        meta_dict = dict(md.get("current_metadata", {}))
    if sample.prev is not None:
        p = sample.prev
        findings.extend(analyze_version_diff(findings, meta_dict, PreviousVersion(
            version=str(p.get("version", "0")), verdict=p.get("verdict", "clean"),
            score=int(p.get("score", 0)), rule_ids=set(p.get("rule_ids", [])),
            finding_count=int(p.get("finding_count", 0)),
            author=p.get("author"), author_email=p.get("author_email"),
            upload_time=p.get("upload_time"), requires_dist=list(p.get("requires_dist", [])),
        )))
    return sample.label, findings


async def run_corpus(stats: dict[str, RuleStat]) -> int:
    import tempfile
    from pathlib import Path

    from tests import corpus_harness as ch

    samples = ch.discover_samples()
    chain_ids = intel.current().behavioral_chain_ids
    for sample in samples:
        with tempfile.TemporaryDirectory(prefix="convprec-") as td:
            try:
                label, findings = await _corpus_findings(sample, Path(td))
            except Exception as e:
                print(f"  ! corpus sample {sample.sample_id} failed: {e}", file=sys.stderr)
                continue
        for f in _trigger_eligible_findings(findings):
            st = _ensure(stats, f.rule_id)
            if label == "good":
                st.good += 1
            else:
                st.bad += 1
            if f.rule_id in chain_ids or f.category == "threat_intel":
                st.high_fidelity = True
    return len(samples)


def run_prod(stats: dict[str, RuleStat], *, ecosystem: Optional[str], limit: Optional[int]) -> int:
    chain_ids = intel.current().behavioral_chain_ids
    total = 0
    with sess.session_scope() as s:
        q = (
            select(Scan, Package)
            .join(Version, Scan.version_id == Version.id)
            .join(Package, Version.package_id == Package.id)
            .where(Scan.llm_verdict.in_(("malicious", "benign", "suspicious")))
        )
        if ecosystem:
            q = q.where(Package.ecosystem == ecosystem)
        q = q.order_by(Scan.started_at.desc())
        if limit:
            q = q.limit(limit)
        for scan, _pkg in s.execute(q):
            total += 1
            rows = s.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
            findings = [
                FindingDC(rule_id=f.rule_id, category=f.category, severity=f.severity,
                          confidence=f.confidence, file=f.file or "", line=f.line,
                          evidence=f.evidence or "")
                for f in rows
            ]
            for f in _trigger_eligible_findings(findings):
                st = _ensure(stats, f.rule_id)
                if scan.verdict == "malicious" and scan.llm_verdict == "malicious":
                    st.confirmed += 1
                elif scan.llm_verdict == "benign":
                    st.cleared += 1
                else:
                    st.ambiguous += 1
                if f.rule_id in chain_ids or f.category == "threat_intel":
                    st.high_fidelity = True
    return total


def _fmt(p: Optional[float]) -> str:
    return f"{p*100:5.1f}%" if p is not None else "   n/a"


def report(stats: dict[str, RuleStat], *, min_precision: float, min_support: int) -> int:
    if not stats:
        print("no trigger-eligible findings observed.")
        return 0
    ordered = sorted(
        stats.values(),
        key=lambda s: (
            min(x for x in (s.corpus_precision, s.prod_precision) if x is not None)
            if any(x is not None for x in (s.corpus_precision, s.prod_precision)) else 1.0,
            -(s.corpus_support + s.prod_support),
        ),
    )
    print(f"\n{'rule_id':45} {'hi-fi':5} {'corpus(bad/good)':18} {'cprec':6} "
          f"{'prod(conf/clr/amb)':20} {'pprec':6}")
    print("-" * 108)
    deny: list[str] = []
    for st in ordered:
        corpus_col = f"{st.bad}/{st.good}"
        prod_col = f"{st.confirmed}/{st.cleared}/{st.ambiguous}"
        print(f"{st.rule_id:45} {'yes' if st.high_fidelity else '  -':5} "
              f"{corpus_col:18} {_fmt(st.corpus_precision):6} "
              f"{prod_col:20} {_fmt(st.prod_precision):6}")
        # Flag a rule as deny-worthy only with enough support and genuinely poor
        # precision in a source that has data — never demote a high-fidelity rule.
        if st.high_fidelity:
            continue
        for prec, support in ((st.corpus_precision, st.corpus_support),
                              (st.prod_precision, st.prod_support)):
            if prec is not None and support >= min_support and prec < min_precision:
                deny.append(st.rule_id)
                break
    print("-" * 108)
    if deny:
        print(f"\n# {len(deny)} rule(s) below {min_precision*100:.0f}% precision "
              f"with >= {min_support} support — consider excluding from the pivot:")
        print(f"PKGWARD_MAINTAINER_PIVOT_TRIGGER_DENY={','.join(sorted(set(deny)))}")
    else:
        print(f"\n# all trigger-eligible rules at/above {min_precision*100:.0f}% "
              f"precision (>= {min_support} support). No deny set suggested.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=("corpus", "prod", "both"), default="both")
    parser.add_argument("--ecosystem", choices=("pypi", "crates", "gomod", "npm"), default=None)
    parser.add_argument("--limit", type=int, default=None, help="prod: sample N most-recent scans")
    parser.add_argument("--min-precision", type=float, default=0.9)
    parser.add_argument("--min-support", type=int, default=5)
    args = parser.parse_args()

    intel.load()
    stats: dict[str, RuleStat] = {}

    if args.source in ("corpus", "both"):
        n = asyncio.run(run_corpus(stats))
        print(f"corpus: scored {n} samples")
    if args.source in ("prod", "both"):
        try:
            n = run_prod(stats, ecosystem=args.ecosystem, limit=args.limit)
            print(f"prod:   replayed {n} adjudicated scans")
        except Exception as e:
            print(f"prod:   skipped (DB unavailable: {e})", file=sys.stderr)

    return report(stats, min_precision=args.min_precision, min_support=args.min_support)


if __name__ == "__main__":
    sys.exit(main())
