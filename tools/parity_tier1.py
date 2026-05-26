# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tier-1 parity test: DB-replay scoring.

For each historical Scan in the DB, load its persisted Finding rows, run
the (possibly refactored) score_and_verdict() function against them, and
compare the result with the stored Scan.verdict / score / alert_tag.

Catches scoring/threshold/chain-rule regressions WITHOUT re-fetching
archives or re-running the analyzers. Tier 2 (parity_tier2.py) covers
analyzer changes.

Run:
    python tools/parity_tier1.py

    # Or scope to a single ecosystem:
    python tools/parity_tier1.py --ecosystem pypi

    # Or sample N scans:
    python tools/parity_tier1.py --limit 1000
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from dataclasses import asdict
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkgsentry import intel
from pkgsentry.detect.score import score_and_verdict
from pkgsentry.store import session as sess
from pkgsentry.store.models import Finding, Package, Scan, Version, Watchlist


def _watchlist_rank(session: Session, ecosystem: str, name: str) -> Optional[int]:
    row = session.scalars(
        select(Watchlist).where(Watchlist.ecosystem == ecosystem, Watchlist.name == name)
    ).first()
    return row.rank if row else None


def run(*, ecosystem: Optional[str], limit: Optional[int], show_diffs: int) -> int:
    intel.load()
    diffs = 0
    total = 0
    diff_examples: list[dict] = []
    verdict_changes: Counter[str] = Counter()

    with sess.session_scope() as s:
        q = (
            select(Scan, Package, Version)
            .join(Version, Scan.version_id == Version.id)
            .join(Package, Version.package_id == Package.id)
        )
        if ecosystem:
            q = q.where(Package.ecosystem == ecosystem)
        q = q.order_by(Scan.started_at.desc())
        if limit:
            q = q.limit(limit)

        for scan, pkg, ver in s.execute(q):
            total += 1
            findings = s.scalars(
                select(Finding).where(Finding.scan_id == scan.id)
            ).all()
            rank = _watchlist_rank(s, pkg.ecosystem, pkg.name)
            from pkgsentry.adapter import Finding as FindingDC
            findings_dc = [
                FindingDC(
                    rule_id=f.rule_id,
                    category=f.category,
                    severity=f.severity,
                    confidence=f.confidence,
                    file=f.file or "",
                    line=f.line,
                    evidence=f.evidence or "",
                )
                for f in findings
            ]
            result = score_and_verdict(findings_dc, watchlist_rank=rank)
            same = (
                result.verdict == scan.verdict
                and result.score == scan.score
                and (result.alert_tag or None) == (scan.alert_tag or None)
            )
            if not same:
                diffs += 1
                verdict_changes[f"{scan.verdict}->{result.verdict}"] += 1
                if len(diff_examples) < show_diffs:
                    diff_examples.append({
                        "pkg": f"{pkg.ecosystem}:{pkg.name}=={ver.version}",
                        "scan_id": scan.id,
                        "stored": {
                            "verdict": scan.verdict,
                            "score": scan.score,
                            "alert_tag": scan.alert_tag,
                        },
                        "replayed": {
                            "verdict": result.verdict,
                            "score": result.score,
                            "alert_tag": result.alert_tag,
                        },
                        "n_findings": len(findings_dc),
                    })

    print(f"total scans replayed: {total}")
    print(f"verdict/score diffs:  {diffs}")
    print(f"parity:               {(total - diffs) / max(total, 1) * 100:.2f}%")
    if verdict_changes:
        print("\nverdict transitions:")
        for k, v in verdict_changes.most_common():
            print(f"  {k:30} {v}")
    if diff_examples:
        print(f"\nfirst {len(diff_examples)} diffs:")
        import json
        for ex in diff_examples:
            print(json.dumps(ex, indent=2, default=str))
    return 0 if diffs == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", choices=("pypi", "crates", "gomod"), default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--show-diffs", type=int, default=10,
                        help="print first N diffs for inspection")
    args = parser.parse_args()
    return run(ecosystem=args.ecosystem, limit=args.limit, show_diffs=args.show_diffs)


if __name__ == "__main__":
    sys.exit(main())
