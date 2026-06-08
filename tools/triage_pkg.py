#!/usr/bin/env python3
"""READ-ONLY: dump the latest scan's findings + LLM reasoning for given packages,
to triage whether an auto-watchlist entry is genuine malware or a false positive.

Usage: triage_pkg.py <ecosystem> <name> [<ecosystem> <name> ...]
"""
from __future__ import annotations

import sys

from sqlalchemy import select

from pkgward.store import session as sess
from pkgward.store.models import Scan, Version, Package, Finding


def main(pairs: list[tuple[str, str]]) -> None:
    sess.init_db()
    with sess.session_scope() as s:
        for eco, name in pairs:
            print("=" * 100)
            print(f"[{eco}] {name}")
            scans = s.execute(
                select(Scan.id, Version.version, Scan.verdict, Scan.score,
                       Scan.llm_verdict, Scan.llm_confidence, Scan.llm_reasoning,
                       Scan.alert_tag, Scan.finished_at)
                .select_from(Scan)
                .join(Version, Scan.version_id == Version.id)
                .join(Package, Version.package_id == Package.id)
                .where(Package.ecosystem == eco, Package.name == name)
                .order_by(Scan.finished_at.desc())
            ).all()
            if not scans:
                print("  (no scans found)\n")
                continue
            # the promoting scan = most recent llm-malicious, else most recent
            sc = next((x for x in scans if x.llm_verdict == "malicious"), scans[0])
            print(f"  version={sc.version}  verdict={sc.verdict} score={sc.score} "
                  f"llm={sc.llm_verdict}@{sc.llm_confidence} tag={sc.alert_tag}  "
                  f"({len(scans)} scans total)")
            print(f"  LLM reasoning: {(sc.llm_reasoning or '').strip()[:700]}")
            findings = s.execute(
                select(Finding.rule_id, Finding.severity, Finding.category,
                       Finding.file, Finding.evidence)
                .where(Finding.scan_id == sc.id)
                .order_by(Finding.severity, Finding.rule_id)
            ).all()
            print(f"  findings ({len(findings)}):")
            for f in findings:
                ev = (f.evidence or "").strip().replace("\n", " ")[:120]
                loc = f" @{f.file}" if f.file else ""
                print(f"    [{f.severity:8}] {f.rule_id}{loc}  {ev}")
            print()


if __name__ == "__main__":
    args = sys.argv[1:]
    main(list(zip(args[::2], args[1::2])))
