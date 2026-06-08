#!/usr/bin/env python3
"""READ-ONLY audit of the auto-watchlist (sentinel rank).

For each auto-added (ecosystem, name), find the most-recent LLM-malicious scan
that promoted it, load that scan's findings, and classify under the NEW
minimum-evidence bar (pipeline._auto_watchlist_qualifies):

  PRIMARY  — has >=1 high/crit finding outside {iocs,dep_intel,metadata,version_diff}
             OR >=2 distinct strong categories  -> genuine, would still promote
  THIN-FP  — strong evidence is a single soft/propagation category -> FP, would drop
  NO-SCAN  — no LLM-malicious scan found in history (promoted some other way)

The rule verdict isn't persisted (Scan.verdict is overwritten with the LLM
verdict), so corroboration here is approximated by llm_confidence; the PRIMARY vs
THIN split (the FP discriminator) is computed exactly from the findings.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select

from pkgward.store import session as sess
from pkgward.store.models import Watchlist, Scan, Version, Package, Finding
from pkgward.watchlist_auto import AUTO_MALICIOUS_RANK
from pkgward.pipeline import _NON_PRIMARY_PROMOTE_CATEGORIES

_STRONG = ("high", "critical")


def main() -> None:
    sess.init_db()
    with sess.session_scope() as s:
        entries = s.execute(
            select(Watchlist.ecosystem, Watchlist.name, Watchlist.refreshed_at)
            .where(Watchlist.rank == AUTO_MALICIOUS_RANK)
            .order_by(Watchlist.ecosystem, Watchlist.name)
        ).all()
        print(f"auto-watchlist (sentinel rank {AUTO_MALICIOUS_RANK}): {len(entries)} entries\n")
        if not entries:
            return

        # Most-recent LLM-malicious scan per (eco, name), with its findings.
        # Pull all candidate scans for the watchlisted packages in one query.
        names_by_eco: dict[str, set[str]] = defaultdict(set)
        for eco, name, _ in entries:
            names_by_eco[eco].add(name)

        scan_rows = s.execute(
            select(
                Package.ecosystem, Package.name, Scan.id, Scan.score,
                Scan.verdict, Scan.llm_verdict, Scan.llm_confidence, Scan.finished_at,
            )
            .select_from(Scan)
            .join(Version, Scan.version_id == Version.id)
            .join(Package, Version.package_id == Package.id)
            .where(Scan.llm_verdict == "malicious")
        ).all()

        # latest llm-malicious scan per (eco, name)
        latest: dict[tuple[str, str], tuple] = {}
        for r in scan_rows:
            key = (r.ecosystem, r.name)
            if key not in names_by_eco_set(names_by_eco):
                continue
            if key not in latest or (r.finished_at and latest[key].finished_at
                                     and r.finished_at > latest[key].finished_at):
                latest[key] = r

        scan_ids = [r.id for r in latest.values()]
        findings_by_scan: dict[int, list[Finding]] = defaultdict(list)
        if scan_ids:
            for f in s.execute(
                select(Finding.scan_id, Finding.category, Finding.severity, Finding.rule_id)
                .where(Finding.scan_id.in_(scan_ids))
            ).all():
                findings_by_scan[f.scan_id].append(f)

        kept, fps, noscan = [], [], []
        for eco, name, refreshed in entries:
            key = (eco, name)
            scan = latest.get(key)
            if scan is None:
                noscan.append((eco, name, refreshed))
                continue
            strong = [f for f in findings_by_scan.get(scan.id, [])
                      if f.severity in _STRONG and not f.rule_id.startswith("opengrep.shadow_")]
            cats = {f.category for f in strong}
            has_primary = bool(cats - _NON_PRIMARY_PROMOTE_CATEGORIES)
            primary = has_primary or len(cats) >= 2
            sev_by_cat = {}
            for f in strong:
                sev_by_cat[f.category] = f.severity
            cat_str = ", ".join(f"{c}:{sev_by_cat[c]}" for c in sorted(sev_by_cat)) or "(no strong findings)"
            row = (eco, name, scan.score, scan.llm_confidence, cat_str)
            (kept if primary else fps).append(row)

        def _dump(title, rows):
            print(f"== {title}: {len(rows)} ==")
            for eco, name, score, conf, cats in rows:
                c = f"{conf:.2f}" if conf is not None else "n/a"
                print(f"  [{eco}] {name}  score={score} llm_conf={c}  strong={{{cats}}}")
            print()

        _dump("GENUINE (primary evidence — would still promote)", sorted(kept))
        _dump("THIN / FP (single soft/propagation category — would NOT promote now)", sorted(fps))
        if noscan:
            print(f"== NO LLM-MALICIOUS SCAN FOUND: {len(noscan)} ==")
            for eco, name, refreshed in sorted(noscan):
                print(f"  [{eco}] {name}  refreshed={refreshed}")
            print()
        print(f"SUMMARY: {len(kept)} genuine, {len(fps)} thin/FP, {len(noscan)} no-scan "
              f"of {len(entries)} total")


def names_by_eco_set(d):
    return {(eco, n) for eco, names in d.items() for n in names}


if __name__ == "__main__":
    main()
