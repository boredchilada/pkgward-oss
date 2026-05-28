#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""pkgsentry live stats / data-mining snapshot.

One-shot view of queue depth, throughput, verdicts, the async detonation queue,
and detection-quality signals — the things worth watching during a soak:
  - scan-queue backlog + churn (ingest vs processed) per ecosystem
  - detonation-queue drain + priority mix
  - LLM-triage source coverage per ecosystem (the "(no source extracted)" gap)
  - detonation-driven verdict flips (what dynamic analysis caught that static missed)

Run:
    docker exec pkgsentry python tools/stats.py
    docker exec pkgsentry python tools/stats.py --window-min 30
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text

from pkgsentry.store import session as sess
from pkgsentry.store.models import DetonationQueue, ScanQueue, Scan

_ECOS = ("pypi", "crates", "gomod", "npm")


def _hr(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> None:
    ap = argparse.ArgumentParser(description="pkgsentry live stats snapshot")
    ap.add_argument("--window-min", type=int, default=60, help="throughput window (minutes)")
    args = ap.parse_args()

    sess.init_db()
    win = args.window_min
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=win)

    with sess.session_scope() as s:
        _hr("scan queue")
        for eco in _ECOS:
            c = {
                st: s.scalar(select(func.count()).where(
                    ScanQueue.ecosystem == eco, ScanQueue.status == st)) or 0
                for st in ("pending", "claimed", "done", "failed")
            }
            print(f"  {eco:7} pending={c['pending']:<7} claimed={c['claimed']:<3} "
                  f"done={c['done']:<8} failed={c['failed']}")

        _hr(f"throughput / churn (last {win}m)")
        print(f"  {'eco':7} {'ingest':>8} {'done':>8} {'net':>8}")
        for eco in _ECOS:
            ingest = s.scalar(select(func.count()).where(
                ScanQueue.ecosystem == eco, ScanQueue.enqueued_at >= cutoff)) or 0
            done = s.scalar(select(func.count()).where(
                ScanQueue.ecosystem == eco, ScanQueue.status == "done",
                ScanQueue.finished_at >= cutoff)) or 0
            net = ingest - done
            arrow = "↑" if net > 0 else ("↓" if net < 0 else "·")
            print(f"  {eco:7} {ingest:>8} {done:>8} {net:>+7}{arrow}")

        _hr("detonation queue")
        for st in ("pending", "claimed", "done", "failed", "expired"):
            n = s.scalar(select(func.count()).where(DetonationQueue.status == st)) or 0
            print(f"  {st:8} {n}")
        prio = s.execute(
            select(DetonationQueue.priority, func.count())
            .where(DetonationQueue.status == "pending")
            .group_by(DetonationQueue.priority)
        ).all()
        if prio:
            print("  pending by priority: " + ", ".join(f"{p}={n}" for p, n in prio))
        det_done = s.scalar(select(func.count()).where(
            DetonationQueue.status == "done", DetonationQueue.finished_at >= cutoff)) or 0
        print(f"  detonated in last {win}m: {det_done}")

        _hr("scans by verdict")
        total = s.scalar(select(func.count()).select_from(Scan)) or 0
        for v in ("malicious", "suspicious", "clean", "error"):
            n = s.scalar(select(func.count()).where(Scan.verdict == v)) or 0
            print(f"  {v:11} {n}")
        print(f"  {'total':11} {total}")

        # --- detection-quality signals ---
        _hr("LLM triage source coverage (lower no-source % = better)")
        rows = s.execute(text(
            "SELECT p.ecosystem, "
            "SUM(CASE WHEN lower(s.llm_reasoning) LIKE '%no source%' THEN 1 ELSE 0 END), "
            "COUNT(*) "
            "FROM scan s JOIN version v ON s.version_id = v.id "
            "JOIN package p ON v.package_id = p.id "
            "WHERE s.llm_reasoning IS NOT NULL "
            "GROUP BY p.ecosystem ORDER BY p.ecosystem"
        )).all()
        if not rows:
            print("  (no LLM triages yet)")
        for eco, no_src, tot in rows:
            no_src, tot = int(no_src or 0), int(tot or 0)
            pct = (no_src * 100 // tot) if tot else 0
            flag = "  <-- gap" if pct >= 10 else ""
            print(f"  {eco:7} {no_src}/{tot} hedged no-source ({pct}%){flag}")

        _hr("detonation-driven verdict flips (dynamic caught what static missed)")
        flips = s.execute(text(
            "SELECT count(*) FROM detonation_queue dq JOIN scan s ON dq.scan_id = s.id "
            "WHERE dq.status = 'done' AND dq.static_verdict != 'malicious' "
            "AND s.verdict = 'malicious'"
        )).scalar() or 0
        print(f"  clean/suspicious -> malicious after detonation: {flips}")
    print()


if __name__ == "__main__":
    main()
