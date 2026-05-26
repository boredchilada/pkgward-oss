# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tier-2 parity test: full pipeline re-run against N historical scans.

For N representative scans, re-fetch the archive from the registry, run
the full analysis pipeline with the current code + loaded intel pack,
and diff finding sets + verdict + score against what's stored in the DB.

Catches analyzer-side regressions (YARA, IOC whitelist, keyword lists,
threshold moves, behavioral chain logic) that tier-1 cannot see.

This is bandwidth-intensive — runs in ~2-4 hours for N=200. Bias the
sample toward suspicious/malicious verdicts (where regressions hurt
most). Run from inside the scanner Docker container so the fetch/extract
code paths are exercised the same way prod uses them.

Run:
    python tools/parity_tier2.py --n 200 --bias suspicious

    # Or pick specific scan IDs:
    python tools/parity_tier2.py --scan-ids 12345 12346 12347

The script writes a CSV diff report to stdout. Pipe to a file for review.
"""
from __future__ import annotations

import argparse
import csv
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Optional

from sqlalchemy import or_, select

from pkgsentry import intel
from pkgsentry.adapter import adapter_registry
from pkgsentry.store import session as sess
from pkgsentry.store.models import Finding, Package, Scan, Version


def _select_sample(
    s, *, n: int, bias: Optional[str], ecosystem: Optional[str],
) -> list[tuple[Scan, Package, Version]]:
    q = (
        select(Scan, Package, Version)
        .join(Version, Scan.version_id == Version.id)
        .join(Package, Version.package_id == Package.id)
    )
    if ecosystem:
        q = q.where(Package.ecosystem == ecosystem)
    if bias == "suspicious":
        q = q.where(or_(Scan.verdict == "suspicious", Scan.verdict == "malicious"))
    elif bias == "malicious":
        q = q.where(Scan.verdict == "malicious")
    elif bias == "clean":
        q = q.where(Scan.verdict == "clean")
    q = q.order_by(Scan.started_at.desc()).limit(n)
    return list(s.execute(q))


def _findings_keyset(findings) -> set[tuple]:
    """Stable identity for a finding for set-diff purposes."""
    out = set()
    for f in findings:
        out.add((f.rule_id, f.category, f.severity, f.file or "", f.line, (f.evidence or "")[:120]))
    return out


def run(*, n: int, bias: Optional[str], ecosystem: Optional[str], scan_ids: Optional[list[int]]) -> int:
    intel.load()
    from pkgsentry.pipeline import process_one
    import asyncio

    diffs = 0
    total = 0
    transitions: Counter[str] = Counter()
    rows: list[dict] = []

    with sess.session_scope() as s:
        if scan_ids:
            scans = []
            for sid in scan_ids:
                row = s.execute(
                    select(Scan, Package, Version)
                    .join(Version, Scan.version_id == Version.id)
                    .join(Package, Version.package_id == Package.id)
                    .where(Scan.id == sid)
                ).first()
                if row:
                    scans.append(row)
        else:
            scans = _select_sample(s, n=n, bias=bias, ecosystem=ecosystem)

        for scan, pkg, ver in scans:
            total += 1
            stored_findings = s.scalars(
                select(Finding).where(Finding.scan_id == scan.id)
            ).all()
            stored_keys = _findings_keyset(stored_findings)

            # NOTE: tier-2 re-runs the pipeline against a fresh tempdir,
            # which produces a NEW scan row. This is unavoidable without
            # restructuring process_one to expose a "dry run" path.
            #
            # Strategy: call process_one with a fake queue_id pointing at
            # the same (ecosystem, name, version) and rely on the pipeline
            # writing a new scan row. We then compare that new scan with
            # the historical one.
            adapter = adapter_registry.get(pkg.ecosystem)
            if adapter is None:
                continue
            try:
                # We cannot reuse the original queue row (already done).
                # Instead, build a synthetic claim and run the pipeline.
                # This requires care: process_one writes to the DB.
                # Use a temp DB URL or mark new scans for cleanup.
                print(f"[skip — tier2 needs a proper dry-run harness] {pkg.ecosystem}:{pkg.name}=={ver.version}", file=sys.stderr)
                continue
            except Exception as e:
                print(f"[error] {pkg.ecosystem}:{pkg.name}=={ver.version}: {e}", file=sys.stderr)
                continue

    # NOTE: This script is currently a skeleton — the dry-run pipeline
    # path isn't built. Two future approaches:
    #   1. Add a `process_one(..., dry_run=True)` parameter that skips DB
    #      writes and returns the result tuple. Then diff in-memory.
    #   2. Run process_one against a separate scratch DB (PKGSENTRY_DB_URL=
    #      sqlite:///parity_scratch.db) and diff scratch vs prod.
    #
    # Option 1 is cleaner; option 2 is easier to implement. Pick during
    # the live-prod parity gate.
    print(f"scanned: {total}  diffs: {diffs}", file=sys.stderr)
    if rows:
        writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return 0 if diffs == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=200)
    parser.add_argument("--bias", choices=("suspicious", "malicious", "clean"), default="suspicious")
    parser.add_argument("--ecosystem", choices=("pypi", "crates", "gomod"), default=None)
    parser.add_argument("--scan-ids", type=int, nargs="+", default=None)
    args = parser.parse_args()
    return run(n=args.n, bias=args.bias, ecosystem=args.ecosystem, scan_ids=args.scan_ids)


if __name__ == "__main__":
    sys.exit(main())
