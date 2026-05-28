# SPDX-License-Identifier: AGPL-3.0-or-later
"""Carry forward prior findings on SHA-unchanged files for known-malicious
packages.

The attacker pattern this addresses: a confirmed-malicious npm package
(e.g. `forge-jsxy`) re-publishes byte-identical RAT code with only a version
bump + a couple of new files. Today our `changed_files` optimization analyses
only the changed files → the new scan reports 3 of the 11 findings the prior
scan reported. The chain rule keeps the verdict malicious, but the LLM
adjudicates on a thin evidence basis — if the chain shifts, we lose them.

Fix: for **auto-watchlisted (confirmed-malicious) names only**, look up the
most-recent prior scan of the same package within `PKGSENTRY_FINDING_REUSE_DAYS`
(default 7) and append its findings for every file whose `(file_path, sha256)`
is unchanged. Scoring + LLM see the full evidence; analysers don't re-run on
unchanged files.

Why scoped to auto-watchlisted only:
* It's the surface where attackers republish byte-identical payloads → near
  100% cache-hit rate, dramatic perf win.
* Limits the staleness blast radius: if a yara/opengrep rule is updated, a
  clean popular pkg isn't affected (it doesn't go through this path).

Staleness handling (v1): a 7-day TTL. Findings older than that are not reused
— forces a fresh analysis after a week, bounded drift on rule updates. A
sharper handle (intel-pack version stamped on each Scan) is a follow-up if
soak shows real false-negative drift.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkgsentry.adapter import Finding as AdapterFinding
from pkgsentry.logging_setup import get_logger
from pkgsentry.store.models import Finding as FindingRow
from pkgsentry.store.models import FileHash, Package, Scan, Version

log = get_logger("scan.finding_reuse")


def _window_days() -> int:
    return int(os.environ.get("PKGSENTRY_FINDING_REUSE_DAYS", "7"))


def carry_forward_findings(
    session: Session,
    ecosystem: str,
    name: str,
    current_scan_id: int,
    current_hashes: dict[str, str],
) -> list[AdapterFinding]:
    """Return findings to carry forward from the most-recent prior scan of
    `(ecosystem, name)` for files whose `(path, sha256)` are unchanged.

    `current_hashes`: dict mapping ``file_path`` → ``sha256`` for the current
    scan's files (build from ``all_file_hashes``).
    `current_scan_id`: excluded from the lookup so we don't self-match a row
    that was just inserted.

    Returns an empty list when there's no prior scan in the TTL window or no
    SHA-stable files. Never raises into the pipeline (best-effort).
    """
    if not current_hashes:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=_window_days())
    try:
        prior_scan_id = session.scalar(
            select(Scan.id)
            .join(Version, Scan.version_id == Version.id)
            .join(Package, Version.package_id == Package.id)
            .where(
                Package.ecosystem == ecosystem,
                Package.name == name,
                Scan.id != current_scan_id,
                Scan.finished_at.isnot(None),
                Scan.finished_at >= cutoff,
            )
            .order_by(Scan.finished_at.desc())
            .limit(1)
        )
        if prior_scan_id is None:
            return []

        prior_hashes = {
            h[0]: h[1]
            for h in session.execute(
                select(FileHash.file_path, FileHash.sha256).where(
                    FileHash.scan_id == prior_scan_id,
                )
            ).all()
        }
        unchanged_paths = {
            path for path, sha in current_hashes.items()
            if prior_hashes.get(path) == sha
        }
        if not unchanged_paths:
            return []

        # Finding.file and FileHash.file_path don't always match cleanly: npm
        # tarballs store hashes under the normalized path (no leading "package/"),
        # but several analyzers record `file` as the relative path *with* the
        # leading prefix, or as basename-only (iocs). Match flexibly: exact
        # normalized path, prefix-stripped path, then basename fallback.
        unchanged_basenames = {p.rsplit("/", 1)[-1] for p in unchanged_paths}

        prior_findings = session.scalars(
            select(FindingRow).where(FindingRow.scan_id == prior_scan_id)
        ).all()
        out: list[AdapterFinding] = []
        for f in prior_findings:
            if not f.file:
                continue
            f_norm = f.file
            for prefix in ("package/", ):
                if f_norm.startswith(prefix):
                    f_norm = f_norm[len(prefix):]
                    break
            if f_norm in unchanged_paths or f_norm.rsplit("/", 1)[-1] in unchanged_basenames:
                out.append(AdapterFinding(
                    rule_id=f.rule_id, category=f.category, severity=f.severity,
                    confidence=f.confidence, file=f.file, line=f.line,
                    evidence=f.evidence or "",
                ))
        return out
    except Exception as e:
        log.warning("findings_carry_forward_failed",
                    ecosystem=ecosystem, name=name, error=str(e))
        return []
