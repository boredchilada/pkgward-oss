# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check scanned files against known-malicious fingerprints.

Three-tier matching (same priority order as dephish):
  1. SHA-256 exact match
  2. ssdeep fuzzy match  (>= threshold, default 70%)
  3. TLSH distance match  (<= threshold, default 120)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkgsentry.adapter import Finding
from pkgsentry.store.models import ThreatIntelHash

log = logging.getLogger(__name__)

try:
    import ppdeep
    _has_ppdeep = True
except ImportError:
    _has_ppdeep = False

try:
    import tlsh as _tlsh
    _has_tlsh = True
except ImportError:
    _has_tlsh = False

SSDEEP_THRESHOLD = 70
TLSH_THRESHOLD = 120


@dataclass
class ThreatMatch:
    tier: str           # "sha256" | "ssdeep" | "tlsh"
    score: float        # 100 for exact, ssdeep %, or 100-tlsh_dist for tlsh
    campaign: str
    label: str
    description: str
    intel_sha256: str


def _load_intel(session: Session) -> list[ThreatIntelHash]:
    return list(session.scalars(select(ThreatIntelHash)).all())


def check_file(
    session: Session,
    sha256: str,
    ssdeep_hash: str = "",
    tlsh_hash: str = "",
) -> Optional[ThreatMatch]:
    intel = _load_intel(session)
    if not intel:
        return None

    for entry in intel:
        if entry.sha256 == sha256:
            return ThreatMatch(
                tier="sha256", score=100.0,
                campaign=entry.campaign, label=entry.label,
                description=entry.description or "",
                intel_sha256=entry.sha256,
            )

    if _has_ppdeep and ssdeep_hash:
        for entry in intel:
            if not entry.ssdeep:
                continue
            similarity = ppdeep.compare(ssdeep_hash, entry.ssdeep)
            if similarity >= SSDEEP_THRESHOLD:
                return ThreatMatch(
                    tier="ssdeep", score=float(similarity),
                    campaign=entry.campaign, label=entry.label,
                    description=entry.description or "",
                    intel_sha256=entry.sha256,
                )

    if _has_tlsh and tlsh_hash and tlsh_hash not in ("TNULL", ""):
        for entry in intel:
            if not entry.tlsh or entry.tlsh == "TNULL":
                continue
            dist = _tlsh.diff(tlsh_hash, entry.tlsh)
            if dist <= TLSH_THRESHOLD:
                return ThreatMatch(
                    tier="tlsh", score=float(dist),
                    campaign=entry.campaign, label=entry.label,
                    description=entry.description or "",
                    intel_sha256=entry.sha256,
                )

    return None


def check_files_batch(
    session: Session,
    files: dict[str, dict],
) -> list[FindingItem]:
    """Check a batch of files against threat intel.

    *files*: ``{path: {"sha256": ..., "ssdeep": ..., "tlsh": ...}}``

    Returns Finding-compatible dicts for any matches.
    """
    findings: list[Finding] = []
    for path, hashes in files.items():
        match = check_file(
            session,
            sha256=hashes.get("sha256", ""),
            ssdeep_hash=hashes.get("ssdeep", ""),
            tlsh_hash=hashes.get("tlsh", ""),
        )
        if match is None:
            continue
        findings.append(Finding(
            rule_id=f"intel.{match.campaign}",
            category="threat_intel",
            severity="critical",
            confidence="high",
            file=path,
            evidence=(
                f"Known malicious file ({match.tier} match, "
                f"score={match.score}, campaign={match.campaign}): "
                f"{match.description}"
            ),
        ))
        log.warning(
            "threat_intel match: %s on %s (%s, score=%.0f, campaign=%s)",
            match.intel_sha256[:16], path, match.tier, match.score, match.campaign,
        )
    return findings
