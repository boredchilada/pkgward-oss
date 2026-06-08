# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check scanned files against known-malicious fingerprints.

Three-tier matching (same priority order as dephish):
  1. SHA-256 exact match
  2. ssdeep fuzzy match  (>= threshold, default 70%)
  3. TLSH distance match  (<= threshold, default 120)
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkgward.adapter import Finding
from pkgward.store.models import ThreatIntelHash
from pkgward.util import capabilities as caps

log = logging.getLogger(__name__)

SSDEEP_THRESHOLD = 70
TLSH_THRESHOLD = 120

# Promoted fingerprints (operator confirmed the family is a real campaign) get a
# TIGHTER fuzzy threshold than the curated baseline pack, because each is a single
# payload rather than a hand-tuned family signature.
PROMOTED_SSDEEP_THRESHOLD = 88
PROMOTED_TLSH_THRESHOLD = 40


def _is_auto(entry: ThreatIntelHash) -> bool:
    """Auto-seeded, UNREVIEWED fingerprint. These match on EXACT sha256 only —
    fuzzy (ssdeep/TLSH) is skipped for them. Reason: a fuzzy match on an unreviewed
    seed cascades false positives (a seeded FP fuzzy-matches a benign lookalike,
    whose verdict then auto-seeds *it* — exactly the chain-signer/@comment-io mess).
    Fuzzy power is opt-in via `threatintel promote`."""
    return (entry.source or "") == "auto"


def _is_promoted(entry: ThreatIntelHash) -> bool:
    return (entry.source or "") == "promoted"

# Per-campaign TLSH override. Lower than the global default for campaigns whose
# fingerprint is short or structurally common enough that the loose 120 default
# false-positives on unrelated small modules. Validated reskins for these
# families clustered at much lower distances (github_contents_exfil: 28).
_CAMPAIGN_TLSH_THRESHOLD = {
    "github_contents_exfil": 60,
}

_LABEL_SEVERITY = {"malicious": "critical", "suspicious": "high", "pua": "medium"}


def _pattern_ok(entry: ThreatIntelHash, name: str) -> bool:
    """Scope a fuzzy match to the fingerprint's intended filename glob (exact
    sha256 matches bypass this)."""
    if not entry.file_pattern or not name:
        return True
    return fnmatch.fnmatch(name, entry.file_pattern)


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
    filename: str = "",
) -> Optional[ThreatMatch]:
    intel = _load_intel(session)
    if not intel:
        return None

    name = filename.rsplit("/", 1)[-1] if filename else ""

    for entry in intel:
        if entry.sha256 == sha256:
            return ThreatMatch(
                tier="sha256", score=100.0,
                campaign=entry.campaign, label=entry.label,
                description=entry.description or "",
                intel_sha256=entry.sha256,
            )

    if caps.HAS_PPDEEP and ssdeep_hash:
        for entry in intel:
            if _is_auto(entry):
                continue  # unreviewed: exact sha256 only (handled above)
            if not entry.ssdeep or not _pattern_ok(entry, name):
                continue
            similarity = caps.ppdeep.compare(ssdeep_hash, entry.ssdeep)
            ssdeep_thr = PROMOTED_SSDEEP_THRESHOLD if _is_promoted(entry) else SSDEEP_THRESHOLD
            if similarity >= ssdeep_thr:
                return ThreatMatch(
                    tier="ssdeep", score=float(similarity),
                    campaign=entry.campaign, label=entry.label,
                    description=entry.description or "",
                    intel_sha256=entry.sha256,
                )

    if caps.HAS_TLSH and tlsh_hash and tlsh_hash not in ("TNULL", ""):
        for entry in intel:
            if _is_auto(entry):
                continue  # unreviewed: exact sha256 only (handled above)
            if not entry.tlsh or entry.tlsh == "TNULL" or not _pattern_ok(entry, name):
                continue
            dist = caps.tlsh.diff(tlsh_hash, entry.tlsh)
            default_thr = PROMOTED_TLSH_THRESHOLD if _is_promoted(entry) else TLSH_THRESHOLD
            threshold = _CAMPAIGN_TLSH_THRESHOLD.get(entry.campaign, default_thr)
            if dist <= threshold:
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
            filename=path,
        )
        if match is None:
            continue
        severity = _LABEL_SEVERITY.get((match.label or "malicious").lower(), "critical")
        findings.append(Finding(
            rule_id=f"intel.{match.campaign}",
            category="threat_intel",
            severity=severity,
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
