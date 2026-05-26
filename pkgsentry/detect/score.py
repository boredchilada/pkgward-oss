# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from pkgsentry import intel
from pkgsentry.adapter import Finding
from pkgsentry.logging_setup import get_logger

log = get_logger("detect.score")


@dataclass
class ScoreResult:
    score: int
    verdict: str
    alert_tag: Optional[str]


def _severity_points(severity: str) -> int:
    return int(intel.current().scoring_weights.get(severity, 0))


def _category_cap() -> int:
    return int(intel.current().thresholds.get("category_cap", 30))


def _suspicious_min() -> int:
    return int(intel.current().thresholds.get("suspicious_min", 20))


def _malicious_min() -> int:
    return int(intel.current().thresholds.get("malicious_min", 61))


def _raw_score(findings: Iterable[Finding]) -> int:
    cap = _category_cap()
    per_cat: dict[str, int] = {}
    for f in findings:
        pts = _severity_points(f.severity)
        per_cat[f.category] = min(per_cat.get(f.category, 0) + pts, cap)
    return sum(per_cat.values())


def _has_any(findings: Iterable[Finding], severity: str) -> bool:
    return any(f.severity == severity for f in findings)


def _has_behavioral_chain(findings: Iterable[Finding]) -> bool:
    chain_ids = intel.current().behavioral_chain_ids
    return any(f.rule_id in chain_ids for f in findings)


def _is_shadow_finding(finding: Finding) -> bool:
    """Findings with rule_id `opengrep.shadow_*` are observation-only.
    They persist to the findings table for offline comparison against the
    legacy regex/AST analyzers but are excluded from scoring and verdict."""
    return finding.rule_id.startswith("opengrep.shadow_")


def score_and_verdict(
    findings: list[Finding],
    *,
    watchlist_rank: Optional[int],
) -> ScoreResult:
    scoring = [f for f in findings if not _is_shadow_finding(f)]

    score = _raw_score(scoring)
    malicious_min = _malicious_min()
    suspicious_min = _suspicious_min()

    if _has_behavioral_chain(scoring) or _has_any(scoring, "critical") or score >= malicious_min:
        verdict = "malicious"
    elif _has_any(scoring, "high") or score >= suspicious_min:
        verdict = "suspicious"
    else:
        verdict = "clean"

    alert_tag: Optional[str] = None
    if watchlist_rank is not None:
        if verdict == "clean" and any(f.severity in ("medium", "high", "critical") for f in scoring):
            verdict = "suspicious"
        if watchlist_rank <= 100 and any(f.severity in ("high", "critical") for f in scoring):
            verdict = "malicious"
            alert_tag = "watchlist_top100"
            log.warning(
                "top100_alert",
                rank=watchlist_rank,
                findings=[{"rule": f.rule_id, "sev": f.severity} for f in scoring],
            )

    return ScoreResult(score=score, verdict=verdict, alert_tag=alert_tag)
