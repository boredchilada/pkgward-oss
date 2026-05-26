# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lure name detection — flags brand-new packages with social-engineering names.

Scores package names against keyword categories commonly used in supply-chain
lure campaigns. A single category hit is ignored (too common). Multi-category
combos are strong signal: a brand-new package named "wallet-security-checker"
hits crypto + security-theater = medium finding.

Categories are loaded from the intel pack at first use. UNION semantics:
operators extend the baseline categories via their private overlay.
"""
from __future__ import annotations

import re
from typing import Optional

from pkgsentry import intel
from pkgsentry.adapter import Finding

CATEGORY = "metadata"

_PATTERN_CACHE: Optional[dict[str, re.Pattern]] = None
_PATTERN_SOURCE: str = ""


def _get_patterns() -> dict[str, re.Pattern]:
    global _PATTERN_CACHE, _PATTERN_SOURCE
    pack = intel.current()
    if _PATTERN_CACHE is not None and _PATTERN_SOURCE == pack.source:
        return _PATTERN_CACHE

    patterns: dict[str, re.Pattern] = {}
    for cat, keywords in pack.lure_keywords.items():
        if not keywords:
            continue
        escaped = [re.escape(kw) for kw in keywords]
        patterns[cat] = re.compile("|".join(escaped), re.IGNORECASE)

    _PATTERN_CACHE = patterns
    _PATTERN_SOURCE = pack.source
    return patterns


def score_name(name: str) -> dict[str, list[str]]:
    """Return {category: [matched_keywords]} for a package name."""
    patterns = _get_patterns()
    hits: dict[str, list[str]] = {}
    for cat, pat in patterns.items():
        matches = pat.findall(name.lower())
        if matches:
            hits[cat] = matches
    return hits


def analyze_lure_name(name: str) -> list[Finding]:
    """Score a package name for social-engineering lure patterns.

    Returns findings only when 2+ distinct categories match — single-category
    hits are too common in legitimate packages to be useful signal.
    """
    hits = score_name(name)
    n_categories = len(hits)

    if n_categories < 2:
        return []

    matched_cats = sorted(hits.keys())
    matched_keywords = []
    for cat in matched_cats:
        matched_keywords.extend(hits[cat])
    evidence = (
        f"name {name!r} matches {n_categories} lure categories: "
        f"{', '.join(matched_cats)} (keywords: {', '.join(matched_keywords)})"
    )

    if n_categories >= 3:
        return [Finding(
            rule_id="metadata.lure_name_combo",
            category=CATEGORY,
            severity="high",
            confidence="medium",
            file="",
            line=None,
            evidence=evidence,
        )]

    return [Finding(
        rule_id="metadata.lure_name",
        category=CATEGORY,
        severity="medium",
        confidence="medium",
        file="",
        line=None,
        evidence=evidence,
    )]
