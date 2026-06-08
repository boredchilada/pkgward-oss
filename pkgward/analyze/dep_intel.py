# SPDX-License-Identifier: AGPL-3.0-or-later
"""Scan-time dependency-intel signal: a package that DECLARES a dependency on a
confirmed-malicious package (same ecosystem) is itself suspect. A weighted
finding, not a verdict — the pipeline/LLM adjudicate. A dependency edge that is
NEWLY added in this version (someone just injected it) is the strongest form."""
from __future__ import annotations

from typing import Optional

from pkgward import known_bad_deps
from pkgward.adapter import Finding

CATEGORY = "dep_intel"


def check_known_bad_deps(
    *,
    ecosystem: str,
    requires_dist: Optional[list],
    prev_requires_dist: Optional[list],
    known_bad: frozenset[str],
) -> list[Finding]:
    hits = known_bad_deps.match_known_bad(ecosystem, requires_dist, known_bad)
    if not hits:
        return []
    prev_norm = {
        known_bad_deps.normalize(
            ecosystem, known_bad_deps.extract_dep_name(ecosystem, e) or "",
        )
        for e in (prev_requires_dist or [])
    }
    out: list[Finding] = []
    for orig, norm in sorted(hits.items()):
        newly_added = bool(prev_requires_dist) and norm not in prev_norm
        if newly_added:
            severity, note = "critical", "newly added in this version"
        else:
            severity, note = "high", "present in this version"
        out.append(Finding(
            rule_id="dep_intel.depends_on_known_malicious",
            category=CATEGORY,
            severity=severity,
            confidence="high",
            file="",
            line=None,
            evidence=(
                f"declares a dependency on confirmed-malicious {ecosystem} package "
                f"{orig!r} ({note}) — supply-chain propagation signal"
            ),
        ))
    return out
