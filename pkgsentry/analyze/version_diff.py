# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from pkgsentry.adapter import Finding

CATEGORY = "version_diff"


@dataclass
class PreviousVersion:
    version: str
    verdict: str
    score: int
    rule_ids: set[str]
    finding_count: int
    author: Optional[str] = None
    author_email: Optional[str] = None
    upload_time: Optional[datetime] = None
    requires_dist: list[str] = field(default_factory=list)


def analyze_version_diff(
    current_findings: list[Finding],
    current_metadata: dict,
    prev: PreviousVersion,
) -> list[Finding]:
    out: list[Finding] = []
    cur_rule_ids = {f.rule_id for f in current_findings}

    new_critical_rules = {
        r for r in cur_rule_ids - prev.rule_ids
        if any(f.rule_id == r and f.severity == "critical" for f in current_findings)
    }
    if new_critical_rules and prev.verdict == "clean":
        out.append(Finding(
            rule_id="version_diff.clean_to_critical",
            category=CATEGORY,
            severity="critical",
            confidence="high",
            file="",
            line=None,
            evidence=(
                f"previous version {prev.version} was clean, "
                f"new version introduces critical rules: {sorted(new_critical_rules)}"
            ),
        ))

    if prev.verdict == "clean" and new_critical_rules:
        pass  # already covered above
    elif prev.verdict == "clean" and cur_rule_ids - prev.rule_ids:
        new_rules = sorted(cur_rule_ids - prev.rule_ids)
        out.append(Finding(
            rule_id="version_diff.new_rules_fired",
            category=CATEGORY,
            severity="medium",
            confidence="medium",
            file="",
            line=None,
            evidence=(
                f"previous version {prev.version} (verdict={prev.verdict}) "
                f"did not trigger: {new_rules[:10]}"
            ),
        ))

    cur_author = current_metadata.get("author_email") or current_metadata.get("author")
    prev_author = prev.author_email or prev.author
    if cur_author and prev_author and cur_author.lower() != prev_author.lower():
        out.append(Finding(
            rule_id="version_diff.author_changed",
            category=CATEGORY,
            severity="high",
            confidence="high",
            file="",
            line=None,
            evidence=f"author changed: {prev_author!r} -> {cur_author!r} (possible account takeover)",
        ))

    cur_deps = set(current_metadata.get("requires_dist") or [])
    prev_deps = set(prev.requires_dist or [])
    new_deps = cur_deps - prev_deps
    if new_deps and len(new_deps) > len(prev_deps) * 0.5 and len(new_deps) >= 3:
        out.append(Finding(
            rule_id="version_diff.dependency_spike",
            category=CATEGORY,
            severity="medium",
            confidence="medium",
            file="",
            line=None,
            evidence=(
                f"added {len(new_deps)} new dependencies vs {len(prev_deps)} previous: "
                f"{sorted(list(new_deps))[:8]}"
            ),
        ))

    return out
