# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from typing import Optional

from pkgsentry.adapter import Finding
from pkgsentry.detect.rules import BEHAVIORAL_CHAIN_RULES


def should_detonate(
    *,
    verdict: str,
    score: int,
    findings: list[Finding],
    watchlist_rank: Optional[int],
    is_new_package: bool,
) -> bool:
    if is_new_package:
        return True

    if watchlist_rank is not None:
        return True

    has_chain = any(f.rule_id in BEHAVIORAL_CHAIN_RULES for f in findings)
    if verdict == "malicious" and has_chain:
        return False

    if verdict in ("suspicious", "malicious"):
        return True

    return False
