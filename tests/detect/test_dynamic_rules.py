# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.adapter import Finding
from pkgsentry.detect.rules import BEHAVIORAL_CHAIN_RULES, DYNAMIC_CHAIN_RULES
from pkgsentry.detect.score import score_and_verdict


def test_dynamic_chain_rules_exist():
    assert "dyn_install_exfil" in DYNAMIC_CHAIN_RULES
    assert "dyn_reverse_shell" in DYNAMIC_CHAIN_RULES
    assert "dyn_proc_inject" in DYNAMIC_CHAIN_RULES


def test_dynamic_chain_rules_in_behavioral():
    for rule in DYNAMIC_CHAIN_RULES:
        assert rule in BEHAVIORAL_CHAIN_RULES


def test_dynamic_finding_escalates_to_malicious():
    findings = [
        Finding(
            rule_id="dyn_install_exfil",
            category="dynamic",
            severity="critical",
            confidence="high",
            evidence="connect(AF_INET, 45.33.32.156:443) during install phase",
        ),
    ]
    result = score_and_verdict(findings, watchlist_rank=None)
    assert result.verdict == "malicious"
