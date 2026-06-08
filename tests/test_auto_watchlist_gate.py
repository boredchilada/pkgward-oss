# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimum-evidence bar for auto-watchlist promotion (pipeline._auto_watchlist_qualifies).

Guards the @zola_do FP cascade: a single soft IOC / dep_intel hit that the LLM
calls malicious must NOT promote a package to sentinel rank (which would feed
known_bad_deps and cascade dep_intel onto its dependents).
"""
from __future__ import annotations

from types import SimpleNamespace

from pkgward.adapter import Finding
from pkgward.pipeline import _auto_watchlist_qualifies


def _f(category: str, severity: str, rule_id: str | None = None) -> Finding:
    return Finding(
        rule_id=rule_id or f"{category}.some_rule",
        category=category, severity=severity, confidence="high",
    )


def _res(verdict: str):
    return SimpleNamespace(verdict=verdict, score=0)


def _tri(verdict: str = "malicious", confidence: float = 0.95):
    return SimpleNamespace(verdict=verdict, confidence=confidence)


def test_single_ioc_hit_does_not_promote():
    # The @zola_do case: one iocs.hardcoded_wan_ip_port, LLM confidently malicious.
    ok, reason = _auto_watchlist_qualifies(
        _res("suspicious"), _tri("malicious", 0.95),
        [_f("iocs", "high", "iocs.hardcoded_wan_ip_port")],
    )
    assert not ok and reason == "thin_evidence_single_soft_category"


def test_single_dep_intel_hit_does_not_promote():
    # Breaks the cascade: a package convicted ONLY by depending on known-bad.
    ok, reason = _auto_watchlist_qualifies(
        _res("suspicious"), _tri("malicious", 0.99),
        [_f("dep_intel", "critical", "dep_intel.depends_on_known_malicious")],
    )
    assert not ok and reason == "thin_evidence_single_soft_category"


def test_primary_evidence_plus_rule_malicious_promotes():
    ok, reason = _auto_watchlist_qualifies(
        _res("malicious"), _tri("malicious", 0.75),
        [_f("yara", "critical", "yara.w4sp_stealer"), _f("iocs", "high")],
    )
    assert ok and reason == "ok"


def test_rule_malicious_with_subfloor_llm_confidence_does_not_promote():
    # The ainx class (2026-06-07): rules malicious + LLM "malicious" at 0.2-0.55.
    # Rule corroboration must not carry a coin-flip LLM verdict to sentinel rank.
    ok, reason = _auto_watchlist_qualifies(
        _res("malicious"), _tri("malicious", 0.5),
        [_f("yara", "critical"), _f("iocs", "high")],
    )
    assert not ok and reason == "llm_confidence_below_floor"


def test_primary_evidence_plus_high_conf_llm_promotes_on_rule_suspicious():
    # LLM-escalation case with real evidence (opengrep), high confidence.
    ok, reason = _auto_watchlist_qualifies(
        _res("suspicious"), _tri("malicious", 0.9),
        [_f("opengrep", "high", "opengrep.install_net_exec")],
    )
    assert ok and reason == "ok"


def test_primary_evidence_but_weak_corroboration_does_not_promote():
    # Real primary category, LLM above the floor but below the high-conf bar,
    # and rules only suspicious — no corroboration from either side.
    ok, reason = _auto_watchlist_qualifies(
        _res("suspicious"), _tri("malicious", 0.75),
        [_f("obfuscation", "high")],
    )
    assert not ok and reason == "weak_corroboration"


def test_two_distinct_soft_categories_with_rule_malicious_promotes():
    # >=2 distinct strong categories counts as corroboration even if both soft.
    ok, reason = _auto_watchlist_qualifies(
        _res("malicious"), _tri("malicious", 0.75),
        [_f("iocs", "high"), _f("metadata", "high")],
    )
    assert ok and reason == "ok"


def test_llm_not_malicious_never_promotes():
    ok, reason = _auto_watchlist_qualifies(
        _res("malicious"), _tri("suspicious", 0.95),
        [_f("yara", "critical")],
    )
    assert not ok and reason == "llm_not_malicious"


def test_shadow_findings_do_not_count_as_evidence():
    ok, reason = _auto_watchlist_qualifies(
        _res("malicious"), _tri("malicious", 0.95),
        [_f("opengrep", "critical", "opengrep.shadow_install_net_exec")],
    )
    assert not ok and reason == "thin_evidence_single_soft_category"


def test_no_tri_never_promotes():
    ok, reason = _auto_watchlist_qualifies(_res("malicious"), None, [_f("yara", "critical")])
    assert not ok and reason == "llm_not_malicious"
