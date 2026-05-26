# SPDX-License-Identifier: AGPL-3.0-or-later
from pkgsentry.adapter import Finding
from pkgsentry.detect.score import score_and_verdict


def _f(severity, category="iocs", rule_id="x"):
    return Finding(rule_id=rule_id, category=category, severity=severity,
                   confidence="medium", file="a.py", line=1, evidence="e")


def test_clean_no_findings():
    res = score_and_verdict([], watchlist_rank=None)
    assert res.verdict == "clean"
    assert res.score == 0
    assert res.alert_tag is None


def test_critical_finding_is_malicious():
    res = score_and_verdict([_f("critical")], watchlist_rank=None)
    assert res.verdict == "malicious"


def test_behavioral_chain_rule_is_malicious():
    f = Finding(rule_id="installer.urlopen_exec_chain", category="installer",
                severity="high", confidence="high", file="setup.py", line=1, evidence="e")
    res = score_and_verdict([f], watchlist_rank=None)
    assert res.verdict == "malicious"


def test_score_thresholds():
    lows = [_f("low") for _ in range(50)]
    res = score_and_verdict(lows, watchlist_rank=None)
    # per-category cap prevents low-noise overwhelming
    assert res.verdict in ("clean", "suspicious")


def test_watchlist_medium_promoted_to_suspicious():
    res = score_and_verdict([_f("medium")], watchlist_rank=500)
    assert res.verdict in ("suspicious", "malicious")


def test_top100_high_promoted_to_malicious_with_alert():
    res = score_and_verdict([_f("high")], watchlist_rank=42)
    assert res.verdict == "malicious"
    assert res.alert_tag == "watchlist_top100"


def test_top100_critical_alerts():
    res = score_and_verdict([_f("critical")], watchlist_rank=5)
    assert res.verdict == "malicious"
    assert res.alert_tag == "watchlist_top100"


def test_network_subprocess_chain_is_malicious():
    from pkgsentry.adapter import Finding
    from pkgsentry.detect.score import score_and_verdict
    f = Finding(rule_id="imports.network_subprocess_chain", category="imports",
                severity="high", confidence="high", file="__init__.py", line=4, evidence="chain")
    res = score_and_verdict([f], watchlist_rank=None)
    assert res.verdict == "malicious"


# --- opengrep shadow-mode filtering ---

def _og_shadow(severity: str, rule_id: str = "shadow_setup_net_to_exec") -> Finding:
    return Finding(
        rule_id=f"opengrep.{rule_id}",
        category="opengrep",
        severity=severity,
        confidence="high",
        file="setup.py",
        line=1,
        evidence="taint",
    ) if not rule_id.startswith("shadow_") else Finding(
        rule_id=f"opengrep.{rule_id}",
        category="opengrep",
        severity=severity,
        confidence="high",
        file="setup.py",
        line=1,
        evidence="taint (shadow)",
    )


def test_shadow_critical_finding_does_not_force_malicious():
    """A lone opengrep.shadow_* critical finding must NOT escalate verdict.
    Shadow findings are observation-only and excluded from scoring."""
    f = _og_shadow("critical", "shadow_setup_net_to_exec")
    res = score_and_verdict([f], watchlist_rank=None)
    assert res.verdict == "clean"
    assert res.score == 0


def test_shadow_high_finding_does_not_make_suspicious():
    f = _og_shadow("high", "shadow_buildrs_net_to_exec")
    res = score_and_verdict([f], watchlist_rank=None)
    assert res.verdict == "clean"


def test_non_shadow_opengrep_critical_is_malicious():
    """Plain opengrep.* (cutover mode) findings DO score normally."""
    f = _og_shadow("critical", "setup_net_to_exec")
    res = score_and_verdict([f], watchlist_rank=None)
    assert res.verdict == "malicious"


def test_shadow_finding_does_not_trigger_watchlist_top100_alert():
    """Shadow critical must NOT trigger top-100 watchlist escalation either."""
    f = _og_shadow("critical", "shadow_setup_net_to_exec")
    res = score_and_verdict([f], watchlist_rank=5)
    assert res.alert_tag is None
    assert res.verdict == "clean"


def test_legacy_findings_score_normally_alongside_shadow():
    """Legacy critical + shadow finding still = malicious from the legacy alone."""
    legacy = _f("critical", category="installer", rule_id="installer.urlopen_exec_chain")
    shadow = _og_shadow("critical", "shadow_setup_net_to_exec")
    res = score_and_verdict([legacy, shadow], watchlist_rank=None)
    assert res.verdict == "malicious"
