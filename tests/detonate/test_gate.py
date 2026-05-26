# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.adapter import Finding
from pkgsentry.detonate.gate import should_detonate


def test_skip_clean_low_score():
    findings = [Finding(rule_id="iocs.url", category="iocs", severity="low", confidence="low")]
    assert should_detonate(verdict="clean", score=1, findings=findings, watchlist_rank=None, is_new_package=False) is False


def test_skip_malicious_behavioral_chain():
    findings = [Finding(rule_id="installer.urlopen_exec_chain", category="installer", severity="critical", confidence="high")]
    assert should_detonate(verdict="malicious", score=85, findings=findings, watchlist_rank=None, is_new_package=False) is False


def test_detonate_suspicious():
    findings = [Finding(rule_id="malware.obfuscation", category="malware", severity="high", confidence="medium")]
    assert should_detonate(verdict="suspicious", score=25, findings=findings, watchlist_rank=None, is_new_package=False) is True


def test_detonate_new_package():
    assert should_detonate(verdict="clean", score=0, findings=[], watchlist_rank=None, is_new_package=True) is True


def test_detonate_watchlist_clean():
    findings = [Finding(rule_id="iocs.url", category="iocs", severity="low", confidence="low")]
    assert should_detonate(verdict="clean", score=1, findings=findings, watchlist_rank=50, is_new_package=False) is True


def test_detonate_malicious_no_chain():
    findings = [
        Finding(rule_id="malware.obfuscation", category="malware", severity="critical", confidence="medium"),
        Finding(rule_id="iocs.suspicious_url", category="iocs", severity="high", confidence="high"),
    ]
    assert should_detonate(verdict="malicious", score=65, findings=findings, watchlist_rank=None, is_new_package=False) is True


def test_skip_clean_no_findings():
    assert should_detonate(verdict="clean", score=0, findings=[], watchlist_rank=None, is_new_package=False) is False
