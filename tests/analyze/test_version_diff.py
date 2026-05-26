# SPDX-License-Identifier: AGPL-3.0-or-later
from pkgsentry.adapter import Finding
from pkgsentry.analyze.version_diff import PreviousVersion, analyze_version_diff


def _finding(rule_id, severity="medium", confidence="medium"):
    return Finding(
        rule_id=rule_id, category="test", severity=severity,
        confidence=confidence, file="", line=None, evidence="test",
    )


def _prev(**kwargs):
    defaults = dict(
        version="1.0.0", verdict="clean", score=0,
        rule_ids=set(), finding_count=0,
    )
    defaults.update(kwargs)
    return PreviousVersion(**defaults)


def test_clean_to_critical():
    findings = [_finding("malware.discord_webhook", severity="critical")]
    prev = _prev(verdict="clean", rule_ids=set())
    result = analyze_version_diff(findings, {}, prev)
    assert any(f.rule_id == "version_diff.clean_to_critical" for f in result)
    assert any(f.severity == "critical" for f in result)


def test_no_diff_when_same_rules():
    findings = [_finding("iocs.url_suspicious")]
    prev = _prev(verdict="suspicious", rule_ids={"iocs.url_suspicious"})
    result = analyze_version_diff(findings, {}, prev)
    assert result == []


def test_new_non_critical_rules():
    findings = [_finding("iocs.url_suspicious", severity="medium")]
    prev = _prev(verdict="clean", rule_ids=set())
    result = analyze_version_diff(findings, {}, prev)
    assert any(f.rule_id == "version_diff.new_rules_fired" for f in result)


def test_author_changed():
    findings = []
    metadata = {"author_email": "attacker@evil.com"}
    prev = _prev(author_email="original@legit.com")
    result = analyze_version_diff(findings, metadata, prev)
    assert any(f.rule_id == "version_diff.author_changed" for f in result)
    assert any("attacker@evil.com" in f.evidence for f in result)


def test_author_same_no_finding():
    findings = []
    metadata = {"author_email": "dev@legit.com"}
    prev = _prev(author_email="dev@legit.com")
    result = analyze_version_diff(findings, metadata, prev)
    assert not any(f.rule_id == "version_diff.author_changed" for f in result)


def test_dependency_spike():
    findings = []
    metadata = {"requires_dist": ["requests", "flask", "cryptography", "pycryptodome"]}
    prev = _prev(requires_dist=["requests"])
    result = analyze_version_diff(findings, metadata, prev)
    assert any(f.rule_id == "version_diff.dependency_spike" for f in result)


def test_no_spike_small_addition():
    findings = []
    metadata = {"requires_dist": ["requests", "flask"]}
    prev = _prev(requires_dist=["requests"])
    result = analyze_version_diff(findings, metadata, prev)
    assert not any(f.rule_id == "version_diff.dependency_spike" for f in result)


def test_first_version_no_diff():
    """No previous version means no diff findings."""
    findings = [_finding("malware.discord_webhook", severity="critical")]
    result = analyze_version_diff(findings, {}, _prev())
    # Still fires clean_to_critical since prev was clean
    ids = {f.rule_id for f in result}
    assert "version_diff.author_changed" not in ids
    assert "version_diff.dependency_spike" not in ids
