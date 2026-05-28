# SPDX-License-Identifier: AGPL-3.0-or-later
from pkgsentry.notify.discord import _build_embed
from pkgsentry.llm.triage import LLMTriageResult


def _fake_triage(**overrides) -> LLMTriageResult:
    defaults = dict(
        model="test-model", verdict="malicious", confidence=0.95,
        reasoning="test", iocs=[], agrees_with_rules=True,
        prompt_tokens=100, completion_tokens=50, cost_usd=0.001,
        latency_ms=500, raw_response={},
    )
    defaults.update(overrides)
    return LLMTriageResult(**defaults)


def test_build_embed_pypi_url():
    embed = _build_embed(
        pkg_name="evil", pkg_version="1.0", ecosystem="pypi",
        rule_verdict="malicious", rule_score=80, n_findings=5,
        triage=_fake_triage(), top_findings=[],
    )
    registry_field = [f for f in embed["fields"] if f["name"] == "Registry"][0]
    assert "pypi[.]org" in registry_field["value"]


def test_build_embed_crates_url():
    embed = _build_embed(
        pkg_name="evil-crate", pkg_version="0.1.0", ecosystem="crates",
        rule_verdict="malicious", rule_score=80, n_findings=3,
        triage=_fake_triage(), top_findings=[],
    )
    registry_field = [f for f in embed["fields"] if f["name"] == "Registry"][0]
    assert "crates[.]io" in registry_field["value"]


def test_build_embed_footer_says_pkgsentry():
    embed = _build_embed(
        pkg_name="foo", pkg_version="1.0", ecosystem="pypi",
        rule_verdict="malicious", rule_score=80, n_findings=1,
        triage=_fake_triage(), top_findings=[],
    )
    assert "pkgsentry" in embed["footer"]["text"]


def test_build_embed_unverified_when_llm_errored():
    """Fail-open alert: LLM couldn't adjudicate → distinct title/desc, grey, no false 'confirmed'."""
    embed = _build_embed(
        pkg_name="bc-pkg", pkg_version="1.0.1", ecosystem="pypi",
        rule_verdict="malicious", rule_score=61, n_findings=2,
        triage=_fake_triage(verdict="error", confidence=0.0, model="z-ai/glm-5.1"),
        top_findings=[],
    )
    assert "unverified" in embed["title"].lower()
    assert "could not verify" in embed["description"].lower()
    assert "confirmed" not in embed["description"].lower()
    assert embed["color"] == 0x95A5A6


def test_build_embed_unverified_when_llm_unavailable():
    embed = _build_embed(
        pkg_name="x", pkg_version="1.0", ecosystem="npm",
        rule_verdict="malicious", rule_score=70, n_findings=1,
        triage=_fake_triage(verdict="unverified", confidence=0.0, model="n/a"),
        top_findings=[],
    )
    assert "unverified" in embed["title"].lower()
    assert embed["color"] == 0x95A5A6
