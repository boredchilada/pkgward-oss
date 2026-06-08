# SPDX-License-Identifier: AGPL-3.0-or-later
from pkgward.notify.discord import _build_embed
from pkgward.llm.triage import LLMTriageResult


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
        triage=_fake_triage(), findings=[],
    )
    registry_field = [f for f in embed["fields"] if f["name"] == "Registry"][0]
    assert "pypi[.]org" in registry_field["value"]


def test_build_embed_crates_url():
    embed = _build_embed(
        pkg_name="evil-crate", pkg_version="0.1.0", ecosystem="crates",
        rule_verdict="malicious", rule_score=80, n_findings=3,
        triage=_fake_triage(), findings=[],
    )
    registry_field = [f for f in embed["fields"] if f["name"] == "Registry"][0]
    assert "crates[.]io" in registry_field["value"]


def test_build_embed_footer_says_pkgward():
    embed = _build_embed(
        pkg_name="foo", pkg_version="1.0", ecosystem="pypi",
        rule_verdict="malicious", rule_score=80, n_findings=1,
        triage=_fake_triage(), findings=[],
    )
    assert "pkgward" in embed["footer"]["text"]


def test_build_embed_unverified_when_llm_errored():
    """Fail-open alert: LLM couldn't adjudicate → distinct title/desc, grey, no false 'confirmed'."""
    embed = _build_embed(
        pkg_name="bc-pkg", pkg_version="1.0.1", ecosystem="pypi",
        rule_verdict="malicious", rule_score=61, n_findings=2,
        triage=_fake_triage(verdict="error", confidence=0.0, model="z-ai/glm-5.1"),
        findings=[],
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
        findings=[],
    )
    assert "unverified" in embed["title"].lower()
    assert embed["color"] == 0x95A5A6

def test_sanitize_embed_clamps_oversized_ioc_field():
    """A package with many long IOCs produced a >1024-char field → Discord 400
    {"embeds": ["0"]} → dropped alert (@barefootjs/xslate, 2026-06-06). Every field
    value must be clamped to Discord's 1024 limit and the embed to 6000 overall."""
    from pkgward.notify.discord import _sanitize_embed
    iocs = [{"type": "url", "value": "https://evil.example.com/" + "a" * 200}
            for _ in range(15)]
    embed = _build_embed(
        pkg_name="@barefootjs/xslate", pkg_version="0.9.0", ecosystem="npm",
        rule_verdict="suspicious", rule_score=36, n_findings=9,
        triage=_fake_triage(verdict="inconclusive", iocs=iocs),
        findings=[],
    )
    clean = _sanitize_embed(embed)
    assert all(len(f["value"]) <= 1024 for f in clean["fields"])
    assert all(f["value"] for f in clean["fields"])  # no empty values (Discord rejects)
    total = (len(clean.get("title", "")) + len(clean.get("description", ""))
             + sum(len(f["name"]) + len(f["value"]) for f in clean["fields"]))
    assert total <= 6000
    assert len(clean["fields"]) <= 25


def test_sanitize_embed_placeholders_empty_value():
    from pkgward.notify.discord import _sanitize_embed
    e = _sanitize_embed({"title": "t", "fields": [{"name": "X", "value": ""}]})
    assert e["fields"][0]["value"] == "—"


def _mk(rule_id, sev, conf, file, line, evidence):
    from pkgward.adapter import Finding
    return Finding(rule_id=rule_id, category="iocs", severity=sev, confidence=conf,
                   file=file, line=line, evidence=evidence)


def test_top_rule_hits_dedupes_identical_evidence_across_files():
    """deepalpha v1.1.0: the same URL finding from three files rendered as three
    identical lines, and file-without-line findings showed `N/A`. Identical
    (rule, evidence) hits must collapse to one ×N line with the files summarized."""
    from pkgward.notify.discord import _render_top_findings
    findings = [
        _mk("iocs.hardcoded_wan_ip_port", "high", "medium", "bot/client.py", None,
            "217.15.163.134:8090 — hardcoded routable IP + port"),
        _mk("iocs.url_suspicious", "low", "low", "bot/api.py", None, "https://api.hyperliquid.xyz/info"),
        _mk("iocs.url_suspicious", "low", "low", "bot/feed.py", None, "https://api.hyperliquid.xyz/info"),
        _mk("iocs.url_suspicious", "low", "low", "bot/main.py", None, "https://api.hyperliquid.xyz/info"),
        _mk("iocs.url_suspicious", "low", "low", "bot/main.py", None, "https://deepalphabot.com"),
    ]
    out = _render_top_findings(findings)
    assert out.count("api.hyperliquid") == 1, "identical evidence must render once"
    assert "×3" in out, "the collapse must carry the occurrence count"
    assert "(+2 more files)" in out
    assert "N/A" not in out, "a finding with a file but no line shows the file, not N/A"
    assert "`bot/client.py`" in out
    assert out.index("hardcoded_wan_ip_port") < out.index("url_suspicious"), "severity order"


def test_top_rule_hits_overflow_notes_remaining_distinct_hits():
    from pkgward.notify.discord import _render_top_findings
    findings = [
        _mk("iocs.url_suspicious", "low", "low", f"f{i}.py", None, f"https://x{i}.example")
        for i in range(12)
    ]
    out = _render_top_findings(findings, limit=8)
    assert "+4 more distinct hits" in out
