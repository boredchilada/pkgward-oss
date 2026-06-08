# SPDX-License-Identifier: AGPL-3.0-or-later
"""The 'inconclusive' triage verdict: the LLM's honest 'I can't tell from what I was
shown' exit (yail/arkclaw FP class). It must downgrade only WEAK rule signals — never
a behavioral chain or exact-intel match — and surface a needs-review alert."""
from __future__ import annotations

from pkgward.adapter import Finding
from pkgward.detect.rules import BEHAVIORAL_CHAIN_RULES
from pkgward.llm.triage import LLMTriageResult, _enforce_no_downgrade
from pkgward.notify import discord


def _f(rule_id, severity="high"):
    return Finding(rule_id=rule_id, category="x", severity=severity,
                   confidence="high", file="x.py", line=None, evidence="e")


def test_inconclusive_passes_through_a_weak_rule_verdict():
    # yail-class: rule said suspicious (lone metadata flag), LLM can't confirm behavior.
    assert _enforce_no_downgrade("inconclusive", "suspicious", [_f("metadata.typosquat_candidate")], 0.0) == "inconclusive"


def test_inconclusive_cannot_downgrade_a_behavioral_chain():
    chain_rule = next(iter(BEHAVIORAL_CHAIN_RULES))
    # a strong chain stays malicious even if the LLM is unsure — never softened
    assert _enforce_no_downgrade("inconclusive", "malicious", [_f(chain_rule)], 0.0) == "malicious"


def _triage(**kw):
    base = dict(
        verdict="inconclusive", confidence=0.4,
        reasoning="only a typosquat-distance flag; no behavioral code shown",
        iocs=[], agrees_with_rules=None, model="deepseek/deepseek-v4-flash",
        prompt_tokens=1, completion_tokens=1, cost_usd=0.0, latency_ms=1,
        raw_response={}, missing_evidence="need lib.rs body to confirm any network/exfil behavior",
    )
    base.update(kw)
    return LLMTriageResult(**base)


def test_review_alert_includes_missing_evidence(monkeypatch):
    monkeypatch.setenv(discord.WEBHOOK_URL_ENV, "https://discord.test/webhook")
    captured = {}

    def _fake_post(embed, *, pkg_name, pkg_version):
        captured["embed"] = embed
        return True

    monkeypatch.setattr(discord, "_post_embed", _fake_post)
    ok = discord.send_review_alert(
        pkg_name="yail", pkg_version="0.0.1", ecosystem="crates",
        rule_verdict="suspicious", rule_score=25, n_findings=1,
        triage=_triage(), findings=[_f("metadata.typosquat_candidate")],
    )
    assert ok is True
    embed = captured["embed"]
    assert "Needs Review" in embed["title"]
    blob = str(embed["fields"])
    assert "INCONCLUSIVE" in blob
    assert "need lib.rs body" in blob  # missing_evidence surfaced


def test_review_alert_noops_without_webhook(monkeypatch):
    monkeypatch.delenv(discord.WEBHOOK_URL_ENV, raising=False)
    assert discord.send_review_alert(
        pkg_name="yail", pkg_version="0.0.1", ecosystem="crates",
        rule_verdict="suspicious", rule_score=25, n_findings=1,
        triage=_triage(), findings=[],
    ) is False
