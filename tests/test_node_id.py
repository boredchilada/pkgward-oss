# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-node alert identification (which scanner fired the alert + its version)."""
from __future__ import annotations

from pkgward import node_id


def test_node_name_from_env(monkeypatch):
    monkeypatch.setenv("PKGWARD_NODE_NAME", "cloud")
    assert node_id.node_name() == "cloud"


def test_node_name_falls_back_to_hostname(monkeypatch):
    monkeypatch.delenv("PKGWARD_NODE_NAME", raising=False)
    assert node_id.node_name()  # non-empty (the hostname)


def test_node_label_format(monkeypatch):
    monkeypatch.setenv("PKGWARD_NODE_NAME", "prod")
    label = node_id.node_label()
    assert label.startswith("prod @ ")


def test_review_alert_footer_carries_node(monkeypatch):
    from pkgward.notify import discord
    from pkgward.llm.triage import LLMTriageResult
    monkeypatch.setenv("PKGWARD_NODE_NAME", "cloud")
    monkeypatch.setenv(discord.WEBHOOK_URL_ENV, "https://discord.test/wh")
    captured = {}
    monkeypatch.setattr(discord, "_post_embed", lambda embed, **k: captured.update(embed) or True)
    tri = LLMTriageResult(verdict="inconclusive", confidence=0.3, reasoning="x", iocs=[],
                          agrees_with_rules=None, model="m", prompt_tokens=1,
                          completion_tokens=1, cost_usd=0.0, latency_ms=1, raw_response={})
    discord.send_review_alert(pkg_name="p", pkg_version="1", ecosystem="npm",
                              rule_verdict="suspicious", rule_score=25, n_findings=1,
                              triage=tri, findings=[])
    assert "cloud @ " in captured["footer"]["text"]
