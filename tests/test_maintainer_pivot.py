# SPDX-License-Identifier: AGPL-3.0-or-later
"""Maintainer-pivot sweep — the third sibling defense (force-scan, never watchlist).

All network is mocked: the catalog resolvers (`_pypi_resolve` / `_npm_resolve`) and
the per-package version lookups are monkeypatched, so nothing reaches the registry.
DB-backed tests run against a tmp sqlite via the module's own `session_scope`.
"""
from __future__ import annotations

import os
import types
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from pkgward import maintainer_pivot as mp
from pkgward.adapter import Finding
from pkgward.store import session as sess
from pkgward.store.models import MaintainerWatch, Package, Scan, Version, Watchlist


# --------------------------------------------------------------------------- helpers
def _f(rule_id, category, severity="high", confidence="high"):
    return Finding(rule_id=rule_id, category=category, severity=severity,
                   confidence=confidence, file="setup.py", evidence="x")


def _tri(verdict="malicious", confidence=0.9):
    return types.SimpleNamespace(verdict=verdict, confidence=confidence)


@pytest.fixture(autouse=True)
def _clean_pivot_env(monkeypatch):
    """Neutralize any ambient pivot env + reset the in-process dedup cache."""
    for k in list(os.environ):
        if k.startswith("PKGWARD_MAINTAINER_PIVOT") or k == "WATCHLIST_AUTO_BLOCKLIST":
            monkeypatch.delenv(k, raising=False)
    mp._reset_dedup_for_tests()
    yield
    mp._reset_dedup_for_tests()


@pytest.fixture()
def stub_chains(monkeypatch):
    """Pin a known behavioral-chain id without loading the intel pack."""
    monkeypatch.setattr(
        mp.intel, "current",
        lambda: types.SimpleNamespace(behavioral_chain_ids=frozenset({"chains.install_exfil"})),
    )


@pytest.fixture()
def pivot_db(tmp_path, monkeypatch):
    """Point the module's own session_scope at a fresh tmp sqlite."""
    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'pivot.db'}")
    sess.reset_engine()
    sess.init_db()
    yield
    sess.reset_engine()


def _seed_double_confirmed(ecosystem: str, name: str, *, days_ago: int = 1) -> None:
    """Insert a double-confirmed (rule + llm malicious) scan for (eco, name)."""
    with sess.session_scope() as s:
        pkg = Package(ecosystem=ecosystem, name=name)
        s.add(pkg)
        s.flush()
        ver = Version(ecosystem=ecosystem, package_id=pkg.id, version="1.0.0")
        s.add(ver)
        s.flush()
        s.add(Scan(
            version_id=ver.id, verdict="malicious", llm_verdict="malicious", score=99,
            finished_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
        ))


# ------------------------------------------------------------------------- parsers
def test_parse_pypi_maintainers():
    html = (
        '<a href="/user/alice/">alice</a> blah '
        '<a href="/project/other/">x</a> '
        '<a href="/user/alice/">dup</a> <a href="/user/bob/">bob</a>'
    )
    assert mp.parse_pypi_maintainers(html) == ["alice", "bob"]


def test_parse_pypi_user_projects():
    html = (
        '<a href="/project/ufish/">ufish</a>'
        '<a href="/project/spateo-release/">s</a>'
        '<a href="/project/ufish/">dup</a>'
        '<a href="/user/alice/">self</a>'
    )
    assert mp.parse_pypi_user_projects(html) == ["ufish", "spateo-release"]


def test_parse_npm_maintainers():
    pack = {"maintainers": [{"name": "carol", "email": "c@x"}, {"name": "dave"}, {"bad": 1}]}
    assert mp.parse_npm_maintainers(pack) == ["carol", "dave"]


def test_parse_npm_search():
    res = {"objects": [
        {"package": {"name": "a", "version": "1.2.3"}},
        {"package": {"name": "b", "version": "0.1.0"}},
        {"nope": True},
    ]}
    assert mp.parse_npm_search(res) == {"a": "1.2.3", "b": "0.1.0"}


# -------------------------------------------------------------- trigger eligibility
def test_trigger_eligible_filters_shadow_soft_and_severity():
    findings = [
        _f("installer.setup_exec", "installer", "critical"),   # eligible
        _f("opengrep.shadow_x", "opengrep", "high"),           # shadow → excluded
        _f("iocs.hardcoded_wan_ip_port", "iocs", "high"),      # non-primary → excluded
        _f("metadata.typosquat", "metadata", "high"),          # non-primary → excluded
        _f("imports.low", "imports", "low"),                   # low severity → excluded
    ]
    out = {f.rule_id for f in mp._trigger_eligible_findings(findings)}
    assert out == {"installer.setup_exec"}


def test_trigger_eligible_allow_deny(monkeypatch):
    findings = [_f("rule.a", "installer"), _f("rule.b", "installer")]
    monkeypatch.setenv("PKGWARD_MAINTAINER_PIVOT_TRIGGER_DENY", "rule.b")
    out = {f.rule_id for f in mp._trigger_eligible_findings(findings)}
    assert out == {"rule.a"}
    monkeypatch.setenv("PKGWARD_MAINTAINER_PIVOT_TRIGGER_ALLOW", "rule.b")
    out = {f.rule_id for f in mp._trigger_eligible_findings(findings)}
    assert out == set()  # allow={b} but b also denied


def test_high_fidelity_chain(stub_chains):
    hi, reason = mp._high_fidelity([_f("chains.install_exfil", "installer", "critical")], None)
    assert hi and reason.startswith("chain:")


def test_high_fidelity_threat_intel(stub_chains):
    hi, reason = mp._high_fidelity([_f("intel.campaignX", "threat_intel", "critical")], None)
    assert hi and reason.startswith("threat_intel:")


def test_high_fidelity_llm_conf(stub_chains):
    assert mp._high_fidelity([], _tri("malicious", 0.96))[0] is True
    assert mp._high_fidelity([], _tri("malicious", 0.80))[0] is False
    assert mp._high_fidelity([_f("installer.x", "installer")], _tri("malicious", 0.5))[0] is False


# ---------------------------------------------------------------------- sweep gate
def test_disabled(monkeypatch):
    monkeypatch.setenv("PKGWARD_MAINTAINER_PIVOT", "0")
    assert mp.sweep_on_malicious("pypi", "x", findings=[], tri=None)["action"] == "disabled"


def test_unsupported_ecosystem_never_crashes():
    for eco in ("crates", "gomod", "bogus"):
        out = mp.sweep_on_malicious(eco, "x", findings=[], tri=None)
        assert out["action"] == "unsupported_ecosystem"


def test_blocklisted(monkeypatch):
    monkeypatch.setenv("WATCHLIST_AUTO_BLOCKLIST", "pypi:innocent")
    out = mp.sweep_on_malicious("pypi", "innocent", findings=[_f("installer.x", "installer")],
                                tri=_tri("malicious", 0.99))
    assert out["action"] == "blocklisted"


def test_soft_conviction_no_primary_evidence_skips(monkeypatch):
    # Only soft (non-primary) findings + a low-confidence LLM → not even resolved.
    out = mp.sweep_on_malicious(
        "pypi", "x",
        findings=[_f("iocs.x", "iocs"), _f("metadata.y", "metadata")],
        tri=_tri("malicious", 0.6),
    )
    assert out["action"] == "skip" and out["reason"] == "no_primary_evidence"


def test_single_primary_no_correlation_does_not_trigger(stub_chains, pivot_db, monkeypatch):
    # A lone primary finding (NOT high-fidelity) with no sibling convictions → skip.
    # Mirror prod: the current package's own conviction is already committed.
    _seed_double_confirmed("pypi", "x")
    monkeypatch.setattr(mp, "_pypi_resolve",
                        lambda name: (["alice"], ["x", "sib1", "sib2"]))
    out = mp.sweep_on_malicious("pypi", "x",
                                findings=[_f("installer.setup_exec", "installer")],
                                tri=_tri("malicious", 0.85))
    assert out["action"] == "skip"
    assert out["reason"] == "single_soft_conviction_no_correlation"
    assert out["correlation"] == 1  # only the current package convicted


def test_high_fidelity_single_triggers_shadow(stub_chains, pivot_db, monkeypatch):
    monkeypatch.setattr(mp, "_pypi_resolve",
                        lambda name: (["alice"], ["x", "sib1", "sib2"]))
    out = mp.sweep_on_malicious("pypi", "x",
                                findings=[_f("chains.install_exfil", "installer", "critical")],
                                tri=_tri("malicious", 0.9))
    assert out["action"] == "shadow"          # default shadow
    assert out["maintainer"] == "alice"
    assert out["catalog_size"] == 3
    assert out["trigger"].startswith("chain:")


def test_correlation_triggers_without_high_fidelity(stub_chains, pivot_db, monkeypatch):
    # A second sibling already convicted → correlation >= 2 fires even though the
    # current conviction is only a plain primary finding (not high-fidelity).
    _seed_double_confirmed("pypi", "x")
    _seed_double_confirmed("pypi", "sib1")
    monkeypatch.setattr(mp, "_pypi_resolve",
                        lambda name: (["alice"], ["x", "sib1", "sib2"]))
    out = mp.sweep_on_malicious("pypi", "x",
                                findings=[_f("installer.setup_exec", "installer")],
                                tri=_tri("malicious", 0.85))
    assert out["action"] == "shadow"
    assert out["trigger"] == "correlation:2"


def test_active_mode_enqueues_high_and_never_watchlists(stub_chains, pivot_db, monkeypatch):
    monkeypatch.setenv("PKGWARD_MAINTAINER_PIVOT_SHADOW", "0")
    monkeypatch.setattr(
        mp, "_npm_resolve",
        lambda name: (["carol"], {"x": "1.0.0", "sib1": "2.0.0", "sib2": "3.0.0"}),
    )
    out = mp.sweep_on_malicious("npm", "x",
                                findings=[_f("installer.npm_install_obfuscated_entrypoint",
                                             "installer", "critical")],
                                tri=_tri("malicious", 0.97))
    assert out["action"] == "swept"
    assert out["enqueued"] == 2  # siblings only, the trigger 'x' is excluded
    assert out["watched"] == 2   # clean siblings get the bounded force-scan watch
    with sess.session_scope() as s:
        from pkgward.store.models import ScanQueue
        rows = s.scalars(select(ScanQueue)).all()
        names = {r.name: r.priority for r in rows}
        assert names == {"sib1": "high", "sib2": "high"}
        # FORCE-SCAN ONLY invariant — the pivot must never touch the watchlist.
        assert s.scalar(select(func.count()).select_from(Watchlist)) == 0
        # …but the clean siblings ARE registered for the bounded future-release watch.
        watched = {r.name for r in s.scalars(select(MaintainerWatch)).all()}
        assert watched == {"sib1", "sib2"}


def test_active_mode_excludes_already_malicious_siblings_from_watch(stub_chains, pivot_db, monkeypatch):
    # sib1 is already double-confirmed malicious → it graduates to watchlist_auto on its
    # own scan, so the bounded clean-watch must NOT cover it. Only sib2 (clean) is watched.
    monkeypatch.setenv("PKGWARD_MAINTAINER_PIVOT_SHADOW", "0")
    _seed_double_confirmed("npm", "x")
    _seed_double_confirmed("npm", "sib1")
    monkeypatch.setattr(
        mp, "_npm_resolve",
        lambda name: (["carol"], {"x": "1.0.0", "sib1": "2.0.0", "sib2": "3.0.0"}),
    )
    out = mp.sweep_on_malicious("npm", "x",
                                findings=[_f("installer.x", "installer")],
                                tri=_tri("malicious", 0.85))
    assert out["action"] == "swept" and out["trigger"] == "correlation:2"
    assert out["watched"] == 1
    with sess.session_scope() as s:
        watched = {r.name for r in s.scalars(select(MaintainerWatch)).all()}
        assert watched == {"sib2"}  # x=trigger, sib1=already-malicious both excluded


def test_dedup_fires_once_per_maintainer(stub_chains, pivot_db, monkeypatch):
    monkeypatch.setattr(mp, "_pypi_resolve",
                        lambda name: (["alice"], ["x", "sib1"]))
    strong = [_f("chains.install_exfil", "installer", "critical")]
    first = mp.sweep_on_malicious("pypi", "x", findings=strong, tri=_tri("malicious", 0.9))
    second = mp.sweep_on_malicious("pypi", "sib1", findings=strong, tri=_tri("malicious", 0.9))
    assert first["action"] == "shadow"
    assert second["action"] == "skip" and second["reason"] == "deduped"


def test_catalog_too_large_skips(stub_chains, pivot_db, monkeypatch):
    monkeypatch.setenv("PKGWARD_MAINTAINER_PIVOT_MAX_PKGS", "5")
    monkeypatch.setattr(mp, "_pypi_resolve",
                        lambda name: (["prolific"], [f"p{i}" for i in range(50)]))
    out = mp.sweep_on_malicious("pypi", "p0",
                                findings=[_f("chains.install_exfil", "installer", "critical")],
                                tri=_tri("malicious", 0.9))
    assert out["action"] == "skip" and out["reason"] == "catalog_too_large"


def test_manual_source_bypasses_evidence_precheck(stub_chains, pivot_db, monkeypatch):
    # CLI/backfill: no findings, but a manual sweep still resolves + (here) triggers
    # via correlation; the in-memory evidence pre-check is skipped.
    _seed_double_confirmed("pypi", "x")
    _seed_double_confirmed("pypi", "sib1")
    monkeypatch.setattr(mp, "_pypi_resolve",
                        lambda name: (["alice"], ["x", "sib1"]))
    out = mp.sweep_on_malicious("pypi", "x", source="manual")
    assert out["action"] == "shadow"
    assert out["trigger"] == "correlation:2"


# ----------------------------------------------------- pipeline-gate contract test
def test_pipeline_promote_gate_matches_pivot_trigger(stub_chains):
    """The pivot is only invoked behind pipeline._auto_watchlist_qualifies. A soft
    conviction must fail that gate (so the pivot never runs); a strong one passes."""
    from pkgward.pipeline import _auto_watchlist_qualifies

    soft = [_f("iocs.hardcoded_wan_ip_port", "iocs", "high")]
    strong = [_f("chains.install_exfil", "installer", "critical")]

    rule_mal = types.SimpleNamespace(verdict="malicious")
    ok_soft, _ = _auto_watchlist_qualifies(rule_mal, _tri("malicious", 0.99), soft)
    ok_strong, _ = _auto_watchlist_qualifies(rule_mal, _tri("malicious", 0.99), strong)
    assert ok_soft is False      # lone soft category never promotes → pivot not called
    assert ok_strong is True     # primary evidence → _promote_ok → pivot invoked
