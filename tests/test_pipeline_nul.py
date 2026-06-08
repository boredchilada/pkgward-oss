# SPDX-License-Identifier: AGPL-3.0-or-later
"""NUL (0x00) sanitization before persistence. Postgres TEXT/JSONB reject
\\u0000, so a single NUL in metadata / finding evidence / a file path would fail
the whole scan's write. Some packages ship UTF-16 or binary-ish metadata that
carries NUL (observed: an npm package with a UTF-16 `summary`); a package could
also embed NUL deliberately to evade scanning. We strip NUL at persistence."""
from __future__ import annotations

from datetime import datetime, timezone

from pkgward.adapter import Finding as AdapterFinding
from pkgward.pipeline import _apply_metadata, _persist_findings, _strip_nul
from pkgward.store.models import Finding, Package, Scan, Version


def test_strip_nul_scalars_and_containers():
    assert _strip_nul("a\x00b") == "ab"
    assert _strip_nul("clean") == "clean"
    assert _strip_nul({"k": "x\x00y", "n": 5}) == {"k": "xy", "n": 5}
    assert _strip_nul(["a\x00", "b"]) == ["a", "b"]
    # nested (mirrors metadata_json audit + llm raw_response)
    assert _strip_nul({"a": [{"b": "S\x00o\x00l"}]}) == {"a": [{"b": "Sol"}]}
    assert _strip_nul(None) is None
    assert _strip_nul(42) == 42


def _make_version(s, name="nul-pkg", version="1.0"):
    pkg = Package(ecosystem="npm", name=name)
    s.add(pkg)
    s.flush()
    ver = Version(ecosystem="npm", package_id=pkg.id, version=version)
    s.add(ver)
    s.flush()
    return ver


def test_apply_metadata_strips_nul(db_session):
    ver = _make_version(db_session)
    # UTF-16-style summary: NUL between every char (the observed real case)
    metadata = {
        "summary": "S\x00o\x00l\x00a\x00n\x00a",
        "author": "ja\x00ne",
        "keywords": "a\x00b",
        "extra_field": "x\x00y",  # rides along into metadata_json
    }
    _apply_metadata(db_session, ver, _strip_nul(metadata), watchlist_rank=None)
    db_session.flush()
    assert "\x00" not in (ver.summary or "")
    assert ver.summary == "Solana"
    assert "\x00" not in (ver.author or "")
    # the metadata_json audit blob (JSONB in prod) must be NUL-free too
    assert "\x00" not in str(ver.metadata_json)
    assert ver.metadata_json["extra_field"] == "xy"


def test_persist_findings_strips_nul(db_session):
    ver = _make_version(db_session, name="nul-pkg2")
    scan = Scan(version_id=ver.id, verdict="malicious", score=61,
                started_at=datetime.now(timezone.utc))
    db_session.add(scan)
    db_session.flush()
    findings = [AdapterFinding(
        rule_id="iocs.url_suspicious", category="iocs", severity="low",
        confidence="medium", file="pkg/ev\x00il.js", line=3,
        evidence="payload\x00 with NUL bytes \x00\x00",
    )]
    _persist_findings(db_session, scan, findings)
    db_session.flush()
    row = db_session.query(Finding).filter(Finding.scan_id == scan.id).one()
    assert "\x00" not in row.evidence
    assert "\x00" not in row.file
    assert row.evidence == "payload with NUL bytes "
