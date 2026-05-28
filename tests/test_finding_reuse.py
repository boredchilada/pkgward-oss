# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for `pkgsentry.finding_reuse.carry_forward_findings` — the
SHA-unchanged-file carry-forward used on auto-watchlisted packages.

Attacker pattern: byte-identical re-publish under a bumped version → most
files unchanged → our changed_files optimization surfaces only the deltas
→ LLM adjudicates on a thin evidence basis. Carry-forward restores the prior
scan's findings for SHA-unchanged files so the merged set matches a full scan.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pkgsentry.finding_reuse import carry_forward_findings
from pkgsentry.store.models import (
    FileHash, Finding, Package, Scan, Version,
)


def _make_pkg_scan(s, ecosystem: str, name: str, version: str, *,
                   sha_map: dict[str, str], findings: list[dict],
                   finished_at: datetime | None = None) -> int:
    """Helper: insert Package + Version + Scan + FileHash + Finding rows.
    Returns the Scan id."""
    pkg = s.scalar(__import__("sqlalchemy").select(Package).where(
        Package.ecosystem == ecosystem, Package.name == name,
    ))
    if pkg is None:
        pkg = Package(ecosystem=ecosystem, name=name)
        s.add(pkg)
        s.flush()
    ver = Version(ecosystem=ecosystem, package_id=pkg.id, version=version)
    s.add(ver)
    s.flush()
    scan = Scan(
        version_id=ver.id, verdict="malicious", score=42,
        started_at=datetime.now(timezone.utc),
        finished_at=finished_at or datetime.now(timezone.utc),
    )
    s.add(scan)
    s.flush()
    for path, sha in sha_map.items():
        s.add(FileHash(
            scan_id=scan.id, archive_kind="npm_tarball",
            file_path=path, sha256=sha,
        ))
    for f in findings:
        s.add(Finding(
            scan_id=scan.id, rule_id=f["rule_id"], category=f.get("category", "x"),
            severity=f.get("severity", "high"), confidence=f.get("confidence", "high"),
            file=f.get("file", ""), line=f.get("line"),
            evidence=f.get("evidence", ""),
        ))
    s.flush()
    return scan.id


def test_carry_forward_pulls_findings_for_unchanged_shas(db_session):
    prior_id = _make_pkg_scan(
        db_session, "npm", "forge-jsxy", "1.0.107",
        sha_map={
            "dist/fsProtocol.js": "AAAA",
            "scripts/postinstall-bootstrap.mjs": "BBBB",
            "package.json": "OLD-PKG-JSON",
        },
        findings=[
            {"rule_id": "opengrep.shadow_js_env_to_net", "file": "dist/fsProtocol.js"},
            {"rule_id": "iocs.url_suspicious", "file": "dist/fsProtocol.js",
             "severity": "low"},
            {"rule_id": "installer.npm_install_script_net_exec",
             "file": "scripts/postinstall-bootstrap.mjs", "severity": "critical"},
        ],
    )

    # Now a new "scan" for the same package, two unchanged files + one changed.
    new_id = _make_pkg_scan(
        db_session, "npm", "forge-jsxy", "1.0.120",
        sha_map={
            "dist/fsProtocol.js": "AAAA",                   # unchanged
            "scripts/postinstall-bootstrap.mjs": "BBBB",    # unchanged
            "package.json": "NEW-PKG-JSON",                  # changed
        },
        findings=[],
    )
    current = {
        "dist/fsProtocol.js": "AAAA",
        "scripts/postinstall-bootstrap.mjs": "BBBB",
        "package.json": "NEW-PKG-JSON",
    }

    carried = carry_forward_findings(
        db_session, "npm", "forge-jsxy", new_id, current,
    )
    rule_ids = sorted(f.rule_id for f in carried)
    # All three prior findings live on files with unchanged SHAs → all carried.
    assert rule_ids == [
        "installer.npm_install_script_net_exec",
        "iocs.url_suspicious",
        "opengrep.shadow_js_env_to_net",
    ]
    # No finding from package.json (whose SHA changed).
    assert all(f.file != "package.json" for f in carried)


def test_no_prior_scan_returns_empty(db_session):
    res = carry_forward_findings(
        db_session, "npm", "never-seen", 999, {"a.js": "X"},
    )
    assert res == []


def test_ttl_window_excludes_old_scans(db_session, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_FINDING_REUSE_DAYS", "7")
    # Prior scan 30 days ago — outside the TTL window.
    _make_pkg_scan(
        db_session, "npm", "stale-bad", "1.0.0",
        sha_map={"a.js": "AAA"},
        findings=[{"rule_id": "yara.bad", "file": "a.js"}],
        finished_at=datetime.now(timezone.utc) - timedelta(days=30),
    )
    new_id = _make_pkg_scan(
        db_session, "npm", "stale-bad", "1.0.1",
        sha_map={"a.js": "AAA"},
        findings=[],
    )
    res = carry_forward_findings(
        db_session, "npm", "stale-bad", new_id, {"a.js": "AAA"},
    )
    assert res == []  # outside TTL → no reuse


def test_only_unchanged_shas_carry_forward(db_session):
    _make_pkg_scan(
        db_session, "npm", "p", "1.0",
        sha_map={"a.js": "AAA", "b.js": "BBB"},
        findings=[
            {"rule_id": "yara.x", "file": "a.js"},
            {"rule_id": "yara.y", "file": "b.js"},
        ],
    )
    new_id = _make_pkg_scan(
        db_session, "npm", "p", "1.1",
        sha_map={"a.js": "AAA", "b.js": "DIFFERENT"},
        findings=[],
    )
    # b.js's SHA changed → its prior finding should NOT carry forward.
    res = carry_forward_findings(
        db_session, "npm", "p", new_id,
        {"a.js": "AAA", "b.js": "DIFFERENT"},
    )
    assert [f.rule_id for f in res] == ["yara.x"]
