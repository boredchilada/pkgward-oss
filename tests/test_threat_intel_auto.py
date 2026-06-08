# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auto-seed threat-intel fingerprints from confirmed-malicious catches (the moat)."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from pkgward import threat_intel_auto as tia
from pkgward.analyze import threat_intel
from pkgward.store.models import (
    FileHash, Finding, Package, Scan, ThreatIntelHash, Version,
)


@pytest.fixture(autouse=True)
def _enable_autoseed(monkeypatch):
    # Auto-seeding is HARD-DISABLED in prod (is_enabled() returns False, env ignored).
    # These tests exercise the seed *logic* in isolation, so patch is_enabled directly.
    import pkgward.threat_intel_auto as tia
    monkeypatch.setattr(tia, "is_enabled", lambda: True)


def _make_malicious_scan(s, name, *, sha, ssdeep="3:abcd:ef", tlsh="T1" + "A" * 68,
                         basename="setup.js"):
    pkg = Package(ecosystem="npm", name=name)
    s.add(pkg); s.flush()
    ver = Version(package_id=pkg.id, version="1.0.0")
    s.add(ver); s.flush()
    scan = Scan(version_id=ver.id, verdict="malicious", llm_verdict="malicious", score=70)
    s.add(scan); s.flush()
    s.add(Finding(scan_id=scan.id, rule_id="installer.npm_install_script_net_exec",
                  category="installer", severity="critical", confidence="high",
                  file=f"package/{basename}", evidence="net+exec"))
    s.add(FileHash(scan_id=scan.id, archive_kind="npm", file_path=f"package/{basename}",
                   sha256=sha, ssdeep=ssdeep, tlsh=tlsh))
    # a benign sibling file that must NOT be seeded (no high/crit finding)
    s.add(FileHash(scan_id=scan.id, archive_kind="npm", file_path="package/package.json",
                   sha256="b" * 64, ssdeep=ssdeep, tlsh=tlsh))
    s.flush()
    return scan


def test_seed_from_scan_seeds_implicated_file(db_session):
    scan = _make_malicious_scan(db_session, "meoo-ui-helpers", sha="a" * 64)
    n = tia.seed_from_scan(db_session, scan.id, "npm", "meoo-ui-helpers")
    assert n == 1  # only setup.js (critical finding), not package.json
    row = db_session.scalar(select(ThreatIntelHash).where(ThreatIntelHash.sha256 == "a" * 64))
    assert row is not None and row.source == "auto" and row.label == "malicious"
    assert row.file_pattern == "*.js"


def test_seed_is_idempotent(db_session):
    scan = _make_malicious_scan(db_session, "meoo-x", sha="c" * 64)
    assert tia.seed_from_scan(db_session, scan.id, "npm", "meoo-x") == 1
    assert tia.seed_from_scan(db_session, scan.id, "npm", "meoo-x") == 0  # sha256 dedup


def test_seeded_fingerprint_matches_future_file(db_session):
    # seed from the first catch, then a NEW file with the same sha256 matches
    scan = _make_malicious_scan(db_session, "meoo-form-validator", sha="d" * 64)
    tia.seed_from_scan(db_session, scan.id, "npm", "meoo-form-validator")
    match = threat_intel.check_file(db_session, sha256="d" * 64, filename="package/setup.js")
    assert match is not None and match.tier == "sha256"
    assert match.campaign == "auto:npm:meoo-form-validator"


def test_backfill_processes_malicious_scans(db_session):
    _make_malicious_scan(db_session, "rookie-security-test-pkg", sha="e" * 64)
    _make_malicious_scan(db_session, "another-stealer", sha="f" * 64)
    scans, seeded = tia.backfill(db_session)
    assert scans == 2 and seeded == 2


def test_auto_fingerprint_uses_tight_tlsh(db_session, monkeypatch):
    # auto-seeds must reject a LOOSELY-similar file (the chain-signer FP class) while
    # the curated baseline keeps its looser threshold.
    from pkgward.analyze import threat_intel
    from pkgward.util import capabilities as caps
    db_session.add(ThreatIntelHash(sha256="a" * 64, tlsh="T1" + "A" * 68, campaign="auto:npm:x",
                                   label="malicious", source="auto", file_pattern="*.js"))
    db_session.add(ThreatIntelHash(sha256="b" * 64, tlsh="T1" + "B" * 68, campaign="curated-pack",
                                   label="malicious", source="baseline", file_pattern="*.js"))
    db_session.flush()

    class _FakeTlsh:
        @staticmethod
        def diff(a, b):
            return 50  # loose distance: > auto(40), < baseline(120)
    monkeypatch.setattr(caps, "HAS_TLSH", True)
    monkeypatch.setattr(caps, "tlsh", _FakeTlsh)
    m = threat_intel.check_file(db_session, sha256="0" * 64, tlsh_hash="T1" + "C" * 68, filename="f.js")
    assert m is not None and m.campaign == "curated-pack"  # auto rejected at dist 50


def test_seed_skips_compiled_binary(db_session):
    pkg = Package(ecosystem="npm", name="evil-bin"); db_session.add(pkg); db_session.flush()
    ver = Version(package_id=pkg.id, version="1.0.0"); db_session.add(ver); db_session.flush()
    scan = Scan(version_id=ver.id, verdict="malicious", llm_verdict="malicious"); db_session.add(scan); db_session.flush()
    db_session.add(Finding(scan_id=scan.id, rule_id="binary.compiled_artifact", category="binary",
                           severity="high", confidence="high", file="package/mcp-publisher"))
    # no extension + high entropy -> a compiled binary, must NOT be seeded
    db_session.add(FileHash(scan_id=scan.id, archive_kind="npm", file_path="package/mcp-publisher",
                            sha256="f" * 64, ssdeep="3:x:y", tlsh="T1" + "A" * 68, entropy=7.6))
    db_session.flush()
    assert tia.seed_from_scan(db_session, scan.id, "npm", "evil-bin") == 0


def test_auto_is_exact_only_then_promote_enables_fuzzy(db_session, monkeypatch):
    from pkgward.analyze import threat_intel
    from pkgward.util import capabilities as caps
    db_session.add(ThreatIntelHash(sha256="a" * 64, tlsh="T1" + "A" * 68, campaign="auto:npm:fam",
                                   label="malicious", source="auto", file_pattern="*.js"))
    db_session.flush()

    class _FakeTlsh:
        @staticmethod
        def diff(a, b):
            return 5  # near-identical
    monkeypatch.setattr(caps, "HAS_TLSH", True)
    monkeypatch.setattr(caps, "tlsh", _FakeTlsh)
    # exact sha256 repeat still matches while auto
    assert threat_intel.check_file(db_session, sha256="a" * 64, filename="x.js") is not None
    # a near-identical-but-DIFFERENT file does NOT fuzzy-match while auto (exact-only)
    assert threat_intel.check_file(db_session, sha256="0" * 64, tlsh_hash="T1" + "B" * 68, filename="x.js") is None
    # promote -> fuzzy now enabled for the family
    assert tia.promote(db_session, "fam") == 1
    m = threat_intel.check_file(db_session, sha256="0" * 64, tlsh_hash="T1" + "B" * 68, filename="x.js")
    assert m is not None and m.tier == "tlsh" and m.campaign == "auto:npm:fam"


def test_remove_deletes_campaign_fingerprints(db_session):
    from pkgward.analyze import threat_intel
    db_session.add(ThreatIntelHash(sha256="c" * 64, campaign="auto:pypi:benign-pth",
                                   label="malicious", source="auto", file_pattern="*.pth"))
    db_session.add(ThreatIntelHash(sha256="d" * 64, campaign="auto:pypi:keep-me",
                                   label="malicious", source="auto", file_pattern="*.pth"))
    db_session.flush()
    # remove by bare name deletes only that campaign's fingerprint
    assert tia.remove(db_session, "benign-pth") == 1
    assert threat_intel.check_file(db_session, sha256="c" * 64, filename="x.pth") is None
    # the other campaign is untouched
    assert threat_intel.check_file(db_session, sha256="d" * 64, filename="x.pth") is not None
    # removing a non-existent campaign is a no-op
    assert tia.remove(db_session, "does-not-exist") == 0


def test_autoseed_hard_disabled_ignores_env(monkeypatch):
    # Prod guard: auto-seeding must stay dead even if the env flag is set to 1.
    monkeypatch.undo()  # drop the autouse is_enabled patch — test the REAL guard
    monkeypatch.setenv("PKGWARD_THREATINTEL_AUTOSEED", "1")
    assert tia.is_enabled() is False
