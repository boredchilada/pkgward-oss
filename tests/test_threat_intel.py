# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import pytest

from pkgsentry.analyze import threat_intel as ti
from pkgsentry.store import session as sess
from pkgsentry.store.models import ThreatIntelHash
from pkgsentry.util import capabilities as caps

_CONTENT = (b"const token = process.env.GITHUB_TOKEN;\n"
            b"for (const f of fs.readdirSync(dir)) { upload(f); }\n") * 4


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'t.db'}")
    sess.reset_engine()
    sess.init_db()
    return tmp_path


def _add(**kw):
    with sess.session_scope() as s:
        s.add(ThreatIntelHash(**kw))


def test_sha256_exact_match(db):
    _add(sha256="a" * 64, campaign="camp1", label="malicious")
    with sess.session_scope() as s:
        m = ti.check_file(s, sha256="a" * 64)
    assert m is not None and m.tier == "sha256" and m.campaign == "camp1"


def test_sha256_exact_ignores_file_pattern(db):
    _add(sha256="b" * 64, campaign="camp2", label="malicious", file_pattern="*.js")
    with sess.session_scope() as s:
        m = ti.check_file(s, sha256="b" * 64, filename="thing.py")
    assert m is not None and m.tier == "sha256"


@pytest.mark.skipif(not caps.HAS_PPDEEP, reason="ppdeep not installed")
def test_ssdeep_file_pattern_scopes_fuzzy_match(db):
    h = caps.ppdeep.hash(_CONTENT)
    _add(sha256="c" * 64, ssdeep=h, campaign="js_camp", label="malicious", file_pattern="*.js")
    with sess.session_scope() as s:
        hit = ti.check_file(s, sha256="0" * 64, ssdeep_hash=h, filename="evil.js")
        miss = ti.check_file(s, sha256="0" * 64, ssdeep_hash=h, filename="evil.py")
    assert hit is not None and hit.tier == "ssdeep"
    assert miss is None  # same fuzzy hash, wrong file type -> scoped out


@pytest.mark.skipif(not caps.HAS_TLSH, reason="tlsh not installed")
def test_tlsh_tier_matches(db):
    t = caps.tlsh.hash(_CONTENT)
    if t in ("", "TNULL"):
        pytest.skip("content too small for tlsh")
    _add(sha256="d" * 64, tlsh=t, campaign="tlsh_camp", label="malicious")
    with sess.session_scope() as s:
        m = ti.check_file(s, sha256="0" * 64, tlsh_hash=t, filename="x.js")
    assert m is not None and m.tier == "tlsh"


def test_label_maps_to_severity(db):
    _add(sha256="e" * 64, campaign="pua_camp", label="pua")
    with sess.session_scope() as s:
        findings = ti.check_files_batch(s, {"mod.js": {"sha256": "e" * 64}})
    assert findings and findings[0].severity == "medium"


def test_default_label_is_critical(db):
    _add(sha256="f" * 64, campaign="mal_camp", label="malicious")
    with sess.session_scope() as s:
        findings = ti.check_files_batch(s, {"mod.js": {"sha256": "f" * 64}})
    assert findings and findings[0].severity == "critical"


def test_seed_upsert_backfills_missing_tlsh(db, monkeypatch):
    from pkgsentry.store import seed_intel

    _add(sha256="1" * 64, ssdeep="x", tlsh=None, campaign="camp", label="malicious")

    fake = type("P", (), {"hash_seeds": [
        {"sha256": "1" * 64, "tlsh": "T1ABCDEF", "ssdeep": "SHOULD_NOT_CLOBBER",
         "campaign": "camp", "label": "malicious"},
        {"sha256": "2" * 64, "tlsh": "T1NEW", "campaign": "new", "label": "malicious"},
    ]})()
    monkeypatch.setattr(seed_intel.intel, "load", lambda: None)
    monkeypatch.setattr(seed_intel.intel, "current", lambda: fake)

    added, updated = seed_intel.seed()
    assert added == 1 and updated == 1

    with sess.session_scope() as s:
        row = s.query(ThreatIntelHash).filter_by(sha256="1" * 64).one()
        assert row.tlsh == "T1ABCDEF"        # backfilled
        assert row.ssdeep == "x"             # present value not clobbered
