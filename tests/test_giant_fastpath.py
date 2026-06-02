# SPDX-License-Identifier: AGPL-3.0-or-later
"""Giant-package fast-path (2026-05-30): skip the heaviest per-file work on huge
packages so they don't blow the per-package timeout under shared-GIL contention."""
from __future__ import annotations

import pkgsentry.pipeline as pl


def test_giant_lite_triggers_on_file_count(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "GIANT_FASTPATH", True)
    monkeypatch.setattr(pl, "GIANT_FILE_THRESHOLD", 5)
    monkeypatch.setattr(pl, "GIANT_MAX_BYTES", 10**9)
    for i in range(7):
        (tmp_path / f"f{i}.txt").write_text("x")
    assert pl._giant_lite(tmp_path) is True


def test_giant_lite_triggers_on_size(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "GIANT_FASTPATH", True)
    monkeypatch.setattr(pl, "GIANT_FILE_THRESHOLD", 10**6)
    monkeypatch.setattr(pl, "GIANT_MAX_BYTES", 1000)
    (tmp_path / "big.bin").write_bytes(b"A" * 2000)
    assert pl._giant_lite(tmp_path) is True


def test_giant_lite_off_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "GIANT_FASTPATH", False)
    monkeypatch.setattr(pl, "GIANT_FILE_THRESHOLD", 1)
    monkeypatch.setattr(pl, "GIANT_MAX_BYTES", 1)
    (tmp_path / "a").write_text("x")
    (tmp_path / "b").write_text("y")
    assert pl._giant_lite(tmp_path) is False


def test_giant_lite_false_for_small(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "GIANT_FASTPATH", True)
    monkeypatch.setattr(pl, "GIANT_FILE_THRESHOLD", 5000)
    monkeypatch.setattr(pl, "GIANT_MAX_BYTES", 100 * 1024 * 1024)
    (tmp_path / "a.py").write_text("print(1)")
    assert pl._giant_lite(tmp_path) is False


def test_lite_hashing_keeps_sha_drops_fuzzy(tmp_path):
    (tmp_path / "f.txt").write_bytes(b"A" * 2000)
    full, _ = pl._compute_file_hashes(tmp_path, "sdist", lite=False)
    lite, _ = pl._compute_file_hashes(tmp_path, "sdist", lite=True)
    k = next(iter(full))
    assert lite[k].sha256 == full[k].sha256          # exact hash always computed
    assert lite[k].ssdeep == "" and lite[k].tlsh == "" and lite[k].entropy == 0.0


def test_lite_run_analyzers_skips_entropy_and_obfuscation(tmp_path, monkeypatch):
    called: list[str] = []
    for fn in ("analyze_imports", "analyze_malware_patterns", "analyze_iocs",
               "analyze_entropy", "analyze_obfuscation", "analyze_binary_artifacts",
               "analyze_yara", "analyze_opengrep"):
        monkeypatch.setattr(pl, fn, (lambda name: (lambda *a, **k: called.append(name) or []))(fn))
    monkeypatch.setattr(pl, "analyze_entropy_delta", lambda *a, **k: [])

    pl._run_analyzers(tmp_path, None, {}, {}, {}, ecosystem="npm", lite=True)
    assert "analyze_entropy" not in called and "analyze_obfuscation" not in called
    assert "analyze_iocs" in called and "analyze_yara" in called  # still run

    called.clear()
    pl._run_analyzers(tmp_path, None, {}, {}, {}, ecosystem="npm", lite=False)
    assert "analyze_entropy" in called and "analyze_obfuscation" in called
