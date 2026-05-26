# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate each shipped opengrep YAML rule with the real binary.

Skipped automatically when the ``opengrep`` binary is not on PATH, so the
local pytest run on a dev machine without opengrep still goes green. CI
(and the Docker container) DO have the binary, and these tests must pass
there — broken rule YAML never ships to prod.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_RULES_ROOT = Path(__file__).resolve().parent.parent.parent / "pkgsentry" / "intel" / "baseline" / "opengrep"


def _opengrep_bin() -> str | None:
    return shutil.which("opengrep")


def _all_rule_files() -> list[Path]:
    if not _RULES_ROOT.is_dir():
        return []
    return sorted(_RULES_ROOT.rglob("*.yaml"))


_SKIP_IF_NO_BINARY = pytest.mark.skipif(
    _opengrep_bin() is None,
    reason="opengrep binary not on PATH — rule validation deferred to CI/Docker.",
)


@_SKIP_IF_NO_BINARY
@pytest.mark.parametrize("rule_file", _all_rule_files(), ids=lambda p: str(p.relative_to(_RULES_ROOT)))
def test_rule_yaml_validates(rule_file: Path) -> None:
    bin_path = _opengrep_bin()
    assert bin_path is not None  # narrowed by pytestmark skip

    result = subprocess.run(
        [bin_path, "scan", "--validate", "-f", str(rule_file)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"opengrep --validate rejected {rule_file.name}:\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )


def test_baseline_ships_at_least_one_rule_per_language() -> None:
    """Static sanity: ensure no language directory accidentally empties."""
    for lang in ("python", "rust", "go"):
        lang_dir = _RULES_ROOT / lang
        files = list(lang_dir.glob("*.yaml")) if lang_dir.is_dir() else []
        assert files, f"baseline/opengrep/{lang}/ ships no rules"
