# SPDX-License-Identifier: AGPL-3.0-or-later
"""Convention guard: every shipped .yar file holds exactly one rule.

Rules are split one-per-file (file name == rule name) so the loader's per-file
compile pre-validation isolates a malformed rule to that single rule instead of
dropping every rule in a shared file. This test fails the build if a multi-rule
file (or a file whose name doesn't match its rule) creeps back in.
"""
from __future__ import annotations

import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_RULE_RE = re.compile(r'^[ \t]*(?:global[ \t]+|private[ \t]+)*rule[ \t]+(\w+)', re.M)

_YARA_DIRS = [
    _ROOT / "pkgward" / "intel" / "baseline" / "yara",
    _ROOT / "intel" / "private" / "yara",   # overlay, present only on the dev checkout
]

_YAR_FILES = [
    p for d in _YARA_DIRS if d.is_dir()
    for p in sorted(d.glob("*.yar"))
]


def _idfn(p: pathlib.Path) -> str:
    return f"{p.parent.parent.name}/{p.name}"


def test_yara_files_exist():
    assert _YAR_FILES, "no .yar rule files discovered"


@pytest.mark.parametrize("yar", _YAR_FILES, ids=_idfn)
def test_one_rule_per_file_named_after_rule(yar: pathlib.Path):
    names = _RULE_RE.findall(yar.read_text(encoding="utf-8"))
    assert len(names) == 1, (
        f"{yar.name}: expected exactly 1 rule, found {len(names)}: {names}. "
        f"Split into one-rule-per-file (file name == rule name)."
    )
    assert names[0] == yar.stem, (
        f"{yar.name}: rule {names[0]!r} should live in {names[0]}.yar "
        f"(file name must match the rule name)."
    )
