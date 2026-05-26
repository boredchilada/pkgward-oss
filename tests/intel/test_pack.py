# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from pkgsentry.intel.pack import IntelPack, load_pack


def _make_pack_dir(root: Path, *, with_opengrep: bool = False, with_yara: bool = False) -> Path:
    """Build a minimal valid pack directory under *root*."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "intel_pack.toml").write_text(
        'name = "test"\nversion = "0.0.0"\nextends = "none"\nlicense = "Apache-2.0"\n',
        encoding="utf-8",
    )
    if with_yara:
        yara_dir = root / "yara"
        yara_dir.mkdir()
        (yara_dir / "noop.yar").write_text("rule noop { condition: false }\n", encoding="utf-8")
    if with_opengrep:
        og_root = root / "opengrep"
        (og_root / "python").mkdir(parents=True)
        (og_root / "python" / "noop.yaml").write_text(
            "rules:\n  - id: noop\n    pattern: foo\n    message: noop\n    languages: [python]\n    severity: INFO\n",
            encoding="utf-8",
        )
    return root


def test_load_pack_with_opengrep_subdir_populates_opengrep_dirs(tmp_path: Path) -> None:
    pack_root = _make_pack_dir(tmp_path / "pack", with_opengrep=True)
    pack = load_pack(pack_root, source_label="test")
    assert pack.opengrep_dirs == [pack_root / "opengrep"]


def test_load_pack_without_opengrep_subdir_has_empty_opengrep_dirs(tmp_path: Path) -> None:
    pack_root = _make_pack_dir(tmp_path / "pack")
    pack = load_pack(pack_root, source_label="test")
    assert pack.opengrep_dirs == []


def test_opengrep_dirs_independent_of_yara_dirs(tmp_path: Path) -> None:
    pack_root = _make_pack_dir(tmp_path / "pack", with_opengrep=True, with_yara=True)
    pack = load_pack(pack_root, source_label="test")
    assert pack.opengrep_dirs == [pack_root / "opengrep"]
    assert pack.yara_dirs == [pack_root / "yara"]


def test_merge_unions_opengrep_dirs(tmp_path: Path) -> None:
    base_root = _make_pack_dir(tmp_path / "base", with_opengrep=True)
    overlay_root = _make_pack_dir(tmp_path / "overlay", with_opengrep=True)
    base = load_pack(base_root, source_label="base")
    overlay = load_pack(overlay_root, source_label="overlay")

    merged = base.merge(overlay)
    assert merged.opengrep_dirs == [
        base_root / "opengrep",
        overlay_root / "opengrep",
    ]


def test_merge_opengrep_dirs_dedupes_identical_paths(tmp_path: Path) -> None:
    pack_root = _make_pack_dir(tmp_path / "pack", with_opengrep=True)
    pack_a = load_pack(pack_root, source_label="a")
    pack_b = load_pack(pack_root, source_label="b")

    merged = pack_a.merge(pack_b)
    assert merged.opengrep_dirs == [pack_root / "opengrep"]


def test_intelpack_default_opengrep_dirs_empty() -> None:
    pack = IntelPack()
    assert pack.opengrep_dirs == []
