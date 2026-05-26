# SPDX-License-Identifier: AGPL-3.0-or-later
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from pkgsentry.ecosystems.pypi.fetch.extract import (
    ExtractionError,
    safe_extract,
)


def _make_tgz(tmp_path: Path, entries: dict[str, bytes]) -> Path:
    p = tmp_path / "a.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return p


def _make_zip(tmp_path: Path, entries: dict[str, bytes]) -> Path:
    p = tmp_path / "a.whl"
    with zipfile.ZipFile(p, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return p


def test_extract_tar_ok(tmp_path):
    arc = _make_tgz(tmp_path, {"pkg/setup.py": b"print(1)"})
    out = tmp_path / "out"
    safe_extract(arc, out)
    assert (out / "pkg/setup.py").read_bytes() == b"print(1)"


def test_extract_wheel_ok(tmp_path):
    arc = _make_zip(tmp_path, {"pkg/__init__.py": b""})
    out = tmp_path / "out"
    safe_extract(arc, out)
    assert (out / "pkg/__init__.py").exists()


def test_skip_path_traversal_tar(tmp_path):
    arc = _make_tgz(tmp_path, {"../evil": b"x"})
    out = tmp_path / "out"
    safe_extract(arc, out)
    assert not (tmp_path / "evil").exists()


def test_skip_path_traversal_zip(tmp_path):
    arc = _make_zip(tmp_path, {"../evil": b"x"})
    out = tmp_path / "out"
    safe_extract(arc, out)
    assert not (tmp_path / "evil").exists()


def test_skip_symlink_tar(tmp_path):
    p = tmp_path / "s.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        t.addfile(info)
    out = tmp_path / "out"
    safe_extract(p, out)
    assert list(out.rglob("*")) == []


def test_reject_too_many_files(tmp_path):
    entries = {f"f{i}": b"x" for i in range(20)}
    arc = _make_zip(tmp_path, entries)
    with pytest.raises(ExtractionError):
        safe_extract(arc, tmp_path / "out", max_files=5)


def test_reject_total_size(tmp_path):
    entries = {f"f{i}": b"x" * 1024 for i in range(5)}
    arc = _make_zip(tmp_path, entries)
    with pytest.raises(ExtractionError):
        safe_extract(arc, tmp_path / "out", max_total_bytes=2048)


def test_safe_extract_crate_tarball(tmp_path):
    """A .crate file (gzipped tarball) is recognized and extracted."""
    from pkgsentry.util.extract import safe_extract

    # Create a fake .crate archive
    crate_dir = tmp_path / "build"
    crate_dir.mkdir()
    (crate_dir / "foo-1.0.0").mkdir()
    (crate_dir / "foo-1.0.0" / "Cargo.toml").write_text('[package]\nname = "foo"')
    (crate_dir / "foo-1.0.0" / "src").mkdir()
    (crate_dir / "foo-1.0.0" / "src" / "lib.rs").write_text("pub fn hello() {}")

    crate_path = tmp_path / "foo-1.0.0.crate"
    with tarfile.open(crate_path, "w:gz") as t:
        t.add(crate_dir / "foo-1.0.0", arcname="foo-1.0.0")

    out = tmp_path / "extracted"
    safe_extract(crate_path, out)
    assert (out / "foo-1.0.0" / "Cargo.toml").exists()
    assert (out / "foo-1.0.0" / "src" / "lib.rs").exists()
