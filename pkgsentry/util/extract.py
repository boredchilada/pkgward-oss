# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

_COPY_CHUNK = 1024 * 1024  # 1 MB — stream members, never read one whole into RAM

DEFAULT_MAX_BYTES = 500 * 1024 * 1024  # 500 MB
DEFAULT_MAX_FILES = 25_000


class ExtractionError(Exception):
    pass


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _safe_path(out_dir: Path, member_name: str) -> Optional[Path]:
    if member_name.startswith(("/", "\\")):
        return None
    normalized = Path(member_name)
    if ".." in normalized.parts:
        normalized = Path(*[p for p in normalized.parts if p != ".."])
    dest = out_dir / normalized
    if not _is_within(out_dir, dest):
        return None
    return dest


def _extract_tar(arc: Path, out: Path, max_files: int, max_total_bytes: int) -> None:
    with tarfile.open(arc, "r:*") as t:
        members = t.getmembers()
        if len(members) > max_files:
            raise ExtractionError(f"too many files: {len(members)}")
        total = 0
        for m in members:
            if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                continue
            dest = _safe_path(out, m.name)
            if dest is None:
                continue
            if m.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            total += m.size
            if total > max_total_bytes:
                raise ExtractionError(f"archive too large: {total} > {max_total_bytes}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = t.extractfile(m)
            if src is None:
                continue
            with open(dest, "wb") as out_f:
                shutil.copyfileobj(src, out_f, _COPY_CHUNK)


def _extract_zip(arc: Path, out: Path, max_files: int, max_total_bytes: int) -> None:
    with zipfile.ZipFile(arc, "r") as z:
        infos = z.infolist()
        if len(infos) > max_files:
            raise ExtractionError(f"too many files: {len(infos)}")
        total = 0
        for info in infos:
            dest = _safe_path(out, info.filename)
            if dest is None:
                continue
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            total += info.file_size
            if total > max_total_bytes:
                raise ExtractionError(f"archive too large: {total} > {max_total_bytes}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(dest, "wb") as out_f:
                shutil.copyfileobj(src, out_f, _COPY_CHUNK)


def safe_extract(
    archive: Path,
    out_dir: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_BYTES,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    # Refuse to start extracting onto a near-full disk: a partial extraction that
    # dies on ENOSPC mid-write leaves junk and a confusing failure. Require room
    # for the worst case (the total-size cap) plus a small margin.
    try:
        free = shutil.disk_usage(out_dir).free
        if free < max_total_bytes + 64 * 1024 * 1024:
            raise ExtractionError(f"insufficient disk: {free} free < cap {max_total_bytes}")
    except OSError:
        pass  # disk_usage failed — proceed; the write path will surface ENOSPC
    name = archive.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar", ".crate")):
        _extract_tar(archive, out_dir, max_files, max_total_bytes)
    elif name.endswith((".whl", ".zip", ".egg")):
        _extract_zip(archive, out_dir, max_files, max_total_bytes)
    else:
        raise ExtractionError(f"unknown archive type: {archive.name}")
    return out_dir
