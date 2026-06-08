# SPDX-License-Identifier: AGPL-3.0-or-later
"""The cross-uid bind-mount contract: a detonation-staged dir must be world-
traversable and the file world-readable, because the scanner writes as root and
the rootless detonation service reads as an unrelated uid. Regression guard for the
vault re-detonation bug (staging dir left at mkdtemp's 0700 -> mount permission
denied -> silent fallback to refetch)."""
from __future__ import annotations

import stat

import pytest

from pkgward import detonation_staging as ds


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def test_staging_dir_is_world_traversable(tmp_path, monkeypatch):
    monkeypatch.setattr(ds, "STAGING_ROOT", tmp_path / "stg")
    d = ds.staging_dir(prefix="vault-")
    # o+rx required so the rootless detonation uid can enter for the bind mount.
    assert _mode(d) & 0o005 == 0o005, f"dir not world-traversable: {oct(_mode(d))}"
    assert _mode(d) == ds.DIR_MODE


def test_stage_bytes_dir_and_file_are_readable(tmp_path, monkeypatch):
    monkeypatch.setattr(ds, "STAGING_ROOT", tmp_path / "stg")
    f = ds.stage_bytes(b"payload-bytes", "pkg-1.0.0.tgz", prefix="vault-")
    assert f.read_bytes() == b"payload-bytes"
    assert f.name == "pkg-1.0.0.tgz"
    # o+r on the file, o+rx on its dir — both halves of the contract.
    assert _mode(f) & 0o004 == 0o004, f"file not world-readable: {oct(_mode(f))}"
    assert _mode(f) == ds.FILE_MODE
    assert _mode(f.parent) & 0o005 == 0o005


def test_stage_bytes_strips_inner_path(tmp_path, monkeypatch):
    # an archive name carrying path separators must not escape the staging dir
    monkeypatch.setattr(ds, "STAGING_ROOT", tmp_path / "stg")
    f = ds.stage_bytes(b"x", "../../etc/evil.tgz", prefix="vault-")
    assert f.name == "evil.tgz"
    assert f.parent.parent == (tmp_path / "stg")


def test_contract_holds_under_restrictive_umask(tmp_path, monkeypatch):
    # the bug class: a tighter umask must NOT produce unreadable staging, because the
    # modes are set explicitly (not inherited from umask).
    import os
    monkeypatch.setattr(ds, "STAGING_ROOT", tmp_path / "stg")
    old = os.umask(0o077)
    try:
        f = ds.stage_bytes(b"x", "p.tgz", prefix="vault-")
        assert _mode(f) == ds.FILE_MODE
        assert _mode(f.parent) == ds.DIR_MODE
    finally:
        os.umask(old)
