# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib

import pytest

from pkgsentry.adapter import IntegrityError, NoFilesError
from pkgsentry.ecosystems.npm.fetch import download as dl

TARBALL = b"fake-npm-tarball-bytes"
REG = "https://registry.npmjs.org"


def _sri(content: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(content).digest()).decode()


def _manifest(name: str, version: str, integrity: str, tarball: str) -> dict:
    return {
        "name": name,
        "version": version,
        "description": "a package",
        "license": "MIT",
        "dist": {"tarball": tarball, "integrity": integrity},
    }


def test_encode_name_unscoped():
    assert dl._encode_name("leftpad") == "leftpad"


def test_encode_name_scoped():
    assert dl._encode_name("@scope/pkg") == "@scope%2fpkg"


def test_verify_integrity_shasum_fallback():
    content = b"abc"
    dl._verify_integrity(content, {"shasum": hashlib.sha1(content).hexdigest()}, "x")


def test_verify_integrity_missing_raises():
    with pytest.raises(IntegrityError):
        dl._verify_integrity(b"abc", {}, "x")


@pytest.mark.asyncio
async def test_download_ok(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    url = f"{REG}/files/leftpad-1.0.0.tgz"
    man = _manifest("leftpad", "1.0.0", _sri(TARBALL), url)
    httpx_mock.add_response(url=f"{REG}/leftpad/1.0.0", json=man)
    httpx_mock.add_response(url=url, content=TARBALL)

    result = await dl.download_tarball("leftpad", "1.0.0")
    assert len(result.archives) == 1
    arc = result.archives[0]
    assert arc.kind == "npm_tarball"
    assert arc.sha256 == hashlib.sha256(TARBALL).hexdigest()
    assert arc.path.read_bytes() == TARBALL
    assert result.metadata["summary"] == "a package"
    assert result.metadata["license"] == "MIT"


@pytest.mark.asyncio
async def test_download_integrity_mismatch(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    url = f"{REG}/files/leftpad-1.0.0.tgz"
    man = _manifest("leftpad", "1.0.0", _sri(b"different-bytes"), url)
    httpx_mock.add_response(url=f"{REG}/leftpad/1.0.0", json=man)
    httpx_mock.add_response(url=url, content=TARBALL)

    with pytest.raises(IntegrityError):
        await dl.download_tarball("leftpad", "1.0.0")


@pytest.mark.asyncio
async def test_download_latest_resolves(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    url = f"{REG}/files/leftpad-2.5.0.tgz"
    man = _manifest("leftpad", "2.5.0", _sri(TARBALL), url)
    httpx_mock.add_response(url=f"{REG}/leftpad/latest", json=man)
    httpx_mock.add_response(url=url, content=TARBALL)

    result = await dl.download_tarball("leftpad", "latest")
    assert "2.5.0" in result.archives[0].path.name


@pytest.mark.asyncio
async def test_download_404_no_files(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    httpx_mock.add_response(url=f"{REG}/ghost/9.9.9", status_code=404)
    with pytest.raises(NoFilesError):
        await dl.download_tarball("ghost", "9.9.9")
