# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib

import pytest

from pkgsentry.adapter import Finding
from pkgsentry.ecosystems.pypi.fetch import download as dl


SDIST_BYTES = b"sdist-payload-bytes"
WHEEL_BYTES = b"wheel-payload-bytes"
SDIST_SHA = hashlib.sha256(SDIST_BYTES).hexdigest()
WHEEL_SHA = hashlib.sha256(WHEEL_BYTES).hexdigest()


def _json_payload(name: str, version: str) -> dict:
    return {
        "info": {"name": name, "version": version},
        "urls": [
            {
                "packagetype": "sdist",
                "url": f"https://files.pythonhosted.org/{name}/{name}-{version}.tar.gz",
                "digests": {"sha256": SDIST_SHA},
                "filename": f"{name}-{version}.tar.gz",
            },
            {
                "packagetype": "bdist_wheel",
                "url": f"https://files.pythonhosted.org/{name}/{name}-{version}-py3-none-any.whl",
                "digests": {"sha256": WHEEL_SHA},
                "filename": f"{name}-{version}-py3-none-any.whl",
            },
        ],
    }


@pytest.mark.asyncio
async def test_download_all_ok(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    payload = _json_payload("foo", "1.0")
    httpx_mock.add_response(url="https://pypi.org/pypi/foo/1.0/json", json=payload)
    httpx_mock.add_response(url=payload["urls"][0]["url"], content=SDIST_BYTES)
    httpx_mock.add_response(url=payload["urls"][1]["url"], content=WHEEL_BYTES)
    result = await dl.download_all("foo", "1.0")
    assert isinstance(result, dl.FetchResult)
    archives = result.archives
    kinds = sorted(a.kind for a in archives)
    assert kinds == ["sdist", "wheel"]
    # info{} block round-tripped from the JSON payload
    assert result.metadata.get("name") == "foo"
    for a in archives:
        assert a.path.exists()
        assert a.path.read_bytes() in (SDIST_BYTES, WHEEL_BYTES)


@pytest.mark.asyncio
async def test_sha_mismatch_returns_finding(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    payload = _json_payload("foo", "1.0")
    payload["urls"][0]["digests"]["sha256"] = "0" * 64  # wrong
    httpx_mock.add_response(url="https://pypi.org/pypi/foo/1.0/json", json=payload)
    httpx_mock.add_response(url=payload["urls"][0]["url"], content=SDIST_BYTES)
    httpx_mock.add_response(url=payload["urls"][1]["url"], content=WHEEL_BYTES)
    with pytest.raises(dl.IntegrityError) as exc:
        await dl.download_all("foo", "1.0")
    # Caller code turns this into a Finding; the exception carries the data.
    assert "sha256_mismatch" in str(exc.value)
