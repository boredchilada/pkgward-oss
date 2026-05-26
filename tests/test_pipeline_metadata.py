# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import io
import tarfile
import zipfile
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from pkgsentry.store import session as sess
from pkgsentry.store.models import ScanQueue, Version, Watchlist


def _tgz(data):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, blob in data.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            t.addfile(info, io.BytesIO(blob))
    return buf.getvalue()


def _whl(data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, blob in data.items():
            z.writestr(name, blob)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_metadata_persisted(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'m.db'}")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from pkgsentry.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgsentry.ecosystems.pypi  # noqa: F401

    sdist_bytes = _tgz({"foo-1/setup.py": b"from setuptools import setup\nsetup(name='foo')\n"})
    whl_bytes = _whl({"foo/__init__.py": b""})
    payload = {
        "info": {
            "name": "foo", "version": "1.0",
            "author": "Jane Dev", "author_email": "jane@example.com",
            "summary": "A foo library", "home_page": "https://foo.example",
            "requires_python": ">=3.11", "keywords": "foo,bar",
            "license": "MIT", "maintainer": "Jane Dev",
            "project_urls": {"Source": "https://github.com/jane/foo"},
            "requires_dist": ["requests>=2.0"],
            "classifiers": ["Programming Language :: Python :: 3"],
            "upload_time": "2026-05-01T12:00:00",
            "description": "x" * 10000,
        },
        "urls": [
            {"packagetype": "sdist", "filename": "foo-1.0.tar.gz",
             "url": "https://files.pythonhosted.org/foo/foo-1.0.tar.gz",
             "digests": {"sha256": hashlib.sha256(sdist_bytes).hexdigest()}},
            {"packagetype": "bdist_wheel", "filename": "foo-1.0-py3-none-any.whl",
             "url": "https://files.pythonhosted.org/foo/foo-1.0-py3-none-any.whl",
             "digests": {"sha256": hashlib.sha256(whl_bytes).hexdigest()}},
        ],
    }
    httpx_mock.add_response(url="https://pypi.org/pypi/foo/1.0/json", json=payload)
    httpx_mock.add_response(url=payload["urls"][0]["url"], content=sdist_bytes)
    httpx_mock.add_response(url=payload["urls"][1]["url"], content=whl_bytes)

    with sess.session_scope() as s:
        s.add(Watchlist(ecosystem="pypi", name="foo", rank=42,
                        downloads_last_30d=12345, refreshed_at=datetime.now(timezone.utc)))
        s.add(ScanQueue(ecosystem="pypi", name="foo", version="1.0",
                        priority="normal", status="claimed", claim_token="test-tok"))

    from pkgsentry.pipeline import process_one
    with sess.session_scope() as s:
        row = s.scalars(select(ScanQueue)).one()
        qid = row.id
    await process_one(qid, "test-tok")

    with sess.session_scope() as s:
        ver = s.scalars(select(Version)).one()
        assert ver.author == "Jane Dev"
        assert ver.author_email == "jane@example.com"
        assert ver.summary == "A foo library"
        assert ver.home_page == "https://foo.example"
        assert ver.requires_python == ">=3.11"
        assert ver.keywords == "foo,bar"
        assert ver.license_text == "MIT"
        assert ver.project_urls == {"Source": "https://github.com/jane/foo"}
        assert ver.requires_dist == ["requests>=2.0"]
        assert ver.classifiers == ["Programming Language :: Python :: 3"]
        assert ver.maintainers == ["Jane Dev"]
        assert ver.downloads_last_30d == 12345
        assert ver.upload_time is not None
        assert ver.metadata_json is not None
        assert "description" not in ver.metadata_json
        assert ver.metadata_fetched_at is not None
