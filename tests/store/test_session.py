# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from sqlalchemy import select

from pkgward.store import session as sess_mod
from pkgward.store.models import Package


def test_pkgward_db_url_takes_precedence(monkeypatch):
    monkeypatch.setenv("PKGWARD_DB_URL", "postgresql://new")
    monkeypatch.setenv("PYPI_SCANNER_DB_URL", "postgresql://old")
    assert sess_mod._url() == "postgresql://new"


def test_falls_back_to_pypi_scanner_db_url(monkeypatch):
    monkeypatch.delenv("PKGWARD_DB_URL", raising=False)
    monkeypatch.delenv("PKGWATCH_DB_URL", raising=False)
    monkeypatch.setenv("PYPI_SCANNER_DB_URL", "postgresql://old")
    assert sess_mod._url() == "postgresql://old"


def test_init_and_get_session(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path/'app.db'}"
    monkeypatch.setenv("PKGWARD_DB_URL", url)
    sess_mod.reset_engine()
    sess_mod.init_db()
    with sess_mod.session_scope() as s:
        s.add(Package(ecosystem="pypi", name="requests"))
    with sess_mod.session_scope() as s:
        rows = s.scalars(select(Package)).all()
        assert len(rows) == 1
