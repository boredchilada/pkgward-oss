# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from typer.testing import CliRunner

from pkgsentry.cli import app

runner = CliRunner()


def test_help():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    assert "init-db" in r.stdout
    assert "run" in r.stdout
    assert "backfill" in r.stdout
    assert "rescan" in r.stdout
    assert "show" in r.stdout


def test_init_db_creates_file(tmp_path: Path, monkeypatch):
    url = f"sqlite:///{tmp_path/'cli.db'}"
    monkeypatch.setenv("PKGSENTRY_DB_URL", url)
    from pkgsentry.store import session as sess
    sess.reset_engine()
    r = runner.invoke(app, ["init-db"])
    assert r.exit_code == 0, r.stdout
    assert (tmp_path / "cli.db").exists()
