# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


# Tests run with the maintainer's private overlay loaded — this matches
# what production sees and lets us validate parity. CI also runs a second
# job with PKGSENTRY_INTEL_PATH unset to validate the baseline pack alone.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PRIVATE_INTEL = _REPO_ROOT / "intel" / "private"
if _PRIVATE_INTEL.is_dir() and not os.environ.get("PKGSENTRY_INTEL_PATH"):
    os.environ["PKGSENTRY_INTEL_PATH"] = str(_PRIVATE_INTEL)


@pytest.fixture(autouse=True)
def _reset_intel():
    """Reset the intel singleton between tests so PKGSENTRY_INTEL_PATH
    overrides set by individual tests are picked up cleanly."""
    from pkgsentry import intel
    intel.reset()
    yield
    intel.reset()


@pytest.fixture()
def sqlite_engine(tmp_path: Path):
    from pkgsentry.store.models import Base
    url = f"sqlite:///{tmp_path/'test.db'}"
    eng = create_engine(url, future=True)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db_session(sqlite_engine) -> Session:
    SessionLocal = sessionmaker(bind=sqlite_engine, expire_on_commit=False, future=True)
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
