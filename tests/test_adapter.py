# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator

import pytest

from pkgsentry.adapter import (
    ArchivePath,
    DiscoveredItem,
    EcosystemAdapter,
    Finding,
    FetchResult,
    IntegrityError,
    NoFilesError,
    adapter_registry,
    register,
)


class FakeAdapter(EcosystemAdapter):
    ecosystem_id = "fake"

    async def discover(self) -> AsyncIterator[DiscoveredItem]:
        yield DiscoveredItem(name="x", version="1", priority="high")

    async def fetch(self, name: str, version: str) -> FetchResult:
        return FetchResult(
            archives=[ArchivePath(path=Path("/tmp/x"), kind="sdist", sha256="0" * 64)],
            metadata={},
        )

    async def analyze_install(self, extracted_root: Path) -> list[Finding]:
        return []


@pytest.mark.asyncio
async def test_register_and_dispatch():
    a = FakeAdapter()
    register(a)
    assert adapter_registry["fake"] is a
    items = [it async for it in a.discover()]
    assert items[0].priority == "high"


def test_finding_fields():
    f = Finding(
        rule_id="r", category="c", severity="high",
        confidence="medium", file="setup.py", line=1, evidence="e",
    )
    assert f.severity == "high"


# ---------- new tests for widened adapter ----------


def test_archive_kind_accepts_arbitrary_strings():
    """ArchiveKind is now str, not Literal — accepts 'crate', 'sdist', etc."""
    arc = ArchivePath(path=Path("/tmp/foo.crate"), kind="crate", sha256="abc")
    assert arc.kind == "crate"


def test_fetch_result_dataclass():
    arc = ArchivePath(path=Path("/tmp/foo.tar.gz"), kind="sdist", sha256="abc")
    fr = FetchResult(archives=[arc], metadata={"name": "foo"})
    assert len(fr.archives) == 1
    assert fr.metadata["name"] == "foo"


def test_integrity_error_is_runtime_error():
    assert issubclass(IntegrityError, RuntimeError)


def test_no_files_error_is_runtime_error():
    assert issubclass(NoFilesError, RuntimeError)


def test_ecosystem_adapter_defaults():
    """Lifecycle methods have no-op defaults."""
    class DummyAdapter(EcosystemAdapter):
        ecosystem_id = "dummy"
        async def discover(self):
            yield  # pragma: no cover
        async def fetch(self, name, version):
            return FetchResult(archives=[], metadata={})
        async def analyze_install(self, extracted_root):
            return []

    a = DummyAdapter()
    assert a.install_archive_kind == "sdist"
    assert a.strips_top_dir is True
    # Lifecycle methods should be callable without error
    a.schedule_jobs(None)
    a.sweep()
    assert a.backfill(7) == 0
