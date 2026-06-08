# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Literal, Optional

Priority = Literal["high", "normal", "low"]
Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
ArchiveKind = str  # was Literal["sdist", "wheel"] — now accepts "crate" etc.


@dataclass(frozen=True)
class DiscoveredItem:
    name: str
    version: str
    priority: Priority = "normal"


@dataclass(frozen=True)
class ArchivePath:
    path: Path
    kind: ArchiveKind
    sha256: str


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: Severity
    confidence: Confidence
    file: str = ""
    line: Optional[int] = None
    evidence: str = ""


class IntegrityError(RuntimeError):
    """SHA256 mismatch during fetch."""
    pass


class NoFilesError(RuntimeError):
    """No release files found for the requested version."""
    pass


@dataclass
class FetchResult:
    archives: list[ArchivePath]
    metadata: dict


class EcosystemAdapter(ABC):
    ecosystem_id: str
    install_archive_kind: str = "sdist"
    strips_top_dir: bool = True

    @abstractmethod
    def discover(self) -> AsyncIterator[DiscoveredItem]:
        ...

    @abstractmethod
    async def fetch(self, name: str, version: str) -> FetchResult:
        ...

    @abstractmethod
    async def analyze_install(
        self,
        extracted_root: Path,
        changed_files: set[str] | None = None,
    ) -> list[Finding]:
        ...

    def schedule_jobs(self, scheduler) -> None:
        """Register APScheduler jobs for this ecosystem. Default: no-op."""
        pass

    async def boot(self) -> None:
        """One-time startup ingest. Default: no-op."""
        pass

    def sweep(self) -> None:
        """Periodic cleanup (e.g. orphan work dirs). Default: no-op."""
        pass

    def backfill(self, days: int) -> int:
        """Pull historical data. Returns count of items enqueued. Default: 0."""
        return 0


adapter_registry: dict[str, EcosystemAdapter] = {}


def register(adapter: EcosystemAdapter) -> None:
    adapter_registry[adapter.ecosystem_id] = adapter
