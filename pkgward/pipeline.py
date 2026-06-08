# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import asyncio
import hashlib
import math
import os
import shutil
import tarfile
import tempfile
import time
import uuid
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import structlog

from sqlalchemy import select
from sqlalchemy.orm import Session

from pkgward.adapter import (
    ArchivePath, EcosystemAdapter, Finding, IntegrityError, NoFilesError, adapter_registry,
)
from pkgward.analyze.binary import analyze_binary_artifacts
from pkgward.analyze.entropy import analyze_entropy, analyze_entropy_delta
from pkgward.analyze.imports import analyze_imports
from pkgward.analyze.iocs import analyze_iocs
from pkgward.analyze.secret_access import analyze_secret_access
from pkgward.analyze.malware_patterns import analyze_malware_patterns
from pkgward.analyze.metadata import MetadataContext, analyze_metadata
from pkgward.analyze.obfuscation import analyze_obfuscation
from pkgward.analyze.opengrep_scan import analyze_opengrep, replaces_install_analyzer_for
from pkgward.analyze.dep_intel import check_known_bad_deps
from pkgward.analyze.version_diff import PreviousVersion, analyze_version_diff
from pkgward.analyze.threat_intel import check_files_batch as check_threat_intel
from pkgward.analyze.yara_scan import analyze_yara
from pkgward.detect.score import score_and_verdict, _is_shadow_finding
from pkgward import vault
from pkgward.util import capabilities as caps
from pkgward.util.extract import safe_extract
from pkgward.logging_setup import get_logger
from pkgward.queue import mark_done, mark_failed
from pkgward.store import session as sess
from pkgward.detonate.client import get_client as get_detonation_client
from pkgward.detonate.gate import should_detonate
from pkgward import detonation_queue
from pkgward.store.models import (
    FileHash,
    Finding as FindingRow,
    Package,
    RuleHit,
    Scan,
    ScanQueue,
    Version,
    Watchlist,
)

log = get_logger("pipeline")

_DETONATION_ECOSYSTEMS = {"pypi", "crates", "gomod", "npm"}
_PREFERRED_ARCHIVE = {"pypi": "sdist", "crates": "crate", "gomod": "gomod_zip", "npm": "npm_tarball"}

# Categories that are FP-prone or are themselves propagation signals: a single
# high/critical hit from one of these does NOT, on its own, justify the
# high-consequence auto-watchlist promotion (sentinel rank → every future release
# force-scanned AND the name joins known_bad_deps, so a dependent gets a dep_intel
# finding). The @zola_do dev-server-IP cascade: one `iocs.hardcoded_wan_ip_port`
# (an Ethio Telecom dev box) → LLM-malicious → sentinel rank → dep_intel cascade.
_NON_PRIMARY_PROMOTE_CATEGORIES = frozenset({"iocs", "dep_intel", "metadata", "version_diff"})


def _auto_watchlist_qualifies(result, tri, findings: list[Finding]) -> tuple[bool, str]:
    """Minimum-evidence bar for sentinel-rank auto-watchlist promotion.

    Promotion is far higher-consequence than an alert, so it requires genuinely
    confirmed malware — not a lone IOC/propagation hit the LLM happened to call
    malicious. Requires the LLM to confirm malicious AND:

      1. PRIMARY evidence — at least one high/critical non-shadow finding OUTSIDE
         the FP-prone / propagation categories, OR at least two distinct
         high/critical categories (corroboration, not one lone hit); AND
      2. corroboration — the LLM is at or above the malicious-confidence floor
         AND (the rule layer independently convicted (verdict ``malicious``),
         OR the LLM is highly confident (>= 0.80)).

    Returns ``(qualifies, reason)``; the reason is logged when it does NOT qualify
    so thin-evidence near-misses stay visible for tuning.
    """
    if tri is None or tri.verdict != "malicious":
        return False, "llm_not_malicious"
    strong = [
        f for f in findings
        if not _is_shadow_finding(f) and f.severity in ("high", "critical")
    ]
    cats = {f.category for f in strong}
    has_primary = bool(cats - _NON_PRIMARY_PROMOTE_CATEGORIES)
    if not has_primary and len(cats) < 2:
        return False, "thin_evidence_single_soft_category"
    from pkgward.llm import triage as llm_triage_mod
    conf = getattr(tri, "confidence", None) or 0.0
    if conf < llm_triage_mod.MALICIOUS_CONF_FLOOR:
        # "Double-confirmed" must not mean rules + a coin-flip: every observed
        # FP promotion (ainx class) rode a sub-floor LLM confidence past the
        # rule-corroboration branch.
        return False, "llm_confidence_below_floor"
    if result.verdict == "malicious" or conf >= 0.80:
        return True, "ok"
    return False, "weak_corroboration"


def _detonation_priority(*, verdict: str, watchlist_rank: Optional[int]) -> str:
    if verdict in ("suspicious", "malicious") or watchlist_rank is not None:
        return "high"
    return "low"


def _detonation_cluster_enabled(det_client) -> bool:
    """Whether to enqueue detonation jobs from this host.

    True if a detonation service is reachable locally, OR detonation is deployed
    elsewhere in the cluster (DETONATION_ENABLED=1) so a scan-only worker host
    still enqueues for a draining host to pick up. Default off keeps single-host
    no-detonation deployments from piling up undrained jobs.
    """
    return det_client.is_enabled() or os.environ.get("DETONATION_ENABLED", "0") != "0"


def _is_watchlist(session: Session, name: str, ecosystem: str) -> Optional[int]:
    """Check if package is on the watchlist. Returns rank or None."""
    row = session.scalars(
        select(Watchlist).where(Watchlist.ecosystem == ecosystem, Watchlist.name == name)
    ).first()
    return row.rank if row else None


def _archive_members(arc: ArchivePath) -> list[str]:
    p = str(arc.path).lower()
    try:
        if p.endswith((".tar.gz", ".tgz", ".tar", ".crate")):
            with tarfile.open(arc.path, "r:*") as t:
                return [m.name for m in t.getmembers() if m.isfile()]
        if p.endswith((".whl", ".zip", ".egg")):
            with zipfile.ZipFile(arc.path, "r") as z:
                return [i.filename for i in z.infolist() if not i.is_dir()]
    except Exception as e:
        # A swallowed-empty here silently blinds the sdist/wheel-mismatch and
        # lure-file metadata checks (they see zero files and can't fire). Log so
        # the degradation is observable rather than a silent detection-loss.
        log.warning("archive_members_failed", path=str(arc.path), error=str(e))
        return []
    return []


def _watchlist_top_names(session: Session, ecosystem: str, limit: int = 5000) -> list[str]:
    rows = session.scalars(
        select(Watchlist).where(Watchlist.ecosystem == ecosystem).order_by(Watchlist.rank.asc()).limit(limit)
    ).all()
    return [w.name for w in rows]


def _upsert_package_and_version(
    session: Session, ecosystem: str, name: str, version: str
) -> Version:
    from sqlalchemy.exc import IntegrityError as SAIntegrityError

    pkg = session.scalars(
        select(Package).where(Package.ecosystem == ecosystem, Package.name == name)
    ).first()
    if pkg is None:
        try:
            pkg = Package(ecosystem=ecosystem, name=name)
            session.add(pkg)
            session.flush()
        except SAIntegrityError:
            session.rollback()
            pkg = session.scalars(
                select(Package).where(Package.ecosystem == ecosystem, Package.name == name)
            ).first()
    ver = session.scalars(
        select(Version).where(
            Version.ecosystem == ecosystem,
            Version.package_id == pkg.id,
            Version.version == version,
        )
    ).first()
    if ver is None:
        try:
            ver = Version(ecosystem=ecosystem, package_id=pkg.id, version=version)
            session.add(ver)
            session.flush()
        except SAIntegrityError:
            session.rollback()
            ver = session.scalars(
                select(Version).where(
                    Version.ecosystem == ecosystem,
                    Version.package_id == pkg.id,
                    Version.version == version,
                )
            ).first()
    return ver


def _apply_metadata(
    session: Session,
    ver: Version,
    metadata: dict,
    watchlist_rank: Optional[int],
) -> None:
    if not metadata:
        return
    ver.author = metadata.get("author") or metadata.get("maintainer") or None
    ver.author_email = metadata.get("author_email") or metadata.get("maintainer_email") or None
    upload_user = metadata.get("upload_user")
    if upload_user:
        ver.upload_user = str(upload_user)[:128]
    ver.home_page = metadata.get("home_page") or None
    summary = metadata.get("summary")
    if summary:
        ver.summary = str(summary)[:1024]
    ver.requires_python = metadata.get("requires_python") or None
    ver.keywords = metadata.get("keywords") or None
    license_val = metadata.get("license")
    if license_val:
        ver.license_text = str(license_val)[:256]
    project_urls = metadata.get("project_urls")
    if isinstance(project_urls, dict):
        ver.project_urls = project_urls
    requires_dist = metadata.get("requires_dist")
    if isinstance(requires_dist, list):
        ver.requires_dist = requires_dist
    classifiers = metadata.get("classifiers")
    if isinstance(classifiers, list):
        ver.classifiers = classifiers
    upload_time_iso = metadata.get("upload_time")
    if upload_time_iso:
        try:
            ver.upload_time = datetime.fromisoformat(
                str(upload_time_iso).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            pass
    maintainers = metadata.get("maintainers")
    if isinstance(maintainers, list) and maintainers:
        ver.maintainers = maintainers
    else:
        maintainer = metadata.get("maintainer")
        if maintainer:
            ver.maintainers = [maintainer]
    if watchlist_rank is not None:
        pkg = session.get(Package, ver.package_id)
        if pkg is not None:
            wl_row = session.scalars(
                select(Watchlist).where(
                    Watchlist.ecosystem == pkg.ecosystem,
                    Watchlist.name == pkg.name,
                )
            ).first()
            if wl_row is not None:
                ver.downloads_last_30d = wl_row.downloads_last_30d
    audit = dict(metadata)
    audit.pop("description", None)
    audit.pop("description_content_type", None)
    ver.metadata_json = audit
    ver.metadata_fetched_at = datetime.now(timezone.utc)


def _get_previous_version(
    session: Session, ecosystem: str, package_id: int, exclude_version_id: int
) -> Optional[PreviousVersion]:
    prev_ver = session.scalars(
        select(Version)
        .where(
            Version.ecosystem == ecosystem,
            Version.package_id == package_id,
            Version.id != exclude_version_id,
        )
        .order_by(Version.first_seen_at.desc())
        .limit(1)
    ).first()
    if prev_ver is None:
        return None
    prev_scan = session.scalars(
        select(Scan)
        .where(Scan.version_id == prev_ver.id)
        .order_by(Scan.started_at.desc())
        .limit(1)
    ).first()
    if prev_scan is None:
        return None
    prev_findings = session.scalars(
        select(FindingRow.rule_id).where(FindingRow.scan_id == prev_scan.id)
    ).all()
    return PreviousVersion(
        version=prev_ver.version,
        verdict=prev_scan.verdict,
        score=prev_scan.score,
        rule_ids=set(prev_findings),
        finding_count=len(prev_findings),
        author=prev_ver.author,
        author_email=prev_ver.author_email,
        upload_time=prev_ver.upload_time,
        requires_dist=prev_ver.requires_dist or [],
    )


def _bump_rulehits_deferred(findings: Iterable[Finding]) -> None:
    """Bump rule hit counts in a separate short transaction to avoid deadlocks."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1

    if not counts:
        return

    with sess.session_scope() as s:
        for rule_id, delta in counts.items():
            row = s.get(RuleHit, rule_id)
            if row is None:
                s.add(RuleHit(rule_id=rule_id, count=delta))
            else:
                row.count += delta


# Files larger than this get SHA-256 only (streamed). Entropy/ssdeep/TLSH are
# O(n) in pure Python (or near it) and ruinously slow on big prebuilt native
# binaries (e.g. ~50-200MB platform packages: esbuild/turbo/swc/AI tools) while
# adding little signal — a compiled binary is always near-max entropy and rarely
# matches a fuzzy fingerprint. Exact SHA-256 (threat-intel) still covers them.
HASH_FULL_MAX_BYTES = int(os.environ.get("PKGWARD_HASH_FULL_MAX_MB", "20")) * 1024 * 1024

# Giant-package fast-path. A handful of huge packages (Go monorepos like gitea /
# go-ethereum, fat JS component libs) take 10s of seconds of pure-Python CPU to
# fuzzy-hash + analyze, and with many workers in one process sharing the GIL they
# blow the per-package timeout and burn a worker for 15 min. When a package is
# "giant" (file count or extracted size over the threshold) and the fast-path is
# ON, skip the heaviest per-file work — ssdeep/TLSH fuzzy hashing, entropy, and
# the obfuscation analyzer — keeping SHA-256 (exact threat-intel), opengrep, yara,
# iocs, imports, malware-patterns, binary, metadata. Detection-critical signatures
# stay; only fuzzy-hash + entropy/obfuscation heuristics are dropped on giants
# (low risk — giants are legitimate big projects, not lures). Toggle with
# PKGWARD_GIANT_FASTPATH=0.
GIANT_FASTPATH = os.environ.get("PKGWARD_GIANT_FASTPATH", "1") != "0"
GIANT_FILE_THRESHOLD = int(os.environ.get("PKGWARD_GIANT_FILE_THRESHOLD", "5000"))
GIANT_MAX_BYTES = int(os.environ.get("PKGWARD_GIANT_MAX_MB", "100")) * 1024 * 1024


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _sha256_stream(path: Path) -> str:
    """SHA-256 without loading the whole file into memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class FileInfo:
    sha256: str
    entropy: float
    ssdeep: str
    tlsh: str = ""


def _compute_file_hashes(
    root: Path, archive_kind: str, lite: bool = False,
) -> tuple[dict[str, FileInfo], dict[str, str]]:
    """Walk *root*, SHA-256 + entropy + ssdeep + tlsh every file.

    Returns ``(normalized_info, norm_to_real)`` where keys are normalized
    relative paths and values are FileInfo with sha256/entropy/ssdeep/tlsh.
    With ``lite`` (giant-package fast-path) the per-file fuzzy hashing + entropy
    are skipped — SHA-256 only — to keep a huge package off the shared-GIL hot
    path.
    """
    _ssdeep = None if lite else (caps.ppdeep.hash if caps.HAS_PPDEEP else None)
    _tlsh = None if lite else (caps.tlsh.hash if caps.HAS_TLSH else None)

    normalized_info: dict[str, FileInfo] = {}
    norm_to_real: dict[str, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        real = rel.as_posix()
        parts = rel.parts
        if archive_kind in ("sdist", "crate", "gomod_zip", "npm_tarball") and len(parts) > 1:
            normalized = "/".join(parts[1:])
        else:
            normalized = real
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size > HASH_FULL_MAX_BYTES:
            # Large file: stream SHA-256 only, skip the expensive metrics.
            try:
                sha = _sha256_stream(p)
            except OSError:
                continue
            normalized_info[normalized] = FileInfo(sha256=sha, entropy=0.0, ssdeep="", tlsh="")
            norm_to_real[normalized] = real
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        sha = hashlib.sha256(data).hexdigest()
        # Entropy is computed even in lite mode: it's a single O(n) histogram (cheaper
        # than the ssdeep/TLSH on the next lines) and analyze_entropy_delta needs it to
        # detect a clean->obfuscated version transition on giant packages. Only the
        # full analyze_entropy/obfuscation rglob passes are skipped in lite (below).
        ent = _shannon_entropy(data) if len(data) >= 64 else 0.0
        fuzzy = _ssdeep(data) if _ssdeep and len(data) >= 64 else ""
        tl = _tlsh(data) if _tlsh and len(data) >= 64 else ""
        normalized_info[normalized] = FileInfo(sha256=sha, entropy=ent, ssdeep=fuzzy, tlsh=tl)
        norm_to_real[normalized] = real
    return normalized_info, norm_to_real


def _get_prev_scan_hashes(
    session: Session, ecosystem: str, name: str, current_version: str,
) -> dict[str, dict[str, FileInfo]]:
    """Return ``{archive_kind: {normalized_path: FileInfo}}`` from the most
    recent scan of any *previous* version of the same package."""
    pkg = session.scalars(
        select(Package).where(Package.ecosystem == ecosystem, Package.name == name)
    ).first()
    if pkg is None:
        return {}
    prev_ver = session.scalars(
        select(Version)
        .where(
            Version.ecosystem == ecosystem,
            Version.package_id == pkg.id,
            Version.version != current_version,
        )
        .order_by(Version.first_seen_at.desc())
        .limit(1)
    ).first()
    if prev_ver is None:
        return {}
    prev_scan = session.scalars(
        select(Scan)
        .where(Scan.version_id == prev_ver.id)
        .order_by(Scan.started_at.desc())
        .limit(1)
    ).first()
    if prev_scan is None:
        return {}
    rows = session.scalars(
        select(FileHash).where(FileHash.scan_id == prev_scan.id)
    ).all()
    result: dict[str, dict[str, FileInfo]] = {}
    for row in rows:
        result.setdefault(row.archive_kind, {})[row.file_path] = FileInfo(
            sha256=row.sha256,
            entropy=row.entropy or 0.0,
            ssdeep=row.ssdeep or "",
        )
    return result


def _find_changed_files(
    current_info: dict[str, FileInfo],
    prev_info: dict[str, FileInfo],
    norm_to_real: dict[str, str],
) -> set[str]:
    """Return extraction-relative paths for files that are new or changed."""
    changed: set[str] = set()
    for norm_path, cur in current_info.items():
        prev = prev_info.get(norm_path)
        if prev is None or prev.sha256 != cur.sha256:
            changed.add(norm_to_real[norm_path])
    return changed


def _persist_file_hashes(
    session: Session,
    scan_id: int,
    hashes_by_kind: list[tuple[str, dict[str, FileInfo]]],
) -> None:
    for kind, infos in hashes_by_kind:
        for path, info in infos.items():
            session.add(FileHash(
                scan_id=scan_id, archive_kind=kind,
                file_path=_strip_nul(path), sha256=info.sha256,
                ssdeep=info.ssdeep or None,
                tlsh=info.tlsh or None,
                entropy=info.entropy,
            ))


def _giant_lite(root: Path) -> bool:
    """Decide whether the extracted tree is 'giant' (skip the heaviest per-file
    work). Cheap single walk: dirent + stat, no file reads."""
    if not GIANT_FASTPATH:
        return False
    count = 0
    total = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        count += 1
        try:
            total += p.stat().st_size
        except OSError:
            pass
        if count > GIANT_FILE_THRESHOLD or total > GIANT_MAX_BYTES:
            return True
    return False


def _extract_and_hash(
    arc: ArchivePath, sub: Path,
) -> tuple[dict[str, FileInfo], dict[str, str], list[str], bool]:
    safe_extract(arc.path, sub)
    # Recover UPX-packed payloads (decompress-only, never executed) before hashing
    # so the real payload is fingerprinted by threat-intel and seen by every
    # analyzer — packed binaries are otherwise a blind spot for static + LLM.
    try:
        from pkgward.analyze.unpack import unpack_packed_executables
        unpacked = unpack_packed_executables(sub)
        if unpacked:
            log.info("unpacked_payloads", kind=arc.kind,
                     n=len(unpacked), results=unpacked[:10])
    except Exception as e:
        log.warning("unpack_pass_failed", error=str(e))
    members = _archive_members(arc)
    lite = _giant_lite(sub)
    if lite:
        log.info("giant_fastpath", kind=arc.kind,
                 file_threshold=GIANT_FILE_THRESHOLD,
                 max_mb=GIANT_MAX_BYTES // (1024 * 1024))
    current_info, norm_to_real = _compute_file_hashes(sub, arc.kind, lite=lite)
    return current_info, norm_to_real, members, lite


def _run_analyzers(
    sub: Path,
    changed: set[str] | None,
    current_info: dict[str, FileInfo],
    prev_info: dict[str, FileInfo],
    norm_to_real: dict[str, str],
    ecosystem: str = "pypi",
    lite: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    if ecosystem == "pypi":
        findings.extend(analyze_imports(sub, changed_files=changed))
        findings.extend(analyze_malware_patterns(sub, changed_files=changed))
    findings.extend(analyze_iocs(sub, changed_files=changed))
    findings.extend(analyze_secret_access(sub, changed_files=changed))
    # Giant fast-path: skip the full per-file entropy + obfuscation rglob passes.
    # entropy_delta still runs — the per-file FileInfo.entropy it compares is computed
    # even in lite mode (see _compute_file_hashes), so the clean->obfuscated version
    # transition detector stays live on giant packages.
    if not lite:
        findings.extend(analyze_entropy(sub, changed_files=changed))
        findings.extend(analyze_obfuscation(sub, changed_files=changed))
    findings.extend(analyze_entropy_delta(current_info, prev_info, norm_to_real))
    findings.extend(analyze_binary_artifacts(sub, changed_files=changed))
    findings.extend(analyze_yara(sub, changed_files=changed))
    findings.extend(analyze_opengrep(sub, changed_files=changed, ecosystem=ecosystem))
    return findings


# Rules whose firing is an artifact of mis-ingesting a NON-Go repo as a Go module.
# The Go module proxy indexes ANY tagged VCS repo on demand, so a repo shipping only
# Python (e.g. a PyArmor-protected commercial package) gets fetched + scanned as
# gomod. The cross-ecosystem + pyarmor "stealer" heuristics then fire on that Python
# content and escalate a non-Go-module FP (the QuantumDatalytica quantum-core-engine
# family). A module with no go.mod and no .go file has no real Go-import attack
# surface — it cannot be imported by a Go build — so these Go-context findings are
# suppressed when no Go is present. Content-based malice rules (threat_intel SHA, IOC,
# binary, secret-access) still run, so a genuinely malicious payload is still caught;
# and a REAL Go module that legitimately ships Python (go.mod present) keeps the
# cross-ecosystem signal.
_GOMOD_NON_GO_SUPPRESS = frozenset({
    "yara.cross_ecosystem_python_in_go",
    "yara.pyarmor_suspicious_deps",
    "yara.pyarmor_obfuscation",
})


def _gomod_has_go(sub: Path) -> bool:
    """True if the extracted gomod tree contains any real Go — a go.mod or any .go
    file. Cheap bounded walk that short-circuits on the first Go artifact."""
    for p in sub.rglob("*"):
        if p.is_file() and (p.name == "go.mod" or p.suffix == ".go"):
            return True
    return False


def _filter_gomod_non_go(sub: Path, findings: list[Finding]) -> list[Finding]:
    """Drop Go-context FP rules from a gomod artifact that contains no actual Go."""
    if _gomod_has_go(sub):
        return findings
    suppressed = sorted({f.rule_id for f in findings if f.rule_id in _GOMOD_NON_GO_SUPPRESS})
    if not suppressed:
        return findings
    log.info("gomod_no_go_suppressed", rules=suppressed)
    return [f for f in findings if f.rule_id not in _GOMOD_NON_GO_SUPPRESS]


async def run_static_analyzers(
    sub: Path,
    *,
    ecosystem: str,
    adapter: EcosystemAdapter,
    arc_kind: str,
    changed: set[str] | None = None,
    current_info: dict[str, FileInfo] | None = None,
    prev_info: dict[str, FileInfo] | None = None,
    norm_to_real: dict[str, str] | None = None,
    lite: bool = False,
) -> list[Finding]:
    """Compose all static analyzers for an extracted archive root.

    Single source of truth for "which static analyzers run for ecosystem X over
    this extracted dir" — the install-analyzer gate plus ``_run_analyzers``. Both
    ``process_one`` and the regression-corpus harness call this so they cannot
    drift. ``_run_analyzers`` is CPU-bound and offloaded to a thread (the install
    analyzer is awaited directly, matching the prod path)."""
    findings: list[Finding] = []
    if arc_kind == adapter.install_archive_kind and not replaces_install_analyzer_for(ecosystem):
        findings.extend(await adapter.analyze_install(sub, changed_files=changed))
    if ecosystem == "npm" and arc_kind == adapter.install_archive_kind:
        # URL-spec dependencies (raw tarball on a suspicious host) — flag them, and
        # fetch + statically analyze the second stage so a staged dependency-confusion
        # payload convicts the parent at scan time. Network + fail-soft; never blocks.
        from pkgward.ecosystems.npm.url_deps import analyze_url_dependencies
        try:
            findings.extend(await analyze_url_dependencies(sub))
        except Exception as e:
            log.warning("url_deps_failed", error=str(e))
    analyzer_findings = await asyncio.to_thread(
        _run_analyzers, sub, changed, current_info or {}, prev_info or {},
        norm_to_real or {}, ecosystem=ecosystem, lite=lite,
    )
    findings.extend(analyzer_findings)
    if ecosystem == "gomod":
        findings = _filter_gomod_non_go(sub, findings)
    return findings


def _strip_nul(value):
    """Remove NUL (0x00) from strings before they hit Postgres. TEXT and JSONB
    columns reject ``\\u0000``, so a single NUL anywhere in metadata, a finding's
    evidence, a file path, or an LLM field would fail the whole scan's write and
    mark it failed (a package can ship UTF-16 / binary-ish content — or embed NUL
    deliberately — to evade scanning this way). Recurses into dict/list for JSON
    columns. NUL carries no meaning in our text fields, so stripping is safe."""
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nul(v) for v in value]
    return value


def _persist_findings(session: Session, scan: Scan, findings: list[Finding]) -> None:
    for f in findings:
        session.add(FindingRow(
            scan_id=scan.id,
            rule_id=f.rule_id, category=f.category, severity=f.severity,
            confidence=f.confidence, file=_strip_nul(f.file or ""), line=f.line,
            evidence=_strip_nul(f.evidence or ""),
        ))


def _cleanup_extract(tmp_extract: Path, archives: list[ArchivePath]) -> None:
    """Remove the extract tree + download staging dirs. Recursive blocking I/O —
    call off the event loop."""
    shutil.rmtree(tmp_extract, ignore_errors=True)
    for arc in archives:
        try:
            shutil.rmtree(Path(arc.path).parent, ignore_errors=True)
        except Exception:
            pass


def _persist_and_finalize(
    *,
    queue_id: int,
    claim_token: Optional[str],
    ecosystem: str,
    name: str,
    version: str,
    started_at: datetime,
    metadata: dict,
    archives: list[ArchivePath],
    tmp_extract: Path,
    all_findings: list[Finding],
    all_file_hashes: list[tuple[str, dict[str, FileInfo]]],
    fetch_error: Optional[Exception],
    fetch_error_type: Optional[str],
    sdist_files: list[str],
    wheel_files: list[str],
) -> None:
    """Scoring, persistence, LLM triage, detonation-enqueue — all sync, runs in thread.

    Detonation is enqueued (DetonationQueue) and run asynchronously by
    detonation_worker.py; the scan is finalized here with the static verdict.
    """
    # Some packages ship UTF-16 / binary-ish metadata (e.g. a summary with NUL
    # bytes). Strip NUL up front so neither the scalar columns, the metadata_json
    # audit blob, nor metadata-derived findings fail the Postgres write.
    metadata = _strip_nul(metadata)
    with sess.session_scope() as s:
        row = s.get(ScanQueue, queue_id)
        if row is None:
            return

        ver = _upsert_package_and_version(s, ecosystem, name, version)
        scan = Scan(version_id=ver.id, started_at=started_at, verdict="clean", score=0)
        s.add(scan)
        s.flush()

        if fetch_error is not None:
            rank = _is_watchlist(s, name, ecosystem)
            result = score_and_verdict(all_findings, watchlist_rank=rank)
            scan.verdict = result.verdict
            scan.score = result.score
            scan.alert_tag = result.alert_tag
            scan.finished_at = datetime.now(timezone.utc)
            _persist_findings(s, scan, all_findings)
            if fetch_error_type == "no_files":
                mark_failed(s, row, str(fetch_error), token=claim_token)
            else:
                mark_done(s, row, token=claim_token)
            # session commits on exit, then bump rulehits separately
            _bump_rulehits_deferred(all_findings)
            return

        prev = _get_previous_version(s, ecosystem, ver.package_id, ver.id)

        cur_author = metadata.get("maintainer") or metadata.get("author")
        prev_maintainers = []
        prev_release_at = None
        if prev is not None:
            prev_maintainers = [prev.author or ""] if prev.author else []
            prev_release_at = prev.upload_time

        ctx = MetadataContext(
            name=name,
            version=version,
            previous_release_at=prev_release_at,
            maintainers_now=[cur_author] if cur_author else [],
            maintainers_prev=prev_maintainers,
            watchlist_top_names=_watchlist_top_names(s, ecosystem),
            sdist_files=sdist_files,
            wheel_files=wheel_files,
        )
        all_findings.extend(analyze_metadata(ctx))

        if prev is not None:
            all_findings.extend(
                analyze_version_diff(all_findings, metadata, prev)
            )

        # Dependency-intel: flag a package that declares a dependency on a
        # confirmed-malicious (auto-watchlisted) package — supply-chain
        # propagation. A weighted finding, not a verdict; triage adjudicates.
        from pkgward import known_bad_deps
        if known_bad_deps.is_enabled():
            _kb = known_bad_deps.load_known_bad(ecosystem, session=s)
            if _kb:
                all_findings.extend(check_known_bad_deps(
                    ecosystem=ecosystem,
                    requires_dist=metadata.get("requires_dist"),
                    prev_requires_dist=(prev.requires_dist if prev is not None else None),
                    known_bad=_kb,
                ))

        # Threat intel: check file hashes against known-malicious fingerprints
        for kind, infos in all_file_hashes:
            intel_batch = {
                path: {"sha256": fi.sha256, "ssdeep": fi.ssdeep, "tlsh": fi.tlsh}
                for path, fi in infos.items()
            }
            all_findings.extend(check_threat_intel(s, intel_batch))

        # For confirmed-malicious (auto-watchlisted) names, carry forward
        # findings on SHA-unchanged files from the most-recent prior scan
        # within the TTL window. The attacker pattern is byte-identical
        # re-publishes; without this, our changed_files optimization would
        # surface only the deltas (3 of 11 findings) and thin the LLM's
        # evidence basis — even though the verdict held via the chain rule.
        try:
            from pkgward.watchlist_auto import is_watchlist_auto_only
            if is_watchlist_auto_only(s, ecosystem, name):
                from pkgward.finding_reuse import carry_forward_findings
                cur_hashes: dict[str, str] = {}
                for _kind, infos in all_file_hashes:
                    for path, fi in infos.items():
                        cur_hashes[path] = fi.sha256
                carried = carry_forward_findings(
                    s, ecosystem, name, scan.id, cur_hashes,
                    existing_findings=all_findings,
                )
                if carried:
                    all_findings.extend(carried)
                    log.info("findings_carried_forward",
                             ecosystem=ecosystem, pkg=f"{name}=={version}",
                             carried=len(carried))
        except Exception as e:
            log.warning("findings_carry_forward_skipped",
                        ecosystem=ecosystem, name=name, error=str(e))

        rank = _is_watchlist(s, name, ecosystem)
        result = score_and_verdict(all_findings, watchlist_rank=rank)
        scan.verdict = result.verdict
        scan.score = result.score
        scan.alert_tag = result.alert_tag
        scan.finished_at = datetime.now(timezone.utc)

        _apply_metadata(s, ver, metadata, watchlist_rank=rank)
        _persist_findings(s, scan, all_findings)
        _persist_file_hashes(s, scan.id, all_file_hashes)

        # --- Detonation: enqueue for async processing (decoupled from this scan) ---
        is_first_version = prev is None
        det_client = get_detonation_client()
        if (
            ecosystem in _DETONATION_ECOSYSTEMS
            and _detonation_cluster_enabled(det_client)
            and should_detonate(
                verdict=result.verdict,
                score=result.score,
                findings=all_findings,
                watchlist_rank=rank,
                is_new_package=is_first_version,
            )
        ):
            detonation_queue.enqueue(
                s,
                scan_id=scan.id,
                version_id=ver.id,
                ecosystem=ecosystem,
                name=name,
                version=version,
                archive_kind=_PREFERRED_ARCHIVE.get(ecosystem, "sdist"),
                priority=_detonation_priority(verdict=result.verdict, watchlist_rank=rank),
                static_verdict=result.verdict,
            )

        # Capture what the post-commit triage/alert needs, then let THIS
        # transaction close before the LLM HTTP call. Holding a session (its
        # pooled connection + the claimed-row locks) across ~180s of triage
        # latency exhausts the connection pool under a burst of malicious packages
        # and stalls every worker. Clean/suspicious scans finalize here in one
        # transaction; only malicious scans (which trigger triage) defer mark_done.
        scan_id = scan.id
        # Triage on suspicious too (not just malicious): lets the LLM rescue
        # rule-under-scored malware (suspicious→malicious escalation → alert + vault).
        do_triage = result.verdict in ("malicious", "suspicious")
        triage_root = None
        if do_triage:
            _triage_adapter = adapter_registry.get(ecosystem)
            _triage_kind = _triage_adapter.install_archive_kind if _triage_adapter else "sdist"
            for arc in archives:
                if arc.kind == _triage_kind:
                    triage_root = tmp_extract / arc.kind
                    break
            if triage_root is None and archives:
                triage_root = tmp_extract / archives[0].kind
        else:
            mark_done(s, row, token=claim_token)
    # ---- transaction 1 committed; no DB session is held past here ----

    final_verdict = result.verdict
    final_alert_tag = result.alert_tag

    if do_triage:
        from pkgward.llm import triage as llm_triage_mod
        from pkgward.notify import discord as discord_notify

        # LLM triage — the blocking HTTP call, run with NO session open.
        tri = None  # None => disabled or crashed (could not adjudicate)
        if llm_triage_mod.is_enabled() and triage_root is not None:
            try:
                log.info("llm_triage_start", rule_verdict=result.verdict,
                         score=result.score, n_findings=len(all_findings))
                tri = llm_triage_mod.triage(
                    pkg_name=name, pkg_version=version,
                    rule_verdict=result.verdict, findings=all_findings,
                    extracted_root=triage_root, ecosystem=ecosystem,
                )
                log.info("llm_triage_done", rule_verdict=result.verdict,
                         llm_verdict=tri.verdict, cost=tri.cost_usd,
                         latency_ms=tri.latency_ms)
            except Exception as e:
                log.warning("llm_triage_skipped", error=str(e))
                tri = None

        # Short transaction: persist LLM fields + verdict override + auto-watchlist.
        with sess.session_scope() as s:
            scan = s.get(Scan, scan_id)
            if scan is not None and tri is not None:
                scan.llm_model = tri.model
                scan.llm_verdict = tri.verdict
                scan.llm_confidence = tri.confidence
                scan.llm_reasoning = _strip_nul(
                    tri.reasoning
                    + (f"\n\nMISSING EVIDENCE: {tri.missing_evidence}" if tri.missing_evidence else "")
                )
                scan.llm_iocs = _strip_nul(tri.iocs)
                scan.llm_agrees_with_rules = tri.agrees_with_rules
                scan.llm_prompt_tokens = tri.prompt_tokens
                scan.llm_completion_tokens = tri.completion_tokens
                scan.llm_cost_usd = tri.cost_usd
                scan.llm_latency_ms = tri.latency_ms
                scan.llm_raw_response = _strip_nul(tri.raw_response)
                if (tri.verdict == "malicious"
                        and tri.confidence < llm_triage_mod.MALICIOUS_CONF_FLOOR
                        and result.verdict != "malicious"):
                    # An unsure "malicious" must not escalate past the rules: every
                    # observed FP escalation came below the floor, real malware
                    # convicts >= 0.95. Rule verdict stands; the raw LLM verdict is
                    # already persisted above for review.
                    log.info("llm_escalation_blocked_low_conf",
                             rule_verdict=result.verdict,
                             llm_confidence=tri.confidence)
                elif tri.verdict in ("malicious", "suspicious", "benign"):
                    scan.verdict = tri.verdict
                    final_verdict = tri.verdict
                elif tri.verdict == "inconclusive" and result.verdict != "malicious":
                    # "I can't tell from what I was shown." Downgrades only a WEAK rule
                    # verdict (yail-class: a lone typosquat/metadata flag the LLM must not
                    # escalate to malicious). A rule-malicious package is never softened —
                    # _enforce_no_downgrade already keeps chains/exact-intel at malicious.
                    scan.verdict = "inconclusive"
                    final_verdict = "inconclusive"
            # Auto-watchlist promotion — gated on a minimum-evidence bar (rule +
            # LLM agreement OR high-confidence LLM, backed by primary evidence),
            # NOT a bare LLM-malicious verdict. Closes the @zola_do FP cascade
            # where one soft IOC hit promoted a benign package to sentinel rank.
            _promote_ok, _promote_reason = _auto_watchlist_qualifies(
                result, tri, all_findings)
            if _promote_ok:
                try:
                    from pkgward import watchlist_auto
                    status = watchlist_auto.add_confirmed_malicious(
                        s, ecosystem, name, scan_id=scan_id,
                    )
                    if status:
                        log.info("watchlist_auto_outcome", ecosystem=ecosystem,
                                 name=name, status=status)
                except Exception as e:
                    log.warning("watchlist_auto_failed", ecosystem=ecosystem,
                                name=name, error=str(e))
                # Sibling-worm defense: watch the whole org scope so a worm's
                # spread to the org's *other* packages is caught within the wave.
                try:
                    from pkgward import scope_watchlist
                    sc = scope_watchlist.auto_watch_on_malicious(s, ecosystem, name)
                    if sc:
                        log.info("scope_watchlist_auto_outcome", ecosystem=ecosystem,
                                 name=name, scope=sc)
                except Exception as e:
                    log.warning("scope_watchlist_auto_failed", ecosystem=ecosystem,
                                name=name, error=str(e))
                # Campaign recognition: seed the implicated files' fingerprints so a
                # future package reusing the same/similar payload matches via
                # threat_intel (SHA-256 / ssdeep / TLSH) — even before the LLM.
                try:
                    from pkgward import threat_intel_auto
                    seeded = threat_intel_auto.seed_from_scan(s, scan_id, ecosystem, name)
                    if seeded:
                        log.info("threat_intel_autoseed_outcome", ecosystem=ecosystem,
                                 name=name, seeded=seeded)
                except Exception as e:
                    log.warning("threat_intel_autoseed_failed", ecosystem=ecosystem,
                                name=name, error=str(e))
            elif tri is not None and tri.verdict == "malicious":
                # LLM said malicious but the evidence bar wasn't met — alert still
                # fires (below), we just don't promote to the known-bad set.
                log.info("watchlist_auto_skipped", ecosystem=ecosystem, name=name,
                         reason=_promote_reason, rule_verdict=result.verdict,
                         llm_confidence=getattr(tri, "confidence", None))
            # Tag the LLM's adjudication state when it neither cleared nor confirmed.
            # needs_review only when inconclusive actually became the verdict (the soft,
            # non-rule-malicious case); a rule-malicious the LLM couldn't confirm still
            # alarms and is tagged llm_unverified below.
            if final_verdict == "inconclusive":
                if scan is not None and not scan.alert_tag:
                    scan.alert_tag = "needs_review"
                    final_alert_tag = "needs_review"
            elif not (tri is not None and tri.verdict in ("benign", "suspicious")):
                if ((tri is None or tri.verdict != "malicious")
                        and scan is not None and not scan.alert_tag):
                    scan.alert_tag = "llm_unverified"
                    final_alert_tag = "llm_unverified"

        # Fail OPEN: alert unless the LLM explicitly cleared it. Sent BEFORE the
        # final mark_done so a crash in this window re-scans (and re-alerts)
        # rather than losing the alert — the outcome this scanner must never have.
        llm_cleared = tri is not None and tri.verdict in ("benign", "suspicious")

        # Frozen-sample vault — collect only on a real malicious determination, never
        # on soft+soft strays:
        #   • the LLM says malicious (rules at malicious OR suspicious — the latter is
        #     the LLM-escalation case), OR
        #   • rules say malicious and the LLM was enabled but couldn't adjudicate (a
        #     transient miss — don't lose a real sample to an LLM hiccup; a globally
        #     DISABLED LLM is excluded so it can't blanket-vault rule-only FPs).
        rule_mal = result.verdict == "malicious"
        llm_mal = tri is not None and tri.verdict == "malicious"
        llm_transient_miss = tri is None and llm_triage_mod.is_enabled()
        vault_keep = llm_mal or (rule_mal and llm_transient_miss)
        if vault_keep and vault.is_enabled() and archives:
            try:
                preferred = _PREFERRED_ARCHIVE.get(ecosystem, "sdist")
                vault_arc = next((a for a in archives if a.kind == preferred), archives[0])
                scored_rules = [f.rule_id for f in all_findings if not _is_shadow_finding(f)]
                vault.archive_to_vault(
                    ecosystem=ecosystem, name=name, version=version,
                    archive_path=Path(vault_arc.path), archive_kind=vault_arc.kind,
                    verdict=result.verdict, score=result.score,
                    expect_rules=scored_rules,
                )
            except Exception as e:
                log.warning("vault_archive_skipped", error=str(e))

        # Alert on a malicious determination: rule-malicious unless the LLM cleared it
        # (fail-open), OR the LLM escalated a rule-suspicious package to malicious.
        # Rule-suspicious with no LLM-malicious (cleared / suspicious / didn't-run)
        # does NOT alert — suspicious stays quiet unless the LLM convicts it. An
        # LLM-malicious below the confidence floor doesn't escalate (mirrors the
        # verdict-override gate above); fail-open on rule_mal is unaffected.
        llm_confident_mal = (
            llm_mal and tri.confidence >= llm_triage_mod.MALICIOUS_CONF_FLOOR
        )
        should_alert = (rule_mal and not llm_cleared) or llm_confident_mal
        if should_alert and discord_notify.is_enabled():
            if tri is None or tri.verdict != "malicious":
                log.warning("alert_llm_unverified", rule_verdict=result.verdict,
                            score=result.score,
                            llm_verdict=(tri.verdict if tri is not None else "unavailable"))
            if tri is None:
                tri = llm_triage_mod.LLMTriageResult(
                    verdict="unverified", confidence=0.0,
                    reasoning="LLM triage unavailable (disabled or skipped)",
                    iocs=[], agrees_with_rules=None, model="n/a",
                    prompt_tokens=0, completion_tokens=0, cost_usd=0.0,
                    latency_ms=0, raw_response={},
                )
            try:
                from pkgward.enrich import downloads as _downloads
                _dl = _downloads.enrich(ecosystem, name)
            except Exception:
                _dl = None
            from pkgward.enrich import publisher as _publisher
            _pub = _publisher.from_scan(scan_id)
            discord_notify.send_alert(
                pkg_name=name, pkg_version=version, ecosystem=ecosystem,
                rule_verdict=result.verdict, rule_score=result.score,
                n_findings=len(all_findings), triage=tri, findings=all_findings,
                downloads_weekly=_dl, publisher=_pub,
            )
        elif final_verdict == "inconclusive" and discord_notify.is_enabled():
            # Needs-review ping: the LLM could not decide (a weak signal it refused to
            # escalate, or evidence it could not see). Surface it for a human look with
            # exactly what it was missing — a separate, lower-key alert, not the alarm.
            try:
                from pkgward.enrich import publisher as _publisher
                _pub = _publisher.from_scan(scan_id)
            except Exception:
                _pub = None
            discord_notify.send_review_alert(
                pkg_name=name, pkg_version=version, ecosystem=ecosystem,
                rule_verdict=result.verdict, rule_score=result.score,
                n_findings=len(all_findings), triage=tri, findings=all_findings,
                publisher=_pub,
            )

        # Finalize the queue row now that the alert has been handled.
        with sess.session_scope() as s:
            row = s.get(ScanQueue, queue_id)
            if row is not None:
                mark_done(s, row, token=claim_token)

        # THIRD sibling defense — same-MAINTAINER force-scan sweep (the same-name
        # watchlist_auto / same-org scope_watchlist promotions ran above inside the
        # short session). Gated on the same _promote_ok evidence bar but run HERE,
        # after the queue row is finalized and with NO DB session held: it reaches
        # out to the registry to enumerate the maintainer's catalog, then opens its
        # own fresh session for the correlation read + enqueues. It force-scans only
        # — never watchlists — so an FP trigger wastes scans, it cannot pollute.
        if _promote_ok:
            try:
                from pkgward import maintainer_pivot
                _piv = maintainer_pivot.sweep_on_malicious(
                    ecosystem, name, findings=all_findings, tri=tri)
                if _piv.get("action") not in (None, "disabled", "skip"):
                    log.info("maintainer_pivot_outcome", ecosystem=ecosystem,
                             name=name, outcome=_piv)
            except Exception as e:
                log.warning("maintainer_pivot_failed", ecosystem=ecosystem,
                            name=name, error=str(e))

    final_score = result.score

    # Rulehit counts in separate transaction — avoids row-lock deadlocks
    _bump_rulehits_deferred(all_findings)

    duration_s = round((datetime.now(timezone.utc) - started_at).total_seconds(), 1)
    log.info(
        "scan_done",
        verdict=final_verdict, score=final_score, n_findings=len(all_findings),
        alert_tag=final_alert_tag, duration_s=duration_s,
    )


def _stage_archive_from_vault(
    ecosystem: str, name: str, version: str, archive_kind: str,
) -> Optional[ArchivePath]:
    """Stage the exact vaulted bytes as a scan archive (replay path).

    Returns None if the package isn't vaulted. Used ONLY by the explicit ``replay``
    CLI — never the live firehose, which always fetches from the registry. Lets us
    re-run a known-bad sample whose registry version was yanked."""
    from pkgward import detonation_staging, vault

    res = vault.read_archive(ecosystem, name, version)
    if res is None:
        return None
    data, inner = res
    dest = detonation_staging.stage_bytes(data, inner, prefix="replay-")
    return ArchivePath(path=dest, kind=archive_kind, sha256=hashlib.sha256(data).hexdigest())


def _load_claimed(queue_id: int, claim_token: Optional[str]) -> Optional[tuple[str, str, str]]:
    with sess.session_scope() as s:
        row = s.get(ScanQueue, queue_id)
        if row is None or row.status != "claimed":
            return None
        if claim_token is not None and row.claim_token != claim_token:
            log.warning("claim_stolen", queue_id=queue_id)
            return None
        return row.ecosystem, row.name, row.version


def _mark_queue_failed(queue_id: int, error: str, claim_token: Optional[str]) -> None:
    with sess.session_scope() as s:
        row = s.get(ScanQueue, queue_id)
        if row is not None and row.status != "done":
            mark_failed(s, row, error, token=claim_token)


def _load_prev_hashes(ecosystem: str, name: str, version: str) -> dict[str, dict[str, FileInfo]]:
    with sess.session_scope() as s:
        return _get_prev_scan_hashes(s, ecosystem, name, version)


async def process_one(
    queue_id: int, claim_token: Optional[str] = None, *,
    replay_from_vault: bool = False,
) -> None:
    """Fetch, analyze, and persist scan results for a single queue item.

    Sessions are opened only for short DB bursts — never held across network I/O.

    ``replay_from_vault=True`` (the ``replay`` CLI only) sources the archive from the
    vault instead of the registry, so a yanked known-bad version still runs the full
    real pipeline (analyze→score→LLM→Discord). The live worker never sets it.

    Every DB burst on this coroutine's own path runs via ``asyncio.to_thread`` —
    on a remote-DB worker each query costs ~wire-RTT, and a sync session here
    freezes the event loop for every coroutine in the process (the 2026-06
    remote-worker ConnectTimeout storm).
    """
    claimed_row = await asyncio.to_thread(_load_claimed, queue_id, claim_token)
    if claimed_row is None:
        return
    ecosystem, name, version = claimed_row

    adapter = adapter_registry.get(ecosystem)
    if adapter is None:
        await asyncio.to_thread(
            _mark_queue_failed, queue_id,
            f"no_adapter_for_ecosystem:{ecosystem}", claim_token)
        return

    # Bind a short scan trace ID so every log line during this scan is
    # searchable with a single grep.  The worker already bound `w=<id>`.
    sid = uuid.uuid4().hex[:8]
    structlog.contextvars.bind_contextvars(
        sid=sid, ecosystem=ecosystem, pkg=f"{name}=={version}",
    )

    # --- Phase 1: Async I/O (no DB session open) ---
    safe_name = name.replace("/", "_")
    _staging = Path("/tmp/pkgward")
    _staging.mkdir(parents=True, exist_ok=True)
    tmp_extract = Path(tempfile.mkdtemp(prefix=f"x-{safe_name}-{version}-", dir=_staging))
    tmp_extract.chmod(0o755)
    archives: list[ArchivePath] = []
    metadata: dict = {}
    fetch_error: Optional[Exception] = None
    fetch_error_type: Optional[str] = None
    persist_started = False
    started_at = datetime.now(timezone.utc)
    log.info("scan_start")

    try:
        try:
            if replay_from_vault:
                arc = _stage_archive_from_vault(
                    ecosystem, name, version, adapter.install_archive_kind)
                if arc is None:
                    raise NoFilesError(f"not_vaulted:{ecosystem}/{name}@{version}")
                archives = [arc]
                metadata = {}
            else:
                fetched = await adapter.fetch(name, version)
                if hasattr(fetched, "archives"):
                    archives = fetched.archives
                    metadata = fetched.metadata or {}
                else:
                    archives = fetched
                    metadata = {}
        except NoFilesError as e:
            fetch_error = e
            fetch_error_type = "no_files"
        except IntegrityError as e:
            fetch_error = e
            fetch_error_type = "sha256_mismatch"

        all_findings: list[Finding] = []
        all_file_hashes: list[tuple[str, dict[str, FileInfo]]] = []
        sdist_files: list[str] = []
        wheel_files: list[str] = []

        if fetch_error is not None:
            if fetch_error_type == "sha256_mismatch":
                all_findings.append(Finding(
                    rule_id="fetch.sha256_mismatch", category="fetch", severity="critical",
                    confidence="high", file="", line=None, evidence=str(fetch_error),
                ))
            else:
                all_findings.append(Finding(
                    rule_id="fetch.no_release_files", category="fetch", severity="medium",
                    confidence="high", file="", line=None, evidence=str(fetch_error),
                ))
        else:
            # --- Phase 1.5: Fetch baseline file hashes (short DB burst) ---
            prev_hashes_by_kind: dict[str, dict[str, FileInfo]] = await asyncio.to_thread(
                _load_prev_hashes, ecosystem, name, version)

            # --- Phase 2: Analysis (CPU-bound, offloaded to thread) ---
            for arc in archives:
                sub = tmp_extract / arc.kind
                arc_size = arc.path.stat().st_size

                t0 = time.monotonic()
                log.info("extracting", kind=arc.kind,
                         size_mb=round(arc_size / (1024 * 1024), 1))
                current_info, norm_to_real, members, lite = await asyncio.to_thread(
                    _extract_and_hash, arc, sub,
                )
                t_extract = round(time.monotonic() - t0, 1)
                log.info("extracted", kind=arc.kind,
                         files=len(current_info), duration_s=t_extract)

                if arc.kind == "sdist":
                    sdist_files = members
                else:
                    wheel_files = members

                all_file_hashes.append((arc.kind, current_info))

                changed: set[str] | None = None
                prev_info = prev_hashes_by_kind.get(arc.kind, {})
                if prev_info:
                    changed = _find_changed_files(current_info, prev_info, norm_to_real)
                    if not changed:
                        log.info("no_code_changes", kind=arc.kind)
                        continue
                    log.info(
                        "code_diff", kind=arc.kind,
                        changed=len(changed), total=len(current_info),
                    )

                # npm-only deobfuscation pre-pass: webcrack unminifies / unpacks bundles
                # / reverses obfuscator.io into `.webcrack/` so the analyzers run on
                # readable code. Off the event loop, fail-soft, bounded; skipped on giant
                # packages. Its outputs join `changed` so the version-diff skip still
                # analyzes them.
                if ecosystem == "npm" and not lite:
                    try:
                        from pkgward.analyze.webcrack_deobf import deobfuscate_npm
                        wc_out = await asyncio.to_thread(deobfuscate_npm, sub)
                        if wc_out and changed is not None:
                            changed = changed | wc_out
                    except Exception as e:
                        log.warning("webcrack_pass_failed", error=str(e))

                t1 = time.monotonic()
                log.info("analyzing", kind=arc.kind)
                analyzer_findings = await run_static_analyzers(
                    sub, ecosystem=ecosystem, adapter=adapter, arc_kind=arc.kind,
                    changed=changed, current_info=current_info, prev_info=prev_info,
                    norm_to_real=norm_to_real, lite=lite,
                )
                t_analyze = round(time.monotonic() - t1, 1)
                all_findings.extend(analyzer_findings)
                log.info("analyzed", kind=arc.kind,
                         findings=len(analyzer_findings), duration_s=t_analyze)

        # --- Phase 3+4: Persist, detonate, triage (all sync, in thread) ---
        log.info("persisting", findings=len(all_findings),
                 hashes=sum(len(h) for _, h in all_file_hashes))

        def _persist_thread() -> None:
            # The thread owns the extract-tree cleanup from here. A worker-timeout
            # cancel stops only the coroutine — this thread keeps running into LLM
            # triage, and the coroutine's finally used to rmtree the tree out from
            # under it: triage then walked an empty dir, gathered NO source, and the
            # LLM adjudicated the findings blind (openprogram 0.5.0, scan 181813).
            try:
                _persist_and_finalize(
                    queue_id=queue_id,
                    claim_token=claim_token,
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    started_at=started_at,
                    metadata=metadata,
                    archives=archives,
                    tmp_extract=tmp_extract,
                    all_findings=all_findings,
                    all_file_hashes=all_file_hashes,
                    fetch_error=fetch_error,
                    fetch_error_type=fetch_error_type,
                    sdist_files=sdist_files,
                    wheel_files=wheel_files,
                )
            finally:
                _cleanup_extract(tmp_extract, archives)

        persist_started = True
        await asyncio.to_thread(_persist_thread)
    except Exception as e:
        err_type = type(e).__name__
        err_msg = str(e).split("\n")[0][:200]
        log.warning("pipeline_failed", error_type=err_type, error=err_msg)
        try:
            await asyncio.to_thread(_mark_queue_failed, queue_id, str(e)[:4000], claim_token)
        except Exception:
            log.exception("pipeline_fail_handler_error")
    finally:
        # Cleanup off the event loop: rmtree of a giant extracted tree (tens of
        # thousands of files) is recursive blocking I/O that freezes the loop for
        # minutes, stalling every other worker + the scheduler. Run in a thread —
        # but only while the coroutine still owns the tree; once the persist thread
        # has started it cleans up after itself (see _persist_thread).
        if not persist_started:
            await asyncio.to_thread(_cleanup_extract, tmp_extract, archives)
