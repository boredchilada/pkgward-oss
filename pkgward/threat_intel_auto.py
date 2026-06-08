# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auto-seed threat-intel fingerprints from confirmed-malicious scans.

**HARD-DISABLED (maintainer directive 2026-06-04).** ``is_enabled()`` returns
``False`` unconditionally and ignores the env flag, so NO auto-seeding happens:
``seed_from_scan`` / ``backfill`` early-return and seed nothing. Auto-seeding
self-perpetuated false positives (a benign-but-rule-tripping file got seeded, then
SHA-256-self-confirmed on every later release). Only the *matching* side stays live —
``threat_intel.check_file`` still matches against reviewed/promoted + baseline seeds,
and manual ``threatintel promote``/``remove`` still work. The rest of this docstring
describes the seeding design as it WOULD work if re-enabled (maintainer's call only).

The moat (when enabled): on a double-confirmed-malicious scan (rules *and* LLM agree),
the fingerprints (SHA-256 + ssdeep + TLSH) of its **implicated files** (the ones that
drew a high/critical finding — the loader, the payload) are inserted into the
``threat_intel_hash`` table with ``source="auto"``. ``threat_intel.check_file``
matches every future file against that table, so the next package reusing the same
(or a *similar* — ssdeep/TLSH) payload matches instantly, even before the LLM —
turning a one-off catch into campaign-wide recognition (e.g. the meoo-* /
rookie-security-test family that rotates package names + tweaks the C2 subdomain
but ships the same implant).

Naturally bounded: dedup is on SHA-256, so the same payload across many package
names collapses to one fingerprint. ``backfill`` replays scan history to seed all
historically confirmed-malicious payloads in one shot.
"""
from __future__ import annotations

import os
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pkgward.logging_setup import get_logger
from pkgward.store.models import (
    FileHash, Finding, Package, Scan, ThreatIntelHash, Version,
)

log = get_logger("threat_intel_auto")

# Basenames that are never seeded — common/benign files whose fingerprint would
# false-positive across unrelated packages.
_SKIP_BASENAMES = {
    "package.json", "package-lock.json", "readme", "readme.md", "license",
    "licence", "license.md", "notice", "changelog.md", "tsconfig.json",
    ".npmignore", ".gitignore", "yarn.lock", "pnpm-lock.yaml",
}
# Per-scan cap so one giant malicious package can't flood the fingerprint table.
_MAX_PER_SCAN = int(os.environ.get("PKGWARD_THREATINTEL_MAX_PER_SCAN", "25"))

# Compiled-binary / opaque file types we never fingerprint: TLSH on a Go/ELF/PE
# binary is dominated by shared runtime structure, so two *unrelated* binaries match
# at a loose distance — a known FP vector (a legit MCP package matched a seeded Go
# binary). We only fingerprint source/script text, where similarity means real reuse.
_BINARY_EXTS = {
    "so", "dll", "exe", "dylib", "bin", "o", "a", "node", "wasm", "pyc", "pyd",
    "class", "jar", "zip", "gz", "tgz", "whl", "png", "jpg", "jpeg", "gif", "ico",
    "woff", "woff2", "ttf", "pdf", "mp4", "mp3", "wasm",
}
# Files at/above this entropy are binary/packed/compressed — skip (see above).
_BINARY_ENTROPY = 7.2


def is_enabled() -> bool:
    # HARD-DISABLED (maintainer directive 2026-06-04). Auto-seeding fingerprints from
    # double-confirmed scans self-perpetuates false positives: a benign-but-rule-tripping
    # file (e.g. cobra's `init()`->`go env GOPATH` helpers.go) gets seeded, then sha256-
    # self-confirms on every later release and case-variant, flooding alerts. The env flag
    # is intentionally IGNORED so it can never be turned back on by accident. The *matching*
    # side (check_file against reviewed/promoted + baseline seeds) is unaffected; only
    # auto-*seeding* is dead. Manual `threatintel promote`/`remove` still work.
    return False


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def seed_from_scan(
    session: Session, scan_id: int, ecosystem: str, name: str,
) -> int:
    """Seed fingerprints of *scan_id*'s implicated files. Returns count inserted.

    Implicated = files that drew a high/critical finding (the malicious files —
    not the package's benign/vendored files, whose fingerprints would FP)."""
    if not is_enabled():
        return 0
    # Never fingerprint from a blocklisted name (operator FP exit ramp — reuses the
    # watchlist-auto blocklist so a known FP can't poison the threat-intel moat).
    try:
        from pkgward.watchlist_auto import _blocklist
        if name.lower() in _blocklist().get(ecosystem, set()):
            return 0
    except Exception:
        pass
    bad_files = session.scalars(
        select(Finding.file).where(
            Finding.scan_id == scan_id,
            Finding.severity.in_(("high", "critical")),
            Finding.file.isnot(None),
            Finding.file != "",
        )
    ).all()
    bad_basenames = {_basename(f) for f in bad_files if f}
    bad_basenames -= _SKIP_BASENAMES
    if not bad_basenames:
        return 0

    seeded = 0
    for fh in session.scalars(select(FileHash).where(FileHash.scan_id == scan_id)).all():
        if seeded >= _MAX_PER_SCAN:
            break
        base = _basename(fh.file_path)
        if base.lower() in _SKIP_BASENAMES or base not in bad_basenames:
            continue
        if not fh.sha256:
            continue
        # Skip compiled binaries / opaque blobs (TLSH-FP-prone): no extension,
        # known binary extension, or high entropy.
        ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
        if not ext or ext in _BINARY_EXTS:
            continue
        if fh.entropy is not None and fh.entropy >= _BINARY_ENTROPY:
            continue
        # dedup on sha256 (same payload across names -> one fingerprint)
        if session.scalar(
            select(ThreatIntelHash.id).where(ThreatIntelHash.sha256 == fh.sha256).limit(1)
        ):
            continue
        session.add(ThreatIntelHash(
            sha256=fh.sha256,
            ssdeep=fh.ssdeep or None,
            tlsh=fh.tlsh or None,
            campaign=f"auto:{ecosystem}:{name}"[:128],
            label="malicious",
            # scope fuzzy matches to same-extension files (ssdeep>=70/TLSH<=120 is
            # the real FP guard; the glob keeps a JS fingerprint off .py, etc.)
            file_pattern=(f"*.{ext}" if ext else None),
            description=f"auto-seeded from confirmed-malicious {ecosystem} {name} ({base})"[:500],
            source="auto",
        ))
        seeded += 1
    if seeded:
        session.flush()
        log.info("threat_intel_autoseed", ecosystem=ecosystem, name=name,
                 scan_id=scan_id, seeded=seeded)
    return seeded


def backfill(session: Session, limit: Optional[int] = None) -> tuple[int, int]:
    """Seed fingerprints from all double-confirmed-malicious scans in history.

    Returns ``(scans_processed, fingerprints_seeded)``. Idempotent (sha256 dedup)."""
    rows = session.execute(
        select(Scan.id, Package.ecosystem, Package.name)
        .join(Version, Scan.version_id == Version.id)
        .join(Package, Version.package_id == Package.id)
        .where(Scan.verdict == "malicious", Scan.llm_verdict == "malicious")
        .order_by(Scan.id.desc())
    ).all()
    if limit:
        rows = rows[:limit]
    scans = 0
    total = 0
    for scan_id, ecosystem, name in rows:
        n = seed_from_scan(session, scan_id, ecosystem, name)
        scans += 1
        total += n
    return scans, total


def _iter_inner_files(archive_name: str, blob: bytes):
    """Yield each member's bytes from an inner package archive (tgz/tar/zip/whl)."""
    import io
    import tarfile
    import zipfile as _zip
    bio = io.BytesIO(blob)
    try:
        if archive_name.endswith((".tgz", ".tar.gz", ".tar")):
            with tarfile.open(fileobj=bio) as tf:
                for m in tf.getmembers():
                    if m.isfile():
                        f = tf.extractfile(m)
                        if f is not None:
                            yield f.read()
        elif archive_name.endswith((".zip", ".whl", ".egg")):
            with _zip.ZipFile(bio) as zf:
                for n in zf.namelist():
                    if not n.endswith("/"):
                        yield zf.read(n)
    except Exception:
        return


def backfill_tlsh_from_vault(session: Session) -> tuple[int, int]:
    """Fill in missing TLSH on auto-seeded fingerprints by re-hashing the original
    archives preserved in the vault (the backfill from history had only ssdeep,
    since old FileHash rows predate the tlsh column). The SHA-256 already on the
    fingerprint is the authoritative link. Returns (archives_read, rows_updated)."""
    import hashlib
    import zipfile as _zip

    from pkgward.util import capabilities as caps
    from pkgward.vault import VAULT_PASSWORD, vault_dir

    if not caps.HAS_TLSH:
        log.warning("threat_intel_tlsh_backfill_skipped", reason="tlsh unavailable")
        return (0, 0)
    vdir = vault_dir()
    if vdir is None:
        return (0, 0)

    rows = session.scalars(
        select(ThreatIntelHash).where(
            ThreatIntelHash.source == "auto",
            ThreatIntelHash.tlsh.is_(None),
            ThreatIntelHash.sha256.isnot(None),
        )
    ).all()
    by_sha = {r.sha256: r for r in rows}
    if not by_sha:
        return (0, 0)
    # filename pre-filter (avoid extracting unrelated archives); sha256 match below
    # is what actually links a file to a fingerprint, so this only bounds work.
    tokens = {r.campaign.split(":")[-1].replace("/", "_").replace("@", "") for r in rows}

    archives = 0
    updated = 0
    for zp in sorted(vdir.glob("*.zip")):
        if not any(tok and tok in zp.name for tok in tokens):
            continue
        try:
            with _zip.ZipFile(zp) as zf:
                for inner in zf.namelist():
                    blob = zf.read(inner, pwd=VAULT_PASSWORD)
                    for content in _iter_inner_files(inner, blob):
                        sha = hashlib.sha256(content).hexdigest()
                        row = by_sha.get(sha)
                        if row is None or row.tlsh is not None or len(content) < 64:
                            continue
                        try:
                            tl = caps.tlsh.hash(content)
                        except Exception:
                            continue
                        if tl and tl not in ("TNULL", ""):
                            row.tlsh = tl
                            updated += 1
            archives += 1
        except Exception:
            continue
    if updated:
        session.flush()
        log.info("threat_intel_tlsh_backfilled", archives=archives, updated=updated)
    return archives, updated


def candidates(session: Session) -> list[tuple[str, int]]:
    """Auto-seeded campaigns awaiting review, as (campaign, fingerprint_count),
    most fingerprints first. These match on exact SHA-256 only until promoted."""
    rows = session.execute(
        select(ThreatIntelHash.campaign, func.count())
        .where(ThreatIntelHash.source == "auto")
        .group_by(ThreatIntelHash.campaign)
        .order_by(func.count().desc())
    ).all()
    return [(c, int(n)) for c, n in rows]


def promote(session: Session, campaign: str) -> int:
    """Promote an auto-seeded campaign to fuzzy matching (operator confirmed it's a
    real malicious family). Promoted fingerprints match via ssdeep/TLSH at a tight
    threshold; auto (unpromoted) ones stay exact-SHA-256-only. Returns count promoted.
    Accepts the full campaign string or a bare package name (auto:<eco>:<name>)."""
    q = select(ThreatIntelHash).where(ThreatIntelHash.source == "auto")
    if campaign.startswith("auto:"):
        q = q.where(ThreatIntelHash.campaign == campaign)
    else:
        q = q.where(ThreatIntelHash.campaign.like(f"auto:%:{campaign}"))
    rows = session.scalars(q).all()
    for r in rows:
        r.source = "promoted"
    if rows:
        session.flush()
        log.info("threat_intel_promoted", campaign=campaign, count=len(rows))
    return len(rows)


def remove(session: Session, campaign: str) -> int:
    """Delete a campaign's auto/promoted fingerprints — the FP exit-ramp for the
    moat. Use when a seed turns out to be a false positive (e.g. a since-fixed
    over-aggressive rule auto-seeded a benign package, and the fingerprint now
    self-confirms on every rescan). Accepts the full campaign string or a bare
    package name (auto:<eco>:<name>). Returns the number of fingerprints removed.

    This does NOT make detection blind: the package is re-evaluated by the current
    rules on its next scan. To stop a name from being re-seeded, add it to
    ``WATCHLIST_AUTO_BLOCKLIST`` (the seed path honors that blocklist)."""
    q = select(ThreatIntelHash).where(
        ThreatIntelHash.source.in_(("auto", "promoted")))
    if campaign.startswith("auto:"):
        q = q.where(ThreatIntelHash.campaign == campaign)
    else:
        q = q.where(ThreatIntelHash.campaign.like(f"auto:%:{campaign}"))
    rows = session.scalars(q).all()
    for r in rows:
        session.delete(r)
    if rows:
        session.flush()
        log.info("threat_intel_removed", campaign=campaign, count=len(rows))
    return len(rows)


def stats(session: Session) -> dict:
    def _n(*where):
        return int(session.scalar(select(func.count()).select_from(ThreatIntelHash).where(*where)) or 0)
    return {
        "auto": _n(ThreatIntelHash.source == "auto"),          # exact-sha256 only
        "promoted": _n(ThreatIntelHash.source == "promoted"),  # fuzzy-enabled
        "total": int(session.scalar(select(func.count()).select_from(ThreatIntelHash)) or 0),
    }
