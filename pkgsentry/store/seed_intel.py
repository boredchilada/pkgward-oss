# SPDX-License-Identifier: AGPL-3.0-or-later
"""Seed threat_intel_hash table from the loaded intel pack.

Reads `intel.current().hash_seeds` (populated from
`hashes/known_malicious.jsonl` in the baseline + private overlay packs)
and upserts each entry into the `threat_intel_hash` table.

Run:  python -m pkgsentry.store.seed_intel
"""
from __future__ import annotations

from sqlalchemy import select

from pkgsentry import intel
from pkgsentry.store.models import Base, ThreatIntelHash
from pkgsentry.store.session import get_engine, session_scope


_BACKFILL_FIELDS = ("ssdeep", "tlsh", "campaign", "label", "file_pattern", "description", "source")


def seed() -> tuple[int, int]:
    """Upsert the loaded hash seeds into ``threat_intel_hash``.

    Returns ``(added, updated)``. Existing rows (matched by sha256) get any
    missing field backfilled — so a fingerprint seeded before py-tlsh built
    (``tlsh`` null) gains its TLSH on re-seed — without clobbering present values.
    """
    eng = get_engine()
    Base.metadata.create_all(eng, tables=[ThreatIntelHash.__table__])
    intel.load()
    entries = intel.current().hash_seeds

    added = 0
    updated = 0
    with session_scope() as session:
        for entry in entries:
            sha256 = entry.get("sha256")
            if not sha256:
                continue
            existing = session.scalars(
                select(ThreatIntelHash).where(ThreatIntelHash.sha256 == sha256)
            ).first()
            if existing is not None:
                changed = False
                for field in _BACKFILL_FIELDS:
                    val = entry.get(field)
                    if val and not getattr(existing, field):
                        setattr(existing, field, val)
                        changed = True
                if changed:
                    updated += 1
                continue
            session.add(ThreatIntelHash(
                sha256=sha256,
                ssdeep=entry.get("ssdeep"),
                tlsh=entry.get("tlsh"),
                campaign=entry.get("campaign"),
                label=entry.get("label", "malicious"),
                file_pattern=entry.get("file_pattern"),
                description=entry.get("description"),
                source=entry.get("source"),
            ))
            added += 1
        session.commit()
    return added, updated


if __name__ == "__main__":
    added, updated = seed()
    print(f"Threat-intel fingerprints: {added} added, {updated} updated in threat_intel_hash")
