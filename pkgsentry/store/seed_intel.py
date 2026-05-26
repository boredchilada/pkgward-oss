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


def seed() -> int:
    eng = get_engine()
    Base.metadata.create_all(eng, tables=[ThreatIntelHash.__table__])
    intel.load()
    entries = intel.current().hash_seeds

    added = 0
    with session_scope() as session:
        for entry in entries:
            sha256 = entry.get("sha256")
            if not sha256:
                continue
            exists = session.scalars(
                select(ThreatIntelHash).where(ThreatIntelHash.sha256 == sha256)
            ).first()
            if exists:
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
    return added


if __name__ == "__main__":
    n = seed()
    print(f"Seeded {n} threat-intel fingerprints into threat_intel_hash")
