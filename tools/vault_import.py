#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Manually import a package archive into the frozen-sample vault.

Backfills the vault with past catches (e.g. crates yanked after disclosure) or
any archive you want preserved as a known-bad regression anchor. The archive is
stored inert (ZipCrypto, pw `infected`) + a TOML manifest, exactly like the
pipeline's auto-archive path.

Requires PKGSENTRY_VAULT_PATH to point at the (private) vault directory.

Usage:
    # Fetch from the registry and store:
    python tools/vault_import.py crates sui-move-build-helper@0.1.0 \
        --verdict malicious --expect crates.build_rs_net_exec_chain

    # Store a local archive you already have:
    python tools/vault_import.py pypi evil-pkg@1.0.0 \
        --archive /path/to/evil-pkg-1.0.0.tar.gz --kind sdist
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def _parse_pkg(spec: str) -> tuple[str, str]:
    if "@" not in spec:
        sys.exit("package must be NAME@VERSION (e.g. sui-move-build-helper@0.1.0)")
    name, version = spec.rsplit("@", 1)
    return name, version


async def _fetch_archive(ecosystem: str, name: str, version: str, kind: str | None):
    import pkgsentry.ecosystems  # noqa: F401  (populate adapter_registry)
    from pkgsentry.adapter import adapter_registry

    adapter = adapter_registry.get(ecosystem)
    if adapter is None:
        sys.exit(f"unknown ecosystem {ecosystem!r}; known: {sorted(adapter_registry)}")
    result = await adapter.fetch(name, version)
    if not result.archives:
        sys.exit(f"no archives returned for {ecosystem}:{name}@{version}")
    want = kind or adapter.install_archive_kind
    arc = next((a for a in result.archives if a.kind == want), result.archives[0])
    return arc.path, arc.kind


def main() -> None:
    ap = argparse.ArgumentParser(description="Import a package archive into the vault.")
    ap.add_argument("ecosystem", choices=("pypi", "crates", "gomod", "npm"))
    ap.add_argument("package", help="NAME@VERSION")
    ap.add_argument("--archive", type=Path, help="local archive file (skip fetching)")
    ap.add_argument("--kind", help="archive kind (default: ecosystem install kind)")
    ap.add_argument("--verdict", default="malicious",
                    choices=("malicious", "suspicious"))
    ap.add_argument("--score", type=int, default=0)
    ap.add_argument("--expect", default="",
                    help="comma-separated rule_ids to pin in the manifest")
    ap.add_argument("--registry-url", default=None)
    args = ap.parse_args()

    from pkgsentry import intel, vault
    intel.load()
    if not vault.is_enabled():
        sys.exit("PKGSENTRY_VAULT_PATH is not set — nothing to import into.")

    name, version = _parse_pkg(args.package)

    if args.archive:
        archive_path, kind = args.archive, (args.kind or "sdist")
        if not archive_path.exists():
            sys.exit(f"archive not found: {archive_path}")
    else:
        archive_path, kind = asyncio.run(
            _fetch_archive(args.ecosystem, name, version, args.kind)
        )

    expect = [r.strip() for r in args.expect.split(",") if r.strip()]
    stored = vault.archive_to_vault(
        ecosystem=args.ecosystem, name=name, version=version,
        archive_path=archive_path, archive_kind=kind,
        verdict=args.verdict, score=args.score, expect_rules=expect,
        registry_url=args.registry_url,
    )
    if stored is None:
        sys.exit("vault write failed (see log).")
    print(f"stored: {stored}")
    print(f"manifest: {stored.with_name(stored.stem + '.manifest.toml')}")


if __name__ == "__main__":
    main()
