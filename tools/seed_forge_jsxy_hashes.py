#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Seed threat-intel hash entries for every published version of `forge-jsxy`.

For each version on npm:
  * the full tarball — sha256 (exact-match tier; catches the same .tgz being
    re-uploaded or bundled into another package).
  * every distinct RAT-bearing file inside — sha256 + ssdeep + TLSH
    (exact + fuzzy tiers; survives reformatting / minor edits).

Output: appends JSONL entries to ``intel/private/hashes/known_malicious.jsonl``.
De-dupes against entries already present in the file (by sha256).

Run once after the YARA family rule is in place. Run again only when new
versions appear.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

import httpx

try:
    import ppdeep
except ImportError:
    ppdeep = None  # type: ignore[assignment]
try:
    import tlsh
except ImportError:
    tlsh = None  # type: ignore[assignment]

PACKAGE = "forge-jsxy"
# Resolve the operator's intel overlay directory: $PKGSENTRY_INTEL_PATH if set
# (the same env var the runtime uses to load the overlay), else a relative
# `./intel/private` so the script works when run from the repo root.
_INTEL_DIR = Path(os.environ.get("PKGSENTRY_INTEL_PATH", "intel/private"))
JSONL_PATH = _INTEL_DIR / "hashes" / "known_malicious.jsonl"
CAMPAIGN = "forge_jsxy_rat_family"
LABEL = "malicious"
SOURCE = "pkgsentry-seeded-2026-05-28"

# Per-file pattern (the path-glob the threat-intel matcher tests against the
# scanned file's basename). Generous patterns — the operator can swap dist/
# layout but the RAT files stay JS.
RAT_PATHS_PATTERN = {
    "package/dist/fsProtocol.js": "*fsProtocol.js",
    "package/dist/fsMessages.js": "*fsMessages.js",
    "package/dist/extensionDbHfUpload.js": "*extensionDbHfUpload.js",
    "package/dist/discordAgentScreenshot.js": "*discordAgentScreenshot.js",
    "package/dist/secretScan/agentStartupAudit.js": "*agentStartupAudit.js",
    "package/dist/autostart/darwin.js": "*autostart/darwin.js",
    "package/dist/autostart/linux.js": "*autostart/linux.js",
    "package/dist/autostart/windows.js": "*autostart/windows.js",
    "package/scripts/postinstall-agent.mjs": "*postinstall-agent.mjs",
    "package/scripts/postinstall-bootstrap.mjs": "*postinstall-bootstrap.mjs",
    "package/scripts/discord-live-probe.mjs": "*discord-live-probe.mjs",
    "package/scripts/queue-reconnect-agent-restarts.mjs": "*queue-reconnect-agent-restarts.mjs",
    "package/scripts/postinstall-clipboard-event.mjs": "*postinstall-clipboard-event.mjs",
    "package/scripts/postinstall-durable-materialize.mjs": "*postinstall-durable-materialize.mjs",
}


def existing_sha256s() -> set[str]:
    if not JSONL_PATH.exists():
        return set()
    out: set[str] = set()
    for line in JSONL_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.add(json.loads(line)["sha256"])
        except Exception:
            continue
    return out


def fetch_versions() -> list[str]:
    meta = httpx.get(f"https://registry.npmjs.org/{PACKAGE}", timeout=20).json()
    return sorted(meta.get("versions", {}).keys())


def fetch_tgz(v: str) -> bytes:
    url = f"https://registry.npmjs.org/{PACKAGE}/-/{PACKAGE}-{v}.tgz"
    return httpx.get(url, timeout=30).content


def make_entry(*, sha: str, body: bytes, file_pattern: str, version: str,
               kind: str) -> dict:
    e: dict = {
        "sha256": sha,
        "file_pattern": file_pattern,
        "campaign": CAMPAIGN,
        "label": LABEL,
        "description": f"{kind} from {PACKAGE}@{version}",
        "source": SOURCE,
    }
    if ppdeep is not None and len(body) >= 64:
        try:
            e["ssdeep"] = ppdeep.hash(body)
        except Exception:
            pass
    if tlsh is not None and len(body) >= 256:
        try:
            h = tlsh.hash(body)
            if h and h != "TNULL":
                e["tlsh"] = h
        except Exception:
            pass
    return e


def main() -> int:
    if not JSONL_PATH.exists():
        print(f"ERROR: JSONL path not found: {JSONL_PATH}", file=sys.stderr)
        return 2
    if ppdeep is None:
        print("WARN: ppdeep not available — ssdeep tier will be empty.", file=sys.stderr)
    if tlsh is None:
        print("WARN: tlsh not available — TLSH tier will be empty.", file=sys.stderr)

    already = existing_sha256s()
    new_entries: list[dict] = []
    seen_in_run: set[str] = set()

    versions = fetch_versions()
    print(f"versions: {len(versions)}")

    for v in versions:
        try:
            tgz = fetch_tgz(v)
        except Exception as e:
            print(f"  {v}: fetch error: {e}", file=sys.stderr)
            continue
        tgz_sha = hashlib.sha256(tgz).hexdigest()
        if tgz_sha not in already and tgz_sha not in seen_in_run:
            new_entries.append(make_entry(
                sha=tgz_sha, body=tgz, file_pattern="*.tgz",
                version=v, kind="tarball",
            ))
            seen_in_run.add(tgz_sha)

        try:
            tf = tarfile.open(fileobj=io.BytesIO(tgz))
        except Exception as e:
            print(f"  {v}: tar open error: {e}", file=sys.stderr)
            continue

        for m in tf.getmembers():
            if not m.isfile() or m.name not in RAT_PATHS_PATTERN:
                continue
            try:
                body = tf.extractfile(m).read()
            except Exception:
                continue
            sha = hashlib.sha256(body).hexdigest()
            if sha in already or sha in seen_in_run:
                continue
            pattern = RAT_PATHS_PATTERN[m.name]
            new_entries.append(make_entry(
                sha=sha, body=body, file_pattern=pattern,
                version=v, kind=m.name.replace("package/", ""),
            ))
            seen_in_run.add(sha)

    if not new_entries:
        print("no new entries — JSONL already up-to-date.")
        return 0

    with JSONL_PATH.open("a", encoding="utf-8") as f:
        for e in new_entries:
            f.write(json.dumps(e) + "\n")
    print(f"appended {len(new_entries)} entries to {JSONL_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
