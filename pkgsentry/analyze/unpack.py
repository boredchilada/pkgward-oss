# SPDX-License-Identifier: AGPL-3.0-or-later
"""Best-effort static unpacking of run-time-packed executables.

A packed binary is opaque to every static analyzer *and* to the LLM (which reads
source, and can't read a compressed stub). So packed payloads are a blind spot:
real packed malware hides its IOCs, and benign packed binaries (e.g. the eqr
crate's UPX-packed Rust CRC16 util) can't be cleared. We close that blind spot by
**detecting the packer and attempting to unpack what is safely unpackable —
statically, without ever executing the binary.**

Scope (deliberate): UPX only. `upx -d` is pure decompression (no execution) and
UPX dominates Linux/supply-chain malware. Commercial protectors (Themida,
VMProtect, Enigma, ...) have *no* static unpacker — they can only be unpacked by
running the binary under a debugger (dynamic), which means executing the malware;
that belongs in a sandbox, not here. Those are detected and flagged by
`analyze/binary.py` instead (kind="commercial" → critical).

Recovered payloads are written back into the extraction tree as
``<name>.upx_unpacked`` so every downstream analyzer (IOCs, YARA, opengrep,
entropy, threat-intel hashing) sees the real payload.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from pkgsentry.analyze.binary import (
    UNPACKED_SUFFIX,
    _MAGIC_BYTES,
    _PACKER_SCAN_BYTES,
    _detect_packer,
)
from pkgsentry.logging_setup import get_logger

log = get_logger("analyze.unpack")

UPX_BIN = os.environ.get("PKGSENTRY_UPX_BIN", "upx")
UNPACK_TIMEOUT_SEC = int(os.environ.get("PKGSENTRY_UNPACK_TIMEOUT", "60"))
# Cap the recovered size — a tiny packed file can decompress to gigabytes
# (decompression bomb); skip anything that unpacks beyond this.
MAX_UNPACKED_MB = int(os.environ.get("PKGSENTRY_UNPACK_MAX_MB", "100"))
# Cap how many binaries we try per package (defence against many-packed-files DoS).
MAX_UNPACK_FILES = int(os.environ.get("PKGSENTRY_UNPACK_MAX_FILES", "25"))


def upx_available() -> bool:
    return shutil.which(UPX_BIN) is not None


def unpack_packed_executables(root: Path) -> list[tuple[str, str]]:
    """Walk *root*, `upx -d` each UPX-packed executable into a ``.upx_unpacked``
    sibling. Returns ``[(rel_path, status), ...]`` for logging. Never executes a
    payload; never raises into the caller (best-effort)."""
    if not upx_available():
        return []
    results: list[tuple[str, str]] = []
    attempts = 0
    for p in sorted(root.rglob("*")):
        if attempts >= MAX_UNPACK_FILES:
            break
        if not p.is_file() or p.name.endswith(UNPACKED_SUFFIX):
            continue
        try:
            with p.open("rb") as fh:
                head = fh.read(_PACKER_SCAN_BYTES)
        except OSError:
            continue
        if not any(head.startswith(m) for m in _MAGIC_BYTES):
            continue
        det = _detect_packer(head)
        if not det or det[1] != "upx":
            continue
        rel = p.relative_to(root).as_posix()
        dest = p.with_name(p.name + UNPACKED_SUFFIX)
        if dest.exists():
            continue
        attempts += 1
        tmp = p.with_name(p.name + ".upxtmp")
        try:
            shutil.copy2(p, tmp)
            # `upx -d` decompresses in place; `-q` quiet. No execution involved.
            proc = subprocess.run(
                [UPX_BIN, "-d", "-q", str(tmp)],
                capture_output=True, timeout=UNPACK_TIMEOUT_SEC,
            )
            if (proc.returncode == 0 and tmp.exists()
                    and tmp.stat().st_size <= MAX_UNPACKED_MB * 1024 * 1024):
                tmp.rename(dest)
                results.append((rel, "unpacked"))
            else:
                tmp.unlink(missing_ok=True)
                status = "too_large" if (tmp.exists() and proc.returncode == 0) else "unpack_failed"
                results.append((rel, status))
        except subprocess.TimeoutExpired:
            tmp.unlink(missing_ok=True)
            results.append((rel, "timeout"))
        except Exception as e:  # noqa: BLE001 — best-effort, never break the scan
            tmp.unlink(missing_ok=True)
            results.append((rel, f"error:{type(e).__name__}"))
    return results
