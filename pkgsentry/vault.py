# SPDX-License-Identifier: AGPL-3.0-or-later
"""Frozen malicious-sample vault.

Preserves the *original, unmodified* archive of a package we flagged malicious,
before the registry yanks it. The artifact is stored **inert** — wrapped in a
password-protected (ZipCrypto, pw ``infected``) zip so it can't be accidentally
installed/built — alongside a plaintext TOML manifest of provenance.

The vault is a private operator asset: enabled only when ``$PKGSENTRY_VAULT_PATH``
is set (a no-op otherwise), and never shipped in the public tree. The regression
harness reads vault entries back with stdlib ``zipfile`` (``pwd=``) and only ever
*statically* analyzes them — it never executes/detonates them.

ZipCrypto is implemented in pure Python on the write side because the scanner
image ships neither the ``zip`` CLI nor ``pyzipper``; stdlib ``zipfile`` handles
the read side natively. ZipCrypto is weak by design — it is an anti-footgun /
anti-autoscanner wrapper, not real confidentiality. The protection that matters
is that the vault directory itself is private.
"""
from __future__ import annotations

import hashlib
import os
import struct
import time
import zlib
from pathlib import Path
from typing import Optional, Sequence

from pkgsentry.logging_setup import get_logger

log = get_logger("vault")

VAULT_PASSWORD = b"infected"

# --- ZipCrypto (traditional PKWARE) ----------------------------------------

_CRC_TABLE = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC_TABLE[_i] = _c


def _crc32_byte(crc: int, b: int) -> int:
    return (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]


class _ZipEncrypter:
    def __init__(self, password: bytes) -> None:
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in password:
            self._update(b)

    def _update(self, b: int) -> None:
        self.k0 = _crc32_byte(self.k0, b)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc32_byte(self.k2, (self.k1 >> 24) & 0xFF)

    def _stream_byte(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, p in enumerate(data):
            out[i] = p ^ self._stream_byte()
            self._update(p)  # keys advance on the plaintext byte
        return bytes(out)


def _encrypt_entry(data: bytes, password: bytes, crc: int) -> bytes:
    """12-byte encryption header (last byte = CRC high byte) + ciphertext."""
    header = bytearray(os.urandom(12))
    header[11] = (crc >> 24) & 0xFF
    enc = _ZipEncrypter(password)
    return enc.encrypt(bytes(header) + data)


def write_encrypted_zip(zip_path: Path, arcname: str, data: bytes,
                        password: bytes = VAULT_PASSWORD) -> None:
    """Write a single STORED, ZipCrypto-encrypted entry. Readable by stdlib
    ``zipfile.ZipFile(...).read(name, pwd=password)``."""
    crc = zlib.crc32(data) & 0xFFFFFFFF
    blob = _encrypt_entry(data, password, crc)
    comp_size, uncomp_size = len(blob), len(data)
    name = arcname.encode("utf-8")
    dt = time.localtime()
    dos_time = (dt.tm_hour << 11) | (dt.tm_min << 5) | (dt.tm_sec // 2)
    dos_date = ((dt.tm_year - 1980) << 9) | (dt.tm_mon << 5) | dt.tm_mday
    flags = 0x0001  # bit 0: encrypted

    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flags, 0, dos_time, dos_date,
        crc, comp_size, uncomp_size, len(name), 0,
    ) + name
    offset = 0
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, 0, dos_time, dos_date,
        crc, comp_size, uncomp_size, len(name), 0, 0, 0, 0, 0, offset,
    ) + name
    cd_offset = len(local) + len(blob)
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), cd_offset, 0,
    )
    with zip_path.open("wb") as fh:
        fh.write(local)
        fh.write(blob)
        fh.write(central)
        fh.write(eocd)


# --- Vault API --------------------------------------------------------------

def vault_dir() -> Optional[Path]:
    p = os.environ.get("PKGSENTRY_VAULT_PATH", "").strip()
    return Path(p) if p else None


def is_enabled() -> bool:
    return vault_dir() is not None


def _safe_stem(ecosystem: str, name: str, version: str) -> str:
    raw = f"{ecosystem}__{name}__{version}"
    return "".join(c if (c.isalnum() or c in "._-") else "_" for c in raw)


def _manifest_toml(*, ecosystem: str, name: str, version: str, sha256: str,
                   verdict: str, score: int, expect_rules: Sequence[str],
                   archive_kind: str, registry_url: Optional[str]) -> str:
    rules = ", ".join(f'"{r}"' for r in sorted(set(expect_rules)))
    lines = [
        f'ecosystem = "{ecosystem}"',
        f'name = "{name}"',
        f'version = "{version}"',
        'label = "bad"',
        f'expected_verdict = "{verdict}"',
        f"expect_rules = [{rules}]",
        f'sha256 = "{sha256}"',
        f'archive_kind = "{archive_kind}"',
        f"score = {score}",
        f'captured_at = "{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}"',
        'provenance = "frozen_sample"',
    ]
    if registry_url:
        lines.append(f'registry_url = "{registry_url}"')
    return "\n".join(lines) + "\n"


def archive_to_vault(*, ecosystem: str, name: str, version: str,
                     archive_path: Path, archive_kind: str, verdict: str,
                     score: int, expect_rules: Sequence[str] = (),
                     registry_url: Optional[str] = None) -> Optional[Path]:
    """Preserve a flagged archive + manifest into the vault. No-op if the vault
    is disabled. Returns the path to the stored zip, or None."""
    vdir = vault_dir()
    if vdir is None:
        return None
    try:
        data = Path(archive_path).read_bytes()
    except Exception as e:
        log.warning("vault_read_failed", error=str(e), archive=str(archive_path))
        return None
    sha256 = hashlib.sha256(data).hexdigest()
    stem = f"{_safe_stem(ecosystem, name, version)}__{sha256[:12]}"
    try:
        vdir.mkdir(parents=True, exist_ok=True)
        zip_path = vdir / f"{stem}.zip"
        if zip_path.exists():
            log.info("vault_already_present", stem=stem)
            return zip_path
        inner_name = Path(archive_path).name
        write_encrypted_zip(zip_path, inner_name, data)
        manifest = _manifest_toml(
            ecosystem=ecosystem, name=name, version=version, sha256=sha256,
            verdict=verdict, score=score, expect_rules=expect_rules,
            archive_kind=archive_kind, registry_url=registry_url,
        )
        (vdir / f"{stem}.manifest.toml").write_text(manifest, encoding="utf-8")
        log.info("vault_archived", stem=stem, ecosystem=ecosystem,
                 name=name, version=version, sha256=sha256[:12])
        return zip_path
    except Exception as e:
        log.warning("vault_write_failed", error=str(e), stem=stem)
        return None
