# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path
from typing import Optional

from pkgsentry.adapter import Finding

CATEGORY = "binary"

# Suffix for payloads we recover by unpacking (see analyze/unpack.py). Written
# back into the extraction tree so every analyzer + threat-intel sees the real
# payload, not the packed stub.
UNPACKED_SUFFIX = ".upx_unpacked"

# Runtime-packer / obfuscator signatures. A source package shipping a *packed*
# executable is a strong evasion signal — packing exists to defeat AV/static
# analysis. `kind` drives handling:
#   "upx"        — open-source, statically unpackable; analyze/unpack.py attempts
#                  `upx -d` and re-analyzes the payload (UPX has occasional legit
#                  use, e.g. the eqr crate's Rust CRC16 binary, so once we can
#                  read the payload this drops to a mild flag).
#   "commercial" — Themida/VMProtect/Enigma/...: no static unpacker exists (only
#                  dynamic, i.e. *running* the malware); ~zero legitimate reason
#                  to ship one in a source package → the signature itself is
#                  strong malicious-evasion evidence (critical).
#   "other"      — open-stub PE packers we flag but don't statically unpack.
# Substring-matched in a bounded head window of files that already look like
# executables, so this is cheap.
_PACKER_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"$Info: This file is packed with the UPX", "UPX", "upx"),
    (b"UPX!", "UPX", "upx"),
    (b"Themida", "Themida", "commercial"),
    (b".themida", "Themida", "commercial"),
    (b"WinLicense", "WinLicense", "commercial"),
    (b"VMProtect", "VMProtect", "commercial"),
    (b".vmp0", "VMProtect", "commercial"),
    (b".vmp1", "VMProtect", "commercial"),
    (b".enigma1", "Enigma", "commercial"),
    (b".enigma2", "Enigma", "commercial"),
    (b"ASPack", "ASPack", "other"),
    (b".aspack", "ASPack", "other"),
    (b".MPRESS1", "MPRESS", "other"),
    (b".MPRESS2", "MPRESS", "other"),
    (b"PECompact2", "PECompact", "other"),
    (b"FSG!", "FSG", "other"),
    (b".petite", "Petite", "other"),
    (b".MEW", "MEW", "other"),
)
_PACKER_SCAN_BYTES = 1 << 20  # 1 MiB head — packer stubs/markers live near the start


def _detect_packer(blob: bytes) -> Optional[tuple[str, str]]:
    """Return ``(packer_name, kind)`` or None. ``kind`` in {upx, commercial, other}."""
    for sig, name, kind in _PACKER_SIGNATURES:
        if sig in blob:
            return name, kind
    return None


_MAGIC_BYTES = {
    b"\x7fELF": "ELF",
    b"MZ": "PE/COFF",
    b"\xfe\xed\xfa\xce": "Mach-O (32-bit)",
    b"\xfe\xed\xfa\xcf": "Mach-O (64-bit)",
    b"\xce\xfa\xed\xfe": "Mach-O (32-bit, swapped)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64-bit, swapped)",
    b"\xca\xfe\xba\xbe": "Mach-O (universal)",
    b"\xd0\xcf\x11\xe0": "OLE2 (MS Office/MSI)",
}

_OK_EXTENSIONS = {
    ".so", ".dll", ".pyd", ".dylib",
    ".exe", ".msi",
    ".whl", ".egg",
}

# Executable-image magics only (subset of _MAGIC_BYTES). Used by the source-text
# analyzers to skip a compiled binary that wears a source extension — e.g. a native
# CLI shipped as `bin/tool.js` that is actually an ELF (esbuild/swc/cxpher pattern).
# Reading such a file as text turns its high-bit bytes into bogus "CJK/homoglyph
# identifiers" and trips entropy. Magic-byte match only — NOT a NUL-byte heuristic,
# which would also skip a genuinely-obfuscated encrypted payload hidden in a .py/.js.
_EXEC_IMAGE_MAGICS = (
    b"\x7fELF", b"MZ",
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
    b"\x00\x61\x73\x6d",  # WebAssembly
)


def looks_like_compiled_binary(path: Path) -> bool:
    """True if the file's *content* is a compiled executable image, regardless of
    extension. Source-text analyzers (obfuscation, entropy) call this to avoid
    scanning a native binary that carries a .js/.py/.txt name. Deliberately strict
    (magic bytes only) so an encrypted text-disguised payload still gets scanned."""
    try:
        header = path.read_bytes()[:8]
    except OSError:
        return False
    return any(header.startswith(m) for m in _EXEC_IMAGE_MAGICS)

_OK_DIRS = {"__pycache__", ".git", "node_modules"}

_DISGUISE_EXTENSIONS = {".py", ".txt", ".json", ".cfg", ".ini", ".yml", ".yaml"}


def analyze_binary_artifacts(
    extracted_root: Path,
    changed_files: set[str] | None = None,
) -> list[Finding]:
    out: list[Finding] = []

    for p in extracted_root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(extracted_root).as_posix()
        # Our own recovered payloads — let the content analyzers scan them, but
        # don't re-flag them here as packed/disguised binaries.
        if p.name.endswith(UNPACKED_SUFFIX):
            continue
        if changed_files is not None and rel not in changed_files:
            continue
        if any(part in _OK_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in _OK_EXTENSIONS:
            continue

        try:
            header = p.read_bytes()[:8]
        except OSError:
            continue
        if len(header) < 2:
            continue

        for magic, label in _MAGIC_BYTES.items():
            if not header.startswith(magic):
                continue
            ext = p.suffix.lower()
            # It's an executable — now (only now, so it stays cheap) read a
            # bounded head window and check whether it's been run-time packed.
            try:
                with p.open("rb") as fh:
                    blob = fh.read(_PACKER_SCAN_BYTES)
            except OSError:
                blob = b""
            packer = _detect_packer(blob)
            if packer:
                name, kind = packer
                unpacked = p.with_name(p.name + UNPACKED_SUFFIX).exists()
                if kind == "commercial":
                    severity = "critical"
                    note = "commercial protector — no static unpacker, ~zero legit use"
                elif kind == "upx" and unpacked:
                    severity = "medium"
                    note = "UPX — unpacked and re-analyzed (payload drives the verdict)"
                else:
                    severity = "high"
                    note = ("UPX — could not unpack (anti-unpack/unavailable)"
                            if kind == "upx" else "packed; no static unpacker")
                out.append(Finding(
                    rule_id="binary.packed_executable",
                    category=CATEGORY,
                    severity=severity,
                    confidence="high",
                    file=rel,
                    line=None,
                    evidence=f"{label} executable packed with {name} ({p.name}) — {note}",
                ))
            if ext in _DISGUISE_EXTENSIONS:
                out.append(Finding(
                    rule_id="binary.hidden_executable",
                    category=CATEGORY,
                    severity="high",
                    confidence="high",
                    file=rel,
                    line=None,
                    evidence=f"{label} binary disguised as {ext} ({p.name})",
                ))
            elif ext == "":
                out.append(Finding(
                    rule_id="binary.compiled_artifact",
                    category=CATEGORY,
                    severity="low",
                    confidence="high",
                    file=rel,
                    line=None,
                    evidence=f"{label} binary, no extension ({p.name})",
                ))
            else:
                out.append(Finding(
                    rule_id="binary.compiled_artifact",
                    category=CATEGORY,
                    severity="medium",
                    confidence="high",
                    file=rel,
                    line=None,
                    evidence=f"{label} binary ({p.name})",
                ))
            break

    return out
