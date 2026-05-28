# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

from pkgsentry.adapter import Finding

CATEGORY = "binary"

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
