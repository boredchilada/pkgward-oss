# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import math
import os
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from pkgsentry.adapter import Finding

if TYPE_CHECKING:
    from pkgsentry.pipeline import FileInfo

CATEGORY = "entropy"

HIGH_ENTROPY_THRESHOLD = 6.0
OBFUSCATED_THRESHOLD = 7.2
ENTROPY_JUMP_THRESHOLD = 1.5
MIN_FILE_SIZE = 256
# Skip entropy on very large files (prebuilt native binaries): O(n) pure-Python
# byte histogram, always near-max entropy (no signal), and binary.compiled_artifact
# already covers them. Mirrors the hashing cap in pipeline._compute_file_hashes.
MAX_FILE_SIZE = int(os.environ.get("PKGSENTRY_HASH_FULL_MAX_MB", "20")) * 1024 * 1024


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values()
    )


_INSTALL_FILES = {"setup.py", "install.py", "post_install.py", "conftest.py", "__init__.py"}

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".gz", ".bz2", ".xz", ".tar", ".whl",
    ".pyc", ".pyo", ".so", ".dll", ".pyd",
    # Binary cert/keystore containers (PKCS#12 / DER) are encrypted by spec and
    # always near-max entropy. Text PEM (.pem/.key) is base64 (~6 bits/byte,
    # under threshold) and deliberately NOT skipped, so a payload disguised as
    # PEM still trips the rule.
    ".pfx", ".p12", ".cer", ".der", ".crt", ".jks",
}


def analyze_entropy(
    extracted_root: Path,
    changed_files: set[str] | None = None,
) -> list[Finding]:
    out: list[Finding] = []

    for p in extracted_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in _SKIP_EXTENSIONS:
            continue
        rel = p.relative_to(extracted_root).as_posix()
        if changed_files is not None and rel not in changed_files:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size < MIN_FILE_SIZE or size > MAX_FILE_SIZE:
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue

        ent = _shannon_entropy(data)

        if ent >= OBFUSCATED_THRESHOLD:
            is_install = p.name.lower() in _INSTALL_FILES
            out.append(Finding(
                rule_id="entropy.obfuscated_payload",
                category=CATEGORY,
                severity="high" if is_install else "medium",
                confidence="medium",
                file=rel,
                line=None,
                evidence=f"entropy {ent:.2f} bits/byte (threshold {OBFUSCATED_THRESHOLD})",
            ))
        elif ent >= HIGH_ENTROPY_THRESHOLD and p.suffix.lower() in (".py", ".js", ".sh"):
            out.append(Finding(
                rule_id="entropy.high_entropy_script",
                category=CATEGORY,
                severity="low",
                confidence="low",
                file=rel,
                line=None,
                evidence=f"entropy {ent:.2f} bits/byte in script file",
            ))

    return out


def analyze_entropy_delta(
    current_info: dict[str, "FileInfo"],
    prev_info: dict[str, "FileInfo"],
    norm_to_real: dict[str, str],
) -> list[Finding]:
    """Flag files whose entropy jumped significantly between versions."""
    if not prev_info:
        return []

    out: list[Finding] = []
    for norm_path, cur in current_info.items():
        prev = prev_info.get(norm_path)
        if prev is None or prev.entropy <= 0:
            continue
        if cur.sha256 == prev.sha256:
            continue
        delta = cur.entropy - prev.entropy
        if delta >= ENTROPY_JUMP_THRESHOLD:
            real = norm_to_real.get(norm_path, norm_path)
            is_install = Path(norm_path).name.lower() in _INSTALL_FILES
            out.append(Finding(
                rule_id="entropy.suspicious_jump",
                category=CATEGORY,
                severity="high" if is_install else "medium",
                confidence="medium",
                file=real,
                line=None,
                evidence=f"entropy jumped {prev.entropy:.2f} -> {cur.entropy:.2f} (+{delta:.2f})",
            ))
    return out
