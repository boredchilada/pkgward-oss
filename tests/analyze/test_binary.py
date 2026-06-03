# SPDX-License-Identifier: AGPL-3.0-or-later
"""Binary-artifact analysis: packer detection (tiered) + UPX static unpacking (0.5.2).

A source package shipping a packed executable is a strong evasion signal. We
unpack what's safely unpackable (UPX, decompress-only) and re-analyze the real
payload; commercial protectors (Themida/VMProtect) can't be statically unpacked
so the signature itself is critical. Motivated by crates `eqr` (a benign QR
crate whose UPX-packed Rust CRC16 binary `cr16` over-flagged as malicious)."""
from __future__ import annotations

import shutil

import pytest

from pkgsentry.analyze.binary import (
    UNPACKED_SUFFIX, _detect_packer, analyze_binary_artifacts,
)
from pkgsentry.analyze.unpack import unpack_packed_executables, upx_available

ELF = b"\x7fELF\x02\x01\x01\x00"


def test_detect_packer_kind():
    assert _detect_packer(b"....UPX!....") == ("UPX", "upx")
    assert _detect_packer(b"...$Info: This file is packed with the UPX...") == ("UPX", "upx")
    assert _detect_packer(b"....Themida....") == ("Themida", "commercial")
    assert _detect_packer(b"....VMProtect....") == ("VMProtect", "commercial")
    assert _detect_packer(b"....ASPack....") == ("ASPack", "other")
    assert _detect_packer(b"a plain unpacked binary") is None


def test_upx_packed_without_unpack_is_high(tmp_path):
    (tmp_path / "cr16").write_bytes(ELF + b"\x00" * 64 + b"UPX!" + b"\x00" * 200)
    fs = analyze_binary_artifacts(tmp_path)
    packed = [f for f in fs if f.rule_id == "binary.packed_executable"]
    assert len(packed) == 1 and packed[0].severity == "high" and "UPX" in packed[0].evidence


def test_commercial_protector_is_critical(tmp_path):
    (tmp_path / "loader").write_bytes(ELF + b"\x00" * 64 + b"Themida" + b"\x00" * 64)
    fs = analyze_binary_artifacts(tmp_path)
    packed = [f for f in fs if f.rule_id == "binary.packed_executable"]
    assert len(packed) == 1 and packed[0].severity == "critical"


def test_upx_with_unpacked_sibling_downgrades_to_medium(tmp_path):
    # once the payload has been recovered + re-analyzed, the packed flag is mild
    (tmp_path / "cr16").write_bytes(ELF + b"\x00" * 64 + b"UPX!" + b"\x00" * 200)
    (tmp_path / ("cr16" + UNPACKED_SUFFIX)).write_bytes(ELF + b"\x00" * 256)
    fs = analyze_binary_artifacts(tmp_path)
    packed = [f for f in fs if f.rule_id == "binary.packed_executable"]
    assert len(packed) == 1 and packed[0].severity == "medium"
    # the recovered sibling itself is NOT re-flagged as a binary artifact
    assert not any(f.file.endswith(UNPACKED_SUFFIX) for f in fs)


def test_unpack_noop_without_upx(tmp_path, monkeypatch):
    monkeypatch.setattr("pkgsentry.analyze.unpack.shutil.which", lambda _: None)
    (tmp_path / "cr16").write_bytes(ELF + b"UPX!" + b"\x00" * 64)
    assert unpack_packed_executables(tmp_path) == []


@pytest.mark.skipif(not upx_available(), reason="upx not installed")
def test_unpack_real_upx_roundtrip(tmp_path):
    # pack a tiny ELF-ish file with upx, then confirm our pass recovers it
    import subprocess
    # build a minimal real binary to pack: copy /bin/true (small, real ELF)
    src = tmp_path / "payload"
    shutil.copy("/bin/true", src)
    subprocess.run(["upx", "-1", "-q", str(src)], check=True, capture_output=True)
    res = unpack_packed_executables(tmp_path)
    assert any(status == "unpacked" for _, status in res)
    assert (tmp_path / ("payload" + UNPACKED_SUFFIX)).exists()


def test_looks_like_compiled_binary_detects_disguised_elf(tmp_path):
    # An ELF wearing a source extension (esbuild/swc/cxpher native-CLI pattern) is
    # detected by content so the source-text analyzers skip it.
    from pkgsentry.analyze.binary import looks_like_compiled_binary
    p = tmp_path / "cXpher.js"
    p.write_bytes(ELF + b"\x90" * 512)
    assert looks_like_compiled_binary(p) is True


def test_looks_like_compiled_binary_does_not_skip_encrypted_text_payload(tmp_path):
    # A genuinely-obfuscated/encrypted blob hidden in a .py is NOT a compiled image —
    # it must still reach entropy/obfuscation (strict magic-byte match, no NUL heuristic).
    import os
    from pkgsentry.analyze.binary import looks_like_compiled_binary
    p = tmp_path / "payload.py"
    p.write_bytes(os.urandom(2048))
    assert looks_like_compiled_binary(p) is False
