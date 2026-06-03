# SPDX-License-Identifier: AGPL-3.0-or-later
"""Recursive, no-exec decode engine.

Unrolls multi-layer encoded blobs — the `base64 -> gzip -> base64 -> payload`
chains real malware uses to hide a C2 URL or a dropper behind several trivially
reversible transforms — by applying only *known transforms to literal bytes*. It
never executes package code; every operation here is pure data.

This generalizes `iocs._decode_blobs` (single-layer base64/hex, which drops
compressed output as non-printable and never recurses). The caller mines the
returned `Decoded` layers for IOCs / code and emits findings; the engine itself
only recovers bytes + the decode chain.

Hard budgets bound adversarial input (a 10 KB gzip bomb expands to gigabytes):
bounded decompression, plus depth / total-size / node caps. All env-overridable.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import zlib
from bz2 import BZ2Decompressor
from collections import deque
from dataclasses import dataclass
from lzma import LZMADecompressor, LZMAError


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


# --- budgets (env-overridable; see docs) -------------------------------------
MAX_DEPTH = _int_env("PKGSENTRY_DECODE_MAX_DEPTH", 6)
MAX_TOTAL_BYTES = _int_env("PKGSENTRY_DECODE_MAX_TOTAL_MB", 64) * 1024 * 1024
MAX_LAYER_BYTES = _int_env("PKGSENTRY_DECODE_MAX_LAYER_MB", 32) * 1024 * 1024
MAX_NODES = _int_env("PKGSENTRY_DECODE_MAX_NODES", 2000)
MAX_BLOBS = _int_env("PKGSENTRY_DECODE_MAX_BLOBS", 400)
MIN_BLOB_LEN = 16
_MIN_OUT_LEN = 4
_SUB_BLOB_CAP = 8          # nested candidates pulled from a decoded text layer
_SCAN_WINDOW = 8192        # cap the byte window scanned for tokens/printability

# --- candidate-blob extraction patterns --------------------------------------
_B64_CAND = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_B64URL_CAND = re.compile(rb"[A-Za-z0-9_-]{16,}={0,2}")
_B32_CAND = re.compile(rb"[A-Z2-7]{16,}={0,6}")
_HEX_CAND = re.compile(rb"(?:[0-9a-fA-F]{2}){12,}")
_XESC_CAND = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){4,}")
_CHARCODE_CAND = re.compile(rb"(?:\d{1,3}\s*,\s*){7,}\d{1,3}")
_A85_CAND = re.compile(rb"<~[\x21-\x75\s]{16,}~>")

_URL_RE = re.compile(rb"https?://[^\s'\"<>()]{4,}")
# Code/command tokens whose presence in a decoded layer means we recovered
# something worth surfacing (not just benign data).
_CODE_TOKENS = (
    b"eval(", b"exec(", b"os.system", b"subprocess", b"__import__", b"compile(",
    b"child_process", b"require(", b"function(", b"powershell", b"/bin/sh",
    b"/bin/bash", b"cmd.exe", b"wscript", b"socket", b".connect(", b"base64",
    b"marshal", b"createdecipher", b"atob(", b"fromcharcode", b"shellexec",
)
# Recovered native executables / scripts are always worth surfacing — a package
# that decodes a hidden PE/ELF/Mach-O or a shebang script is a dropper shape.
_EXE_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
              b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"#!/")


def _is_executable(b: bytes) -> bool:
    return any(b.startswith(m) for m in _EXE_MAGIC)


@dataclass(frozen=True)
class Decoded:
    """One recovered layer: the bytes plus the chain of transforms that produced
    it (e.g. ``("b64", "gzip", "b64")``)."""
    data: bytes
    chain: tuple[str, ...]

    @property
    def depth(self) -> int:
        return len(self.chain)


class _Budget:
    def __init__(self) -> None:
        self.total = 0
        self.nodes = 0

    def node(self) -> bool:
        self.nodes += 1
        return self.nodes <= MAX_NODES

    def charge(self, n: int) -> bool:
        self.total += n
        return self.total <= MAX_TOTAL_BYTES


# --- bounded decompressors (the decompression-bomb guard) --------------------
def _inflate(data: bytes, wbits: int) -> bytes | None:
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(data, MAX_LAYER_BYTES)
    except zlib.error:
        return None
    if obj.unconsumed_tail:        # hit the per-layer cap -> treat as a bomb, drop
        return None
    return out or None


def _gzip_zlib(data: bytes) -> bytes | None:
    # wbits 47 = 32 + MAX_WBITS: auto-detects both the gzip and zlib headers.
    return _inflate(data, 47)


def _bz2(data: bytes) -> bytes | None:
    try:
        out = BZ2Decompressor().decompress(data, max_length=MAX_LAYER_BYTES)
    except (OSError, ValueError, EOFError):
        return None
    return out or None


def _xz(data: bytes) -> bytes | None:
    try:
        out = LZMADecompressor().decompress(data, max_length=MAX_LAYER_BYTES)
    except (LZMAError, EOFError, ValueError):
        return None
    return out or None


# --- text decoders -----------------------------------------------------------
def _b64(blob: bytes) -> bytes | None:
    try:
        return base64.b64decode(blob + b"=" * ((-len(blob)) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None


def _b64url(blob: bytes) -> bytes | None:
    # Only fire on url-safe-specific input; standard `b64` already covers the
    # alphanumeric / +/ case, so this avoids duplicate branches on ambiguous blobs.
    if b"-" not in blob and b"_" not in blob:
        return None
    try:
        return base64.urlsafe_b64decode(blob + b"=" * ((-len(blob)) % 4))
    except (binascii.Error, ValueError):
        return None


def _b32(blob: bytes) -> bytes | None:
    pad = (-len(blob)) % 8
    try:
        return base64.b32decode(blob + b"=" * pad)
    except (binascii.Error, ValueError):
        return None


def _hex(blob: bytes) -> bytes | None:
    if len(blob) % 2:
        blob = blob[:-1]
    try:
        return bytes.fromhex(blob.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


def _xesc(blob: bytes) -> bytes | None:
    try:
        return bytes(int(h, 16) for h in re.findall(rb"\\x([0-9a-fA-F]{2})", blob))
    except ValueError:
        return None


def _charcode(blob: bytes) -> bytes | None:
    try:
        vals = [int(x) for x in re.findall(rb"\d{1,3}", blob)]
    except ValueError:
        return None
    if not all(0 <= v <= 255 for v in vals):
        return None
    return bytes(vals)


def _a85(blob: bytes) -> bytes | None:
    try:
        return base64.a85decode(blob, adobe=blob.startswith(b"<~"))
    except (ValueError, binascii.Error):
        return None


def _reverse(blob: bytes) -> bytes | None:
    # Reverse a base64/hex token so the next layer can decode it — the
    # `b64decode(s[::-1])` / "reversed base64 executable" evasion. Self-gated to
    # token-shaped input so we don't reverse arbitrary bytes. reverse(reverse(x))
    # is caught by the `seen` set in recover().
    s = blob.strip()
    if len(s) < MIN_BLOB_LEN:
        return None
    if not (_B64_CAND.fullmatch(s) or _HEX_CAND.fullmatch(s) or _B32_CAND.fullmatch(s)):
        return None
    return s[::-1]


# Each entry: (name, applies(blob)->bool, decode(blob)->bytes|None).
_COMPRESSORS = (
    ("gzip", lambda b: b[:3] == b"\x1f\x8b\x08", _gzip_zlib),
    ("zlib", lambda b: len(b) > 2 and b[0] == 0x78 and (b[0] * 256 + b[1]) % 31 == 0, _gzip_zlib),
    ("bz2", lambda b: b[:3] == b"BZh", _bz2),
    ("xz", lambda b: b[:6] == b"\xfd7zXZ\x00", _xz),
)
_TEXT_DECODERS = (
    ("b64", _b64),
    ("b64url", _b64url),
    ("b32", _b32),
    ("hex", _hex),
    ("xesc", _xesc),
    ("charcode", _charcode),
    ("a85", _a85),
)

_TERMINAL, _RECURSE, _DROP = 0, 1, 2


def _printable_ratio(b: bytes) -> float:
    window = b[:_SCAN_WINDOW]
    if not window:
        return 0.0
    ok = sum(1 for c in window if 0x20 <= c <= 0x7E or c in (9, 10, 13))
    return ok / len(window)


def _sniff_compression(b: bytes) -> bool:
    return any(applies(b) for _name, applies, _fn in _COMPRESSORS)


def _looks_like_blob(b: bytes) -> bool:
    """The whole thing is one base64/hex token worth another decode pass."""
    s = b.strip()
    if len(s) < MIN_BLOB_LEN:
        return False
    m = _B64_CAND.fullmatch(s) or _HEX_CAND.fullmatch(s) or _B32_CAND.fullmatch(s)
    return m is not None


def _has_nested_candidate(b: bytes) -> bool:
    w = b[:_SCAN_WINDOW]
    return bool(_B64_CAND.search(w) or _HEX_CAND.search(w) or _XESC_CAND.search(w)
                or _CHARCODE_CAND.search(w))


def _has_code_token(b: bytes) -> bool:
    low = b[:_SCAN_WINDOW].lower()
    return any(t in low for t in _CODE_TOKENS)


def _classify(out: bytes) -> int:
    if _is_executable(out):
        return _TERMINAL              # recovered a hidden binary / script
    pr = _printable_ratio(out)
    if pr >= 0.85:
        if _URL_RE.search(out[:_SCAN_WINDOW]) or _has_code_token(out):
            return _TERMINAL          # recovered an IOC / code — surface it
        if _has_nested_candidate(out):
            return _RECURSE           # printable wrapper around another blob
        return _DROP                  # printable but benign (cert, config, prose)
    if _sniff_compression(out) or _looks_like_blob(out):
        return _RECURSE               # binary-but-structured: keep going
    return _DROP                      # high-entropy random / key / ciphertext — stop


def _candidates(data: bytes, cap: int):
    seen: set[bytes] = set()
    n = 0
    for rx in (_B64_CAND, _B64URL_CAND, _HEX_CAND, _XESC_CAND, _CHARCODE_CAND, _A85_CAND):
        for m in rx.finditer(data):
            if n >= cap:
                return
            blob = m.group(0)
            if len(blob) < MIN_BLOB_LEN or blob in seen:
                continue
            seen.add(blob)
            n += 1
            yield blob


def _decoders_for(blob: bytes):
    """Yield (name, fn) decoders that plausibly apply to *blob* — magic-sniffed
    compressors first (deterministic, no garbage), then charset-gated text codecs."""
    for name, applies, fn in _COMPRESSORS:
        if applies(blob):
            yield name, fn
    for name, fn in _TEXT_DECODERS:
        yield name, fn
    yield "reverse", _reverse


def recover(data: bytes) -> list[Decoded]:
    """Recover every meaningful decoded layer reachable from *data*.

    Returns the terminal layers — decoded bytes that contain a URL/IP or a
    code/command token — each tagged with the transform chain that produced it.
    Bounded by the module's depth / total-size / node budgets.
    """
    results: list[Decoded] = []
    budget = _Budget()
    seen: set[int] = set()
    stack: deque[tuple[bytes, tuple[str, ...]]] = deque(
        (blob, ()) for blob in _candidates(data, MAX_BLOBS)
    )
    while stack:
        if not budget.node():
            break
        cur, chain = stack.pop()
        if len(chain) >= MAX_DEPTH:
            continue
        fp = hash(cur)
        if fp in seen:
            continue
        seen.add(fp)
        for name, fn in _decoders_for(cur):
            out = fn(cur)
            if out is None or len(out) < _MIN_OUT_LEN or out == cur:
                continue
            if not budget.charge(len(out)):
                break
            new_chain = chain + (name,)
            cls = _classify(out)
            if cls == _TERMINAL:
                results.append(Decoded(out, new_chain))
            elif cls == _RECURSE:
                stack.append((out, new_chain))
                for sub in _candidates(out, _SUB_BLOB_CAP):
                    if sub != out:
                        stack.append((sub, new_chain))
    return results
