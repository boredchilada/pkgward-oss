# SPDX-License-Identifier: AGPL-3.0-or-later
"""webcrack npm deobfuscation pre-pass: candidate selection + fail-soft."""
from __future__ import annotations

from pkgward.analyze import webcrack_deobf as wc


def test_looks_obfuscated_markers():
    assert wc._looks_obfuscated(b"var _0x1a2b = ['a','b']; _0x1a2b[0]")        # obfuscator.io
    assert wc._looks_obfuscated(b"function(){__webpack_require__(0)}")          # webpack bundle
    assert wc._looks_obfuscated(b"eval(function(p,a,c,k,e,d){return p}('x'))")  # packer wrapper
    assert wc._looks_obfuscated(b"x=String.fromCharCode(104,105)")             # char-code builder


def test_looks_obfuscated_minified_long_line():
    assert wc._looks_obfuscated(b"a=1;" + b"b=b+1;" * 500)  # one 3000+ col line


def test_clean_source_not_flagged():
    src = b"\n".join(b"  const x = require('lodash');" for _ in range(50))
    assert not wc._looks_obfuscated(src)


def test_fail_soft_when_binary_missing(tmp_path, monkeypatch):
    # No webcrack on the test image -> shutil.which returns None -> empty set, no raise.
    monkeypatch.setattr(wc.shutil, "which", lambda _b: None)
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "a.js").write_text("var _0xabcd=['x']")
    assert wc.deobfuscate_npm(tmp_path) == set()


def test_disabled_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("PKGWARD_WEBCRACK_ENABLED", "0")
    assert wc.deobfuscate_npm(tmp_path) == set()
