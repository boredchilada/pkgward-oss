# SPDX-License-Identifier: AGPL-3.0-or-later
"""A single malformed YARA rule file — most often a typo in an operator's private
overlay — must NOT take down the entire YARA layer (layer 8) for the process."""
from __future__ import annotations

import types

import pytest

import pkgward.analyze.yara_scan as ys
from pkgward.util import capabilities as caps


def test_one_bad_yara_file_does_not_kill_the_layer(tmp_path, monkeypatch):
    if caps.yara is None:
        pytest.skip("yara not available in this environment")
    ydir = tmp_path / "yara"
    ydir.mkdir()
    (ydir / "good.yar").write_text('rule GoodRule { strings: $a = "TROPHYHIT" condition: $a }')
    (ydir / "bad.yar").write_text("rule BadRule { @@@ not valid yara @@@ }")

    monkeypatch.setattr(ys.intel, "current", lambda: types.SimpleNamespace(yara_dirs=[ydir]))
    ys._compiled_rules = None
    ys._compiled_from = ()
    try:
        rules = ys._get_rules()
        assert rules is not None, "a single bad rule file must not disable the whole layer"
        matches = rules.match(data=b"prefix TROPHYHIT suffix", externals={"filename": "x"})
        assert any(m.rule == "GoodRule" for m in matches), "the valid rule must still match"
    finally:
        ys._compiled_rules = None
        ys._compiled_from = ()
