# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.ecosystems.npm.ingest.cursor import _seq_to_int


def test_seq_to_int_plain():
    assert _seq_to_int(12345) == 12345


def test_seq_to_int_string():
    assert _seq_to_int("67890") == 67890


def test_seq_to_int_composite():
    # CouchDB composite seq "N-<b64hash>" — take the leading integer.
    assert _seq_to_int("4521-g1AAAABXeJ") == 4521


def test_seq_to_int_garbage():
    assert _seq_to_int("not-a-number") == 0
    assert _seq_to_int("") == 0
