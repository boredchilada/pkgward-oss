# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared version-update anomaly core (crates/pypi ingest gates)."""
from __future__ import annotations

from pkgward.ecosystems import version_anomaly as va
from pkgward.ecosystems.version_anomaly import VersionMeta, detect_anomaly


def _m(ver, t, size=None, pub=None, hook=False):
    return VersionMeta(version=ver, published_at=t, size=size, publisher=pub, runs_bundled_hook=hook)


def test_size_jump_flagged():
    a = detect_anomaly([_m("1.0.0", "2024-01-01", size=40000), _m("1.0.1", "2024-02-01", size=1_000_000)])
    assert a is not None and "size_jump" in a.flags and not a.high_priority


def test_small_growth_not_flagged():
    assert detect_anomaly([_m("1.0.0", "2024-01-01", size=40000), _m("1.0.1", "2024-02-01", size=45000)]) is None


def test_publisher_change_flagged():
    a = detect_anomaly([_m("2.0.0", "2024-01-01", size=5000, pub="alice"),
                        _m("2.0.1", "2024-02-01", size=5000, pub="mallory")])
    assert a is not None and "publisher_change" in a.flags


def test_bundled_hook_is_high_priority():
    a = detect_anomaly([_m("1.0.0", "2024-01-01"), _m("1.0.1", "2024-02-01", hook=True)])
    assert a is not None and a.high_priority


def test_newest_chosen_by_time_not_order():
    # newest by time is 1.0.1 even though listed second; size jump 1.0.0->1.0.1
    a = detect_anomaly([_m("1.0.1", "2024-02-01", size=1_000_000), _m("1.0.0", "2024-01-01", size=40000)])
    assert a is not None and a.version == "1.0.1"


def test_single_version_no_anomaly():
    assert detect_anomaly([_m("1.0.0", "2024-01-01", size=999999)]) is None


def test_absolute_delta_catches_small_bump_behind_big_decoy():
    # nhmpy class: a 60KB payload bump on a 5MB package — ratio is 1.012x (the ratio
    # gate never fires) but the absolute delta clears the 50KB default trigger.
    a = detect_anomaly([_m("1.0.0", "2024-01-01", size=5_000_000),
                        _m("1.0.1", "2024-02-01", size=5_060_000)])
    assert a is not None and "size_jump" in a.flags


def test_absolute_delta_below_threshold_not_flagged():
    # +30KB is under the 50KB default and well under the 3x ratio gate → no trigger.
    assert detect_anomaly([_m("1.0.0", "2024-01-01", size=5_000_000),
                           _m("1.0.1", "2024-02-01", size=5_030_000)]) is None


def test_absolute_delta_requires_substantial_base():
    # Data-driven floor: a +60KB delta on a SMALL (100KB) package does NOT fire — the
    # small-package firehose is where the flooding (not the decoy malware) lives.
    assert detect_anomaly([_m("1.0.0", "2024-01-01", size=100_000),
                           _m("1.0.1", "2024-02-01", size=160_000)]) is None
    # The same +60KB delta on a package above the 256KB base floor DOES fire.
    a = detect_anomaly([_m("1.0.0", "2024-01-01", size=300_000),
                        _m("1.0.1", "2024-02-01", size=360_000)])
    assert a is not None and "size_jump" in a.flags


def test_absolute_delta_base_floor_configurable(monkeypatch):
    monkeypatch.setattr(va, "_SIZE_JUMP_ABS_MIN_BASE", 0)
    # Floor removed → the +60KB on a 100KB package now fires.
    a = detect_anomaly([_m("1.0.0", "2024-01-01", size=100_000),
                        _m("1.0.1", "2024-02-01", size=160_000)])
    assert a is not None and "size_jump" in a.flags


def test_absolute_delta_disabled_falls_back_to_ratio(monkeypatch):
    monkeypatch.setattr(va, "_SIZE_JUMP_ABS_BYTES", 0)
    # Same 60KB-on-5MB bump now does NOT fire (abs trigger off, ratio gate misses it).
    assert detect_anomaly([_m("1.0.0", "2024-01-01", size=5_000_000),
                           _m("1.0.1", "2024-02-01", size=5_060_000)]) is None
    # The ratio gate still fires on a genuine 3x+ jump.
    a = detect_anomaly([_m("1.0.0", "2024-01-01", size=40000),
                        _m("1.0.1", "2024-02-01", size=1_000_000)])
    assert a is not None and "size_jump" in a.flags
