# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm version-update anomaly gate: diff newest-vs-prior from the packument and
flag the IronWorm-class compromise tells. A scan trigger, not a verdict."""
from __future__ import annotations

from pkgward.ecosystems.npm.ingest.anomaly import (
    detect_update_anomaly, hook_runs_bundled_path, new_known_bad_dep_edge,
)


def _pk(versions, times):
    return {"versions": versions, "time": times}


def test_ironworm_hook_added_and_bundled_exec_and_size_jump():
    pk = _pk(
        {"0.45.2": {"scripts": {}, "dist": {"unpackedSize": 38431, "fileCount": 4}, "_npmUser": {"name": "a"}},
         "0.45.3": {"scripts": {"preinstall": "./tools/setup"}, "dist": {"unpackedSize": 1015053, "fileCount": 6}, "_npmUser": {"name": "a"}}},
        {"0.45.2": "2024-10-14T00:00:00Z", "0.45.3": "2026-05-26T00:00:00Z"},
    )
    a = detect_update_anomaly(pk)
    assert a is not None and a.version == "0.45.3"
    assert "install_hook_added" in a.flags and "install_hook_bundled_exec" in a.flags
    assert "size_jump" in a.flags
    assert a.high_priority is True  # bundled-exec -> high


def test_clean_revert_is_not_flagged():
    # newest removes the hook + shrinks back — the attacker's cleanup, not anomalous
    pk = _pk(
        {"0.45.3": {"scripts": {"preinstall": "./tools/setup"}, "dist": {"unpackedSize": 1015053}, "_npmUser": {"name": "a"}},
         "0.45.4": {"scripts": {}, "dist": {"unpackedSize": 38431}, "_npmUser": {"name": "a"}}},
        {"0.45.3": "2026-05-26T00:00:00Z", "0.45.4": "2026-05-27T00:00:00Z"},
    )
    assert detect_update_anomaly(pk) is None


def test_publisher_change_is_flagged():
    pk = _pk(
        {"2.0.0": {"dist": {"unpackedSize": 50000}, "_npmUser": {"name": "realdev"}},
         "2.0.1": {"scripts": {"postinstall": "node x.js"}, "dist": {"unpackedSize": 50000}, "_npmUser": {"name": "attacker"}}},
        {"2.0.0": "2024-01-01T00:00:00Z", "2.0.1": "2024-02-01T00:00:00Z"},
    )
    a = detect_update_anomaly(pk)
    assert a is not None and "publisher_change" in a.flags
    # publisher change (account takeover) + a newly-added install hook is the attacker-
    # republish pattern — high priority so it jumps the backlog before the version is yanked.
    assert a.high_priority is True


def test_benign_update_not_flagged():
    pk = _pk(
        {"1.0.0": {"scripts": {"postinstall": "node-gyp rebuild"}, "dist": {"unpackedSize": 50000, "fileCount": 10}, "_npmUser": {"name": "a"}},
         "1.0.1": {"scripts": {"postinstall": "node-gyp rebuild"}, "dist": {"unpackedSize": 51000, "fileCount": 10}, "_npmUser": {"name": "a"}}},
        {"1.0.0": "2024-01-01T00:00:00Z", "1.0.1": "2024-02-01T00:00:00Z"},
    )
    assert detect_update_anomaly(pk) is None


def test_first_publish_has_no_prior():
    pk = _pk({"1.0.0": {"scripts": {"preinstall": "./x"}, "dist": {"unpackedSize": 99999}}},
             {"1.0.0": "2024-01-01T00:00:00Z"})
    assert detect_update_anomaly(pk) is None  # nothing to diff


def test_file_count_jump_alone_is_too_weak():
    pk = _pk(
        {"1.0.0": {"dist": {"unpackedSize": 50000, "fileCount": 10}},
         "1.0.1": {"dist": {"unpackedSize": 50000, "fileCount": 11}}},
        {"1.0.0": "2024-01-01T00:00:00Z", "1.0.1": "2024-02-01T00:00:00Z"},
    )
    assert detect_update_anomaly(pk) is None


def test_hook_runs_bundled_path():
    assert hook_runs_bundled_path({"preinstall": "./tools/setup"})
    assert hook_runs_bundled_path({"postinstall": "sh ./bin/run"})
    assert not hook_runs_bundled_path({"postinstall": "node ./install.js"})
    assert not hook_runs_bundled_path({"postinstall": "node-gyp rebuild"})


def test_established_size_jump_is_high_priority():
    # An established package (>=5 versions) that suddenly balloons — the binding.gyp /
    # node-gyp class whose package.json scripts stay clean. Must jump the queue.
    vers = {f"1.0.{i}": {"dist": {"unpackedSize": 200_000}, "_npmUser": {"name": "a"}}
            for i in range(5)}
    times = {f"1.0.{i}": f"2026-0{i + 1}-01T00:00:00Z" for i in range(5)}
    vers["1.2.2"] = {"dist": {"unpackedSize": 4_700_000}, "_npmUser": {"name": "a"}}
    times["1.2.2"] = "2026-06-04T00:00:00Z"
    a = detect_update_anomaly(_pk(vers, times))
    assert a is not None and a.flags == ("size_jump",) and a.high_priority is True


def test_new_package_size_jump_is_normal_priority():
    # Only 2 versions = not established — a size jump here is normal priority so benign
    # growth on young packages doesn't flood the high-priority queue.
    pk = _pk(
        {"1.0.0": {"dist": {"unpackedSize": 200_000}, "_npmUser": {"name": "a"}},
         "1.0.1": {"dist": {"unpackedSize": 4_700_000}, "_npmUser": {"name": "a"}}},
        {"1.0.0": "2026-06-01T00:00:00Z", "1.0.1": "2026-06-04T00:00:00Z"},
    )
    a = detect_update_anomaly(pk)
    assert a is not None and "size_jump" in a.flags and a.high_priority is False


def test_new_known_bad_dep_edge_fires_on_injected_dep():
    # newest version adds a dependency on a confirmed-malicious npm package
    pk = _pk(
        {"1.0.0": {"dependencies": {"lodash": "^4"}},
         "1.0.1": {"dependencies": {"lodash": "^4", "evil-utils": "1.0.0"}}},
        {"1.0.0": "2026-05-01T00:00:00Z", "1.0.1": "2026-06-04T00:00:00Z"},
    )
    hit = new_known_bad_dep_edge(pk, frozenset({"evil-utils"}))
    assert hit == ("1.0.1", "evil-utils")


def test_known_bad_dep_already_present_is_not_a_new_edge():
    # the bad dep was there last version too — not the inject moment; ingest gate
    # stays quiet (scan-time finding handles the pre-existing edge)
    pk = _pk(
        {"1.0.0": {"dependencies": {"evil-utils": "1.0.0"}},
         "1.0.1": {"dependencies": {"evil-utils": "1.0.0", "lodash": "^4"}}},
        {"1.0.0": "2026-05-01T00:00:00Z", "1.0.1": "2026-06-04T00:00:00Z"},
    )
    assert new_known_bad_dep_edge(pk, frozenset({"evil-utils"})) is None


def test_known_bad_dep_edge_empty_set_is_none():
    pk = _pk({"1.0.0": {"dependencies": {"evil-utils": "1"}}}, {"1.0.0": "2026-06-04T00:00:00Z"})
    assert new_known_bad_dep_edge(pk, frozenset()) is None


def test_known_bad_dep_edge_matches_scoped_name():
    pk = _pk(
        {"1.0.0": {"dependencies": {}},
         "1.0.1": {"dependencies": {"@bad/dropper": "1.0.0"}}},
        {"1.0.0": "2026-05-01T00:00:00Z", "1.0.1": "2026-06-04T00:00:00Z"},
    )
    hit = new_known_bad_dep_edge(pk, frozenset({"@bad/dropper"}))
    assert hit == ("1.0.1", "@bad/dropper")


def test_anomaly_overflow_is_carried_forward(monkeypatch):
    import asyncio
    from pkgward.ecosystems.npm.ingest import cursor as _cursor
    monkeypatch.setattr(_cursor, "NPM_ANOMALY_MAX_CHECKS", 4)
    _cursor._anomaly_carryover.clear()

    async def _fake_fetch(client, n):
        return None  # no packument -> no hit; we only test carry-over bookkeeping

    monkeypatch.setattr(_cursor, "_fetch_packument", _fake_fetch)
    cands = {f"pkg{i}" for i in range(10)}  # 10 candidates, cap 4
    asyncio.run(_cursor._check_anomalies(None, cands))
    # 4 checked this poll; the other 6 carried forward, NOT dropped
    assert len(_cursor._anomaly_carryover) == 6
    _cursor._anomaly_carryover.clear()
