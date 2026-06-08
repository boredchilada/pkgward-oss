# SPDX-License-Identifier: AGPL-3.0-or-later
"""Analyze package.json lifecycle scripts for supply-chain attack patterns.

npm runs ``preinstall``/``install``/``postinstall`` (and ``prepare`` for local
installs) automatically on ``npm install`` — the JavaScript equivalent of
PyPI's setup.py and Rust's build.rs. ``postinstall`` is the most-abused vector.

This analyzer parses the *root* package.json (never bundled ``node_modules``
manifests), inspects the lifecycle script command strings, and follows local
script files they invoke (e.g. ``node scripts/postinstall.js``) to scan the JS.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Optional

from pkgward.adapter import Finding
from pkgward import intel
from pkgward.analyze.binary import looks_like_compiled_binary
from pkgward.logging_setup import get_logger

CATEGORY = "installer"
log = get_logger("ecosystems.npm.installer")

# Lifecycle scripts that execute automatically on a consumer's `npm install`.
_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")

# --- Shell-command (script string) patterns ---

# Network fetchers commonly chained in install scripts.
_SHELL_NET = re.compile(
    r"\b(?:curl|wget|fetch|nc|ncat|certutil|bitsadmin|Invoke-WebRequest|iwr|"
    r"scp|rsync)\b|https?://|ftp://",
    re.IGNORECASE,
)

# Shell/interpreter execution and code-eval entry points.
_SHELL_EXEC = re.compile(
    r"\b(?:sh|bash|zsh|cmd|powershell|pwsh)\b\s+-\w*c|"
    r"\beval\b|\bexec\b|"
    r"\bnode\b\s+-e|\bpython3?\b\s+-c|\bperl\b\s+-e|\bruby\b\s+-e",
    re.IGNORECASE,
)

# base64/hex decode-and-run shapes inside a shell command.
_SHELL_DECODE = re.compile(
    r"base64\s+(?:-d|--decode)|\batob\b|\bxxd\b\s+-r|"
    r"Buffer\.from\([^)]*['\"]base64['\"]",
    re.IGNORECASE,
)

# --- JS source patterns (for followed script files) ---

_JS_NET = re.compile(
    r"require\(\s*['\"](?:https?|net|dns|tls|dgram)['\"]\s*\)|"
    r"\b(?:fetch|axios|node-fetch|got|undici|superagent)\b|"
    r"\bhttps?\.(?:get|request)\b|\bXMLHttpRequest\b",
    re.IGNORECASE,
)

_JS_EXEC = re.compile(
    r"require\(\s*['\"]child_process['\"]\s*\)|"
    r"\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(|"
    r"\beval\s*\(|new\s+Function\s*\(|process\.binding\s*\(",
)

_JS_DECODE = re.compile(
    r"Buffer\.from\([^)]*['\"]base64['\"]|\batob\s*\(",
)

# --- reconnaissance / collection (MITRE Collection) --------------------------
# Scoped to INSTALL scripts, where system/network/CI recon has near-zero legit use.
# os.platform / os.arch / os.cpus are deliberately EXCLUDED — native wrappers check
# them to pick the right prebuilt binary, so they FP heavily.
_JS_HOST_RECON = re.compile(
    r"\bos\.(?:hostname|userInfo)\s*\(|"
    r"\b(?:whoami|systeminfo)\b|\buname\s+-|\bid\s+-un\b|echo\s+%USERNAME%",
    re.IGNORECASE,
)
_JS_NET_RECON = re.compile(
    r"\bos\.networkInterfaces\s*\(|\b(?:ifconfig|ipconfig|ip\s+addr)\b",
    re.IGNORECASE,
)
_JS_CI_HARVEST = re.compile(
    r"GITHUB_TOKEN|GITHUB_ACTOR|GITHUB_REPOSITORY|GH_TOKEN|"
    r"NPM_TOKEN|NODE_AUTH_TOKEN|CIRCLECI|JENKINS_URL|GITLAB_CI",
)


def _recon_findings(content: str, rel: str) -> list["Finding"]:
    """Install-time reconnaissance/collection findings. Fires even with no
    child_process — closes the recon-stealer FN shape (brave-search-mcp-server)."""
    out: list[Finding] = []
    host = bool(_JS_HOST_RECON.search(content))
    netr = bool(_JS_NET_RECON.search(content))
    ci = bool(_JS_CI_HARVEST.search(content))
    if host:
        out.append(Finding(
            rule_id="installer.npm_install_host_recon", category=CATEGORY,
            severity="medium", confidence="medium", file=rel,
            evidence="install script gathers host info (hostname/user/whoami/uname)"))
    if netr:
        out.append(Finding(
            rule_id="installer.npm_install_network_recon", category=CATEGORY,
            severity="medium", confidence="medium", file=rel,
            evidence="install script enumerates network interfaces / internal IPs"))
    if ci:
        out.append(Finding(
            rule_id="installer.npm_install_ci_secret_harvest", category=CATEGORY,
            severity="high", confidence="medium", file=rel,
            evidence="install script reads CI / GitHub Actions secrets or tokens"))
    if (host or netr or ci) and _JS_NET.search(content):
        out.append(Finding(
            rule_id="installer.npm_install_recon_exfil", category=CATEGORY,
            severity="high", confidence="high", file=rel,
            evidence="install script collects system/network/CI recon and sends it over the network"))
    return out

# Self-decoding packer inside a referenced install script: a char-code decode
# (String.fromCharCode / charCodeAt / a long decimal array) or a runtime
# crypto-decrypt (createDecipheriv), whose output is run through eval/Function
# (_JS_EXEC). The @redhat-cloud-services worm hid curl->download-bun->exec behind
# Caesar(char-codes) -> AES-128-GCM -> eval, so the visible install file had only
# a bare `eval(` and no network/base64 — invisible to every rule above.
_JS_CHARCODE_DECODE = re.compile(
    r"\bString\.fromCharCode\b|\.charCodeAt\s*\(|(?:\d{1,4}\s*,\s*){40,}",
)
_JS_CRYPTO_DECRYPT = re.compile(r"\bcreateDecipher(?:iv)?\s*\(")

# Install-time OS persistence registration: systemd user unit, launchd plist,
# Windows Run-key / VBS autostart, XDG autostart, cron. An install hook that
# registers persistence is staging a resident agent — near-zero legitimate use in
# an npm lifecycle script. (logger-active / utils-terminal loader does all three.)
_JS_PERSISTENCE = re.compile(
    r"LaunchAgents|LaunchDaemons|\blaunchctl\b|\.plist\b"
    r"|systemd[/\\]user|\bsystemctl\b"
    r"|CurrentVersion\\+Run|HKEY_CURRENT_USER|\bwscript\b|\.vbs\b"
    r"|[/\\]\.config[/\\]autostart"
    r"|\bcrontab\b|/etc/cron",
    re.IGNORECASE,
)
# A detached, unref'd background spawn — the loader pattern that keeps a dropped
# payload running after the installer process exits.
_JS_DETACHED_SPAWN = re.compile(r"detached\s*:\s*true", re.IGNORECASE)

# Large encoded blob (base64 run or \xNN escape run).
_ENCODED_PAYLOAD = re.compile(
    r"[A-Za-z0-9+/]{200,}={0,2}|(?:\\x[0-9a-fA-F]{2}){50,}",
)

# --- Remote-binary "dropper" chain: download -> write-to-disk -> make-executable.
# A native-wrapper that downloads its prebuilt binary at install does this too,
# so the host (below) is what separates the norm from a payload drop.
_JS_WRITE = re.compile(
    r"createWriteStream|writeFileSync?\b|\.pipe\s*\(|\bpipeline\s*\(|fs\.write\b",
    re.IGNORECASE,
)
# chmod that sets an executable bit: chmodSync(x, 0o755) / chmod +x / chmod 755.
_JS_CHMOD_EXEC = re.compile(
    r"chmod(?:Sync)?\s*\([^)]*0o?[0-7]*[1357][0-7]{2}"
    # symbolic / fs.constants exec bits (chmodSync(p, fs.constants.S_IRWXU) etc.) —
    # evades the numeric-octal match; part of the multi-signal dropper chain so safe.
    r"|chmod(?:Sync)?\s*\([^)]*S_I(?:RWX|X)(?:USR|GRP|OTH)?"
    r"|\bchmod\s+\+x\b"
    r"|\bchmod\s+0?[0-7]*[1357][0-7]{2}\b",
    re.IGNORECASE,
)
_URL_HOST = re.compile(r"https?://([A-Za-z0-9.\-]+)", re.IGNORECASE)

# Integrity verification of the downloaded binary: the install script computes a
# SHA-256/512 of the download (to compare against a published checksum and refuse/
# delete on mismatch). This is the legit prebuilt-binary distribution pattern
# (esbuild/swc/@vscode-ripgrep and the huayoungtk-cli vendor CLI all do it); malware
# droppers chmod+exec whatever they fetched without verifying it. A strong (if not
# unforgeable) discriminator — it down-weights the remote-binary-drop finding.
_CHECKSUM_VERIFY = re.compile(
    r"createHash\s*\(\s*['\"]sha(?:256|512)['\"]", re.IGNORECASE,
)

# Universal release hosts a native wrapper may legitimately pull a binary from,
# independent of the package's own repo. Subdomain-matched (endswith ".<host>").
_TRUSTED_RELEASE_HOSTS = frozenset({
    "github.com", "githubusercontent.com", "codeload.github.com",
    "registry.npmjs.org", "npmjs.org", "npmmirror.com", "registry.yarnpkg.com",
    "nodejs.org", "github.io", "gitlab.com", "bitbucket.org",
})


def _declared_hosts(data: dict) -> set[str]:
    """Hosts the package itself points at (repository / homepage / bugs)."""
    hosts: set[str] = set()
    fields: list[str] = []
    for key in ("repository", "bugs"):
        v = data.get(key)
        if isinstance(v, str):
            fields.append(v)
        elif isinstance(v, dict) and isinstance(v.get("url"), str):
            fields.append(v["url"])
    if isinstance(data.get("homepage"), str):
        fields.append(data["homepage"])
    for f in fields:
        m = _URL_HOST.search(f)
        if m:
            hosts.add(m.group(1).lower())
        elif f.startswith("gitlab:"):
            hosts.add("gitlab.com")
        elif f.startswith("bitbucket:"):
            hosts.add("bitbucket.org")
        elif f.startswith("github:") or re.match(r"^[\w-]+/[\w.-]+$", f):
            hosts.add("github.com")
    return hosts


def _host_trusted(host: str, declared_hosts: set[str]) -> bool:
    host = host.lower()
    for t in _TRUSTED_RELEASE_HOSTS:
        if host == t or host.endswith("." + t):
            return True
    for d in declared_hosts:
        if host == d or host.endswith("." + d) or d.endswith("." + host):
            return True
    return False

# Reference to a local script file in a command, e.g. `node ./scripts/x.js`.
# Local script a hook runs. Includes TypeScript (.ts/.mts/.cts/.tsx) — npm packages
# routinely run install hooks via `tsx`/`ts-node` (e.g. `postinstall: tsx setup.ts`),
# and an attacker can ship the payload as .ts to evade a .js-only follow.
_LOCAL_SCRIPT_REF = re.compile(r"(?:^|\s)(?:\./)?([\w./-]+\.(?:[cm]?jsx?|[cm]?tsx?))\b")

# Extensionless reference run by a JS interpreter: `postinstall: node install` or
# `tsx setup` — a payload shipped without a file extension dodges the extension-only
# matcher above. Resolved by trying common JS/TS extensions (+ <dir>/index.js).
_INTERP_SCRIPT_REF = re.compile(
    r"(?:^|[\s;&|()])(?:node|tsx|ts-node|babel-node)\s+(?:--?\S+\s+)*(?:\./)?([\w./-]+)"
)
_RESOLVE_EXTS = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts")
_JS_TS_SUFFIXES = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx"}

_SUSPICIOUS_BIN_EXT = {".sh", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".so", ".bin"}


def _benign_tools() -> frozenset[str]:
    """Allowlist of benign build/setup tool basenames from the intel pack.

    Falls back to a built-in baseline if the pack does not ship an npm list.
    """
    try:
        pack = intel.current()
        tools = getattr(pack, "npm_benign_tools", None)
        if tools:
            return frozenset(str(t).lower() for t in tools)
    except Exception:
        pass
    return _BUILTIN_BENIGN


_BUILTIN_BENIGN = frozenset({
    "node-gyp", "node-gyp-build", "prebuild-install", "prebuildify",
    "tsc", "tsup", "webpack", "rollup", "vite", "esbuild", "babel",
    "gulp", "grunt", "parcel", "rimraf", "mkdirp", "cpy", "copyfiles",
    "eslint", "prettier", "jest", "mocha", "husky", "patch-package",
    "npm", "yarn", "pnpm", "echo", "true", "exit", "cd", "node",
    "is-ci", "cross-env", "shx", "ncc", "tscw", "nest", "ng",
})


def _is_benign_script(script: str) -> bool:
    """True when every command token chain resolves to a benign tool.

    Splits on shell operators and checks the leading token of each segment
    against the benign-tool allowlist; any unknown leading token makes the
    whole script non-benign (conservative).
    """
    benign = _benign_tools()
    # Split into command segments on &&, ||, ;, |.
    segments = re.split(r"&&|\|\||;|\|", script)
    saw_cmd = False
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        try:
            tokens = shlex.split(seg)
        except ValueError:
            return False
        if not tokens:
            continue
        head = Path(tokens[0]).name.lower()
        # `node ./scripts/x.js` is only benign if it runs no followed payload;
        # treat bare `node <file>` as non-benign so the file gets scanned.
        if head == "node" and len(tokens) > 1 and not tokens[1].startswith("-"):
            return False
        if head not in benign:
            return False
        saw_cmd = True
    return saw_cmd


def _root_package_json_paths(extracted_root: Path) -> list[Path]:
    """Return the install-time package.json(s): the archive root manifest only.

    npm tarballs extract under a single ``package/`` dir, so the real manifest
    lives at depth 1 or 2. Bundled ``node_modules`` manifests are dependencies,
    not this package's install hooks, and are skipped.
    """
    candidates: list[Path] = []
    direct = extracted_root / "package.json"
    if direct.is_file():
        candidates.append(direct)
    for child in extracted_root.iterdir():
        if child.is_dir() and child.name != "node_modules":
            nested = child / "package.json"
            if nested.is_file():
                candidates.append(nested)
    return candidates


def _analyze_script(name: str, script: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    if _is_benign_script(script):
        return findings

    has_net = bool(_SHELL_NET.search(script))
    has_exec = bool(_SHELL_EXEC.search(script))
    has_decode = bool(_SHELL_DECODE.search(script))

    if has_net and (has_exec or has_decode):
        findings.append(Finding(
            rule_id="installer.npm_lifecycle_net_exec",
            category=CATEGORY, severity="critical", confidence="high",
            file=rel,
            evidence=f"{name} script chains network fetch + exec/decode: {script[:160]}",
        ))
    elif has_net:
        findings.append(Finding(
            rule_id="installer.npm_lifecycle_network",
            category=CATEGORY, severity="high", confidence="medium",
            file=rel,
            evidence=f"{name} script makes a network call: {script[:160]}",
        ))
    elif has_exec or has_decode:
        findings.append(Finding(
            rule_id="installer.npm_lifecycle_subprocess",
            category=CATEGORY, severity="medium", confidence="medium",
            file=rel,
            evidence=f"{name} script runs a shell/eval: {script[:160]}",
        ))
    return findings


# Shell interpreters that, when leading a command, execute their first non-flag arg.
_SHELL_INTERPS = {"sh", "bash", "dash", "zsh", "ksh", "ash"}


def _executed_local_targets(script: str, pkg_dir: Path):
    """Yield (ref, resolved Path) for each command segment whose leading token executes
    a file bundled INSIDE the package — a directly-run ``./tools/setup``, ``sh ./x``, etc.
    This is how an install hook runs a dropped binary/script with no `node`/`curl` in
    sight, so the net/exec/decode string heuristics never fire (the IronWorm gap)."""
    pkg_root = pkg_dir.resolve()
    for seg in re.split(r"&&|\|\||;|\|", script):
        seg = seg.strip()
        if not seg:
            continue
        try:
            tokens = shlex.split(seg)
        except ValueError:
            continue
        if not tokens:
            continue
        cand = tokens[0]
        if Path(cand).name.lower() in _SHELL_INTERPS and len(tokens) > 1:
            cand = next((t for t in tokens[1:] if not t.startswith("-")), cand)
        # only path-shaped refs into the package (skip bare commands like `tsc`, `npm`)
        if "/" not in cand and not cand.startswith("."):
            continue
        tgt = (pkg_dir / cand).resolve()
        try:
            tgt.relative_to(pkg_root)  # must stay inside the package
        except ValueError:
            continue
        if tgt.is_file():
            yield cand, tgt


def _analyze_bundled_exec(hook: str, script: str, pkg_dir: Path, rel_prefix: str) -> list[Finding]:
    """A lifecycle hook that directly executes a file BUNDLED in the package. Running a
    bundled native binary at install time is the dropper/loader signature (IronWorm:
    ``preinstall: ./tools/setup`` / ``./.github/scripts/precheck`` — a packed Rust ELF).
    Legit native modules launch via a JS shim (`node install.js`) or node-gyp/prebuild,
    never by exec-ing a prebuilt binary straight from a hook."""
    findings: list[Finding] = []
    for ref, tgt in _executed_local_targets(script, pkg_dir):
        rel = f"{rel_prefix}{ref}"
        if looks_like_compiled_binary(tgt):
            findings.append(Finding(
                rule_id="installer.npm_install_runs_bundled_binary",
                category=CATEGORY, severity="critical", confidence="high",
                file=rel,
                evidence=f"{hook} hook directly executes a bundled native binary: {ref}",
            ))
        elif Path(ref).suffix.lower() not in _JS_TS_SUFFIXES:
            # a bundled shell/extensionless executable run at install (not a .js the
            # referenced-JS scanner already follows) — strong, not auto-convicting
            findings.append(Finding(
                rule_id="installer.npm_install_runs_bundled_file",
                category=CATEGORY, severity="high", confidence="medium",
                file=rel,
                evidence=f"{hook} hook directly executes a bundled non-JS file: {ref}",
            ))
    return findings


def _analyze_referenced_js(
    script: str, pkg_dir: Path, rel_prefix: str, declared_hosts: set[str] | None = None
) -> list[Finding]:
    """Scan local .js files invoked by a lifecycle script."""
    declared_hosts = declared_hosts or set()
    findings: list[Finding] = []

    # Build the set of referenced local scripts to follow: explicit-extension refs
    # plus extensionless interpreter refs resolved via JS/TS module resolution.
    candidates: list[tuple[str, Path]] = []
    seen_targets: set[Path] = set()

    def _add(ref: str) -> None:
        tgt = (pkg_dir / ref).resolve()
        if tgt in seen_targets:
            return
        seen_targets.add(tgt)
        candidates.append((ref, tgt))

    for m in _LOCAL_SCRIPT_REF.finditer(script):
        _add(m.group(1))
    for m in _INTERP_SCRIPT_REF.finditer(script):
        ref = m.group(1)
        if Path(ref).suffix.lower() in _JS_TS_SUFFIXES:
            continue  # already handled by the extension matcher
        for ext in _RESOLVE_EXTS:
            if (pkg_dir / (ref + ext)).resolve().is_file():
                _add(ref + ext)
                break
        else:
            if (pkg_dir / ref / "index.js").resolve().is_file():
                _add(f"{ref.rstrip('/')}/index.js")

    for ref, target in candidates:
        try:
            target.relative_to(pkg_dir.resolve())  # stay inside the package
        except ValueError:
            continue
        if not target.is_file():
            continue
        if looks_like_compiled_binary(target):
            continue  # a hook-referenced native binary is not obfuscated JS — same
            # guard as the runtime-entrypoint path; binary covered elsewhere.
        try:
            content = target.read_text(errors="replace")
        except Exception:
            continue
        rel = f"{rel_prefix}{ref}"
        findings.extend(_recon_findings(content, rel))
        has_net = bool(_JS_NET.search(content))
        has_exec = bool(_JS_EXEC.search(content))
        if has_net and has_exec:
            findings.append(Finding(
                rule_id="installer.npm_install_script_net_exec",
                category=CATEGORY, severity="critical", confidence="high",
                file=rel,
                evidence="install script JS contains both network and child_process/eval",
            ))
        elif has_net:
            findings.append(Finding(
                rule_id="installer.npm_install_script_network",
                category=CATEGORY, severity="high", confidence="medium",
                file=rel, evidence="install script JS makes a network call",
            ))
        if _JS_DECODE.search(content) and has_exec:
            findings.append(Finding(
                rule_id="installer.npm_install_script_decode_exec",
                category=CATEGORY, severity="high", confidence="medium",
                file=rel, evidence="install script JS decodes base64 then executes",
            ))
        # Obfuscated self-decoding entrypoint: a hook executing a local script
        # that reconstructs code at runtime (char-code / crypto-decrypt) and
        # eval/Function's it. Install-time + obfuscated = malware-grade, even when
        # the network/exec payload is hidden inside the encoded stage.
        if has_exec and (_JS_CHARCODE_DECODE.search(content) or _JS_CRYPTO_DECRYPT.search(content)):
            findings.append(Finding(
                rule_id="installer.npm_install_obfuscated_entrypoint",
                category=CATEGORY, severity="critical", confidence="high",
                file=rel,
                evidence=(
                    "install hook runs a local script that self-decodes "
                    "(char-code / runtime-crypto) into eval/Function"
                ),
            ))
        # Resident-agent loader: an install script that registers OS persistence
        # AND detaches a background process is the dropper/loader fingerprint —
        # stable across payload variants (catches the family even when the payload
        # blob evades YARA). The combination is near-zero-FP; each alone is high.
        has_persist = bool(_JS_PERSISTENCE.search(content))
        has_detached = bool(_JS_DETACHED_SPAWN.search(content))
        if has_persist and has_detached:
            findings.append(Finding(
                rule_id="installer.npm_install_persistence_loader",
                category=CATEGORY, severity="critical", confidence="high",
                file=rel,
                evidence="install hook registers OS persistence + detaches a background process (resident-agent loader)",
            ))
        else:
            if has_persist:
                findings.append(Finding(
                    rule_id="installer.npm_install_persistence",
                    category=CATEGORY, severity="high", confidence="high",
                    file=rel,
                    evidence="install hook registers OS persistence (systemd/launchd/Run-key/autostart/cron)",
                ))
            if has_detached:
                findings.append(Finding(
                    rule_id="installer.npm_install_detached_spawn",
                    category=CATEGORY, severity="high", confidence="medium",
                    file=rel,
                    evidence="install hook spawns a detached, unref'd background process",
                ))
        if _ENCODED_PAYLOAD.search(content):
            findings.append(Finding(
                rule_id="installer.npm_install_script_encoded_payload",
                category=CATEGORY, severity="medium", confidence="medium",
                file=rel, evidence="large encoded payload in install script JS",
            ))

        # Remote-binary dropper: download -> write-to-disk -> make-executable.
        # Native wrappers do this from their own repo / a known release host;
        # a payload drop pulls the binary from an unrelated host (and may defer
        # the exec to the `bin` wrapper, evading the net+exec rule above).
        if has_net and _JS_WRITE.search(content) and _JS_CHMOD_EXEC.search(content):
            hosts = {h.lower() for h in _URL_HOST.findall(content)}
            untrusted = sorted(h for h in hosts if not _host_trusted(h, declared_hosts))
            if untrusted:
                if _CHECKSUM_VERIFY.search(content):
                    # Checksum-verified prebuilt-binary download (legit native-wrapper
                    # pattern). Down-weighted; the host is recorded after "hosts:" so the
                    # detonation re-score recognizes an install-time connect to it as the
                    # legit self-download rather than chaining dyn_install_exfil to malicious.
                    findings.append(Finding(
                        rule_id="installer.npm_install_remote_binary_drop",
                        category=CATEGORY, severity="low", confidence="medium",
                        file=rel,
                        evidence=(
                            "checksum-verified prebuilt-binary download (legit native-wrapper "
                            f"pattern); hosts: {', '.join(untrusted[:3])}"
                        ),
                    ))
                else:
                    findings.append(Finding(
                        rule_id="installer.npm_install_remote_binary_drop",
                        category=CATEGORY, severity="high", confidence="high",
                        file=rel,
                        evidence=(
                            "install script downloads + chmod-executes a binary from a host "
                            f"unrelated to the package repo: {', '.join(untrusted[:3])}"
                        ),
                    ))
            elif not hosts:
                findings.append(Finding(
                    rule_id="installer.npm_install_remote_binary_drop",
                    category=CATEGORY, severity="medium", confidence="medium",
                    file=rel,
                    evidence="install script downloads + chmod-executes a binary from a dynamic URL",
                ))
    return findings


def _analyze_bin(bin_field, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    targets: list[str] = []
    if isinstance(bin_field, str):
        targets = [bin_field]
    elif isinstance(bin_field, dict):
        targets = [str(v) for v in bin_field.values()]
    for t in targets:
        if Path(t).suffix.lower() in _SUSPICIOUS_BIN_EXT:
            findings.append(Finding(
                rule_id="installer.npm_suspicious_bin",
                category=CATEGORY, severity="low", confidence="low",
                file=rel, evidence=f"bin entry points to a script/binary: {t}",
            ))
    return findings


_RUNTIME_ENTRY_RESOLVE_EXTS = ("", ".js", ".cjs", ".mjs", "/index.js")


def _resolve_runtime_entries(data: dict, pkg_dir: Path) -> list[tuple[str, Path]]:
    """Resolve the package's require/CLI entry files — `main` (defaults to index.js)
    and every `bin` target. These run at require()/CLI time, NOT install time, so the
    lifecycle-script analyzers never see them; a self-decoding loader shipped AS the
    entry point (turbo-dls 1.3.5: main=gifted.js) slips past every install-time rule."""
    refs: list[str] = []
    main = data.get("main")
    refs.append(main if isinstance(main, str) and main else "index.js")
    binf = data.get("bin")
    if isinstance(binf, str):
        refs.append(binf)
    elif isinstance(binf, dict):
        refs.extend(str(v) for v in binf.values() if isinstance(v, str))

    out: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    root = pkg_dir.resolve()
    for ref in refs:
        ref = ref.lstrip("./")
        for ext in _RUNTIME_ENTRY_RESOLVE_EXTS:
            cand = (pkg_dir / (ref + ext)).resolve()
            try:
                cand.relative_to(root)
            except ValueError:
                break
            if cand.is_file() and cand not in seen:
                seen.add(cand)
                out.append((ref, cand))
                break
    return out


def _analyze_runtime_entrypoints(
    data: dict, pkg_dir: Path, rel_prefix: str
) -> list[Finding]:
    """Flag a package whose require/CLI entry point IS a self-decoding eval loader
    (char-code or runtime-crypto reconstruction feeding eval/Function). This is the
    runtime-time twin of installer.npm_install_obfuscated_entrypoint: a legitimate
    package does not ship its `main`/`bin` as an opaque self-modifying VM. Reuses the
    obfuscation analyzer's validated discriminators (proximity + build-bundle
    downgrade) so a legitimately minified bundle declared as `main` doesn't FP."""
    from pkgward.analyze import obfuscation as _obf

    out: list[Finding] = []
    for ref, target in _resolve_runtime_entries(data, pkg_dir):
        rel = f"{rel_prefix}{ref}"
        if _obf._is_build_bundle(rel):
            continue  # a minified dist bundle as `main` is normal — not a loader
        if looks_like_compiled_binary(target):
            # A bin/main entry that IS a compiled native binary (Bun/Deno/pkg/
            # Node-SEA `--compile` CLIs; esbuild/swc-style per-platform shims) is
            # not a self-decoding JS loader: read as text, the embedded JS bundle +
            # engine trivially match the char-code/eval heuristic. The binary is
            # still covered by binary.compiled_artifact + YARA + threat-intel +
            # detonation — the JS-source heuristic must not run on it.
            # (@hellyeah/cli-darwin-arm64 FP.)
            continue
        try:
            content = target.read_text(errors="replace")
        except OSError:
            continue
        charcode = _obf._charcode_feeds_eval(content)
        crypto = _obf._crypto_feeds_eval(content)
        if charcode or crypto:
            prim = "char-code" if charcode else "runtime-crypto"
            out.append(Finding(
                rule_id="installer.npm_runtime_obfuscated_entrypoint",
                category=CATEGORY, severity="critical", confidence="high",
                file=rel, line=None,
                evidence=(
                    f"package {('main' if ref == (data.get('main') or 'index.js') else 'bin')} "
                    f"entry self-decodes ({prim}) into eval/Function — the whole module "
                    "is an opaque runtime loader"
                ),
            ))
    return out


def _analyze_manifest(path: Path, extracted_root: Path) -> list[Finding]:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    rel = str(path.relative_to(extracted_root))
    pkg_dir = path.parent
    rel_prefix = (str(pkg_dir.relative_to(extracted_root)) + "/") if pkg_dir != extracted_root else ""

    declared_hosts = _declared_hosts(data)
    findings: list[Finding] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in _INSTALL_HOOKS:
            script = scripts.get(hook)
            if not isinstance(script, str) or not script.strip():
                continue
            findings.extend(_analyze_script(hook, script, rel))
            findings.extend(_analyze_bundled_exec(hook, script, pkg_dir, rel_prefix))
            findings.extend(_analyze_referenced_js(script, pkg_dir, rel_prefix, declared_hosts))

    findings.extend(_analyze_bin(data.get("bin"), rel))
    findings.extend(_analyze_runtime_entrypoints(data, pkg_dir, rel_prefix))
    return findings


# --- binding.gyp / node-gyp command-expansion ("Phantom Gyp" / Miasma) ---------
# node-gyp runs a package's `binding.gyp` for ANY package with native components —
# with no preinstall/postinstall entry in package.json. GYP's `<!(...)` / `<!@(...)`
# command-expansion runs a shell command at *configure* time, so `<!(node index.js …)`
# is arbitrary code execution during `npm install` that lifecycle-script tooling
# (and `--ignore-scripts`) never sees. Legit native modules use it ONLY to read a
# config value, e.g. `<!(node -p "require('node-addon-api').include")`.
_GYP_CMD_EXPANSION = re.compile(r"<!@?\(([^)]*)\)")
_GYP_RUNS_SCRIPT_FILE = re.compile(
    r"\b(?:node|bun|deno|sh|bash|zsh|python[0-9.]*|ruby|perl)\s+[^\s|&;<>]*\."
    r"(?:js|cjs|mjs|ts|sh|bash|py|rb|pl)\b")
_GYP_CONFIG_EVAL = re.compile(r"^\s*(?:node|bun|deno|python[0-9.]*)\s+(?:-p|-e|--print|--eval|-c)\b")
_GYP_SHELL_OP = re.compile(r"&&|\|\||;|\||>|2>&1|`|\$\(")
_GYP_FETCH = re.compile(r"\b(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b")


def _binding_gyp_findings(content: str, rel: str) -> list[Finding]:
    """Flag install-time code execution via node-gyp command-expansion in binding.gyp."""
    out: list[Finding] = []
    seen: set[str] = set()
    for m in _GYP_CMD_EXPANSION.finditer(content):
        cmd = m.group(1).strip().strip("\"'").strip()
        if not cmd or cmd in seen:
            continue
        runs_script = bool(_GYP_RUNS_SCRIPT_FILE.search(cmd))
        has_shell = bool(_GYP_SHELL_OP.search(cmd))
        has_fetch = bool(_GYP_FETCH.search(cmd))
        # a bare config-value read (`node -p "require('x').include"`) is benign
        if _GYP_CONFIG_EVAL.match(cmd) and not (runs_script or has_shell or has_fetch):
            continue
        seen.add(cmd)
        sev = "critical" if (runs_script or has_fetch) else "high"
        out.append(Finding(
            rule_id="installer.npm_binding_gyp_command_exec", category=CATEGORY,
            severity=sev, confidence="high", file=rel, line=None,
            evidence=("binding.gyp runs code at install time via node-gyp command-expansion "
                      f"(bypasses lifecycle scripts): <!({cmd[:140]})"),
        ))
    return out


def analyze_install_scripts(
    extracted_root: Path,
    changed_files: Optional[set[str]] = None,
) -> list[Finding]:
    """Analyze the package's lifecycle scripts for install-time attack patterns."""
    findings: list[Finding] = []
    for manifest in _root_package_json_paths(extracted_root):
        findings.extend(_analyze_manifest(manifest, extracted_root))
        # binding.gyp / node-gyp command-expansion — install-time exec with no
        # lifecycle script (Phantom Gyp). Sits next to the root manifest.
        gyp = manifest.parent / "binding.gyp"
        if gyp.is_file():
            try:
                content = gyp.read_bytes().decode("utf-8", "replace")
            except OSError as e:
                # A binding.gyp we can stat but not read would SILENTLY skip an
                # install-time-exec rule (Phantom Gyp) — a malware miss with no
                # trace. Surface it rather than fail to a clean verdict.
                log.warning("binding_gyp_unreadable", path=str(gyp), error=str(e))
                content = ""
            findings.extend(_binding_gyp_findings(content, str(gyp.relative_to(extracted_root))))
    return findings
