# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fetch + statically analyze second-stage dependencies pulled from URL specs on
suspicious file hosters (cloud buckets, abuse/tunnel hosts).

npm allows a dependency value to be a raw tarball URL instead of a registry range.
A dependency-confusion / staged-payload package points that URL at attacker infra —
e.g. ``corporate-front-vue`` ->
``https://<bucket>.storage.googleapis.com/depenconf/ltidisafe-*.tgz`` whose
``preinstall`` hex-exfils host/user to a Burp Collaborator callback. We:

  1. ALWAYS flag the URL dependency statically (``installer.npm_url_dependency``).
  2. For suspicious hosts, fetch the tarball (bounded + SSRF-guarded, NEVER executed),
     extract it, run the static analyzers over it, and merge the findings so the
     second-stage payload convicts the parent at scan time.

The fetch reaches out to attacker-controlled infrastructure from the scanner host,
so it's gated by ``PKGWARD_FETCH_URL_DEPS`` (default on) for operators who want to
keep the scanner's egress dark.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import socket
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from pkgward.adapter import Finding
from pkgward.logging_setup import get_logger
from pkgward.util.extract import safe_extract
from pkgward.util.user_agent import user_agent

log = get_logger("npm.url_deps")

CATEGORY = "installer"
_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_URL_SPEC_RE = re.compile(r"^https?://", re.IGNORECASE)

# Hosts with ~zero legitimate reason to host an npm dependency tarball and that are
# favored for staged-payload delivery. Suffix-matched.
_SUSPICIOUS_SUFFIXES = (
    "storage.googleapis.com", "s3.amazonaws.com", "amazonaws.com",
    "blob.core.windows.net", "r2.dev", "r2.cloudflarestorage.com",
    "workers.dev", "pages.dev", "trycloudflare.com", "ngrok.io", "ngrok-free.app",
    "ngrok.app", "ngrok.dev", "deno.dev", "val.run", "glitch.me", "repl.co",
    "replit.dev", "surge.sh", "serveo.net", "loca.lt", "telebit.io",
    "transfer.sh", "anonfiles.com", "gofile.io", "file.io", "0x0.st", "termbin.com",
    "pastebin.com", "paste.ee", "ghostbin.com", "rentry.co",
    "gist.githubusercontent.com", "raw.githubusercontent.com",
)

MAX_FETCH_BYTES = int(os.environ.get("PKGWARD_URL_DEP_MAX_MB", "20")) * 1024 * 1024
FETCH_TIMEOUT = float(os.environ.get("PKGWARD_URL_DEP_TIMEOUT", "15"))
MAX_DEPS = int(os.environ.get("PKGWARD_URL_DEP_MAX_COUNT", "3"))


def _fetch_enabled() -> bool:
    return os.environ.get("PKGWARD_FETCH_URL_DEPS", "1") == "1"


def _host_suspicious(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in _SUSPICIOUS_SUFFIXES)


def _extract_url_deps(manifest: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key in _DEP_KEYS:
        deps = manifest.get(key)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if isinstance(spec, str) and _URL_SPEC_RE.match(spec.strip()):
                out.append((str(name), spec.strip()))
    return out


def _ssrf_safe(host: str) -> bool:
    """Reject hosts that resolve to a private/loopback/link-local/reserved IP so the
    scanner can't be coerced into fetching internal resources (incl. cloud metadata)."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    if not infos:
        return False
    for *_rest, sockaddr in infos:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return True


async def _bounded_get(url: str) -> bytes:
    # No redirect-following: a 30x to an internal host would bypass the SSRF check.
    async with httpx.AsyncClient(headers={"User-Agent": user_agent()},
                                 follow_redirects=False) as client:
        async with client.stream("GET", url, timeout=FETCH_TIMEOUT) as resp:
            if resp.status_code != 200:
                return b""
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > MAX_FETCH_BYTES:
                    raise ValueError("url dependency exceeds size cap")
            return bytes(buf)


def _analyze_stage_bytes(dep_name: str, data: bytes) -> list[Finding]:
    """Extract the fetched archive and run the static analyzers over it (never exec).
    Findings keep their rule_ids (so they convict the parent) but their file path is
    namespaced to the fetched dependency."""
    from pkgward.analyze.iocs import analyze_iocs
    from pkgward.analyze.malware_patterns import analyze_malware_patterns
    from pkgward.analyze.yara_scan import analyze_yara
    from pkgward.ecosystems.npm.installer import analyze_install_scripts

    with tempfile.TemporaryDirectory(prefix="urldep-") as td:
        tdp = Path(td)
        arc = tdp / ("stage.zip" if data[:2] == b"PK" else "stage.tgz")
        arc.write_bytes(data)
        dest = tdp / "x"
        try:
            root = safe_extract(arc, dest, max_files=5000, max_total_bytes=MAX_FETCH_BYTES)
        except Exception as e:
            log.warning("url_dep_extract_failed", name=dep_name, error=str(e))
            return []
        out: list[Finding] = []
        for fn in (analyze_install_scripts, analyze_iocs, analyze_malware_patterns, analyze_yara):
            try:
                out.extend(fn(root))
            except Exception as e:
                log.warning("url_dep_analyze_failed", name=dep_name, analyzer=fn.__name__, error=str(e))
        for f in out:
            f.file = f"[fetched-dep:{dep_name}] {f.file}"
        if out:
            log.warning("url_dep_second_stage_findings", name=dep_name, n=len(out),
                        rules=sorted({f.rule_id for f in out})[:10])
        return out


async def _fetch_and_analyze(dep_name: str, url: str) -> list[Finding]:
    try:
        data = await _bounded_get(url)
    except Exception as e:
        log.warning("url_dep_fetch_failed", name=dep_name, error=str(e))
        return []
    if not data:
        return []
    return await asyncio.to_thread(_analyze_stage_bytes, dep_name, data)


async def analyze_url_dependencies(extracted_root: Path) -> list[Finding]:
    """Flag URL-spec dependencies; fetch + statically analyze ones on suspicious hosts."""
    from pkgward.ecosystems.npm.installer import _root_package_json_paths

    url_deps: list[tuple[str, str]] = []
    for mp in _root_package_json_paths(extracted_root):
        try:
            manifest = json.loads(mp.read_text(errors="replace"))
        except Exception:
            continue
        if isinstance(manifest, dict):
            url_deps.extend(_extract_url_deps(manifest))
    if not url_deps:
        return []

    seen: set[str] = set()
    findings: list[Finding] = []
    fetched = 0
    for name, url in url_deps:
        if url in seen:
            continue
        seen.add(url)
        host = (urlparse(url).hostname or "").lower()
        suspicious = _host_suspicious(host)
        findings.append(Finding(
            rule_id="installer.npm_url_dependency", category=CATEGORY,
            severity="high" if suspicious else "medium", confidence="high",
            file="package.json", line=None,
            evidence=(f"dependency {name!r} is a direct URL"
                      + (" on a suspicious file host" if suspicious else "")
                      + f" (not a registry range): {url[:200]}"),
        ))
        if suspicious and _fetch_enabled() and fetched < MAX_DEPS:
            if not _ssrf_safe(host):
                log.warning("url_dep_ssrf_blocked", host=host, name=name)
                continue
            fetched += 1
            findings.extend(await _fetch_and_analyze(name, url))
    return findings
