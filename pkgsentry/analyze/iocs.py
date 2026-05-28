# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import re
from pathlib import Path

from pkgsentry import intel
from pkgsentry.adapter import Finding

CATEGORY = "iocs"

_URL_RE = re.compile(rb"https?://([^\s'\"<>()]+)")
_OCTET = rb"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4_RE = re.compile(rb"\b" + _OCTET + rb"(?:\." + _OCTET + rb"){3}\b")
_ONION_RE = re.compile(rb"\b[a-z2-7]{16,56}\.onion\b")
_B64_RE = re.compile(rb"['\"]([A-Za-z0-9+/]{160,}={0,2})['\"]")

_PRIVATE_OR_LOCAL = re.compile(
    rb"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|169\.254\.|255\.|"
    rb"169\.254\.|224\.|240\.|0\.)"
)
_DOC_RANGE_RE = re.compile(rb"^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)")
# Textbook placeholder IPs used in docs/examples (kept tight — real public
# resolvers like 1.1.1.1/8.8.8.8 are left flaggable, whitelistable via intel).
_PLACEHOLDER_IPS = frozenset({b"1.2.3.4", b"4.3.2.1"})

# Benign-domain whitelist is loaded from the intel pack (baseline + overlay,
# UNION-merged). See pkgsentry/intel/baseline/ioc_whitelist.toml for the
# public defaults; operators add tuning via their private overlay.
def _benign_domains() -> set[bytes]:
    return intel.current().ioc_whitelist

def _domain_of(url: bytes) -> bytes:
    host = url.split(b"/", 1)[0].split(b":", 1)[0].lower()
    parts = host.split(b".")
    if len(parts) > 2:
        return b".".join(parts[-2:])
    return host

_TEMPLATE_URL_RE = re.compile(rb"[{%$]|^\.{2,}$|^:$|^test")
# Markdown/RST artifacts that leak into URL captures: trailing backticks, punctuation, brackets
_JUNK_SUFFIX_RE = re.compile(rb"[`),;'\"\]>]+$")

# Placeholder hosts in docs/config examples: `http://host:port`, `http://server/...`
_PLACEHOLDER_HOSTS = frozenset({
    b"host", b"hostname", b"your-host", b"your_host", b"yourhost", b"server",
    b"ip", b"ipaddress", b"ip-address", b"address", b"domain", b"yourdomain",
    b"example", b"host1", b"host2", b"myhost",
})
# RFC 2606 reserved example domains (and the .example TLD).
_PLACEHOLDER_DOMAINS = frozenset({
    b"example.com", b"example.org", b"example.net", b"example.edu",
})

def _is_benign_url(url: bytes) -> bool:
    benign = _benign_domains()
    # Strip trailing markdown/RST junk before extracting host
    cleaned = _JUNK_SUFFIX_RE.sub(b"", url)
    host = cleaned.split(b"/", 1)[0].split(b":", 1)[0].lower()
    if host in benign:
        return True
    if host in _PLACEHOLDER_HOSTS:
        return True
    if host.startswith(b"localhost") or host.endswith(b".localhost"):
        return True
    if _TEMPLATE_URL_RE.search(host):
        return True
    if host.endswith((b".test", b".invalid", b".localdomain")):
        return True
    # Also check the full URL for template variables anywhere (f-strings, Jinja, etc.)
    if b"{" in url or b"${" in url or b"{{" in url:
        return True
    base = _domain_of(cleaned)
    if base in _PLACEHOLDER_DOMAINS:
        return True
    return base in benign

_TEXT_SUFFIXES = {
    ".py", ".cfg", ".toml", ".ini", ".txt", ".md", ".rst", ".json", ".yml", ".yaml",
    ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".rs", ".go", ".sh", ".ps1", ".bat",
}

# Documentation / attribution files: URLs and IPs here are almost always doc
# links or example addresses, not IOCs. Skip the low/low url/ipv4 extraction for
# them (onion + base64 blobs are still flagged — notable in any file).
_DOC_BASENAMES = (
    "readme", "notice", "license", "licence", "copying", "copyright",
    "changelog", "changes", "history", "authors", "contributors", "credits", "thanks",
    "security", "support", "code_of_conduct", "code-of-conduct", "governance",
    "maintainers", "contributing",
)
_DOC_SUFFIXES = (".md", ".rst")


def _is_doc_file(name: str) -> bool:
    lower = name.lower()
    # Markdown/reStructuredText is prose: URLs and IPs in it are doc links or
    # example addresses, not IOCs. (onion + base64 blobs still fire — notable
    # anywhere.) Named doc files without a doc extension (SECURITY, AUTHORS…)
    # are covered by the basename prefixes.
    if lower.endswith(_DOC_SUFFIXES):
        return True
    return any(lower.startswith(d) for d in _DOC_BASENAMES)


def _scan_file(path: Path) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    out: list[Finding] = []
    seen: set[tuple[str, bytes]] = set()
    is_doc = _is_doc_file(path.name)
    for m in _URL_RE.finditer(data):
        url_body = m.group(1)
        full_url = m.group(0)
        key = ("url", full_url)
        if key in seen:
            continue
        seen.add(key)
        if is_doc or _is_benign_url(url_body):
            continue
        out.append(Finding(
            rule_id="iocs.url_suspicious", category=CATEGORY, severity="low", confidence="low",
            file=path.name, line=None, evidence=full_url.decode("utf-8", errors="replace")[:200],
        ))
    for m in _IPV4_RE.finditer(data):
        if is_doc:
            continue
        ip = m.group(0)
        if _PRIVATE_OR_LOCAL.match(ip):
            continue
        if _DOC_RANGE_RE.match(ip):
            continue
        if ip in _PLACEHOLDER_IPS:
            continue
        key = ("ip", ip)
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            rule_id="iocs.ipv4", category=CATEGORY, severity="low", confidence="low",
            file=path.name, line=None, evidence=ip.decode("ascii", errors="replace"),
        ))
    for m in _ONION_RE.finditer(data):
        key = ("onion", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            rule_id="iocs.onion", category=CATEGORY, severity="high", confidence="high",
            file=path.name, line=None, evidence=m.group(0).decode("ascii"),
        ))
    for m in _B64_RE.finditer(data):
        out.append(Finding(
            rule_id="iocs.base64_blob", category=CATEGORY, severity="medium", confidence="low",
            file=path.name, line=None,
            evidence=m.group(1)[:64].decode("ascii", errors="replace") + "...",
        ))
    return out


def analyze_iocs(
    extracted_root: Path,
    changed_files: set[str] | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    for p in extracted_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        if changed_files is not None and p.relative_to(extracted_root).as_posix() not in changed_files:
            continue
        out.extend(_scan_file(p))
    return out
