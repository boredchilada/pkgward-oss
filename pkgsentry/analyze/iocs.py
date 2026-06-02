# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import binascii
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

# Cloud metadata endpoints — link-local (normally skipped below) but high-signal:
# SSRF / cloud-credential theft (AWS IMDS, ECS task-role). Flagged despite the
# link-local skip. (metadata.google.internal is a hostname, caught via URLs.)
_METADATA_IPS = frozenset({b"169.254.169.254", b"169.254.170.2"})
# Well-known benign public IPs (public DNS resolvers) — public but not C2; do NOT
# raise the hardcoded-IP+port C2 signal on these.
_BENIGN_PUBLIC_IPS = frozenset({
    b"8.8.8.8", b"8.8.4.4", b"1.1.1.1", b"1.0.0.1", b"9.9.9.9",
    b"149.112.112.112", b"208.67.222.222", b"208.67.220.220", b"4.2.2.1", b"4.2.2.2",
})
# A :port immediately following an IP literal — the C2-beacon shape 1.2.3.4:8080.
_PORT_AFTER_RE = re.compile(rb"^:(\d{1,5})\b")

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


# Out-of-band interaction / request-capture services. A package beaconing to one
# of these — especially at install time — is near-certainly exfil/recon C2; they
# have no legitimate install-time use (unlike dual-use dev tunnels such as ngrok,
# deliberately excluded). Seen live: oastify.com (oob.moika.tech campaign used a
# self-hosted domain; adminui-deps used oastify.com). Suffix-matched so subdomains
# (zkn54….oastify.com) hit. Operators can extend via the intel overlay later.
# Pure pentest / OOB-interaction services only. Dual-use HTTP-mock / webhook /
# automation services (webhook.site, beeceptor.com, pipedream.net, requestbin.*)
# were REMOVED — they have heavy legitimate use (test fixtures, integrations) and
# FP'd on benign packages (aoticombr/golang). Such URLs still fire iocs.url_suspicious
# (low); we just don't escalate them to the high oast_callback signal. dnslog.cn and
# requestcatcher.com are kept (overwhelmingly OOB-exfil, used by live campaigns).
_OAST_DOMAINS = (
    "oastify.com", "interact.sh", "oast.fun", "oast.site", "oast.pro",
    "oast.live", "oast.online", "oast.me", "burpcollaborator.net",
    "dnslog.cn", "requestcatcher.com", "canarytokens.com", "canarytokens.org",
)


def _is_oast_url(url_bytes: bytes) -> bool:
    """True if the URL's host is (a subdomain of) a known OOB-interaction service."""
    try:
        u = url_bytes.decode("utf-8", "replace").lower()
    except Exception:
        return False
    host = u.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    host = host.split("#", 1)[0].split("@")[-1].split(":", 1)[0].strip().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in _OAST_DOMAINS)


# --- simple-encoding decode pass: surface IOCs hidden behind base64 / hex / \xNN.
# A C2 URL or IP concealed in an encoded blob is a deliberate-concealment signal,
# stronger than a plaintext one — decode candidate blobs and re-run URL + IP
# extraction on the decoded bytes.
_B64_CAND_RE = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_HEXSTR_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){12,}")
_XESC_RE = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){4,}")
_DECODE_BLOB_CAP = 400  # bound per-file work on big/minified files


def _mostly_printable(b: bytes) -> bool:
    if len(b) < 6:
        return False
    ok = sum(1 for c in b if 0x20 <= c <= 0x7E or c in (9, 10, 13))
    return ok / len(b) >= 0.85


def _decode_blobs(data: bytes) -> list[bytes]:
    out: list[bytes] = []
    n = 0
    for m in _B64_CAND_RE.finditer(data):
        if n >= _DECODE_BLOB_CAP:
            break
        n += 1
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + b"=" * ((-len(blob)) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        if _mostly_printable(dec):
            out.append(dec)
    for m in _XESC_RE.finditer(data):
        if n >= _DECODE_BLOB_CAP:
            break
        n += 1
        try:
            dec = bytes(int(h, 16) for h in re.findall(rb"\\x([0-9a-fA-F]{2})", m.group(0)))
        except ValueError:
            continue
        if _mostly_printable(dec):
            out.append(dec)
    for m in _HEXSTR_RE.finditer(data):
        if n >= _DECODE_BLOB_CAP:
            break
        n += 1
        h = m.group(0)
        if len(h) % 2:
            h = h[:-1]
        try:
            dec = bytes.fromhex(h.decode("ascii"))
        except ValueError:
            continue
        if _mostly_printable(dec):
            out.append(dec)
    return out


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
        if _is_oast_url(full_url):
            out.append(Finding(
                rule_id="iocs.oast_callback", category=CATEGORY, severity="high", confidence="high",
                file=path.name, line=None,
                evidence=full_url.decode("utf-8", errors="replace")[:200],
            ))
            continue
        out.append(Finding(
            rule_id="iocs.url_suspicious", category=CATEGORY, severity="low", confidence="low",
            file=path.name, line=None, evidence=full_url.decode("utf-8", errors="replace")[:200],
        ))
    for m in _IPV4_RE.finditer(data):
        if is_doc:
            continue
        ip = m.group(0)
        # Cloud metadata SSRF endpoint (link-local, but credential-theft signal).
        if ip in _METADATA_IPS:
            key = ("meta", ip)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                rule_id="iocs.cloud_metadata_endpoint", category=CATEGORY,
                severity="medium", confidence="high", file=path.name, line=None,
                evidence=f"cloud metadata endpoint {ip.decode('ascii')} (SSRF / credential theft)",
            ))
            continue
        if _PRIVATE_OR_LOCAL.match(ip):
            continue
        if _DOC_RANGE_RE.match(ip):
            continue
        if ip in _PLACEHOLDER_IPS:
            continue
        # Hardcoded routable IP with an explicit :port — the C2-beacon shape. Legit
        # code resolves DNS hostnames; malware hardcodes an IP+port to dodge DNS /
        # sinkholes. (Public DNS resolvers are excluded.)
        pm = _PORT_AFTER_RE.match(data[m.end():m.end() + 7])
        if pm and ip not in _BENIGN_PUBLIC_IPS:
            port = int(pm.group(1))
            if 1 <= port <= 65535:
                key = ("ipport", ip, port)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding(
                    rule_id="iocs.hardcoded_wan_ip_port", category=CATEGORY,
                    severity="high", confidence="medium", file=path.name, line=None,
                    evidence=f"{ip.decode('ascii')}:{port} — hardcoded routable IP + port (C2-beacon shape)",
                ))
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

    # Decode-and-rescan: a URL or routable/C2/metadata IP hidden inside a base64 /
    # hex / \xNN blob is deliberate concealment — surface it (the analyzer otherwise
    # only sees the opaque blob).
    if not is_doc:
        for dec in _decode_blobs(data):
            for um in _URL_RE.finditer(dec):
                url_body = um.group(1)
                full = um.group(0)
                host = url_body.split(b"/", 1)[0]
                # require a dotted host; benign/oast are handled by the raw pass
                if b"." not in host or _is_benign_url(url_body) or _is_oast_url(full):
                    continue
                key = ("enc_url", full)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding(
                    rule_id="iocs.encoded_url", category=CATEGORY,
                    severity="medium", confidence="medium", file=path.name, line=None,
                    evidence="decoded: " + full.decode("utf-8", errors="replace")[:160],
                ))
            for im in _IPV4_RE.finditer(dec):
                ip = im.group(0)
                if ip in _METADATA_IPS:
                    why = "cloud metadata endpoint (SSRF / credential theft)"
                elif (_PRIVATE_OR_LOCAL.match(ip) or _DOC_RANGE_RE.match(ip)
                        or ip in _PLACEHOLDER_IPS or ip in _BENIGN_PUBLIC_IPS):
                    continue
                else:
                    why = "routable IP"
                key = ("enc_ip", ip)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding(
                    rule_id="iocs.encoded_ip", category=CATEGORY,
                    severity="high", confidence="medium", file=path.name, line=None,
                    evidence=f"decoded: {ip.decode('ascii')} ({why})",
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
