# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import binascii
import os
import re
from pathlib import Path

from pkgward import intel
from pkgward.adapter import Finding

CATEGORY = "iocs"

# Per-file size ceiling for the recursive multi-layer decode pass (decode_engine).
# The engine is internally budgeted, but candidate extraction on a huge bundle is
# still work we run per-file across every package — skip the largest files.
_DECODE_RECOVER_MAX_BYTES = int(os.environ.get("PKGWARD_DECODE_RECOVER_MAX_MB", "2")) * 1024 * 1024

# A genuinely HIDDEN payload is base64/hex/compression-encoded — never merely
# "reversed". A decode chain that's purely `reverse` recovers visible source (which
# trivially contains code tokens), so it is not evidence of concealment. Require at
# least one real transform before treating a recovered layer as a hidden payload.
def _chain_has_real_decode(chain) -> bool:
    return any(step != "reverse" for step in chain)

# For decoded_code: the recovered bytes must contain an actual EXECUTION sink, not the
# require()/function() that appears in every JS/Go file. This is what separates a
# concealed loader from a bundle that happens to base64 a code chunk (source maps,
# webpack eval-chunks, inline templates).
_DECODED_EXEC_SINK = re.compile(
    rb"eval\s*\(|new\s+Function\s*\(|Function\s*\(\s*['\"]|child_process|"
    rb"\.exec(?:File|Sync)?\s*\(|\bspawn(?:Sync)?\s*\(|execSync|os\.system|"
    rb"subprocess\.(?:Popen|call|run|check_output)",
    re.IGNORECASE,
)

# File-level execution primitives, used to qualify iocs.decoded_executable. A
# concealed *native* binary (PE/ELF/Mach-O) does not carry an eval/require sink in
# its own bytes the way a decoded *script* does — the run happens in the surrounding
# source. So the "dropper shape" (decode -> write -> EXECUTE) is only real when the
# file that embeds the binary can also launch a process. Spans Go/native in addition
# to the JS/Python sinks above: legit cert/installer/resource tooling embeds binaries
# to parse or ship them (smallstep/cli winpe_test.go decodes a PE to test PE parsing
# and never execs it) — only the embed+exec conjunction is a dropper.
_FILE_EXEC_SINK = re.compile(
    rb"exec\.Command(?:Context)?\s*\(|syscall\.(?:Exec|ForkExec|StartProcess)\s*\(|"
    rb"\bos/exec\b|child_process|\.exec(?:File|Sync)?\s*\(|\bspawn(?:Sync)?\s*\(|"
    rb"execSync|os\.system|subprocess\.(?:Popen|call|run|check_output)|"
    rb"CreateProcess|ShellExecute|WinExec",
    re.IGNORECASE,
)

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
# WebRTC TURN/STUN context. A hardcoded `turn:<ip>:3478` / `stun:<ip>:port` is the
# CORRECT, canonical way to configure a real-time client (every video-call / KYC /
# telehealth SDK does it; TURN relay creds are low-value and routinely shipped
# client-side), so a routable IP:port here is configuration, NOT a C2 beacon — the
# @b8safe react-native-safe FP. Suppress the hardcoded_wan_ip_port signal when the
# IP sits in a turn:/turns:/stun: URI or an iceServers/RTCPeerConnection context.
_WEBRTC_URI_PREFIX_RE = re.compile(rb"(?:turns?|stun):$", re.IGNORECASE)
_WEBRTC_CONTEXT_RE = re.compile(
    rb"iceServers|RTCPeerConnection|RTCIceServer|createDataChannel|urls?\s*:\s*['\"]turns?:",
    re.IGNORECASE,
)
# How far around the IP literal to look for WebRTC context tokens.
_WEBRTC_WINDOW = 400

# Benign-domain whitelist is loaded from the intel pack (baseline + overlay,
# UNION-merged). See pkgward/intel/baseline/ioc_whitelist.toml for the
# public defaults; operators add tuning via their private overlay.
def _benign_domains() -> set[bytes]:
    return intel.current().ioc_whitelist

def _domain_of(url: bytes) -> bytes:
    host = url.split(b"/", 1)[0].split(b":", 1)[0].lower()
    parts = host.split(b".")
    if len(parts) > 2:
        return b".".join(parts[-2:])
    return host

# Template/placeholder host whitelist. The test-placeholder arm is anchored to the
# WHOLE host (test, testserver, test.com, ...) — a bare "^test" prefix silently
# whitelisted real C2 on any host starting with "test" (test-c2.evil.com).
_TEMPLATE_URL_RE = re.compile(
    rb"[{%$]|^\.{2,}$|^:$|^test(?:server|host|ing|bed|\.(?:com|org|net|local|example|invalid))?$"
)
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


# Unit-test / fixture files. Hardcoded IPs (often IP:port), example URLs, and
# placeholder hosts are normal *test data* there, not IOCs — a routable IP:port
# in `plugin_test.go` is a fixture, not a C2 beacon. The low/low url+ipv4 noise is
# suppressed and the high `hardcoded_wan_ip_port` is down-weighted to low so a big
# project's test suite (e.g. kgateway) doesn't read as suspicious. Genuinely
# notable IOCs (oast/abuse-hosting/cloud-metadata/onion/encoded) still fire here —
# malware hiding in a test/ path shouldn't get a free pass.
_TEST_BASENAME_RES = (
    re.compile(r".*_test\.go$"),                       # Go: foo_test.go
    re.compile(r"(^test_.*|.*_test)\.py$"),            # Python: test_x.py / x_test.py
    re.compile(r"^conftest\.py$"),                     # pytest
    re.compile(r".*\.(test|spec)\.[cm]?[jt]sx?$"),     # JS/TS: x.test.ts / x.spec.js
)
_TEST_DIR_PARTS = frozenset((
    "test", "tests", "testdata", "testing",
    "__tests__", "__test__", "fixtures", "fixture", "spec", "specs", "e2e",
))


def _is_test_file(path: Path) -> bool:
    name = path.name.lower()
    if any(rx.match(name) for rx in _TEST_BASENAME_RES):
        return True
    return any(part.lower() in _TEST_DIR_PARTS for part in path.parts)


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

# Bare/concatenated OAST-domain literal — catches string-built callbacks like
# `"http://" + data + ".oastify.com"` that the full-URL matcher misses (the payload
# splits the URL specifically to dodge URL-literal scanners). These domains have
# ~zero legitimate use inside package source.
_OAST_LITERAL_RE = re.compile(
    rb"\b(?:" + b"|".join(re.escape(d.encode("ascii")) for d in _OAST_DOMAINS) + rb")\b",
    re.IGNORECASE,
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


# Abuse-prone serverless / tunnel hosting. These hosts sit behind a big provider's
# trusted CDN IPs (Cloudflare/Vercel/etc.), so IP-based allowlists wave them through
# even though they're disproportionately used for C2 / install-time exfil — a package
# beaconing to one is near-certainly malicious. Matched by DOMAIN (the static layer
# sees the hostname; detonation can't, which is exactly the gap). Heavy-legit app
# hosts (vercel.app/netlify.app/herokuapp.com) are deliberately NOT in this general
# list — they're handled in the install-script context to avoid FP on legit links.
_ABUSE_HOSTING = (
    "workers.dev", "pages.dev", "trycloudflare.com", "r2.dev",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev",
    "deno.dev", "val.run", "glitch.me", "repl.co", "replit.dev",
    "surge.sh", "serveo.net", "loca.lt", "telebit.io", "webhook.cool",
)


def _is_abuse_hosting_url(url_bytes: bytes) -> bool:
    """True if the URL's host is (a subdomain of) an abuse-prone hosting/tunnel host."""
    try:
        u = url_bytes.decode("utf-8", "replace").lower()
    except Exception:
        return False
    host = u.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    host = host.split("#", 1)[0].split("@")[-1].split(":", 1)[0].strip().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in _ABUSE_HOSTING)


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
    # Per-type budgets, NOT one shared cap: a base64-heavy file must not exhaust the
    # budget before the hex/\xNN passes run — deliberately-concealed C2 (the highest-
    # signal case this exists to catch) routinely hides in exactly those encodings.
    nb = 0
    for m in _B64_CAND_RE.finditer(data):
        if nb >= _DECODE_BLOB_CAP:
            break
        nb += 1
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + b"=" * ((-len(blob)) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        if _mostly_printable(dec):
            out.append(dec)
    nx = 0
    for m in _XESC_RE.finditer(data):
        if nx >= _DECODE_BLOB_CAP:
            break
        nx += 1
        try:
            dec = bytes(int(h, 16) for h in re.findall(rb"\\x([0-9a-fA-F]{2})", m.group(0)))
        except ValueError:
            continue
        if _mostly_printable(dec):
            out.append(dec)
    nh = 0
    for m in _HEXSTR_RE.finditer(data):
        if nh >= _DECODE_BLOB_CAP:
            break
        nh += 1
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


# LLM-triage manipulation text, split by confidence:
#
# SCHEMA-MIMICRY (iocs.llm_prompt_injection, high, NON-downgradable in triage): the
# source contains our exact internal triage-output field — essentially zero
# legitimate reason, so an injected verdict can't be trusted to clear the package.
_LLM_SCHEMA_MIMIC_RES = (
    re.compile(rb"agrees_with_rules", re.IGNORECASE),  # our exact output-schema field
)
# INSTRUCTION-OVERRIDE PHRASES (iocs.llm_injection_phrase, medium, downgradable):
# real but FP-prone — they appear in large minified bundles incidentally AND in
# DEFENSIVE security tools that list injection patterns to block them
# (mindforge INJECTION_GUARD, capgo bundle). So this is informational: the LLM still
# sees it and adjudicates; it does NOT force the verdict.
_LLM_OVERRIDE_RES = (
    re.compile(rb"[\"']verdict[\"']\s*:\s*[\"'](?:benign|safe)", re.IGNORECASE),
    re.compile(rb"ignore\s+(?:all\s+|the\s+|any\s+)*(?:previous|prior|above|preceding|earlier|system)\s+(?:instruction|prompt|message|rule)", re.IGNORECASE),
    re.compile(rb"disregard\s+(?:all\s+|the\s+|any\s+)*(?:previous|prior|above|preceding|earlier|system)\b", re.IGNORECASE),
    re.compile(rb"(?:mark|classify|label|treat|rate|consider|report)\s+(?:this|it|the\s+\w+)\s+(?:package\s+|code\s+|file\s+)?(?:as\s+)?(?:safe|benign|clean|trusted|not\s+malicious|non-malicious|a\s+false\s+positive)", re.IGNORECASE),
)


def _scan_file(path: Path) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    out: list[Finding] = []
    seen: set[tuple[str, bytes]] = set()
    is_doc = _is_doc_file(path.name)
    is_test = _is_test_file(path)
    for _rx in _LLM_SCHEMA_MIMIC_RES:
        _mi = _rx.search(data)
        if _mi:
            out.append(Finding(
                rule_id="iocs.llm_prompt_injection", category=CATEGORY,
                severity="high", confidence="high", file=path.name, line=None,
                evidence="LLM triage output-schema mimicry in source: "
                + _mi.group(0).decode("utf-8", errors="replace")[:160],
            ))
            break
    for _rx in _LLM_OVERRIDE_RES:
        _mi = _rx.search(data)
        if _mi:
            out.append(Finding(
                rule_id="iocs.llm_injection_phrase", category=CATEGORY,
                severity="medium", confidence="low", file=path.name, line=None,
                evidence="LLM instruction-override phrase in source (informational; "
                "also appears in defensive injection-guard lists): "
                + _mi.group(0).decode("utf-8", errors="replace")[:160],
            ))
            break
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
        if _is_abuse_hosting_url(full_url):
            out.append(Finding(
                rule_id="iocs.abuse_hosting_callback", category=CATEGORY,
                severity="medium", confidence="high", file=path.name, line=None,
                evidence="callback to abuse-prone hosting/tunnel host: "
                + full_url.decode("utf-8", errors="replace")[:160],
            ))
            continue
        if is_test:
            continue  # example URLs in test fixtures are not IOCs
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
                # WebRTC TURN/STUN config — not a C2 beacon. Suppress when the IP is
                # the host of a turn:/turns:/stun: URI, or sits in an iceServers /
                # RTCPeerConnection context window (the react-native-safe FP).
                if _WEBRTC_URI_PREFIX_RE.search(data[max(0, m.start() - 8):m.start()]) or \
                   _WEBRTC_CONTEXT_RE.search(
                       data[max(0, m.start() - _WEBRTC_WINDOW):m.end() + _WEBRTC_WINDOW]):
                    continue
                key = ("ipport", ip, port)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding(
                    rule_id="iocs.hardcoded_wan_ip_port", category=CATEGORY,
                    # In a test/fixture file a routable IP:port is fixture data, not a
                    # beacon — keep the signal but drop it to low so it can't drive a verdict.
                    severity="low" if is_test else "high", confidence="medium",
                    file=path.name, line=None,
                    evidence=f"{ip.decode('ascii')}:{port} — hardcoded routable IP + port (C2-beacon shape)"
                    + (" [test fixture]" if is_test else ""),
                ))
                continue
        if is_test:
            continue  # example IPs in test fixtures are not IOCs
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

        # Recursive multi-layer decode (decode_engine.recover): catches what the
        # single-layer pass above can't — b64->gzip->b64 chains, and recovered
        # executables / shebang scripts / hidden code. recover() returns ONLY layers
        # carrying a URL, code token, or executable magic (benign printable layers —
        # certs, serialized framework data — are dropped), so it does NOT fire on
        # benign base64 data (the fazzgram class).
        if len(data) <= _DECODE_RECOVER_MAX_BYTES:
            try:
                from pkgward.analyze import decode_engine
                _layers = decode_engine.recover(data)
            except Exception:
                _layers = []
            for _d in _layers:
                _chain = "->".join(_d.chain)
                # A hidden executable is base64/hex/compressed — a pure-reverse "chain"
                # is a false recovery (reversed text that happens to start with a magic).
                if decode_engine._is_executable(_d.data) and _chain_has_real_decode(_d.chain):
                    _k = ("dec_exe", _chain, _d.data[:4])
                    if _k in seen:
                        continue
                    seen.add(_k)
                    _kind = "shebang script" if _d.data.startswith(b"#!/") else "native executable"
                    # "Dropper shape" = decode -> write -> EXECUTE. The decoded bytes are a
                    # raw binary, so the execution primitive lives in the surrounding source,
                    # not the blob — qualify on the file's own exec sink. No sink => the file
                    # embeds a binary to parse/ship it (cert/installer tooling), not run it.
                    # Test files de-escalate further: they only execute under an explicit test
                    # run, never on the victim's install/import, and are the dominant FP source
                    # (PE-parse tests, fuzz corpora — smallstep/cli winpe_test.go).
                    _has_sink = bool(_FILE_EXEC_SINK.search(data))
                    if _has_sink and not is_test:
                        _sev, _conf = "critical", "high"
                        _ev = f"source decodes a hidden {_kind} via [{_chain}] with an execution sink — dropper shape"
                    elif _has_sink and is_test:
                        _sev, _conf = "high", "medium"
                        _ev = f"test file decodes a hidden {_kind} via [{_chain}] with an execution sink [test fixture]"
                    elif is_test:
                        _sev, _conf = "low", "low"
                        _ev = f"embedded {_kind} via [{_chain}], no execution sink in file [test fixture]"
                    else:
                        _sev, _conf = "medium", "medium"
                        _ev = f"embedded {_kind} via [{_chain}], no execution sink in file"
                    out.append(Finding(
                        rule_id="iocs.decoded_executable", category=CATEGORY,
                        severity=_sev, confidence=_conf, file=path.name, line=None,
                        evidence=_ev,
                    ))
                    continue
                for um in _URL_RE.finditer(_d.data):
                    full = um.group(0)
                    if b"." not in um.group(1).split(b"/", 1)[0] or _is_benign_url(um.group(1)) or _is_oast_url(full):
                        continue
                    key = ("enc_url", full)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(Finding(
                        rule_id="iocs.encoded_url", category=CATEGORY,
                        severity="medium", confidence="medium", file=path.name, line=None,
                        evidence=f"decoded [{_chain}]: " + full.decode("utf-8", errors="replace")[:160],
                    ))
                # Hidden code behind a REAL encoding chain that decodes to an actual
                # execution sink (eval/Function/child_process/exec/spawn) — the concealed-
                # loader shape. Requires a non-reverse decoder (a `reverse->reverse` no-op
                # recovers visible source) AND a true sink (not the require()/function()
                # in every file), so it doesn't fire on bundles or reversed source.
                if (_chain_has_real_decode(_d.chain)
                        and _DECODED_EXEC_SINK.search(_d.data)):
                    _k = ("dec_code", _chain)
                    if _k in seen:
                        continue
                    seen.add(_k)
                    out.append(Finding(
                        rule_id="iocs.decoded_code", category=CATEGORY,
                        severity="high", confidence="medium", file=path.name, line=None,
                        evidence=f"execution sink recovered through decode chain [{_chain}]",
                    ))

    # Fallback: a bare/concatenated OAST-domain literal the full-URL scan above missed
    # (string-built callbacks). Only if no oast finding already fired; skip docs.
    if not is_doc and not any(f.rule_id == "iocs.oast_callback" for f in out):
        _om = _OAST_LITERAL_RE.search(data)
        if _om:
            out.append(Finding(
                rule_id="iocs.oast_callback", category=CATEGORY, severity="high",
                confidence="high", file=path.name, line=None,
                evidence="OOB-interaction callback domain in source (string-built): "
                + _om.group(0).decode("utf-8", "replace")[:80],
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
