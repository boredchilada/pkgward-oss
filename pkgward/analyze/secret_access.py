# SPDX-License-Identifier: AGPL-3.0-or-later
"""Credential-store-sweep detection.

An info-stealer reaches into MANY distinct secret stores; a legitimate library
touches one (its own config). So a single source file that references >= 3
distinct credential stores — /etc/shadow, /proc/<pid>/environ, the Kubernetes
service-account token, ~/.ssh keys, ~/.aws/credentials, ~/.npmrc, browser/crypto
cred stores, or a bulk process-env harvest — is a credential implant, regardless
of how it exfiltrates. Catches the meoo-* / rookie-security-test campaign (form-
validator / ui-helper facades over a stealer reading shadow + SSH + k8s SA + env)
that previously fired only the single install-time net+exec rule.

This complements the dynamic ``dyn_credential_read`` (which needs detonation + a
file-open trace) by catching the harvest statically, in the auto-exec source.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from pkgward.adapter import Finding

CATEGORY = "malware"

_CODE_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".go", ".rs", ".sh"}
MAX_FILE_SIZE = int(os.environ.get("PKGWARD_SECRET_SWEEP_MAX_MB", "4")) * 1024 * 1024

# label -> regex for one distinct credential/secret store. Distinctness is what
# matters: legit code touches one store, a stealer sweeps several.
_STORES: list[tuple[str, re.Pattern[bytes]]] = [
    ("etc_shadow", re.compile(rb"/etc/shadow")),
    ("proc_environ", re.compile(rb"/proc/(?:\d+|self|[0-9a-z]+)/environ")),
    ("k8s_sa_token", re.compile(rb"/var/run/secrets/kubernetes\.io|serviceaccount/(?:token|namespace)")),
    ("ssh_keys", re.compile(
        rb"\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa)|identity|authorized_keys|known_hosts|config)\b")),
    ("aws_creds", re.compile(rb"\.aws/credentials")),
    ("gcloud_creds", re.compile(rb"application_default_credentials|gcloud/[^\"'\s]*credential")),
    ("kube_config", re.compile(rb"\.kube/config")),
    ("docker_config", re.compile(rb"\.docker/config\.json")),
    ("npmrc", re.compile(rb"(?:^|[^\w])\.npmrc\b")),
    ("pypirc", re.compile(rb"\.pypirc\b")),
    ("git_creds", re.compile(rb"\.git-credentials\b|(?:^|[^\w])\.netrc\b")),
    ("gpg", re.compile(rb"\.gnupg\b")),
    ("browser_creds", re.compile(rb"Login Data|cookies\.sqlite|key4\.db|logins\.json")),
    ("crypto_wallet", re.compile(rb"wallet\.dat|\.electrum\b|MetaMask|Exodus|keystore")),
    # bulk process-env harvest (iterate ALL env, not read one var)
    ("env_harvest", re.compile(
        rb"Object\.(?:keys|entries|values)\s*\(\s*process\.env"
        rb"|for\s*\([^)]*\bin\b[^)]*process\.env"
        rb"|os\.environ\.(?:items|keys|values)\s*\(\)"
        rb"|dict\s*\(\s*os\.environ"
    )),
]

_SWEEP_THRESHOLD = 3

# --- Regex-literal denylist regions -----------------------------------------
# A security/redaction module ENUMERATES credential files as regex literals in an
# array (``[/^\.npmrc$/, /^Login Data$/, ...]``) so the agent can SKIP them — the
# opposite of a harvest (octocode-mcp 15.0.0 FP, 2026-06-07: a 150-entry
# SecurityRegistry denylist). A real stealer passes a credential path as a STRING
# literal to a read call. So a store counts toward the sweep only when it occurs
# OUTSIDE such a regex-literal array: an attacker can't both READ a file (the path
# must appear as a string) and HIDE it (as a ``/regex/``) in the same place, and a
# decoy array of throwaway regexes never contains the real string-path reads — so
# this can't be disarmed by pasting marker tokens or filler regexes next to a live
# harvest. ``etc_shadow`` uses the same span-aware set, so a denylisted
# ``/^\/etc\/shadow$/`` doesn't fire either. A run of >= 3 comma-separated regex
# literals is the array signature (a lone ``/re/`` elsewhere isn't a denylist).
_REGEX_LITERAL_ARRAY = re.compile(
    rb"(?:/(?:\\.|[^/\n\\]){1,200}/[gimsuyd]*\s*,\s*){3,}"
)


def _regex_array_spans(data: bytes) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in _REGEX_LITERAL_ARRAY.finditer(data)]


def _store_hits_outside_denylist(
    data: bytes, spans: list[tuple[int, int]]
) -> list[str]:
    """Distinct stores with >= 1 occurrence OUTSIDE every regex-literal array."""
    hits: set[str] = set()
    for label, rx in _STORES:
        if label in hits:
            continue
        for m in rx.finditer(data):
            if not any(s <= m.start() < e for s, e in spans):
                hits.add(label)
                break
    return sorted(hits)


def analyze_secret_access(
    extracted_root: Path,
    changed_files: set[str] | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    for p in extracted_root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _CODE_EXTENSIONS:
            continue
        rel = p.relative_to(extracted_root).as_posix()
        if changed_files is not None and rel not in changed_files:
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
            data = p.read_bytes()
        except OSError:
            continue

        spans = _regex_array_spans(data)
        hits = _store_hits_outside_denylist(data, spans)
        if "etc_shadow" in hits:
            out.append(Finding(
                rule_id="malware.etc_shadow_read", category=CATEGORY,
                severity="high", confidence="high", file=rel, line=None,
                evidence="source references /etc/shadow (password-hash theft)",
            ))
        if len(hits) >= _SWEEP_THRESHOLD:
            out.append(Finding(
                rule_id="malware.credential_store_sweep", category=CATEGORY,
                severity="critical", confidence="high", file=rel, line=None,
                evidence=f"single file reaches into {len(hits)} distinct credential stores: {', '.join(hits)}",
            ))
    return out
