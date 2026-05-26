# SPDX-License-Identifier: AGPL-3.0-or-later
"""Analyze build.rs for supply-chain attack patterns.

build.rs runs at compile time with full system access -- it's the Rust
equivalent of PyPI's setup.py. This analyzer checks for network calls,
command execution, environment variable harvesting, and writes outside
OUT_DIR.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from pkgsentry.adapter import Finding

CATEGORY = "installer"

# --- Patterns ---

_NETWORK_PATTERNS = re.compile(
    r"(?:reqwest|ureq|hyper|curl|std::net::TcpStream|"
    r"std::net::UdpSocket|attohttpc|minreq|isahc)",
    re.IGNORECASE,
)

_EXEC_PATTERNS = re.compile(
    r"(?:std::process::Command|Command::new|"
    r"std::os::unix::process|exec::Command)",
)

_SENSITIVE_ENV_VARS = {
    "HOME", "USERPROFILE", "SSH_AUTH_SOCK", "SSH_PRIVATE_KEY",
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
    "GH_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN",
    "DOCKER_PASSWORD", "NPM_TOKEN", "CARGO_REGISTRY_TOKEN",
    "DATABASE_URL", "SECRET_KEY", "PRIVATE_KEY",
}

_ENV_READ = re.compile(r'(?:std::env::var|env::var|env!)\s*\(\s*"([^"]+)"')

_OUTDIR_ESCAPE = re.compile(
    r'(?:fs::write|File::create|OpenOptions)\s*\(\s*"(/[^"]+|(?:\$HOME|~)[^"]*)"',
)

_INCLUDE_BYTES = re.compile(
    r'include_bytes!\s*\(\s*"([^"]+)"',
)

_SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".so", ".sh", ".ps1", ".bat", ".cmd", ".bin"}

_ENCODED_PAYLOAD = re.compile(
    r'(?:[A-Za-z0-9+/]{200,}={0,2}|(?:\\x[0-9a-fA-F]{2}){50,})',
)


def _find_build_rs_files(root: Path) -> list[Path]:
    """Find all build.rs files in the extracted crate."""
    results = []
    for p in root.rglob("build.rs"):
        if p.is_file():
            results.append(p)
    return results


def analyze_build_rs(extracted_root: Path) -> list[Finding]:
    """Analyze build.rs files for supply-chain attack patterns."""
    findings: list[Finding] = []
    build_files = _find_build_rs_files(extracted_root)

    if not build_files:
        return findings

    for build_rs in build_files:
        try:
            content = build_rs.read_text(errors="replace")
        except Exception:
            continue

        rel_path = str(build_rs.relative_to(extracted_root))
        has_network = bool(_NETWORK_PATTERNS.search(content))
        has_exec = bool(_EXEC_PATTERNS.search(content))

        # Network + exec chain = critical (the mistralai-equivalent pattern)
        if has_network and has_exec:
            findings.append(Finding(
                rule_id="crates.build_rs_net_exec_chain",
                category=CATEGORY,
                severity="critical",
                confidence="high",
                file=rel_path,
                evidence="build.rs contains both network calls and command execution",
            ))

        # Network calls alone
        if has_network:
            match = _NETWORK_PATTERNS.search(content)
            findings.append(Finding(
                rule_id="crates.build_rs_network",
                category=CATEGORY,
                severity="high",
                confidence="high",
                file=rel_path,
                evidence=f"network library in build.rs: {match.group(0) if match else ''}",
            ))

        # Command execution alone
        if has_exec:
            match = _EXEC_PATTERNS.search(content)
            findings.append(Finding(
                rule_id="crates.build_rs_exec",
                category=CATEGORY,
                severity="medium",
                confidence="medium",
                file=rel_path,
                evidence=f"command execution in build.rs: {match.group(0) if match else ''}",
            ))

        # Environment variable harvesting (3+ sensitive vars)
        env_reads = _ENV_READ.findall(content)
        sensitive_reads = [v for v in env_reads if v in _SENSITIVE_ENV_VARS]
        if len(sensitive_reads) >= 3:
            findings.append(Finding(
                rule_id="crates.build_rs_env_harvest",
                category=CATEGORY,
                severity="high",
                confidence="high",
                file=rel_path,
                evidence=f"bulk env reads: {', '.join(sensitive_reads[:5])}",
            ))

        # Writes outside OUT_DIR
        for match in _OUTDIR_ESCAPE.finditer(content):
            findings.append(Finding(
                rule_id="crates.build_rs_outdir_escape",
                category=CATEGORY,
                severity="high",
                confidence="medium",
                file=rel_path,
                evidence=f"write outside OUT_DIR: {match.group(1)}",
            ))

        # Suspicious include_bytes!
        for match in _INCLUDE_BYTES.finditer(content):
            included = match.group(1)
            ext = Path(included).suffix.lower()
            if ext in _SUSPICIOUS_EXTENSIONS:
                findings.append(Finding(
                    rule_id="crates.build_rs_suspicious_include",
                    category=CATEGORY,
                    severity="high",
                    confidence="medium",
                    file=rel_path,
                    evidence=f"include_bytes! of suspicious file: {included}",
                ))

        # Encoded payloads
        if _ENCODED_PAYLOAD.search(content):
            findings.append(Finding(
                rule_id="crates.build_rs_encoded_payload",
                category=CATEGORY,
                severity="medium",
                confidence="medium",
                file=rel_path,
                evidence="large encoded payload in build.rs",
            ))

    return findings
