# SPDX-License-Identifier: AGPL-3.0-or-later
"""Analyze Go source for supply-chain attack patterns.

Checks go:generate directives, init() functions with suspicious behavior,
CGO imports, unsafe usage, and go.mod replace directives.
"""
from __future__ import annotations

import re
from pathlib import Path

from pkgsentry import intel
from pkgsentry.adapter import Finding

CATEGORY = "installer"

# --- go:generate ---

_GO_GENERATE = re.compile(r"^//go:generate\s+(.+)$", re.MULTILINE)

_GENERATE_EXEC_COMMANDS = re.compile(
    r"\b(?:curl|wget|bash|powershell|python|ruby|perl|"
    r"ncat|socat|chmod|chown)\b|"
    r"\brm\s+-rf\b|/bin/|/usr/bin/",
    re.IGNORECASE,
)

# sh/cmd/nc need special handling — too short, match inside words.
# Anchored: only match as the first token or after shell metacharacters.
_GENERATE_SHELL_WRAP = re.compile(
    r"^(?:ba)?sh\s+-c\s+",
    re.IGNORECASE,
)
_GENERATE_SHORT_EXEC = re.compile(
    r"(?:^|\s|[|;&])(?:sh|cmd|nc)\s",
    re.IGNORECASE,
)

# go:generate has zero confirmed real-world attacks (as of 2026-05).
# It requires explicit `go generate` invocation — not part of go build.
# Known benign tools are skipped entirely; unknown tools get low severity.
# Tool list lives in the intel pack — see baseline/gomod_benign_tools.toml.
def _benign_generate_tools() -> frozenset[str]:
    return frozenset(intel.current().gomod_benign_tools)

# --- init() function detection ---

_INIT_FUNC = re.compile(
    r"^func\s+init\s*\(\s*\)\s*\{",
    re.MULTILINE,
)

_NET_IMPORTS = re.compile(
    r'"(?:net/http|net|net/smtp|net/rpc|golang\.org/x/net)"',
)

_EXEC_IMPORTS = re.compile(
    r'"os/exec"',
)

# Patterns that indicate actual exec/net usage inside a function body
_EXEC_USAGE = re.compile(
    r"exec\.(?:Command|CommandContext|LookPath)\b",
)
_NET_USAGE = re.compile(
    r"(?:http\.(?:Get|Post|Head|Do|NewRequest|DefaultClient)|"
    r"net\.(?:Dial|DialTimeout|Listen|ListenPacket|ResolveIPAddr)|"
    r"smtp\.(?:SendMail|Dial)|"
    r"rpc\.(?:Dial|DialHTTP))",
)

_ENV_GETENV = re.compile(
    r"os\.Getenv\s*\(\s*\"([^\"]+)\"",
)

_SENSITIVE_ENV_VARS = {
    "HOME", "USERPROFILE", "SSH_AUTH_SOCK", "SSH_PRIVATE_KEY",
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
    "GH_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN",
    "DOCKER_PASSWORD", "NPM_TOKEN", "CARGO_REGISTRY_TOKEN",
    "DATABASE_URL", "SECRET_KEY", "PRIVATE_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
}

# --- CGO ---

_CGO_IMPORT = re.compile(r'^import\s+"C"', re.MULTILINE)
_CGO_COMMENT_BLOCK = re.compile(r"/\*.*?\*/\s*\nimport\s+\"C\"", re.DOTALL)

_CGO_DANGEROUS = re.compile(
    r"(?:system\s*\(|popen\s*\(|exec[lv]p?\s*\(|"
    r"socket\s*\(|connect\s*\(|getenv\s*\()",
)

# --- unsafe ---

_UNSAFE_IMPORT = re.compile(r'"unsafe"')

# --- go.mod ---

_REPLACE_DIRECTIVE = re.compile(
    r"^\s*replace\s+(\S+)\s+=>\s+(\S+)",
    re.MULTILINE,
)

# --- encoded payloads ---

_ENCODED_PAYLOAD = re.compile(
    r"(?:[A-Za-z0-9+/]{200,}={0,2}|(?:\\x[0-9a-fA-F]{2}){50,})",
)


def _is_generate_dangerous(cmd: str) -> bool:
    """Check if a go:generate command is genuinely dangerous."""
    if _GENERATE_EXEC_COMMANDS.search(cmd):
        return True
    benign = _benign_generate_tools()
    # sh -c "go tool mockgen ..." — shell wrapping a benign tool
    shell_match = _GENERATE_SHELL_WRAP.match(cmd)
    if shell_match:
        inner = cmd[shell_match.end():].strip().strip("'\"")
        inner_tool = inner.split()[0] if inner else ""
        if inner_tool in benign:
            return False
        if _GENERATE_EXEC_COMMANDS.search(inner):
            return True
        return False
    if _GENERATE_SHORT_EXEC.search(cmd):
        return True
    return False


def _extract_init_bodies(content: str) -> list[str]:
    """Extract the body text of each init() function using brace matching."""
    bodies = []
    for m in _INIT_FUNC.finditer(content):
        depth = 1
        pos = m.end()
        while pos < len(content) and depth > 0:
            ch = content[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            pos += 1
        bodies.append(content[m.end():pos - 1])
    return bodies


def _analyze_go_file(path: Path, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    is_test = path.name.endswith("_test.go")
    try:
        content = path.read_text(errors="replace")
    except Exception:
        return findings

    # go:generate directives
    for m in _GO_GENERATE.finditer(content):
        cmd = m.group(1).strip()
        line_num = content[:m.start()].count("\n") + 1
        if _is_generate_dangerous(cmd):
            findings.append(Finding(
                rule_id="gomod.go_generate_exec",
                category=CATEGORY,
                severity="critical",
                confidence="high",
                file=rel_path,
                line=line_num,
                evidence=f"go:generate runs suspicious command: {cmd[:120]}",
            ))
        else:
            tool = cmd.split()[0] if cmd else ""
            if tool not in _benign_generate_tools():
                findings.append(Finding(
                    rule_id="gomod.go_generate",
                    category=CATEGORY,
                    severity="low",
                    confidence="medium",
                    file=rel_path,
                    line=line_num,
                    evidence=f"go:generate with unrecognized tool: {cmd[:120]}",
                ))

    # _test.go files are only compiled during `go test`, never imported
    # by non-test code — init() there can't auto-execute on import.
    if is_test:
        return findings

    # Extract init() bodies and check for actual usage within them
    init_bodies = _extract_init_bodies(content)
    if init_bodies:
        combined_body = "\n".join(init_bodies)

        if _EXEC_USAGE.search(combined_body):
            findings.append(Finding(
                rule_id="gomod.init_exec_chain",
                category=CATEGORY,
                severity="critical",
                confidence="high",
                file=rel_path,
                evidence="init() calls os/exec — auto-executes on import",
            ))

        if _NET_USAGE.search(combined_body):
            findings.append(Finding(
                rule_id="gomod.init_net_chain",
                category=CATEGORY,
                severity="high",
                confidence="high",
                file=rel_path,
                evidence="init() makes network calls — auto-executes on import",
            ))

        env_reads = _ENV_GETENV.findall(combined_body)
        sensitive = [v for v in env_reads if v in _SENSITIVE_ENV_VARS]
        if len(sensitive) >= 3:
            findings.append(Finding(
                rule_id="gomod.init_env_harvest",
                category=CATEGORY,
                severity="high",
                confidence="high",
                file=rel_path,
                evidence=f"init() harvests env vars: {', '.join(sensitive[:5])}",
            ))

        # Soft fallback: init() exists + os/exec or net imported, but not
        # used directly inside init(). Catches indirect-call patterns.
        has_exec = bool(_EXEC_IMPORTS.search(content))
        has_net = bool(_NET_IMPORTS.search(content))
        if has_exec and not _EXEC_USAGE.search(combined_body):
            findings.append(Finding(
                rule_id="gomod.init_exec_coexist",
                category=CATEGORY,
                severity="low",
                confidence="medium",
                file=rel_path,
                evidence="init() + os/exec import in same file (exec not directly in init body)",
            ))
        if has_net and not _NET_USAGE.search(combined_body):
            findings.append(Finding(
                rule_id="gomod.init_net_coexist",
                category=CATEGORY,
                severity="low",
                confidence="medium",
                file=rel_path,
                evidence="init() + network import in same file (net calls not directly in init body)",
            ))

    # CGO
    if _CGO_IMPORT.search(content):
        cgo_block = _CGO_COMMENT_BLOCK.search(content)
        if cgo_block and _CGO_DANGEROUS.search(cgo_block.group(0)):
            findings.append(Finding(
                rule_id="gomod.cgo_exec_chain",
                category=CATEGORY,
                severity="high",
                confidence="high",
                file=rel_path,
                evidence="CGO with dangerous C function calls (exec/socket/system)",
            ))
        else:
            findings.append(Finding(
                rule_id="gomod.cgo_import",
                category=CATEGORY,
                severity="medium",
                confidence="medium",
                file=rel_path,
                evidence="CGO import — compiles C code at build time",
            ))

    # unsafe
    if _UNSAFE_IMPORT.search(content):
        findings.append(Finding(
            rule_id="gomod.unsafe_import",
            category=CATEGORY,
            severity="low",
            confidence="medium",
            file=rel_path,
            evidence="unsafe package import",
        ))

    # Encoded payloads (skip test files — crypto test vectors are normal)
    if not is_test and _ENCODED_PAYLOAD.search(content):
        findings.append(Finding(
            rule_id="gomod.encoded_payload",
            category=CATEGORY,
            severity="medium",
            confidence="medium",
            file=rel_path,
            evidence="large encoded payload in Go source",
        ))

    return findings


def _analyze_go_mod(path: Path, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = path.read_text(errors="replace")
    except Exception:
        return findings

    for m in _REPLACE_DIRECTIVE.finditer(content):
        target = m.group(2)
        line_num = content[:m.start()].count("\n") + 1
        # Local path replace is more suspicious
        if target.startswith(".") or target.startswith("/"):
            findings.append(Finding(
                rule_id="gomod.replace_local_path",
                category=CATEGORY,
                severity="high",
                confidence="high",
                file=rel_path,
                line=line_num,
                evidence=f"replace directive points to local path: {m.group(1)} => {target}",
            ))
        else:
            findings.append(Finding(
                rule_id="gomod.replace_directive",
                category=CATEGORY,
                severity="medium",
                confidence="high",
                file=rel_path,
                line=line_num,
                evidence=f"replace directive: {m.group(1)} => {target}",
            ))

    return findings


def analyze_go_directives(
    extracted_root: Path,
    changed_files: set[str] | None = None,
) -> list[Finding]:
    """Analyze Go module source for supply-chain attack patterns."""
    findings: list[Finding] = []

    for p in extracted_root.rglob("*.go"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(extracted_root))
        if changed_files is not None and rel not in changed_files:
            continue
        findings.extend(_analyze_go_file(p, rel))

    for p in extracted_root.rglob("go.mod"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(extracted_root))
        if changed_files is not None and rel not in changed_files:
            continue
        findings.extend(_analyze_go_mod(p, rel))

    return findings
