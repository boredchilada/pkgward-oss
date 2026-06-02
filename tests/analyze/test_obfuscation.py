# SPDX-License-Identifier: AGPL-3.0-or-later
"""Source-obfuscation detection: custom radix alphabets + CJK identifiers (0.5.2).

Motivated by npm `baileys-mbuilder` — basE91 with 19 rotating alphabets and
hiragana identifiers hid an install-time remote-code fetcher that the base64 /
entropy heuristics missed."""
from __future__ import annotations

from pkgsentry.analyze.obfuscation import analyze_obfuscation

# Two distinct 90-char alphabets (same printable set, different orderings) — each
# a near-distinct run of printable ASCII, i.e. a base85/basE91-style charset.
_PRINTABLE = "".join(chr(c) for c in range(0x21, 0x7f) if chr(c) not in "'\"`\\")  # 90 chars
ALPHA1 = _PRINTABLE
ALPHA2 = _PRINTABLE[::-1]


def _ids(findings):
    return {f.rule_id for f in findings}


def test_rotating_alphabets_high(tmp_path):
    (tmp_path / "loader.js").write_text(
        f"const a = '{ALPHA1}';\nconst b = '{ALPHA2}';\nfunction d(x){{return x}}\n"
    )
    fs = analyze_obfuscation(tmp_path)
    rot = [f for f in fs if f.rule_id == "obfuscation.rotating_alphabet_codec"]
    assert len(rot) == 1 and rot[0].severity == "high"
    assert "obfuscation.custom_alphabet_codec" not in _ids(fs)


def test_single_alphabet_low(tmp_path):
    # one alphabet alone = a codec library, not a packer
    (tmp_path / "base91.js").write_text(f"export const ALPHA = '{ALPHA1}';\n")
    fs = analyze_obfuscation(tmp_path)
    one = [f for f in fs if f.rule_id == "obfuscation.custom_alphabet_codec"]
    assert len(one) == 1 and one[0].severity == "low"


def test_cjk_identifiers_medium(tmp_path):
    src = "var にし=1, ふく=2, きつ=3, つす=4, れを=5, らに=6, すけ=7, とる=8, にく=9;\n"
    (tmp_path / "obf.js").write_text(src)
    fs = analyze_obfuscation(tmp_path)
    cjk = [f for f in fs if f.rule_id == "obfuscation.nonascii_identifiers"]
    assert len(cjk) == 1 and cjk[0].severity == "medium"


def test_cjk_in_comments_and_strings_not_counted(tmp_path):
    # A CJK-authored library: Japanese in comments + string literals must NOT flag.
    src = (
        "// これは日本語のコメントです、たくさんの単語があります\n"
        "/* 設定 初期化 接続 認証 暗号 復号 送信 受信 完了 */\n"
        'const msg = "こんにちは世界、これはメッセージテキストです";\n'
        "function build(payload){ return payload.length; }\n"
    )
    (tmp_path / "lib.js").write_text(src)
    fs = analyze_obfuscation(tmp_path)
    assert "obfuscation.nonascii_identifiers" not in _ids(fs)


def test_homoglyph_latin_cyrillic_flagged(tmp_path):
    # `rеquests` / `аxios` carry a Cyrillic е / а — reads as a trusted symbol.
    src = "const rеquests = require('./payload');\nconst аxios = rеquests;\n"
    (tmp_path / "obf.js").write_text(src, encoding="utf-8")
    fs = analyze_obfuscation(tmp_path)
    hg = [f for f in fs if f.rule_id == "obfuscation.homoglyph_identifiers"]
    assert len(hg) == 1 and hg[0].severity == "medium"


def test_homoglyph_fullwidth_flagged(tmp_path):
    # padded above MIN_FILE_SIZE (64B); the fullwidth-Latin identifier is the tell.
    src = "function helperOne(a, b){ return a + b; }\nvar ｅｖａｌ = helperOne;\n"
    (tmp_path / "obf.js").write_text(src, encoding="utf-8")
    assert "obfuscation.homoglyph_identifiers" in _ids(analyze_obfuscation(tmp_path))


def test_pure_cyrillic_identifier_not_flagged(tmp_path):
    # legit Russian-authored identifier (all-Cyrillic, no Latin mix) must NOT flag.
    # Padded above MIN_FILE_SIZE so the analyzer actually runs on it.
    src = (
        "def compute_total(items):\n"
        "    функция = 1\n"
        "    пароль = функция + len(items)\n"
        "    return пароль\n"
    )
    (tmp_path / "lib.py").write_text(src, encoding="utf-8")
    assert "obfuscation.homoglyph_identifiers" not in _ids(analyze_obfuscation(tmp_path))


def test_homoglyph_in_strings_not_counted(tmp_path):
    # Cyrillic inside a string/comment (i18n) is not an identifier homoglyph.
    src = 'const label = "Привет мир";\n// тест комментарий\nfunction ok(){ return 1; }\n'
    (tmp_path / "lib.js").write_text(src, encoding="utf-8")
    assert "obfuscation.homoglyph_identifiers" not in _ids(analyze_obfuscation(tmp_path))


def test_benign_code_clean(tmp_path):
    (tmp_path / "index.js").write_text(
        "const x = 1;\nfunction add(a, b){ return a + b; }\nmodule.exports = { add };\n"
    )
    assert analyze_obfuscation(tmp_path) == []


def test_base64_blob_is_not_an_alphabet(tmp_path):
    # a long base64 string has <=64 unique chars -> not flagged as a radix alphabet
    blob = "QUJD" * 40  # 160 chars, few unique
    (tmp_path / "data.js").write_text(f'const b = "{blob}";\n')
    assert analyze_obfuscation(tmp_path) == []


def test_changed_files_filter(tmp_path):
    (tmp_path / "a.js").write_text(f"const a='{ALPHA1}'; const b='{ALPHA2}';")
    (tmp_path / "b.js").write_text(f"const a='{ALPHA1}'; const b='{ALPHA2}';")
    fs = analyze_obfuscation(tmp_path, changed_files={"a.js"})
    assert {f.file for f in fs} == {"a.js"}


def test_non_code_extension_skipped(tmp_path):
    (tmp_path / "notes.txt").write_text(f"const a='{ALPHA1}'; const b='{ALPHA2}';")
    assert analyze_obfuscation(tmp_path) == []


# --- self-decoding-packer family (the @redhat-cloud-services worm, June 2026) ---

def test_charcode_eval_high(tmp_path):
    # Caesar(char-codes) -> eval, layer 1 of the RH worm's 4MB index.js
    (tmp_path / "index.js").write_text(
        "try{eval(function(s,n){return s.replace(/[a-z]/g,c=>String.fromCharCode("
        "(c.charCodeAt(0)-97+n)%26+97))}('ogmbq',12))}catch(e){}\n"
    )
    fs = analyze_obfuscation(tmp_path)
    cc = [f for f in fs if f.rule_id == "obfuscation.charcode_eval"]
    assert len(cc) == 1 and cc[0].severity == "high"


def test_charcode_eval_downgraded_in_build_bundle(tmp_path):
    # Same pattern inside a minified web build bundle (content-hash name in a
    # browser/ output dir, like google-adk's main-TCIQIOZ3.js) -> low, not high.
    payload = (
        "try{eval(function(s,n){return s.replace(/[a-z]/g,c=>String.fromCharCode("
        "(c.charCodeAt(0)-97+n)%26+97))}('ogmbq',12))}catch(e){}\n"
    )
    d = tmp_path / "src" / "app" / "browser"
    d.mkdir(parents=True)
    (d / "main-TCIQIOZ3.js").write_text(payload)
    fs = analyze_obfuscation(tmp_path)
    cc = [f for f in fs if f.rule_id == "obfuscation.charcode_eval"]
    assert len(cc) == 1 and cc[0].severity == "low"


def test_charcode_eval_min_js_downgraded(tmp_path):
    # a *.min.js anywhere is a build artifact -> downgraded too.
    payload = (
        "eval(String.fromCharCode(104,105)); /* " + ("a" * 80) + " */\n"
    )
    (tmp_path / "vendor.min.js").write_text(payload)
    fs = analyze_obfuscation(tmp_path)
    cc = [f for f in fs if f.rule_id == "obfuscation.charcode_eval"]
    assert len(cc) == 1 and cc[0].severity == "low"


def test_numeric_array_eval_high(tmp_path):
    arr = ",".join(str(i % 90 + 33) for i in range(60))
    (tmp_path / "loader.js").write_text(f"eval(String.fromCharCode.apply(0,[{arr}]))\n")
    assert "obfuscation.charcode_eval" in _ids(analyze_obfuscation(tmp_path))


def test_decrypt_then_exec_high(tmp_path):
    (tmp_path / "stage.js").write_text(
        "const c=require('crypto');"
        "const d=c.createDecipheriv('aes-128-gcm',k,iv);"
        "new Function(d.update(ct).toString())();\n"
    )
    fs = analyze_obfuscation(tmp_path)
    de = [f for f in fs if f.rule_id == "obfuscation.decrypt_then_exec"]
    assert len(de) == 1 and de[0].severity == "high"


def test_charcode_without_eval_clean(tmp_path):
    # fromCharCode without an eval/Function sink is normal string building
    (tmp_path / "x.js").write_text("const s=String.fromCharCode(72,105);console.log(s);\n")
    assert "obfuscation.charcode_eval" not in _ids(analyze_obfuscation(tmp_path))


def test_packer_scanned_above_alphabet_cap(tmp_path, monkeypatch):
    import pkgsentry.analyze.obfuscation as ob
    monkeypatch.setattr(ob, "MAX_FILE_SIZE", 1024)  # tiny alphabet/CJK cap
    body = "// pad\n" + "x" * 4000 + "\neval(String.fromCharCode(65,66,67));\n"
    (tmp_path / "big.js").write_text(body)
    # alphabet pass is skipped (over cap) but the cheap packer scan still runs
    assert "obfuscation.charcode_eval" in _ids(ob.analyze_obfuscation(tmp_path))
