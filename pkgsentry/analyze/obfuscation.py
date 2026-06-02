# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-ecosystem source-obfuscation / custom-encoding detection.

Catches the obfuscation family that the base64 and entropy heuristics miss:
custom radix alphabets (base85 / basE91 / z85 and shuffled variants) and
non-ASCII (CJK) identifier renaming. Motivated by npm ``baileys-mbuilder``
(basE91 with 19 rotating alphabets + hiragana identifiers hiding an install-time
remote-code fetcher) — the encoding layer was blind to it because basE91 strings
are full of punctuation (no long ``[A-Za-z0-9+/]`` run) and the decoder is a
hand-rolled accumulator loop, not ``atob`` / ``Buffer.from(...,'base64')``. Only
the net+exec heuristic fired; this closes the encoding gap.

Runs across every ecosystem; naturally scoped to the source extensions where
these packers live (JS install scripts + library source, Python install scripts).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from pkgsentry.adapter import Finding

CATEGORY = "obfuscation"

# Source files where these obfuscators live (install scripts + library source).
_CODE_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py"}

# The alphabet/CJK passes regex over every string literal — costly on a big blob,
# so they cap out (anything this size is a minified vendor bundle, not a hand-
# crafted packer). Raised 4->10MB so a multi-MB hand-packed install file isn't
# skipped (the @redhat-cloud-services worm's index.js was 4.1MB).
MAX_FILE_SIZE = int(os.environ.get("PKGSENTRY_OBFUSCATION_MAX_MB", "10")) * 1024 * 1024
# The self-decoding-packer scan below is 3 cheap regexes — it runs on much larger
# files too, because an install-time packer is routinely a multi-MB single bundle.
PACKER_MAX_FILE_SIZE = int(os.environ.get("PKGSENTRY_OBFUSCATION_PACKER_MAX_MB", "32")) * 1024 * 1024
MIN_FILE_SIZE = 64

# JS self-decoding-packer family: code that reconstructs a hidden payload at
# runtime and runs it through eval/Function. Two reconstruction primitives we see:
# a char-code decode (String.fromCharCode / charCodeAt / a long decimal array) and
# a runtime crypto-decrypt (createDecipheriv). The @redhat-cloud-services npm worm
# (preinstall: node index.js) layered Caesar(char-codes) -> AES-128-GCM -> eval,
# which is invisible to the radix-alphabet and base64 heuristics (the payload is a
# decimal array, no long [A-Za-z0-9+/] run, and the inner stage is AES at runtime).
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
_JS_EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]")
_CHARCODE_DECODE = re.compile(
    r"\bString\.fromCharCode\b|\.charCodeAt\s*\(|(?:\d{1,4}\s*,\s*){40,}"
)
_CRYPTO_DECRYPT = re.compile(r"\bcreateDecipher(?:iv)?\s*\(")

# Minified web build artifacts (webpack/esbuild/vite/angular output) legitimately
# use String.fromCharCode + Function and ship long numeric lookup arrays, so
# charcode_eval false-fires on them (e.g. google-adk's bundled CLI browser UI,
# `.../browser/main-TCIQIOZ3.js`). Recognize a build bundle by an output-dir
# segment or a content-hashed bundle filename and DOWNGRADE charcode_eval there
# to low (still visible as a corroborator, but not verdict-driving). decrypt_then_exec
# is NOT downgraded — createDecipheriv->eval is not a normal bundle pattern.
_BUILD_BUNDLE_DIR = re.compile(
    r"(?:^|/)(?:dist|build|out|static|assets|public|browser|vendor|vendors"
    r"|_next|\.next|node_modules)/", re.IGNORECASE
)
_BUNDLE_HASH_NAME = re.compile(
    r"(?:^|/)(?:main|chunk|runtime|polyfills?|vendors?|index|app|bundle|styles?"
    r"|common|scripts|[0-9]+)[.\-][A-Za-z0-9_]{6,}\.(?:m|c)?js$"
    r"|\.min\.(?:m|c)?js$", re.IGNORECASE
)


def _is_build_bundle(rel: str) -> bool:
    return bool(_BUILD_BUNDLE_DIR.search(rel) or _BUNDLE_HASH_NAME.search(rel))

# A radix alphabet for base85 / basE91 / z85 / base92 is a dense, near-distinct
# run of printable ASCII ~85-91 chars long. We accept 84-95 and require all-but-
# one chars distinct and printable non-whitespace. A base64 blob (<=64 unique) or
# a path/sentence (repeated chars) fails the uniqueness test, so FP is minimal.
_ALPHABET_MIN_LEN = 84
_ALPHABET_MAX_LEN = 95

# String-literal inners, per quote type. A single-quoted basE91 alphabet contains
# " and ` but not its own ' (and never \, which the alphabets exclude), so these
# capture the whole alphabet. Used both for alphabet extraction and for stripping
# strings before CJK-identifier counting.
_STR_SQ = re.compile(r"'((?:[^'\\\n]|\\.)*)'")
_STR_DQ = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_STR_BT = re.compile(r"`((?:[^`\\]|\\.)*)`", re.DOTALL)

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"(?://|#)[^\n]*")

# Hiragana, katakana, half-width katakana, and CJK ideographs. Obfuscators rename
# identifiers to e.g. にし / ふく to defeat human review; legit npm/PyPI source
# almost never *names identifiers* in CJK (comments / i18n strings are stripped
# first, so CJK-authored libraries don't false-positive).
_CJK_RUN = re.compile(r"[぀-ヿ㐀-䶿一-鿿ｦ-ﾟ]+")
_NONASCII_IDENT_THRESHOLD = 8

# Homoglyph identifiers: a confusable Cyrillic/Greek letter swapped into an
# otherwise-Latin token (`rеquests` with a Cyrillic е), or fullwidth-Latin forms.
# This makes malicious code read like a call to a trusted symbol. Distinct from
# the CJK pass (which catches wholesale renaming): the homoglyph attack swaps only
# a *few* tokens, so it lives below the CJK threshold.
#   - Latin+Cyrillic / Latin+Greek *mixed in one token* is the attack signature.
#     We require the mix so legit pure-Cyrillic (Russian-authored) and pure-Greek
#     (scientific `α`/`β`) identifiers don't false-positive.
#   - Fullwidth-Latin has no legitimate identifier use -> flagged pure or mixed.
_LATIN_ASCII = re.compile(r"[A-Za-z]")
_CYR_GREEK = re.compile(r"[Ͱ-ϿЀ-ԯ]")
_FULLWIDTH_LATIN = re.compile(r"[Ａ-Ｚａ-ｚ]")
_IDENT_TOKEN = re.compile(r"[A-Za-z_$-￿][\w$-￿]*", re.UNICODE)
_HOMOGLYPH_IDENT_THRESHOLD = 1


def _is_alphabet(s: str) -> bool:
    n = len(s)
    if n < _ALPHABET_MIN_LEN or n > _ALPHABET_MAX_LEN:
        return False
    if any(ord(c) < 0x21 or ord(c) > 0x7e for c in s):
        return False
    return len(set(s)) >= n - 1


def _custom_alphabets(text: str) -> set[str]:
    out: set[str] = set()
    for rx in (_STR_SQ, _STR_DQ, _STR_BT):
        for m in rx.finditer(text):
            inner = m.group(1)
            if _is_alphabet(inner):
                out.add(inner)
    return out


def _strip_strings_and_comments(text: str) -> str:
    text = _BLOCK_COMMENT.sub(" ", text)
    text = _STR_SQ.sub(" ", text)
    text = _STR_DQ.sub(" ", text)
    text = _STR_BT.sub(" ", text)
    text = _LINE_COMMENT.sub(" ", text)
    return text


def _nonascii_identifier_count(text: str) -> int:
    code = _strip_strings_and_comments(text)
    return len({m.group(0) for m in _CJK_RUN.finditer(code)})


def _homoglyph_identifier_count(text: str) -> int:
    """Distinct confusable identifiers: a token mixing ASCII Latin with Cyrillic/
    Greek, or containing fullwidth-Latin. Strings/comments stripped first."""
    code = _strip_strings_and_comments(text)
    found: set[str] = set()
    for m in _IDENT_TOKEN.finditer(code):
        tok = m.group(0)
        if _FULLWIDTH_LATIN.search(tok):
            found.add(tok)
        elif _LATIN_ASCII.search(tok) and _CYR_GREEK.search(tok):
            found.add(tok)
    return len(found)


def analyze_obfuscation(
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
            size = p.stat().st_size
        except OSError:
            continue
        if size < MIN_FILE_SIZE:
            continue
        is_js = p.suffix.lower() in _JS_EXTENSIONS
        do_alphabets = size <= MAX_FILE_SIZE
        do_packer = is_js and size <= PACKER_MAX_FILE_SIZE
        if not (do_alphabets or do_packer):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if do_packer and _JS_EVAL.search(text):
            if _CRYPTO_DECRYPT.search(text):
                out.append(Finding(
                    rule_id="obfuscation.decrypt_then_exec",
                    category=CATEGORY,
                    severity="high",
                    confidence="high",
                    file=rel,
                    line=None,
                    evidence="runtime crypto-decrypt (createDecipheriv) feeding eval/Function",
                ))
            if _CHARCODE_DECODE.search(text):
                bundle = _is_build_bundle(rel)
                out.append(Finding(
                    rule_id="obfuscation.charcode_eval",
                    category=CATEGORY,
                    severity="low" if bundle else "high",
                    confidence="low" if bundle else "high",
                    file=rel,
                    line=None,
                    evidence=(
                        "char-code decode in a minified build bundle (fromCharCode / numeric "
                        "array feeding eval/Function) — common in framework runtimes"
                        if bundle else
                        "char-code decode (fromCharCode / numeric array) feeding eval/Function"
                    ),
                ))

        if not do_alphabets:
            continue

        alphabets = _custom_alphabets(text)
        if len(alphabets) >= 2:
            out.append(Finding(
                rule_id="obfuscation.rotating_alphabet_codec",
                category=CATEGORY,
                severity="high",
                confidence="high",
                file=rel,
                line=None,
                evidence=f"{len(alphabets)} distinct custom radix alphabets (base85/basE91 packer)",
            ))
        elif len(alphabets) == 1:
            out.append(Finding(
                rule_id="obfuscation.custom_alphabet_codec",
                category=CATEGORY,
                severity="low",
                confidence="medium",
                file=rel,
                line=None,
                evidence="custom radix alphabet literal (base85/basE91-style)",
            ))

        cjk = _nonascii_identifier_count(text)
        if cjk >= _NONASCII_IDENT_THRESHOLD:
            out.append(Finding(
                rule_id="obfuscation.nonascii_identifiers",
                category=CATEGORY,
                severity="medium",
                confidence="medium",
                file=rel,
                line=None,
                evidence=f"{cjk} distinct non-ASCII (CJK) identifiers in source",
            ))

        homoglyph = _homoglyph_identifier_count(text)
        if homoglyph >= _HOMOGLYPH_IDENT_THRESHOLD:
            out.append(Finding(
                rule_id="obfuscation.homoglyph_identifiers",
                category=CATEGORY,
                severity="medium",
                confidence="medium",
                file=rel,
                line=None,
                evidence=f"{homoglyph} confusable (Latin+Cyrillic/Greek or fullwidth) identifier(s) in source",
            ))

    return out
