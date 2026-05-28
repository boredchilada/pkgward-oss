# Detection regression testing

pkgsentry ships a **detection regression suite**: a labeled corpus of known-bad
and known-good sample packages that are run through the real analyze→score path,
so a code/rule/threshold/intel change that silently starts *missing* malware
(false negative) or *over-flagging* clean packages (false-positive creep) fails
the build instead of reaching production.

It complements the other two regression layers:

| Layer | Catches | Speed |
|-------|---------|-------|
| **Corpus** (this doc) | a specific known sample stops being detected / a clean one gets flagged | seconds, offline |
| `tools/parity_tier1.py` | scoring/threshold/chain drift across the whole historical DB | fast, needs DB |
| Prod soak | behavior on live traffic | 48–72h |

## Running it

opengrep and the Python deps aren't on bare dev hosts, so run against the
scanner image with the working tree mounted (clean, doesn't touch the running
scanner):

```bash
# Corpus + rule-coverage meta-test
docker run --rm --entrypoint python -v "$PWD:/src" -w /src pkgsentry-scanner \
  -m pytest tests/test_regression_corpus.py tests/test_rule_coverage.py -q

# opengrep rules self-test (all four language dirs)
docker run --rm --entrypoint bash -v "$PWD:/src" -w /src pkgsentry-scanner \
  tools/test_opengrep_rules.sh
```

Include your private corpus and the frozen-sample vault by setting the env vars
(see tiers below):

```bash
docker run --rm --entrypoint python \
  -v "$PWD:/src" -v /path/to/private:/private -w /src \
  -e PKGSENTRY_CORPUS_PATH=/private/corpus \
  -e PKGSENTRY_VAULT_PATH=/private/vault \
  pkgsentry-scanner -m pytest tests/test_regression_corpus.py -q
```

## How a sample is checked

The primary gate is the **verdict label**:

- a `bad` sample must score `malicious`/`suspicious` — a `clean` result is a
  false-negative regression and **fails**;
- a `good` sample must stay `clean` — any flag is false-positive creep and **fails**.

Optional per-sample rule pinning (`expect_rules` / `forbid_rules`) says *which*
scored rule should/shouldn't fire, so a break points at the exact layer. Extra
findings on a `bad` sample beyond `expect_rules` are surfaced as a warning, not a
failure (shadow `opengrep.shadow_*` findings are excluded — they don't score).

## Adding a sample

A sample is a directory laid out as the **extracted archive root** for its
ecosystem, plus a `manifest.toml`:

```
tests/corpus/<ecosystem>/<sample-name>/
    manifest.toml
    ...the package's source files...
```

```toml
ecosystem = "pypi"            # pypi | crates | gomod | npm
name = "evil-pkg"             # used for metadata typosquat/lure rules
version = "1.0.0"
label = "bad"                 # bad | good
expected_verdict = "malicious"  # bad -> malicious|suspicious ; good -> clean
expect_rules = ["installer.urlopen_exec_chain"]   # optional; must fire
forbid_rules = []             # optional; must NOT fire (FP guard)
notes = "what this exercises"
provenance = "synthetic"

# optional — only when targeting metadata.* rules (no DB needed):
[metadata]
watchlist_top_names = ["requests"]   # for typosquat
maintainers_now = ["alice"]

# optional — only for version_diff.* rules:
[prev]
version = "0.9.0"
verdict = "clean"
rule_ids = []
```

### Per-ecosystem layout

The sample dir must match what the analyzers see *inside the extracted archive*:

| Ecosystem | Layout |
|-----------|--------|
| pypi | `setup.py` / package modules at the root (or under a `pkg-ver/` wrapper) |
| crates | `build.rs` + `src/` (`Cargo.toml` optional) |
| gomod | `go.mod` + `.go` source files |
| npm | root `package.json` (the `package/` wrapper is stripped) |

Keep payloads **inert**: point at `example`/`.invalid` domains. Detection is
static — the code is read, never executed.

After adding a sample, run the corpus to confirm the verdict, then (optionally)
pin the rules it fires. If your sample exercises a previously-uncovered rule,
remove that rule from `ALLOW_UNCOVERED` in `tests/test_rule_coverage.py`.

## The rule-coverage meta-test

`tests/test_rule_coverage.py` enumerates every scored `rule_id` from the source
of truth (analyzer literals + the baseline intel pack's opengrep/yara rules) and
asserts:

1. every `expect_rules`/`forbid_rules` entry in a manifest is a **real** rule_id
   — catches a rule renamed/removed out from under a sample;
2. every static scored rule is either pinned by a sample **or** listed in the
   explicit `ALLOW_UNCOVERED` backlog — so a **new** rule can't ship untested by
   accident; you must add a sample or consciously waive it.

## Tiers: public vs private

| Tier | Location | Intel pinning | Ships publicly |
|------|----------|---------------|----------------|
| public | `tests/corpus/` | baseline only (deterministic) | yes |
| private | `tests/corpus_private/` or `$PKGSENTRY_CORPUS_PATH` | baseline + overlay | no (excluded from the OSS tarball) |
| vault | `$PKGSENTRY_VAULT_PATH` | baseline + overlay | no |

Public samples are pinned to the **baseline** intel pack so their expectations
are deterministic regardless of any operator overlay — keep them dependent only
on baseline rules/keywords. Anything that relies on private overlay content
(richer lure keywords, private YARA/threat-intel) belongs in a private tier.

## The frozen-sample vault

Registries yank malicious packages quickly. The vault preserves the **original
archive** of anything the engine flags `malicious`, so it remains a permanent
regression anchor and forensic reference.

- **Auto-capture:** when `$PKGSENTRY_VAULT_PATH` is set, the pipeline copies the
  flagged archive into the vault (inert, ZipCrypto pw `infected`) + a manifest,
  before the temp dir is cleaned. Unset (the public default), it's a no-op.
- **Manual backfill:** import past catches with `tools/vault_import.py`:

  ```bash
  PKGSENTRY_VAULT_PATH=/path/to/vault \
    python tools/vault_import.py crates sui-move-build-helper@0.1.0 \
      --verdict malicious --expect crates.build_rs_net_exec_chain
  ```

  (Add `--archive PATH` to store a local file instead of fetching.)

Vault entries are discovered as private known-bad corpus samples and **only ever
statically analyzed** — never detonated. The vault is a private operator asset
and never ships in the public tree.
