#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Validate the baseline opengrep rules against their co-located `--test`
# fixtures. Each rule file (e.g. js_net_to_exec.yaml) is paired with a target
# (js_net_to_exec.js / .py / .go) whose `// ruleid:` lines must match and
# `// ok:` lines must not.
#
# Skips gracefully (exit 0) when the opengrep binary is unavailable — the
# pipeline already degrades without it, and dev machines may not have it.
#
# Usage:
#   tools/test_opengrep_rules.sh                 # all language dirs
#   tools/test_opengrep_rules.sh javascript      # one language dir
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_BASE="$ROOT/pkgsentry/intel/baseline/opengrep"
BIN="${OPENGREP_BIN:-opengrep}"

if ! command -v "$BIN" >/dev/null 2>&1; then
  echo "opengrep binary '$BIN' not found — skipping rule tests (shadow layer)." >&2
  exit 0
fi

langs=("$@")
if [ ${#langs[@]} -eq 0 ]; then
  langs=(python rust go javascript)
fi

rc=0
for lang in "${langs[@]}"; do
  dir="$RULES_BASE/$lang"
  [ -d "$dir" ] || { echo "no rule dir: $dir (skip)"; continue; }
  echo "== opengrep --test $lang =="
  if ! "$BIN" --test --config "$dir" "$dir"; then
    rc=1
  fi
done
exit "$rc"
