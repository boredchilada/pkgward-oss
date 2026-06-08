#!/usr/bin/env bash
# audit-deps.sh — audit pkgward's OWN Python dependencies with piptastic
# (drift + known CVEs via pip-audit). The scanner that audits everyone else's
# packages should keep its own dependency tree clean.
#
# Runs piptastic in a throwaway scanner-image container with the tree mounted
# read-only — installs nothing on the host, touches nothing in the running
# scanner. piptastic is git-only (not on PyPI), pulled from the GitHub tarball
# so the container needs no `git`.
#
# Usage:
#   bash tools/audit-deps.sh                 # human-readable table
#   bash tools/audit-deps.sh --format sarif  # SARIF for CI / GitHub code scanning
#   bash tools/audit-deps.sh --format json   # machine-readable
#
# Exit code mirrors piptastic (non-zero when vulnerabilities are found), so it
# doubles as a CI gate.
set -euo pipefail

SRC="${PKGWARD_SRC:-/home/pkgward}"
IMAGE="${PKGWARD_IMAGE:-pkgward-scanner}"
PIPTASTIC_SRC="https://github.com/boredchilada/piptastic/archive/refs/heads/main.tar.gz"
COLS="${COLUMNS:-200}"

exec docker run --rm \
  -v "$SRC:/src:ro" -w /src \
  -e "COLUMNS=$COLS" \
  --entrypoint bash "$IMAGE" -c "
    pip install -q '$PIPTASTIC_SRC' >/dev/null 2>&1
    python -m piptastic audit /src ${*:-}
  "
