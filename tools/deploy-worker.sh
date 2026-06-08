#!/usr/bin/env bash
# deploy-worker.sh — pull the latest committed code onto every distributed scan
# worker and restart it. Pairs with sync-worker.sh (which does the same for the
# private intel overlay): code ships via git, intel ships via rsync, both one-command.
#
# This works because the scanner image installs the package editable
# (`pip install -e .`), and the worker bind-mounts a git checkout over /app — so a
# `git pull` + `docker restart` picks up new code with NO image rebuild/transfer.
# The image only needs re-shipping when requirements.txt changes.
#
# Usage:
#   bash tools/deploy-worker.sh                 # git pull + restart on all hosts
#   bash tools/deploy-worker.sh <git-ref>       # check out a specific ref first
#
# Config (default: tools/worker-hosts.conf, gitignored):
#   <ssh_key>  <user@host>  <remote_intel_dir>  <container>  <repo_dir>
#   repo_dir is the worker's git checkout of the private repo (default /root/pkgward).
set -euo pipefail

CONF="${PKGWARD_WORKER_HOSTS:-$(dirname "$0")/worker-hosts.conf}"
REF="${1:-}"
SSH_OPTS="-o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15"

if [[ ! -f "$CONF" ]]; then
  echo "FATAL: worker-hosts config not found: $CONF" >&2; exit 1
fi

fail=0
while read -r key target _intel container repo_dir _rest; do
  [[ -z "${key:-}" || "$key" == \#* ]] && continue
  repo_dir="${repo_dir:-/root/pkgward}"
  if [[ -z "${target:-}" || -z "${container:-}" ]]; then
    echo "WARN: malformed config line: $key $target ... $container" >&2; fail=1; continue
  fi
  echo "==> $target  ($repo_dir -> $container)"

  remote_cmd="set -e
    cd '$repo_dir'
    git fetch --quiet origin
    git checkout --quiet ${REF:-modernize}
    git pull --quiet --ff-only || { echo 'pull not fast-forward'; exit 1; }
    echo \"  at \$(git rev-parse --short HEAD) — \$(git log -1 --format=%s)\"
    docker restart '$container' >/dev/null"
  if ! ssh -i "$key" $SSH_OPTS "$target" "$remote_cmd"; then
    echo "    deploy FAILED for $target" >&2; fail=1; continue
  fi

  # confirm the worker came back up and re-read its intel
  sleep 6
  line="$(ssh -i "$key" $SSH_OPTS "$target" "docker logs $container --since 30s 2>&1 | grep -m1 intel_loaded" || true)"
  if [[ "$line" == *baseline+overlay* ]]; then
    echo "    OK — worker restarted, intel_loaded source=baseline+overlay"
  else
    echo "    WARN: restarted but no 'intel_loaded' yet — check 'docker logs $container'" >&2; fail=1
  fi
done < "$CONF"

[[ "$fail" == 0 ]] && echo "All workers deployed." || { echo "One or more hosts failed (see above)." >&2; exit 1; }
