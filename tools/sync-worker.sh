#!/usr/bin/env bash
# sync-worker.sh — push the private intel overlay (prompts, YARA, hashes, genes,
# noise/net-allow lists) to every distributed scan-worker host and restart it so
# the change takes effect. The overlay is read once at process start, so a worker
# that isn't restarted keeps triaging with the OLD prompt/rules — this collapses
# "edit overlay -> sync -> restart" into one command and kills that drift.
#
# Usage:
#   bash tools/sync-worker.sh                 # sync to all hosts in the config
#   bash tools/sync-worker.sh --dry-run       # show what would transfer, change nothing
#   PKGWARD_WORKER_HOSTS=/path/to/conf bash tools/sync-worker.sh
#
# Config file (default: tools/worker-hosts.conf, gitignored — contains host IPs/keys):
#   one host per line, whitespace-separated, '#' comments allowed:
#     <ssh_key>  <user@host>  <remote_intel_dir>  <container_name>
#
# The local source is the live overlay at $PKGWARD_INTEL_SRC (default
# /home/pkgward/intel/private). Transfer is a mirror (rsync --delete) so a rule
# or gene you removed locally is removed on the worker too.
set -euo pipefail

SRC="${PKGWARD_INTEL_SRC:-/home/pkgward/intel/private}"
CONF="${PKGWARD_WORKER_HOSTS:-$(dirname "$0")/worker-hosts.conf}"
DRY=""
[[ "${1:-}" == "--dry-run" ]] && DRY="--dry-run"

SSH_OPTS="-o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15"

if [[ ! -d "$SRC" ]]; then
  echo "FATAL: intel source not found: $SRC" >&2; exit 1
fi
if [[ ! -f "$CONF" ]]; then
  echo "FATAL: worker-hosts config not found: $CONF" >&2
  echo "  Create it (one host per line):  <ssh_key> <user@host> <remote_intel_dir> <container>" >&2
  exit 1
fi

fail=0
while read -r key target remote_dir container _rest; do
  # skip comments + blank lines
  [[ -z "${key:-}" || "$key" == \#* ]] && continue
  if [[ -z "${target:-}" || -z "${remote_dir:-}" || -z "${container:-}" ]]; then
    echo "WARN: malformed config line (need 4 fields): $key $target $remote_dir $container" >&2
    fail=1; continue
  fi
  echo "==> $target  (container: $container)"

  # 1. mirror the overlay (trailing slashes = sync contents into remote_dir)
  if ! rsync -az --delete $DRY -e "ssh -i $key $SSH_OPTS" "$SRC/" "$target:$remote_dir/"; then
    echo "    rsync FAILED for $target" >&2; fail=1; continue
  fi
  if [[ -n "$DRY" ]]; then echo "    (dry-run: not restarting)"; continue; fi

  # 2. restart so the worker re-reads the overlay at startup
  if ! ssh -i "$key" $SSH_OPTS "$target" "docker restart $container >/dev/null"; then
    echo "    restart FAILED for $target" >&2; fail=1; continue
  fi

  # 3. confirm the overlay loaded (intel_loaded source=baseline+overlay)
  sleep 6
  line="$(ssh -i "$key" $SSH_OPTS "$target" "docker logs $container --since 30s 2>&1 | grep -m1 intel_loaded" || true)"
  if [[ "$line" == *baseline+overlay* ]]; then
    n="$(sed -n 's/.*"hash_seeds_n": \([0-9]*\).*/\1/p' <<<"$line")"
    echo "    OK — intel_loaded source=baseline+overlay (hash_seeds_n=${n:-?})"
  else
    echo "    WARN: restarted but did not see 'intel_loaded ... baseline+overlay' yet — check 'docker logs $container'" >&2
    fail=1
  fi
done < "$CONF"

[[ "$fail" == 0 ]] && echo "All workers synced." || { echo "One or more hosts had problems (see above)." >&2; exit 1; }
