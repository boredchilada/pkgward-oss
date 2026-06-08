#!/usr/bin/env bash
# Build the per-ecosystem detonation sandbox images (pkgward-det-<eco>) — the
# upstream base + the broad runtime libs/tools malware payloads need to actually
# execute (so they trace instead of dying at dlopen). Run as the detonation user
# against its rootless Docker daemon. Idempotent; safe to re-run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKERFILE="$HERE/sandbox.Dockerfile"

# Shared: runtime shared-libraries + downloader/recon/crypto tools that real
# payloads link or invoke (libbpf=eBPF, libsqlite3=browser cred DBs, libpcap,
# libnss3/libsecret=keyrings, gnupg=GPG-key theft, git=self-replication, ...).
SHARED="ca-certificates curl wget git openssl gnupg xz-utils unzip \
libbpf1 libelf1 zlib1g libssl3 libcurl4 libsqlite3-0 libpcap0.8 \
libstdc++6 libffi8 libreadline8 libncursesw6 libnss3 libsecret-1-0 \
liblzma5 libbz2-1.0 libzstd1 libgmp10 libuuid1 \
procps iproute2 net-tools dnsutils file"
# Native toolchain for ecosystems whose install/build actually compiles.
TOOLCHAIN="gcc g++ make libc6-dev pkg-config"

# Trixie/glibc-2.41 bases so even bleeding-edge native payloads run (IronWorm's Rust
# ELF needs GLIBC 2.39; bookworm only had 2.36). glibc is backward-compatible, so a
# newer base runs old AND new binaries — strictly more coverage.
declare -A BASES=(
  [pypi]="python:3.13-slim-trixie"
  [npm]="node:22-trixie-slim"
  [crates]="rust:1-trixie"
  [gomod]="golang:1.24-trixie"
)
declare -A EXTRA=(
  [pypi]="$TOOLCHAIN"
  [npm]="$TOOLCHAIN python3"
  [crates]="$TOOLCHAIN"
  [gomod]="$TOOLCHAIN"
)

DOCKER="${DOCKER:-docker}"
for eco in "${!BASES[@]}"; do
  base="${BASES[$eco]}"
  pkgs="$SHARED ${EXTRA[$eco]}"
  echo "==> building pkgward-det-$eco  (FROM $base)"
  "$DOCKER" build \
    --build-arg "BASE=$base" \
    --build-arg "PKGS=$pkgs" \
    -t "pkgward-det-$eco" \
    -f "$DOCKERFILE" "$HERE" 1>&2
done
echo "==> done: $("$DOCKER" images --format '{{.Repository}}' | grep -c '^pkgward-det-') sandbox images"
