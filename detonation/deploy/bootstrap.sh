#!/usr/bin/env bash
# One-command deploy for the pkgsentry detonation sandbox.
# Installs Docker and a Go toolchain if absent, builds and stages the service,
# runs setup.sh, and starts the sandbox. Run as root.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root." >&2; exit 1; }

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DET_DIR="$(dirname "$DEPLOY_DIR")"

# 1. Docker (+ rootless extras + uidmap).
if ! command -v docker >/dev/null 2>&1; then
    echo "Installing Docker..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg
        install -m0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
        . /etc/os-release
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras uidmap
    elif command -v dnf >/dev/null 2>&1; then
        dnf -y install dnf-plugins-core
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
        systemctl enable --now docker
    else
        echo "ERROR: unsupported package manager; install Docker manually." >&2; exit 1
    fi
fi

# 2. Go 1.22+ (build-time only).
need_go=1
if command -v go >/dev/null 2>&1; then
    ver="$(go env GOVERSION 2>/dev/null | sed 's/go//')"
    major="${ver%%.*}"; rest="${ver#*.}"; minor="${rest%%.*}"
    if [ "${major:-0}" -gt 1 ] || { [ "${major:-0}" -eq 1 ] && [ "${minor:-0}" -ge 22 ]; }; then need_go=0; fi
fi
if [ "$need_go" -eq 1 ]; then
    echo "Installing Go..."
    GO_VER=1.22.12
    case "$(uname -m)" in aarch64) goarch=arm64;; *) goarch=amd64;; esac
    curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-${goarch}.tar.gz" -o /tmp/go.tgz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
fi
command -v go >/dev/null 2>&1 || export PATH="/usr/local/go/bin:$PATH"

# 3. Build (buildvcs off so ownership mismatch doesn't fail the build).
echo "Building detonation-svc..."
( cd "$DET_DIR" && GOOS=linux GOARCH=amd64 go build -buildvcs=false -o bin/detonation-svc ./cmd/detonation-svc/ )

# 4. Stage deploy tree + binary where setup.sh and the systemd unit expect them.
id detonation &>/dev/null || { groupadd -f detonation; useradd -r -m -d /home/detonation -s /bin/bash -g detonation detonation; }
mkdir -p /home/detonation/deploy /home/detonation/bin
cp -r "$DEPLOY_DIR/." /home/detonation/deploy/
cp "$DET_DIR/bin/detonation-svc" /home/detonation/bin/
chown -R detonation:detonation /home/detonation

# 5. Provision.
bash /home/detonation/deploy/setup.sh

# 6. Start + verify.
systemctl start tetragon
systemctl start detonation-svc
sleep 2
echo ""
echo "Health check:"
curl -s --unix-socket /var/run/detonation/detonation.sock http://localhost/api/v1/health || true
echo ""
echo "Scanner (Tier A): docker compose -f docker-compose.standalone.yml up -d --build"
