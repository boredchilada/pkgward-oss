#!/usr/bin/env bash
# Provisions a Linux host for the pkgsentry detonation sandbox.
# Prerequisites (see bootstrap.sh for a one-command path): kernel 5.8+ with BTF,
# systemd, curl, Docker, the built binary at /home/detonation/bin/detonation-svc,
# and the deploy/ tree at /home/detonation/deploy. Run as root.
set -euo pipefail

echo "=== pkgsentry Host Setup ==="

# 0. Prerequisite checks (fail before mutating the host).
fail() { echo "ERROR: $1" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail "Docker not installed (run bootstrap.sh first)."
command -v curl  >/dev/null 2>&1 || fail "curl not installed."
[ -f /sys/kernel/btf/vmlinux ] || fail "BTF unavailable; Tetragon needs CONFIG_DEBUG_INFO_BTF=y."
[ -f /home/detonation/deploy/detonation-svc.service ] || fail "Stage deploy/ at /home/detonation/deploy first."
[ -x /home/detonation/bin/detonation-svc ] || fail "Build + stage the binary at /home/detonation/bin/detonation-svc first."

# 1. Users — one dedicated user per app, no docker group, no sudo.
if ! id detonation &>/dev/null; then
    useradd -r -m -d /home/detonation -s /bin/bash detonation
fi
if ! id pkgsentry &>/dev/null; then
    useradd -r -m -d /home/pkgsentry -s /bin/bash pkgsentry
fi
usermod -a -G detonation pkgsentry

# 2. Directories.
mkdir -p /var/lib/detonation/{overlays,traces,images} /var/run/detonation /home/detonation/bin
chown -R detonation:detonation /var/lib/detonation /var/run/detonation /home/detonation
mkdir -p /home/pkgsentry/bin /home/pkgsentry/intel /var/lib/pkgsentry/{archives,logs}
chown -R pkgsentry:pkgsentry /home/pkgsentry /var/lib/pkgsentry
chmod 750 /var/run/detonation

# 3. Tetragon.
if ! command -v tetragon &>/dev/null; then
    echo "Installing Tetragon..."
    TETRAGON_VERSION="v1.3.0"
    TETRAGON_DIR="tetragon-${TETRAGON_VERSION}-amd64"
    [ -f /tmp/tetragon.tar.gz ] || curl -fsSL "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/${TETRAGON_DIR}.tar.gz" -o /tmp/tetragon.tar.gz
    rm -rf "/tmp/${TETRAGON_DIR}"
    tar xzf /tmp/tetragon.tar.gz -C /tmp
    pushd "/tmp/${TETRAGON_DIR}" >/dev/null && ./install.sh && popd >/dev/null
    rm -rf "/tmp/${TETRAGON_DIR}" /tmp/tetragon.tar.gz
fi

# 4. Tetragon tuning. export-file-perm=0644 survives log rotation (the service
# reads the log as the detonation user); rb-size/rb-queue-size prevent event
# drops under execve storms.
mkdir -p /var/log/tetragon /var/lib/tetragon /etc/tetragon/tetragon.conf.d
printf '0644\n'           > /etc/tetragon/tetragon.conf.d/export-file-perm
printf '4M\n'             > /etc/tetragon/tetragon.conf.d/rb-size
printf '262144\n'         > /etc/tetragon/tetragon.conf.d/rb-queue-size
printf '200\n'            > /etc/tetragon/tetragon.conf.d/export-file-max-size-mb
printf '20\n'             > /etc/tetragon/tetragon.conf.d/export-file-max-backups
printf '1h\n'             > /etc/tetragon/tetragon.conf.d/export-file-rotation-interval
printf '127.0.0.1:2112\n' > /etc/tetragon/tetragon.conf.d/metrics-server
printf '127.0.0.1:8118\n' > /etc/tetragon/tetragon.conf.d/gops-address

mkdir -p /etc/systemd/system/tetragon.service.d
cat > /etc/systemd/system/tetragon.service.d/hardening.conf <<'HARDEN'
[Service]
MemoryHigh=1G
MemoryMax=2G
OOMScoreAdjust=-500
HARDEN

systemctl daemon-reload
systemctl enable tetragon

# 5. Detonation systemd units.
cp /home/detonation/deploy/detonation-svc.service /etc/systemd/system/
cp /home/detonation/deploy/detonation.slice /etc/systemd/system/
systemctl daemon-reload
systemctl enable detonation-svc

# 6. Rootless Docker for the detonation user — the isolation boundary. The user
# is NOT in the docker group; it runs untrusted package code in its own Docker
# daemon that cannot see the system engine's containers or volumes.
gpasswd -d detonation docker 2>/dev/null || true
echo "Configuring rootless Docker..."

# uidmap (newuidmap/newgidmap) and docker-ce-rootless-extras are both required.
if command -v dnf &>/dev/null; then
    dnf install -y -q fuse-overlayfs slirp4netns shadow-utils docker-ce-rootless-extras 2>/dev/null || true
elif command -v apt-get &>/dev/null; then
    apt-get install -y -qq fuse-overlayfs slirp4netns uidmap docker-ce-rootless-extras 2>/dev/null || true
fi

grep -q '^detonation:' /etc/subuid 2>/dev/null || echo "detonation:100000:65536" >> /etc/subuid
grep -q '^detonation:' /etc/subgid 2>/dev/null || echo "detonation:100000:65536" >> /etc/subgid
loginctl enable-linger detonation

DET_UID=$(id -u detonation)
DET_RUNTIME_DIR="/run/user/$DET_UID"
mkdir -p "$DET_RUNTIME_DIR"
chown detonation:detonation "$DET_RUNTIME_DIR"
sleep 2

if ! su - detonation -c "DOCKER_HOST=unix://$DET_RUNTIME_DIR/docker.sock docker info" &>/dev/null; then
    command -v dockerd-rootless-setuptool.sh &>/dev/null || fail "dockerd-rootless-setuptool.sh not found (install docker-ce-rootless-extras + uidmap)."
    su - detonation -c "XDG_RUNTIME_DIR=$DET_RUNTIME_DIR dockerd-rootless-setuptool.sh install" 2>&1 \
        || fail "rootless Docker setup failed (check uidmap + docker-ce-rootless-extras)."
fi
su - detonation -c "XDG_RUNTIME_DIR=$DET_RUNTIME_DIR systemctl --user enable docker" 2>/dev/null || true
su - detonation -c "XDG_RUNTIME_DIR=$DET_RUNTIME_DIR systemctl --user start docker" 2>/dev/null || true

INTEL_OVERLAY="/home/pkgsentry/intel/private"
cat > /etc/default/detonation-svc <<ENVEOF
DOCKER_HOST=unix://$DET_RUNTIME_DIR/docker.sock
PKGSENTRY_INTEL_PATH=$INTEL_OVERLAY
ENVEOF

# ReadWritePaths in a drop-in replaces the base unit's list, so repeat all paths.
mkdir -p /etc/systemd/system/detonation-svc.service.d
cat > /etc/systemd/system/detonation-svc.service.d/rootless-docker.conf <<DROPEOF
[Service]
ReadWritePaths=/var/lib/detonation /var/run/detonation /tmp $DET_RUNTIME_DIR
DROPEOF

# 7. Pre-pull base images into rootless Docker.
echo "Pre-pulling base images..."
for img in python:3.11-slim node:20-slim rust:1-slim golang:1.22-alpine; do
    su - detonation -c "DOCKER_HOST=unix://$DET_RUNTIME_DIR/docker.sock docker pull $img" 2>/dev/null || true
done

# 8. Tetragon tracing policy (loaded from /etc/tetragon/tetragon.tp.d/ at startup).
mkdir -p /etc/tetragon/tetragon.tp.d/
cp /home/detonation/deploy/tetragon-policy.yaml /etc/tetragon/tetragon.tp.d/detonation-monitor.yaml

# 9. SELinux: allow detonation-svc (init_t) to read the private intel overlay,
# which lives under user_home_t. Relabel to public_content_t + load the module.
if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
    echo "Configuring SELinux for the intel overlay..."
    command -v semanage &>/dev/null || dnf install -y -q policycoreutils-python-utils 2>/dev/null || true
    if [ -d "$INTEL_OVERLAY" ]; then
        semanage fcontext -a -t public_content_t "${INTEL_OVERLAY}(/.*)?" 2>/dev/null \
            || semanage fcontext -m -t public_content_t "${INTEL_OVERLAY}(/.*)?" 2>/dev/null || true
        restorecon -R "$INTEL_OVERLAY" 2>/dev/null || true
    fi
    SEL_DIR="/home/detonation/deploy/selinux"
    if [ -f "$SEL_DIR/detonation_intel_read.pp" ]; then
        semodule -i "$SEL_DIR/detonation_intel_read.pp" 2>/dev/null || true
    elif [ -f "$SEL_DIR/detonation_intel_read.te" ] && command -v checkmodule &>/dev/null; then
        ( cd "$SEL_DIR" \
          && checkmodule -M -m -o detonation_intel_read.mod detonation_intel_read.te \
          && semodule_package -o detonation_intel_read.pp -m detonation_intel_read.mod \
          && semodule -i detonation_intel_read.pp ) 2>/dev/null || true
    fi
fi

echo ""
echo "=== Setup complete ==="
echo "  sudo systemctl start tetragon detonation-svc"
echo "  curl --unix-socket /var/run/detonation/detonation.sock http://localhost/api/v1/health"
