#!/usr/bin/env bash
# Provisions a Linux host for the pkgsentry scanner + detonation sandbox.
# Requires: kernel 5.8+ with BTF support, systemd, curl.
# Tested on AlmaLinux 9; should work on any modern Linux with eBPF/BTF.
# Run as root on the target host.
set -euo pipefail

echo "=== pkgsentry Host Setup ==="

# 1. Create OS users — one dedicated user per app, matching the rest of the
#    operator's stack (no sudo, no privilege escalation between apps).
if ! id detonation &>/dev/null; then
    useradd -r -m -d /home/detonation -s /bin/bash detonation
    echo "Created user: detonation"
fi
if ! id pkgsentry &>/dev/null; then
    useradd -r -m -d /home/pkgsentry -s /bin/bash pkgsentry
    echo "Created user: pkgsentry"
fi
# pkgsentry needs read access to the detonation UNIX socket so the scanner
# container / process can dispatch sandbox jobs.
usermod -a -G detonation pkgsentry

# 2. Create directories
mkdir -p /var/lib/detonation/{overlays,traces,images}
mkdir -p /var/run/detonation
mkdir -p /home/detonation/bin
chown -R detonation:detonation /var/lib/detonation /var/run/detonation /home/detonation

# pkgsentry working tree + private intel overlay path. The overlay
# directory is empty by default — populate it manually after first run.
mkdir -p /home/pkgsentry/bin
mkdir -p /home/pkgsentry/intel
mkdir -p /var/lib/pkgsentry/{archives,logs}
chown -R pkgsentry:pkgsentry /home/pkgsentry /var/lib/pkgsentry
# Group-read on the runtime socket dir so pkgsentry can connect via its
# membership in the detonation group.
chmod 750 /var/run/detonation

# 3. Install gVisor (runsc)
if ! command -v runsc &>/dev/null; then
    echo "Installing gVisor..."
    GVISOR_URL="https://storage.googleapis.com/gvisor/releases/release/latest/x86_64"
    curl -fsSL "${GVISOR_URL}/runsc" -o /usr/local/bin/runsc
    curl -fsSL "${GVISOR_URL}/containerd-shim-runsc-v1" -o /usr/local/bin/containerd-shim-runsc-v1
    chmod +x /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
    echo "gVisor installed: $(runsc --version)"
fi

# 4. Install Tetragon
if ! command -v tetragon &>/dev/null; then
    echo "Installing Tetragon..."
    TETRAGON_VERSION="v1.3.0"
    TETRAGON_DIR="tetragon-${TETRAGON_VERSION}-amd64"
    if [ ! -f "/tmp/tetragon.tar.gz" ]; then
        curl -fsSL "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/${TETRAGON_DIR}.tar.gz" -o /tmp/tetragon.tar.gz
    fi
    rm -rf "/tmp/${TETRAGON_DIR}"
    tar xzf /tmp/tetragon.tar.gz -C /tmp
    # Use Tetragon's own install.sh — it handles binaries, BPF objects, and systemd unit.
    pushd "/tmp/${TETRAGON_DIR}" >/dev/null
    ./install.sh
    popd >/dev/null
    rm -rf "/tmp/${TETRAGON_DIR}" /tmp/tetragon.tar.gz
    echo "Tetragon installed"
fi

# 5. Check BTF support
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "WARNING: BTF not available. Tetragon requires BTF."
    echo "Install kernel-debuginfo or set CONFIG_DEBUG_INFO_BTF=y"
fi

# 6. Tetragon systemd service — Tetragon's install.sh already drops a unit at
# /usr/lib/systemd/system/tetragon.service and the baseline tetragon.conf.d
# files (bpf-lib, log-format, log-level, verbose, server-address,
# export-filename, export-file-compress). We add export dirs, prod tuning,
# memory hardening, and enable.
mkdir -p /var/log/tetragon /var/lib/tetragon

# Prod daemon tuning — one file per flag in /etc/tetragon/tetragon.conf.d/.
# These layer on top of the baseline files written by Tetragon's install.sh.
#
#   export-file-perm=0644 is THE fix for log readability by the `detonation`
#   user (the detonation-svc reads /var/log/tetragon/tetragon.log). Tetragon
#   RECREATES the log file on every rotation at this mode, so a one-off
#   chmod/setfacl on the file — or a default ACL on the dir — does NOT survive
#   a rotation. Setting export-file-perm is the only durable fix.
#
#   rb-size / rb-queue-size enlarge the per-CPU ring buffer and Go-side channel
#   so execve storms (e.g. a fork-bomb sample) don't drop events.
mkdir -p /etc/tetragon/tetragon.conf.d
printf '0644\n'             > /etc/tetragon/tetragon.conf.d/export-file-perm
printf '4M\n'               > /etc/tetragon/tetragon.conf.d/rb-size
printf '262144\n'           > /etc/tetragon/tetragon.conf.d/rb-queue-size
printf '200\n'              > /etc/tetragon/tetragon.conf.d/export-file-max-size-mb
printf '20\n'               > /etc/tetragon/tetragon.conf.d/export-file-max-backups
printf '1h\n'               > /etc/tetragon/tetragon.conf.d/export-file-rotation-interval
printf '127.0.0.1:2112\n'   > /etc/tetragon/tetragon.conf.d/metrics-server
printf '127.0.0.1:8118\n'   > /etc/tetragon/tetragon.conf.d/gops-address

# Memory hardening drop-in — bound Tetragon's memory so a fork-bomb /
# execve-storm sample cannot OOM the tracer before the sandbox container dies.
# OOMScoreAdjust biases the kernel OOM killer toward the workload, not the
# observer.
mkdir -p /etc/systemd/system/tetragon.service.d
cat > /etc/systemd/system/tetragon.service.d/hardening.conf <<'HARDEN'
[Service]
MemoryHigh=1G
MemoryMax=2G
OOMScoreAdjust=-500
HARDEN

systemctl daemon-reload
systemctl enable tetragon

# 7. Install systemd units for detonation
cp /home/detonation/deploy/detonation-svc.service /etc/systemd/system/
cp /home/detonation/deploy/detonation.slice /etc/systemd/system/

# The detonation-svc unit declares ReadWritePaths=/var/run/runsc — that path
# is gVisor's runtime state dir, created lazily when gVisor first runs a
# container. systemd refuses to set up the namespace if a ReadWritePaths
# target is missing, so pre-create it and persist via tmpfiles.d.
mkdir -p /var/run/runsc
cat > /etc/tmpfiles.d/detonation.conf <<'TMPFILES'
d /var/run/runsc 0755 root root -
TMPFILES
systemd-tmpfiles --create /etc/tmpfiles.d/detonation.conf

systemctl daemon-reload
systemctl enable detonation-svc

# 8. Allow detonation user to run runsc
setcap cap_sys_admin,cap_sys_chroot+eip /usr/local/bin/runsc 2>/dev/null || true

# 9. Register runsc as a Docker runtime so `docker run --runtime=runsc` works.
# Detonation invokes Docker (not runsc directly) to delegate OCI bundle
# generation and image management to Docker.
if command -v docker &>/dev/null; then
    DAEMON_JSON=/etc/docker/daemon.json
    mkdir -p /etc/docker
    if [ ! -f "$DAEMON_JSON" ]; then
        cat > "$DAEMON_JSON" <<'JSON'
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc"
    }
  }
}
JSON
        systemctl restart docker
        echo "Registered runsc runtime in $DAEMON_JSON; docker restarted."
    else
        # Idempotent merge: only add the runtime if it's not already there.
        if ! grep -q '"runsc"' "$DAEMON_JSON"; then
            echo "WARNING: $DAEMON_JSON already exists. Add this to its 'runtimes' map manually and restart docker:"
            echo '  "runsc": { "path": "/usr/local/bin/runsc" }'
        fi
    fi
fi

# 10. Rootless Docker for detonation — ISOLATION CRITICAL
#
# The detonation user runs UNTRUSTED package code inside Docker containers.
# Docker group membership is root-equivalent: any process in the docker
# group can see, create, and destroy ALL containers and volumes on the host.
# A malicious package escaping the sandbox — or a bug in this service —
# could wipe every other container on the machine.
#
# Rootless Docker gives detonation its own completely separate Docker daemon
# and image/volume store. It literally cannot see the system Docker engine.

# Remove detonation from docker group if present (migration from older setup)
gpasswd -d detonation docker 2>/dev/null || true

echo "Setting up rootless Docker for detonation user..."

# Prerequisites
if command -v dnf &>/dev/null; then
    dnf install -y -q fuse-overlayfs slirp4netns 2>/dev/null || true
elif command -v apt-get &>/dev/null; then
    apt-get install -y -qq fuse-overlayfs slirp4netns 2>/dev/null || true
fi

# Subordinate UID/GID ranges for user namespaces
grep -q '^detonation:' /etc/subuid 2>/dev/null || echo "detonation:100000:65536" >> /etc/subuid
grep -q '^detonation:' /etc/subgid 2>/dev/null || echo "detonation:100000:65536" >> /etc/subgid

# Persistent user session — creates /run/user/<UID> at boot and starts
# the user's systemd instance immediately.
loginctl enable-linger detonation

DET_UID=$(id -u detonation)
DET_RUNTIME_DIR="/run/user/$DET_UID"
mkdir -p "$DET_RUNTIME_DIR"
chown detonation:detonation "$DET_RUNTIME_DIR"
# Short wait for systemd user instance to come up after enable-linger
sleep 2

# Install rootless Docker if not already set up
if ! su - detonation -c "DOCKER_HOST=unix://$DET_RUNTIME_DIR/docker.sock docker info" &>/dev/null; then
    if command -v dockerd-rootless-setuptool.sh &>/dev/null; then
        su - detonation -c "XDG_RUNTIME_DIR=$DET_RUNTIME_DIR dockerd-rootless-setuptool.sh install" 2>&1 || {
            echo "ERROR: rootless Docker setup failed."
            echo "Install docker-ce-rootless-extras and re-run."
            exit 1
        }
    else
        echo "ERROR: dockerd-rootless-setuptool.sh not found."
        echo "Install: dnf install docker-ce-rootless-extras  (or apt-get install docker-ce-rootless-extras)"
        exit 1
    fi
fi

# Enable + start rootless Docker
su - detonation -c "XDG_RUNTIME_DIR=$DET_RUNTIME_DIR systemctl --user enable docker" 2>/dev/null || true
su - detonation -c "XDG_RUNTIME_DIR=$DET_RUNTIME_DIR systemctl --user start docker" 2>/dev/null || true

# Environment file consumed by detonation-svc.service — tells it where the
# rootless Docker socket is (UID-dependent, generated at setup time) and where
# to find the optional private intel overlay (extra noise filters + network
# allowlists, merged UNION over the embedded baseline).
INTEL_OVERLAY="/home/pkgsentry/intel/private"
cat > /etc/default/detonation-svc <<ENVEOF
DOCKER_HOST=unix://$DET_RUNTIME_DIR/docker.sock
PKGSENTRY_INTEL_PATH=$INTEL_OVERLAY
ENVEOF

# Systemd drop-in: grant detonation-svc access to rootless Docker's runtime dir.
# ReadWritePaths in a drop-in replaces the base unit's list, so repeat all paths.
mkdir -p /etc/systemd/system/detonation-svc.service.d
cat > /etc/systemd/system/detonation-svc.service.d/rootless-docker.conf <<DROPEOF
[Service]
ReadWritePaths=/var/lib/detonation /var/run/detonation /tmp $DET_RUNTIME_DIR
DROPEOF

echo "Rootless Docker configured for detonation user (UID $DET_UID)"

# 11. Pre-pull base images into rootless Docker (NOT system Docker)
echo "Pre-pulling base images into rootless Docker..."
for img in python:3.11-slim node:20-slim rust:1-slim golang:1.22-alpine; do
    su - detonation -c "DOCKER_HOST=unix://$DET_RUNTIME_DIR/docker.sock docker pull $img" 2>/dev/null || true
done

# 12. Apply Tetragon tracing policy. Tetragon loads /etc/tetragon/tetragon.tp.d/
# at startup, so this does not depend on the `tetra` CLI being present. The
# policy is kprobes-only (a TracingPolicy cannot mix kprobes + tracepoints):
# 7 namespace-filtered kprobes covering connect, credential/environ reads,
# persistence writes, ptrace/process_vm_writev injection, memfd_create +
# execveat(AT_EMPTY_PATH) fileless exec. Pid-namespace 4026531836 (host) is
# excluded so only container syscalls are traced.
mkdir -p /etc/tetragon/tetragon.tp.d/
cp /home/detonation/deploy/tetragon-policy.yaml /etc/tetragon/tetragon.tp.d/detonation-monitor.yaml
echo "Tetragon policy installed"

# 13. SELinux: let detonation-svc (init_t) read the private intel overlay.
# The overlay lives under /home/pkgsentry (user_home_t); SELinux denies system
# services reading user-home content, so the overlay silently fails to load
# (intel_loaded source=baseline instead of baseline+overlay) under Enforcing.
# Fix = relabel the tree to public_content_t (shared read-only content) + a
# minimal policy letting init_t read public_content_t (NOT user_home_t).
if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
    echo "Configuring SELinux for the intel overlay..."
    command -v semanage &>/dev/null || dnf install -y -q policycoreutils-python-utils 2>/dev/null || true
    if [ -d "$INTEL_OVERLAY" ]; then
        semanage fcontext -a -t public_content_t "${INTEL_OVERLAY}(/.*)?" 2>/dev/null \
            || semanage fcontext -m -t public_content_t "${INTEL_OVERLAY}(/.*)?" 2>/dev/null || true
        restorecon -R "$INTEL_OVERLAY" 2>/dev/null || true
    fi
    # Install the policy module (prebuilt .pp if present, else compile the .te).
    SEL_DIR="/home/detonation/deploy/selinux"
    if [ -f "$SEL_DIR/detonation_intel_read.pp" ]; then
        semodule -i "$SEL_DIR/detonation_intel_read.pp" 2>/dev/null || true
    elif [ -f "$SEL_DIR/detonation_intel_read.te" ] && command -v checkmodule &>/dev/null; then
        ( cd "$SEL_DIR" \
          && checkmodule -M -m -o detonation_intel_read.mod detonation_intel_read.te \
          && semodule_package -o detonation_intel_read.pp -m detonation_intel_read.mod \
          && semodule -i detonation_intel_read.pp ) 2>/dev/null || true
    fi
    echo "SELinux intel-overlay access configured (verify: intel_loaded source=baseline+overlay)"
fi

echo ""
echo "=== Setup complete ==="
echo "Start services:"
echo "  sudo systemctl start tetragon"
echo "  sudo systemctl start detonation-svc"
echo ""
echo "Verify:"
echo "  curl --unix-socket /var/run/detonation/detonation.sock http://localhost/api/v1/health"
