# Detonation Service

The detonation service runs package install phases inside isolated Docker containers and
observes behavior via Tetragon eBPF tracing. It is a separate Go binary (`detonation-svc`)
that the scanner communicates with over a UNIX socket.

Currently PyPI-only. Crates.io and Go modules detonation is planned.

## Architecture

```
pkgsentry scanner
    └─ UNIX socket /var/run/detonation/detonation.sock
         └─ detonation-svc (Go, systemd, User=detonation)
              ├─ rootless Docker daemon      ← separate daemon, separate storage
              │    └─ docker run --runtime=runc
              │         └─ pip install <package>  ← guest process
              └─ tetragon (eBPF, root)       ← traces guest syscalls on the host
                   └─ /var/log/tetragon/tetragon.log  → behavioral rules → findings
```

### Rootless Docker isolation

The detonation service runs untrusted package code. It uses **rootless Docker** — a
completely separate Docker daemon running as the `detonation` user, with its own image
store and volume store at `/home/detonation/.local/share/docker/`.

The detonation user is **not** in the `docker` group and has **no access** to the system
Docker daemon. This means:

- A sandbox escape or bug in detonation-svc cannot see, modify, or destroy containers or
  volumes managed by the system Docker engine (your other services).
- A malicious package that escapes the container is confined to the `detonation` user's
  namespace — it cannot reach the system Docker socket.

`setup.sh` provisions rootless Docker automatically. The `DOCKER_HOST` environment
variable in the systemd unit points detonation-svc at the rootless socket
(`/run/user/<UID>/docker.sock`); the `docker` CLI inside detonation-svc respects this
without any code changes.

Tetragon (eBPF) still works: rootless Docker containers execute real syscalls on the host
kernel (unlike gVisor), so Tetragon traces them normally.

### Why runc, not gVisor/runsc

gVisor intercepts syscalls in userspace before they reach the kernel. This makes the guest
process opaque to host-level BPF tracers — Tetragon can see the Docker daemon's syscalls but
not the package's. Using runc keeps the guest's syscalls visible on the host kernel, where
Tetragon can trace them.

gVisor is installed and registered as an optional runtime in `/etc/docker/daemon.json`, but it
is not the default. You can still run `docker run --runtime=runsc` manually for defense-in-depth
analysis where Tetragon visibility is not required.

Isolation provided by the runc path: Docker PID/mount/network/UTS namespaces, seccomp default
profile, dropped capabilities, cgroup limits (2 CPU / 2 GB), `--no-new-privileges`, network
bridged (controlled per-call).

## Host requirements

- Linux, kernel 5.8+ with BTF support (`/sys/kernel/btf/vmlinux` must exist)
- systemd
- Docker (community edition, no EE requirement)
- x86-64 (gVisor + Tetragon are amd64-only)

Tested on AlmaLinux 9. Any modern RHEL-derivative or Debian-derivative with a BTF-enabled
kernel should work.

## Provisioning

Run `detonation/deploy/setup.sh` as root on the target host. The script is idempotent — safe to
re-run.

```bash
# Copy the binary and deploy assets to the target host first, then:
sudo bash /home/detonation/deploy/setup.sh
```

What `setup.sh` does:

1. Creates OS users `detonation` and `pkgsentry` (dedicated users, no sudo).
2. Creates directories: `/var/lib/detonation/`, `/var/run/detonation/`, `/var/lib/pkgsentry/`.
3. Installs gVisor (`runsc`) from the official release URL.
4. Installs Tetragon v1.3.0 via Cilium's `install.sh` (handles BPF objects + systemd unit).
5. Enables the `tetragon` systemd service.
6. Installs and enables the `detonation-svc` systemd unit and cgroup slice.
7. Creates `/var/run/runsc` and persists it via `/etc/tmpfiles.d/detonation.conf`.
   (systemd refuses to namespace a `ReadWritePaths` target that doesn't exist at unit start.)
8. Registers `runsc` as a Docker runtime in `/etc/docker/daemon.json`.
9. Pre-pulls `python:3.11-slim`, `node:20-slim`, `rust:1-slim` base images.
10. Installs the Tetragon tracing policy.

### BTF check

After running setup.sh, verify BTF is available:

```bash
ls /sys/kernel/btf/vmlinux
```

If the file is missing, Tetragon will start but not trace. Install `kernel-debuginfo` or rebuild
the kernel with `CONFIG_DEBUG_INFO_BTF=y`.

## Building and deploying the binary

From the repository root on your dev machine:

```bash
# Cross-compile for Linux/amd64 from Windows
cd detonation
make build    # outputs detonation-svc

# Copy to the host
make deploy   # uses rsync over SSH; configure DEPLOY_HOST in Makefile or env
```

Or build directly on the Linux host if Go is installed there:

```bash
cd detonation && go build -o detonation-svc ./cmd/detonation-svc/
sudo cp detonation-svc /home/detonation/bin/
sudo systemctl restart detonation-svc
```

## Starting services

```bash
sudo systemctl start tetragon
sudo systemctl start detonation-svc
```

Check status:

```bash
systemctl status tetragon detonation-svc
```

## Verifying the deployment

Health check:

```bash
curl --unix-socket /var/run/detonation/detonation.sock http://localhost/api/v1/health
```

Expected response: `{"status":"ok"}`.

Smoke test (scan a known-clean package):

```bash
curl --unix-socket /var/run/detonation/detonation.sock \
  -X POST http://localhost/api/v1/detonate \
  -H 'Content-Type: application/json' \
  -d '{"ecosystem":"pypi","package":"requests","version":"2.32.3","archive_path":"/tmp/requests-2.32.3.tar.gz"}'
```

A clean package should return `{"verdict":"clean","findings":[],"trace_events":<N>}` with zero
findings and a non-zero trace event count.

## Intel pack data in the Go service

`detonation-svc` embeds baseline TOMLs at build time from `pkgsentry/intel/baseline/detonation/`:

- `rules_data.toml` — sensitive path/env/shell lists used by behavioral rules
- `noise_baseline.toml` — per-ecosystem noise filters (known-benign pip/npm syscalls)

A private overlay can be mounted and pointed to via the `--intel-path` flag:

```bash
detonation-svc --intel-path /home/pkgsentry/intel/private
```

Overlay TOMLs are merged over the baseline using the same UNION/REPLACE semantics as the Python
side.

## Behavioral rules

Eight rules evaluated against Tetragon trace events:

| Rule ID | Signal |
|---------|--------|
| `exfil_http` | HTTP/HTTPS connection to external host during install |
| `credential_access` | Read of credential files (`~/.ssh/`, `~/.aws/`, keychain paths) |
| `reverse_shell` | Outbound TCP connection with shell invocation |
| `process_injection` | ptrace or `/proc/<pid>/mem` write to a foreign PID |
| `dns_exfil` | Unusually long DNS query (potential data-in-subdomain) |
| `env_harvest` | Read of sensitive environment variables |
| `suspicious_write` | Write to system directories or PATH locations |
| `net_beacon` | Repeated outbound connection at fixed intervals |

Findings from the detonation layer are returned to the scanner, merged into the package's
finding set, and feed the re-scoring step before LLM triage.

## Data persistence

Every detonation run persists three layers of data to the database:

### Detonation metadata (`detonation` table)

One row per sandbox run, linked to the parent `scan`. Stores execution details:

| Column | Description |
|--------|-------------|
| `sandbox_id` | Unique container ID for this run |
| `status` | `completed`, `timeout`, or `error` |
| `install_exit_code` / `install_duration_ms` | pip install phase result |
| `import_exit_code` / `import_duration_ms` | Python import phase result |
| `total_trace_events` | Raw Tetragon event count (before noise filtering) |
| `filtered_trace_events` | Events remaining after baseline noise filter |

### Trace events (`trace_event` table)

Every filtered Tetragon event is persisted, linked to the `detonation` row. Each row
captures a single syscall-level observation:

| Column | Description |
|--------|-------------|
| `phase` | `install` or `import` |
| `category` | `network`, `file`, `process`, `dns` |
| `operation` | `connect`, `exec`, `open`, `write`, `read`, etc. |
| `pid` | Guest process ID |
| `binary` | Path to the executable that made the syscall |
| `detail` | JSON — structured event data (addresses, paths, args) |
| `matched_rule` | Which behavioral rule matched this event (if any) |
| `ts` | Timestamp |

This gives you the full behavioral timeline of a package install. Example queries:

```sql
-- All network connections made during a detonation
SELECT te.operation, te.binary, te.detail, te.ts
FROM trace_event te
JOIN detonation d ON te.detonation_id = d.id
JOIN scan s ON d.scan_id = s.id
WHERE s.id = 12345
  AND te.category = 'network'
ORDER BY te.ts;

-- Packages that read SSH keys during install
SELECT p.name, v.version, te.binary, te.detail
FROM trace_event te
JOIN detonation d ON te.detonation_id = d.id
JOIN scan s ON d.scan_id = s.id
JOIN version v ON s.version_id = v.id
JOIN package p ON v.package_id = p.id
WHERE te.category = 'file'
  AND te.operation = 'open'
  AND te.detail::text LIKE '%/.ssh/%';

-- Most common binaries executed across all detonations
SELECT te.binary, COUNT(*) as n
FROM trace_event te
WHERE te.category = 'process' AND te.operation = 'exec'
GROUP BY te.binary
ORDER BY n DESC
LIMIT 20;

-- Full timeline for a specific scan (by trace ID)
SELECT te.phase, te.category, te.operation, te.binary, te.pid, te.detail, te.ts
FROM trace_event te
JOIN detonation d ON te.detonation_id = d.id
JOIN scan s ON d.scan_id = s.id
WHERE s.id = (SELECT id FROM scan WHERE sid = 'a1b2c3d4')
ORDER BY te.ts;
```

### Dynamic findings (`finding` table)

Behavioral rule hits are stored as regular `Finding` rows with `category = 'dynamic'`
and rule IDs like `dyn_install_exfil`, `dyn_reverse_shell`, `dyn_proc_inject`. They sit
alongside static analysis findings in the same table, queryable the same way.

## Troubleshooting

**detonation-svc fails to start:**

```bash
journalctl -u detonation-svc -n 50
```

Common causes: `/var/run/runsc` missing (re-run `systemd-tmpfiles --create`), `detonation-svc`
binary not at the path specified in the unit file, Docker not running.

**No trace events from Tetragon:**

```bash
journalctl -u tetragon -n 20
```

Verify BTF: `ls /sys/kernel/btf/vmlinux`. Verify the tracing policy is loaded:
`tetra tracingpolicy list`.

**Socket permission denied from scanner container:**

The scanner process must run as a user in the `detonation` group, or the socket permissions
must be widened. The `pkgsentry` OS user is added to the `detonation` group by `setup.sh`.
Inside Docker, ensure the container's UID maps to a group with socket read/write access.
