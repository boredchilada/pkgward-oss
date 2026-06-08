# Detonation Service

The detonation service runs package install phases inside isolated Docker containers and
observes behavior via Tetragon eBPF tracing. It is a separate Go binary (`detonation-svc`)
that the scanner communicates with over a UNIX socket.

Runs for PyPI, crates, Go modules, and npm (max-concurrent 6). The pipeline reads
Tetragon's JSONL log per detonation, tags events with the install/import phase
by time window, filters host/build noise, then evaluates the Go behavioral rules.

## Architecture

```
pkgward scanner
    └─ UNIX socket /var/run/detonation/detonation.sock
         └─ detonation-svc (Go, systemd, User=detonation)
              ├─ rootless Docker daemon      ← separate daemon, separate storage
              │    └─ docker run --runtime=runc
              │         └─ pip install <package>  ← guest process
              └─ tetragon (eBPF, root)       ← traces guest syscalls on the host
                   └─ /var/log/tetragon/tetragon.log  → behavioral rules → findings
```

### Phase commands per ecosystem

Each phase is a **separate `docker run --rm`** with only the package archive bind-mounted
read-only — phases do **not** share a writable filesystem. Profiles live in
`detonation/internal/sandbox/profile.go`.

- **PyPI** — install: `pip install --no-deps`; import: in-process `import` of the top-level
  module(s) + an in-process settle window (an import-time payload often runs in a daemon
  thread that dies when the interpreter exits, so the sleep must be *inside* the process).
- **npm** — install phase does the work (the import phase runs in a fresh container where
  the package isn't installed, so `node -e require(<name>)` would just `MODULE_NOT_FOUND`).
  It extracts the tarball, places deps with scripts off, runs the `preinstall`/`install`/
  `postinstall` hooks, **then runs the package's runtime entry (`node <main>`, as an entry
  module so `require.main === module`-gated payloads fire) and each `bin` target** —
  backgrounded + time-boxed into the settle window. This is what catches a self-decoding
  loader or downloader shipped as `main`/`bin` with no lifecycle hook (the turbo-dls class).
- **crates** — `cargo install` (exercises `build.rs` at build time); no import phase.
- **gomod** — extract zip → `go mod download` → `go generate ./...` → `go build ./...`
  (Go has no install hook; the surface is `go:generate` + build-time execution).

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

gVisor (`runsc`) is not installed or used. For defense-in-depth where Tetragon visibility is
not required, install runsc separately, register it in `/etc/docker/daemon.json`, and run
`docker run --runtime=runsc` manually.

Isolation provided by the runc path: Docker PID/mount/network/UTS namespaces, seccomp default
profile, dropped capabilities, cgroup limits (2 CPU / 2 GB), `--no-new-privileges`, network
bridged (controlled per-call).

## Host requirements

- Linux, kernel 5.8+ with BTF support (`/sys/kernel/btf/vmlinux` must exist)
- systemd
- Docker (community edition, no EE requirement)
- x86-64 (Tetragon is amd64-only)
- Go 1.22+ to build the service (build-time only; `bootstrap.sh` installs it if missing)

Tested on AlmaLinux 9. Any modern RHEL-derivative or Debian-derivative with a BTF-enabled
kernel should work.

## Provisioning

### One command

On a clean host, as root, from the repo's `detonation/` directory:

```bash
sudo bash deploy/bootstrap.sh
```

`bootstrap.sh` installs Docker and a Go 1.22+ toolchain if missing, builds the service
(`-buildvcs=false`), stages it to `/home/detonation/{deploy,bin}`, runs `setup.sh`, and starts
the sandbox.

### Manual

Build and stage first, then run `setup.sh` (idempotent):

```bash
cd detonation
make build
mkdir -p /home/detonation/deploy /home/detonation/bin /home/detonation/src
cp -r deploy/. /home/detonation/deploy/
cp bin/detonation-svc /home/detonation/bin/
# Stage the dns-forwarder build context so setup.sh can build its image (rootless
# build context must be readable by the detonation user):
cp -r cmd internal go.mod go.sum /home/detonation/src/ 2>/dev/null || true
cp deploy/dns-forwarder.Dockerfile /home/detonation/src/
chown -R detonation:detonation /home/detonation/src
sudo bash /home/detonation/deploy/setup.sh
```

`setup.sh` fails fast if a prerequisite (Docker, BTF, the staged binary/deploy tree) is missing,
then:

1. Creates OS users `detonation` and `pkgward` (dedicated, no sudo, not in `docker`).
2. Creates `/var/lib/detonation/`, `/var/run/detonation/`, `/var/lib/pkgward/`.
3. Installs Tetragon v1.3.0 via Cilium's `install.sh` and enables it.
4. Installs and enables the `detonation-svc` unit and cgroup slice.
5. Provisions rootless Docker for the `detonation` user (installs `uidmap`,
   `docker-ce-rootless-extras`, `fuse-overlayfs`, `slirp4netns`).
6. Pre-pulls the `python:3.13-slim-trixie`, `node:22-trixie-slim`, `rust:1-trixie`, `golang:1.24-trixie`
   base images (the per-ecosystem `pkgward-det-<eco>` sandbox images are derived from these — see
   `deploy/build-sandbox-images.sh`).
7. Builds the `pkgward-dnsforwarder` image into rootless Docker (DNS-aware abuse-host
   detection). The service queries it via `docker exec`, so no host port is published. The
   build context is staged at `/home/detonation/src` by `bootstrap.sh`; if it is absent
   (standalone `setup.sh`), DNS capture stays off and detonation judges connects by IP until
   the image is built (`make forwarder-image`, into the rootless store).
8. Installs the Tetragon tracing policy.
9. Under SELinux Enforcing, relabels the intel overlay so detonation-svc can read it.

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

Or build directly on the Linux host (requires **Go 1.22+**; `go.mod` declares `go 1.22`).
On AlmaLinux: `dnf install -y golang`. Go is a build-time dependency only — it is not
needed at runtime, so `deploy/setup.sh` (which provisions the runtime host) does not
install it.

```bash
cd detonation && go build -o detonation-svc ./cmd/detonation-svc/
sudo systemctl stop detonation-svc          # avoid ETXTBSY on the running binary
sudo cp -f detonation-svc /home/detonation/bin/
sudo chown detonation:detonation /home/detonation/bin/detonation-svc
sudo systemctl start detonation-svc
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

**Restarting `detonation-svc` requires restarting the scanner.** The scanner
container bind-mounts the API socket *file* (`/var/run/detonation/detonation.sock`),
and the service recreates that socket (new inode) on startup, so the container's
mount strands on the deleted inode → the worker gets `Connection refused` (jobs
requeue, none lost). After deploying a new binary:

```bash
sudo systemctl restart detonation-svc
docker restart pkgward        # re-binds the socket; never `docker compose up -d`
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

`detonation-svc` embeds baseline TOMLs at build time from `pkgward/intel/baseline/detonation/`
(the embedded copies live at `detonation/internal/intel/baseline/` — keep both in sync):

- `rules_data.toml` — sensitive path/env/shell lists used by behavioral rules
- `noise_baseline.toml` — per-ecosystem noise filters, two kinds:
  - **file/exec noise** (`{eco}_file_noise`, `{eco}_exec_noise`) — known-benign syscalls
    dropped before rules run (e.g. `/.npm/_cacache/`, `.npmrc`, `/node`).
  - **network allowlist** (`{eco}_net_allow`) — registry/CDN destinations that legitimate
    dependency fetches reach. Entries are hostnames (resolved to IPs at detonation time via
    DNS) or literal IPs. `Filter()` drops `network`/`connect` events to these, so normal
    registry traffic does not false-positive as `dyn_import_exfil` / `dyn_install_exfil`.
    Baseline covers the canonical registries (`registry.npmjs.org`, `files.pythonhosted.org`,
    `static.crates.io`, `proxy.golang.org`, …). **Do not add broad CDN CIDRs** (e.g. all of
    Cloudflare) — that would mask real exfil. Never allowlist internal infra.

A private overlay extends the baseline (UNION merge) — point the service at it with the
`PKGWARD_INTEL_PATH` env var (set in `/etc/default/detonation-svc`):

```
PKGWARD_INTEL_PATH=/path/to/your/intel/pack
```

The service reads `$PKGWARD_INTEL_PATH/detonation/{rules_data,noise_baseline}.toml`. Operators
pin extra/private domains and observed registry IPs there (the npm/pypi/crates/gomod CDN IPs can
be mined from the `trace_event` table — see `docs/operations.md`). Successful load logs
`intel_loaded source=baseline+overlay`.

### DNS-aware network filtering

Tetragon reports a connect's **destination IP**, never the hostname. Serverless/tunnel hosts
(`*.workers.dev`, `pages.dev`, `trycloudflare`, `ngrok`, …) resolve *into* the same shared CDN
ranges legitimate registry/CDN fetches use, so by IP a `workers.dev` C2 beacon is
indistinguishable from a `jsdelivr` fetch. To tell them apart the service captures DNS:

- A small `pkgward-dnsforwarder` container runs on the detonation bridge; each sandbox is
  pointed at it (`--dns <forwarder>`), so every name a package resolves passes through and the
  forwarder records resolved-IP → hostname.
- Before rules run, each `network`/`connect` event is annotated with the domain the sandbox
  resolved, and `Filter()` then judges it by **domain**: an abuse-prone host (`abuse_hosts` in
  `noise_baseline.toml`) is kept and flagged `dyn_abuse_hosting_callback` (critical); a
  `net_allow` domain (or an allowlisted-CIDR IP) is dropped; anything else is kept for the
  exfil rules. Exfil-rule evidence shows `hostname (ip):port` when a domain was captured.
- The service queries the forwarder over the **rootless Docker socket** (`docker exec
  det-dnslog /dns-forwarder lookup <ip>`), not a host TCP port — the confined `init_t` service
  is denied connecting to rootless-published loopback ports.
- An exact-match `net_allow` entry is written `=host` (e.g. `=storage.googleapis.com`): it
  allows the bare host but **not** per-tenant `<bucket>.storage.googleapis.com` subdomains (the
  bucket-exfil shape), so path-style cloud CDNs can be allowlisted without opening every bucket.

Gated by `DNS_FORWARDER_IMAGE` (default `pkgward-dnsforwarder`, built into rootless Docker by
`setup.sh`). **Best-effort**: if the forwarder can't start, the service logs a loud `WARNING`,
sandboxes fall back to a public resolver, and the filter degrades to IP-only matching — abuse-host
detection is inert but detonation keeps working. Startup logs `dns capture: enabled|disabled`.

### SELinux gotcha (SELinux Enforcing)

`detonation-svc` runs as `init_t`. If your intel pack lives under a user's home directory, its
files are labelled `user_home_t`, and SELinux **denies a system service reading user-home
content** — so the overlay silently fails to load (`permission denied` → `source=baseline`) even
though Unix perms and a `sudo -u <svc-user>` read both succeed. Diagnose with
`ausearch -m avc -ts recent | grep detonation-svc`.

The fix (keeps a single private-intel source of truth — substitute your own pack path):

```bash
# 1. relabel the private intel tree to shared-read content
semanage fcontext -a -t public_content_t "$PKGWARD_INTEL_PATH(/.*)?"
restorecon -Rv "$PKGWARD_INTEL_PATH"
# 2. allow init_t to read public_content_t (minimal, scoped — NOT user_home_t)
semodule -i detonation/deploy/selinux/detonation_intel_read.pp
systemctl restart detonation-svc   # expect: intel_loaded source=baseline+overlay
```

The policy source is `detonation/deploy/selinux/detonation_intel_read.te` (build with
`checkmodule -M -m -o x.mod x.te && semodule_package -o x.pp -m x.mod`).

## Behavioral rules

Rules in `internal/rules/definitions.go`, evaluated against phase-tagged Tetragon trace
events (see `docs/detection-rules.md` Layer 10 for severity/confidence):

| Rule ID | Severity | Signal |
|---------|----------|--------|
| `dyn_install_exfil` | high | **Chain**: a secret was read (`run_sensitive_access`) **and** an external-host connect, during the install phase |
| `dyn_import_exfil` | high | **Chain**: secret read **and** external-host connect, during the import phase |
| `dyn_install_egress` | low | Lone external connect during install (non-convicting note for visibility) |
| `dyn_import_egress` | low | Lone external connect during import (non-convicting note) |
| `dyn_abuse_hosting_callback` | critical | connect to an abuse-prone serverless/tunnel host (`workers.dev`, `ngrok`, …) — matched by hostname, so a shared-CDN IP can't hide it |
| `dyn_honeytoken_exfil` | critical | a decoy credential planted in the sandbox surfaced in exec args / a file / a DNS name — proof of theft (no chain needed) |
| `dyn_credential_read` | — | read of a sensitive file (`/root/.ssh`, cloud creds, `/etc/shadow`) |
| `dyn_env_harvest` | — | read of another process's environment via `/proc/<pid>/environ` |
| `dyn_screen_capture_probe` | high | exec of a screenshot/input-capture tool (`scrot`, `grim`, `xinput`, …) — desktop-surveillance staging |
| `dyn_proc_inject` | — | `ptrace` (ATTACH/SEIZE/POKE) or `process_vm_writev` injection |
| `dyn_suspicious_write` | — | write to a persistence path (`/etc/cron`, `.bashrc`, authorized_keys) |
| `dyn_fileless_exec` | — | `execveat(AT_EMPTY_PATH)` / `memfd_create` |
| `dyn_reverse_shell` | — | shell spawned with an open socket (**dormant** — needs socket-fd tracking) |
| `dyn_dns_exfil` | — | high-entropy DNS query (**dormant** — needs UDP-payload parsing) |

`dyn_install_exfil` / `dyn_import_exfil` are the first **dynamic behavioral chain**: a bare
network connect is dual-use (fetching deps, prebuilt binaries, params) and used to false-positive
constantly, so exfil now requires the data-theft *shape* — a secret was touched in the same
detonation **and** the connect leaves the sandbox for an external host (private/loopback/bridge
addresses, incl. the DNS forwarder, are infra, never egress). A lone external connect emits the
low, non-convicting `dyn_install_egress` / `dyn_import_egress` note instead. The
**`{eco}_net_allow` allowlist** (see above) still drops connects to known registry/CDN hosts
first. All events are attributed to the sandbox container by its `docker` id before rules run
(see "Event attribution" below), so concurrent detonations and host activity don't
cross-contaminate.

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

## Tetragon configuration

Daemon options live in `/etc/tetragon/tetragon.conf.d/` (one file per flag) and a
systemd drop-in. Current prod tuning:

| Setting | Value | Why |
|---------|-------|-----|
| `rb-size` | `4M` | per-CPU ring buffer; default 65K drops events under execve storms |
| `rb-queue-size` | `262144` | Go-side channel; prevents downstream drops |
| `export-file-perm` | `0644` | log readable by the `detonation` user **across rotations** (rotation recreates the file at this mode; a one-off `chmod`/ACL does not survive) |
| `export-file-max-size-mb` / `-backups` / `rotation-interval` | `200` / `20` / `1h` | retention |
| `metrics-server` | `127.0.0.1:2112` | event-loss metrics; alert on `rate(tetragon_observer_ringbuf_events_lost_total[5m]) > 0` |
| systemd drop-in | `MemoryHigh=1G MemoryMax=2G OOMScoreAdjust=-500` | a fork-bomb sample must not OOM the tracer before the sandbox |

**Event attribution is by container id, not PID namespace.** The host's Tetragon
export carries no `ns` field, so the old `ns.pid_for_children` filter matched every
container (the scanner and all concurrent sandboxes bled into each detonation's
trace). The collector now keeps only events whose `docker` container id matches the
ids the sandbox captured via `--cidfile` for that detonation; if capture fails it
logs a warning and falls back to the time window alone. `enable-process-ns` is no
longer needed and the collector does not read it.

The tracing policy is loaded from `/etc/tetragon/tetragon.tp.d/` **at startup only** —
dropping a file in after Tetragon is running does nothing until reload. Hot-reload with
`tetra tracingpolicy delete/add`. Validate a new policy under a temporary
`metadata.name` first: a single bad hook makes the **whole** policy `load_error` →
zero events. A `TracingPolicy` cannot mix `kprobes` and `tracepoints` sections.
`matchArgs` has no `In` operator — use `Equal` with multiple values.

## Troubleshooting

**Detonations error with `NanoCPUs can not be set`:** rootless Docker here has no CPU
CFS controller, so `--cpus` makes `docker run` fail. The sandbox omits `--cpus`
(`internal/sandbox/gvisor.go`); keep it omitted.

**Detonations stop after restarting `detonation-svc`** (`[Errno 111] Connection
refused` in the scanner): the service recreated the socket inode, but the `pkgward`
container bind-mounts the socket *file*, so it holds the dead inode. Run
`docker restart pkgward` (single container — never `docker compose up -d`). Durable
fix: bind-mount the parent directory instead of the socket file.

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
must be widened. The `pkgward` OS user is added to the `detonation` group by `setup.sh`.
Inside Docker, ensure the container's UID maps to a group with socket read/write access.
