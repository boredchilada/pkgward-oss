# Tetragon Research Brief (2026-05-26)

Consolidated reference for pkgward's detonation Tetragon deployment.
Four parallel research passes: policy syntax, detonation use cases, performance tuning, ecosystem.

---

## Part 1 — TracingPolicy reference

### CRD shape
Two kinds, both `apiVersion: cilium.io/v1alpha1`:
- **`TracingPolicy`** — cluster/host-wide. What we use (standalone, no k8s).
- **`TracingPolicyNamespaced`** — k8s-namespace-scoped, irrelevant here.

`spec` top-level fields: `kprobes[]`, `tracepoints[]` (with optional `raw: true`), `uprobes[]`, `usdts[]`, `lsmhooks[]`, `enforcers[]`, `lists[]` (reusable arg lists referenced via `InMap`), `options[]`, `selectorsMacros[]`.

Source: https://tetragon.io/docs/reference/tracing-policy/

### Hook types — when to use what
| Hook | Best for | Notes |
|---|---|---|
| `kprobes` (`syscall: false`) | Internal kernel funcs (`security_*`, `tcp_connect`). | Strip arch prefix (`__x64_`, `__arm64_`) when `syscall: true`. |
| `kprobes` (`syscall: true`) | Syscall entries by name (`sys_openat`). | Auto-resolves arch ABI; different from raw tracepoint. |
| `tracepoints` | Stable kernel events (`sched_process_exec`). | Stable ABI across kernels. |
| `tracepoints` + `raw: true` | Same event, faster, raw pointer args. | When you need `linux_binprm` etc. |
| `uprobes` | User-space binaries/libs. | Path + symbol; tied to binary build. |
| `lsmhooks` | MAC-style enforcement (`file_open`, `bprm_check_security`). | Needs `CONFIG_BPF_LSM=y` AND `lsm=...,bpf` boot param. |

For our detonation rig: **tracepoints** for process exec/exit, **kprobes** with `syscall: true` for syscalls we want to filter or override, **lsmhooks** for file-open enforcement (after enabling BPF-LSM on grub cmdline).

### Selectors (in-kernel, OR-ed, short-circuited)

**`matchArgs` operators:** `Equal`/`NotEqual`, `Prefix`/`Postfix`, `Mask`, `GT`/`LT`, `InRange`/`NotInRange`, `SAddr`/`DAddr` (CIDR), `SPort`/`DPort` (+ `SPortPriv`/`DPortPriv`), `Protocol`, `Family`, `State`, `FileType`, `InMap`/`NotInMap`.

**Process/identity selectors:** `matchPIDs` (with `followForks: true`, `isNamespacePID: true`), `matchBinaries` (with `Prefix`/`Postfix` operators), `matchParentBinaries`, `matchNamespaces` (`Uts`/`Ipc`/`Mnt`/`Pid`/`PidForChildren`/`Net`/`Cgroup`/`User`/`Time`), `matchCapabilities` (`Effective`/`Permitted`/`Inheritable`), `matchNamespaceChanges`, `matchCapabilityChanges`, `matchReturnArgs`, `matchReturnActions`.

### Actions
| Action | Kind | Notes |
|---|---|---|
| `Post` | observe | Default; supports `rateLimit`, `kernelStackTrace`, `userStackTrace`, `imaHash`. |
| `NoPost` | observe | Drop in-kernel; pair with `RateLimit` to track without emitting. |
| `Override` | **enforce** | Force return value. Needs `CONFIG_BPF_KPROBE_OVERRIDE` and function in `/sys/kernel/debug/error_injection/list`. |
| `Sigkill` | **enforce** | SIGKILL offending task. Synchronous. |
| `Signal` | **enforce** | Arbitrary signal via `argSig`. |
| `NotifyEnforcer` | **enforce** | Hand off to a referenced `enforcers[]` program (v1.4+). |
| `GetUrl` / `DnsLookup` | observe | Side-effecting; rare. |
| `TrackSock` / `UntrackSock` | observe | Builds sock→pid map. Kernel ≥5.3. |
| `RateLimit` | observe | Per-thread/process/global window. |
| `FollowFD` / `UnfollowFD` / `CopyFD` | **DEPRECATED v1.5** | Migrate to `file`/`path` arg types. |

### Argument types
`int`, `uint32`, `uint64`, `size_t`, `string`, `char_buf` (≤4096 bytes, up to 327360 with `maxData: true`; needs **1-based** `sizeArgIndex`), `char_iovec`, `sock`, `skb`, `file`, `path`, `dentry`, `fd`, `linux_binprm`, `bpf_attr`, `bpf_map`, `perf_event`, `user_namespace`, `capability`, `cred`, `kiocb`, `iov_iter`, `load_info`, `module`.

Modifiers: `returnCopy: true` (read buffer at return), `resolve: "field.subfield"` (walk nested struct, kernel ≥5.4), `label`.

### Gotchas (the ones that bite)
- **`sizeArgIndex` is 1-based.** Everything else is 0-based. Off-by-one #1 cause of empty captures.
- **`syscall: true` kprobe ≠ `raw_syscalls/sys_enter` tracepoint** — different arg shape.
- **kprobe-multi** (kernel ≥5.18) auto-enabled when available. **AlmaLinux 9 stock 5.14 does NOT have it backported** — falls back to per-fn attach (slower startup, identical runtime cost). Check `tetra status`.
- **LSM BPF on AlmaLinux 9:** compiled but not enabled. Add `bpf` to existing `lsm=` GRUB cmdline, regen grub, reboot. Verify `/sys/kernel/security/lsm` contains `bpf`.
- **`Override` silently dropped** for functions not in `/sys/kernel/debug/error_injection/list`.
- **`matchPIDs` with `isNamespacePID: true` required** for in-container PID semantics.
- **Deprecated FD actions removed in v1.5.**
- **Tetragon must run on the host**, not inside rootless-Docker's user namespace.

---

## Part 2 — Recommendations for THIS detonation rig

### Current policy gaps (`detonation/deploy/tetragon-policy.yaml`)

Audited against `detonation/internal/rules/definitions.go`:

| Go rule | Status | Cause |
|---|---|---|
| `dyn_reverse_shell` | **dormant** | No `process_exec` events emitted; rule has nothing to join on. |
| `dyn_suspicious_write` | **dormant** | Policy hooks `openat` for reads only; no write hook. |
| `dyn_env_harvest` | **dormant** | No `/proc/*/environ` postfix selector. |
| `dyn_dns_exfil` | **dormant** | No `udp_sendmsg` port-53 hook. |
| `sys_ptrace` | **too noisy** | No `matchArgs` filter — fires on every `PTRACE_TRACEME` debugger child. |

Single `matchNamespaces: Pid NotIn 4026531836` is fragile (hardcoded host inode constant) and cannot distinguish concurrent detonations from each other.

### Action list (priority order)

1. **Enable `process_exec` + `process_exit` event export** (one-line config). Unlocks parent-chain rules and `dyn_reverse_shell`.
2. **Replace `__x64_sys_openat` with `security_file_permission` LSM hook** — catches `open`/`openat`/`openat2`/direct mmap in one place, separate read/write selector blocks feed both `dyn_credential_read` and `dyn_suspicious_write`.
3. **Add `memfd_create` + `execveat AT_EMPTY_PATH`** — zero coverage for fileless exec today.
4. **Add `udp_sendmsg` port-53 hook** — wires up `dyn_dns_exfil`.
5. **Add `/proc/*/environ` postfix selector** — wires up `dyn_env_harvest`.
6. **Cgroup-id correlation in Go collector** — replaces brittle host-PID-NS constant; required for concurrent detonations.
7. **Tighten `sys_ptrace`** with `matchArgs index:0 In [PTRACE_ATTACH, PTRACE_SEIZE, PTRACE_POKETEXT, PTRACE_POKEDATA]`.

### Container-isolation pattern (belt + suspenders)
```yaml
selectors:
  - matchNamespaces:
      - {namespace: Pid, operator: NotIn, values: ["host_ns"]}
    matchPIDs:
      - operator: NotIn
        followForks: true
        isNamespacePID: true
        values: ["0"]
```
Plus emit container cgroup path from Go launcher and correlate events by `process.cgroup_id` server-side.

### Concrete snippets (drop into `tetragon-policy.yaml`)

**Fileless exec:**
```yaml
- call: "__x64_sys_memfd_create"
  syscall: true
  args: [{index: 0, type: "string"}, {index: 1, type: "uint32"}]
- call: "__x64_sys_execveat"
  syscall: true
  args:
    - {index: 0, type: "int"}
    - {index: 1, type: "string"}
    - {index: 4, type: "int"}
  selectors:
    - matchArgs:
        - {index: 4, operator: "Equal", values: ["4096"]}  # AT_EMPTY_PATH
```

**Credential/env sweep via LSM:**
```yaml
- call: "security_file_permission"
  syscall: false
  args: [{index: 0, type: "file"}, {index: 1, type: "int"}]
  selectors:
    - matchArgs:
        - index: 0
          operator: "Prefix"
          values: ["/root/.ssh/", "/root/.aws/", "/root/.gnupg/",
                   "/root/.docker/", "/root/.netrc", "/root/.bash_history", "/etc/shadow"]
        - index: 1
          operator: "Equal"
          values: ["4"]   # MAY_READ
    - matchArgs:
        - {index: 0, operator: "Postfix", values: ["/environ"]}
```

**Persistence writes:**
```yaml
- call: "security_file_permission"
  args: [{index: 0, type: "file"}, {index: 1, type: "int"}]
  selectors:
    - matchArgs:
        - index: 0
          operator: "Prefix"
          values: ["/etc/cron", "/etc/systemd/", "/root/.bashrc",
                   "/root/.profile", "/root/.bash_profile", "/root/.ssh/authorized_keys"]
        - index: 1
          operator: "Equal"
          values: ["2"]   # MAY_WRITE
```

**DNS exfil:**
```yaml
- call: "udp_sendmsg"
  args: [{index: 0, type: "sock"}, {index: 2, type: "int"}]
  selectors:
    - matchArgs:
        - {index: 2, operator: "Equal", values: ["53"]}
```

### Build-noise filtering
Two tiers:
- **In-kernel `matchBinaries` `NotIn`** for `gcc`/`ld`/`python3.11`/`cc1`/`as`. Note 64-entry cap on `followChildren: true`.
- **Userspace baseline** in `internal/baseline/`: extend benign corpus by running clean `pip install --dry-run` on top-100 wheels.

Critical: **keep build-tool events for the `import` phase**. `npm install` running `gcc` is normal; `import foo` triggering `gcc` is not. Filter on `evt.Phase` in the Go rule, not on binary in the kprobe selector.

### Prior art
- **OSSF [package-analysis](https://github.com/ossf/package-analysis)** — gVisor+strace, not Tetragon, but the phase-split schema (install/import) is the standard.
- **[DySec](https://arxiv.org/html/2503.00324v1)** — eBPF PyPI scanner; 36-feature set useful as a checklist.
- **[SafeDep dynamic analysis](https://safedep.io/dynamic-analysis-oss-package-at-scale/)** — closest production peer.
- Tetragon `examples/tracingpolicy/` — `sys_ptrace.yaml`, `tcp-connect.yaml`, `open_dnsrequest.yaml`, `filename_monitoring.yaml`, `lsm_*.yaml`, `uprobe-*.yaml`.

---

## Part 3 — Operational tuning (AlmaLinux 9 / kernel 5.14)

### Overhead
Published Isovalent figures: standard `process_exec` + a few kprobes = **<1% CPU**, worst-case process tracking **~1.68% CPU**. Memory steady-state 20–60 MB. Cost goes non-linear if you kprobe high-frequency funcs (`vfs_write`/`vfs_read`) — **don't**.

### Event-loss metrics (enable `--metrics-server=:2112`)
- `tetragon_observer_ringbuf_events_lost_total` — kernel→user drops
- `tetragon_observer_ringbuf_queue_events_lost_total` — Go-side channel drops
- `tetragon_bpf_missed_events_total` — kernel-side miss
- `tetragon_notify_overflowed_events_total` — listener buffer overflow

Single alert that catches almost everything: `rate(tetragon_observer_ringbuf_events_lost_total[5m]) > 0`.

### Recommended flag set for the detonation host
```
--metrics-server=:2112
--gops-address=127.0.0.1:8118
--enable-process-cred
--enable-process-ns
--rb-size=4M
--rb-queue-size=262144
--export-filename=/var/log/tetragon/tetragon.log
--export-file-max-size-mb=200
--export-file-max-backups=20
--export-file-rotation-interval=1h
--export-rate-limit=-1
--field-filters=/etc/tetragon/field-filters.yaml
--redaction-filters=/etc/tetragon/redaction-filters.yaml
```

Rationale:
- Default `--rb-size=65K` is too small for a single sample firing thousands of execves.
- Default log rotation = 50 MB total retained; bump to ~4 GB for ~100–500 samples/day.
- Rate-limit `-1`: keep every event during malware burst, rate-limit downstream in Go consumer.
- **Loi 25 / GDPR:** `--redaction-filters` regex for any host paths that could carry user identifiers — mandatory before log retention.

### systemd hardening (missing from shipped unit)
Add `MemoryHigh=2G`, `MemoryMax=4G`, `OOMScoreAdjust=-500` so a fork-bomb sample doesn't OOM-kill Tetragon before the container.

### AlmaLinux 9 / kernel 5.14 specifics
- BTF/CO-RE, classic kprobes, raw_tracepoint, fmod_ret, cgroup v2 — **work**.
- kprobe-multi — **not backported**, falls back to per-fn attach.
- LSM BPF — compiled, **not enabled by default**. Edit `/etc/default/grub`, add `bpf` to `lsm=...,` list, regen grub, reboot.

### Other gotchas
- 4096-byte `char_buf` default truncation; set `maxData: true` for full argv/payload capture (kernel ≥5.4).
- `returnCopy: true` required for syscalls where kernel populates buffer at return.
- Verifier rejects complex chained selectors over 512-instruction-block limit — split into multiple policies.
- Policy reload momentarily detaches probes; do off-hours.

Sources: https://tetragon.io/docs/reference/daemon-configuration/, https://tetragon.io/docs/reference/metrics/, https://tetragon.io/docs/installation/faq/, https://github.com/cilium/tetragon/issues/575

---

## Part 4 — Ecosystem & tooling

### `tetra` CLI (subcommands we'd actually use)
- `tetra status` — health, BPF maps, attached probes. First thing after restart.
- `tetra getevents -o json --event-types EXEC,PROCESS_KPROBE` — live stream from gRPC socket without touching JSON file.
- `tetra tracingpolicy list|get|add|delete` — hot-reload policies, no restart.
- `tetra probe` — lists BPF features detected on running kernel (kprobe_multi, override_return, LSM, large maps). Tells us what features actually work on this 5.14 kernel.
- `tetra bugtool` — tarball for upstream issues.
- `tetra loglevel set debug` — flip log level live.

### Sinks
- **File JSON** (what we use) — configurable via drop-ins in `/etc/tetragon/tetragon.conf.d/`.
- **gRPC `getevents`** — if we want backpressure-aware delivery and skip log-rotation parsing in Go, dial the unix socket directly. Proto at `cilium/tetragon/api/v1/tetragon/`. **Worth considering** for our consumer.
- **OTel** — no first-party exporter as of v1.5. Path: OTel Collector `filelog` receiver → `json_parser`.

### Recent releases (relevant for us)
- **v1.4** — `NotifyEnforcer` action + standalone enforcer agent for kernels **without `kprobe_multi`** (exactly AlmaLinux 9's case). `FollowFD`/`UnfollowFD`/`CopyFD` deprecated. Policy Library shipped.
- **v1.5** — ringbuf consumption perf, file-monitoring selectors, expanded policy library, RHEL 9 / kernel 5.14 backport confirmed.

### Comparison (malware-detonation lens, honest)
- **Falco** — bigger community rule set, weaker enforcement, JSON schema less process-tree-friendly. Tetragon's event output is friendlier for our reconstruction use case.
- **Aqua Tracee** — closest peer, deeper forensic catalog (anti-debug, LD_PRELOAD, ptrace tricks), but **2–4× the CPU/memory** and no in-kernel enforcement. Tracee wins when you only scan one sample slowly; Tetragon wins for many-samples-per-minute (our case).
- **bpftrace** — keep as ad-hoc debugging tool alongside Tetragon, not as replacement.
- **auditd** — keep for compliance, useless for malware behavior.

Tetragon weaknesses to know about: smaller community rule set than Falco, docs heavily k8s-flavored (standalone is second-class), DNS/HTTP L7 parsing minimal, **JSON schema changes between minor versions** — version-pin Go consumer struct tags.

### Policy libraries
- `github.com/cilium/tetragon/tree/main/examples/tracingpolicy` — official examples.
- `github.com/cilium/tetragon/tree/main/examples/policylibrary` rendered at `tetragon.io/docs/policy-library/` — curated "production-grade" policies consolidated in v1.4/v1.5. **Worth reading before writing new policies from scratch.**
- No community equivalent of `falco-rules`.

---

## Key sources (deep-linkable)
- TracingPolicy: https://tetragon.io/docs/reference/tracing-policy/
- Selectors: https://tetragon.io/docs/concepts/tracing-policy/selectors/
- Hooks: https://tetragon.io/docs/concepts/tracing-policy/hooks/
- Daemon config: https://tetragon.io/docs/reference/daemon-configuration/
- Metrics: https://tetragon.io/docs/reference/metrics/
- Policy Library: https://tetragon.io/docs/policy-library/
- Examples: https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy
- FAQ (kernel reqs): https://tetragon.io/docs/installation/faq/
- char_buf 4096 bug: https://github.com/cilium/tetragon/issues/575
- OSSF package-analysis: https://github.com/ossf/package-analysis
- DySec paper: https://arxiv.org/html/2503.00324v1
