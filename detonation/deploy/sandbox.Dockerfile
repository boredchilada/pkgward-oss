# Derived detonation sandbox image: a base runtime + the broad set of shared
# libraries and tools that real-world malware payloads dynamically link against or
# invoke. The minimal upstream images (node:20-slim, python:3.11-slim, ...) make
# native payloads die at dlopen/exec before they do anything (IronWorm's Rust ELF
# crashed on a missing libbpf.so.1), giving zero behavioral signal. This image lets
# them RUN — safely: the host still neuters the dangerous parts (rootless user-ns,
# unprivileged_bpf_disabled=2, kernel lockdown, default seccomp), so e.g. an eBPF
# rootkit's bpf() still EPERMs while the credential-sweep / C2 / file behavior traces.
#
# Built per-ecosystem by deploy/build-sandbox-images.sh as pkgward-det-<eco>.
ARG BASE=debian:bookworm-slim
FROM ${BASE}

ARG PKGS=""
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
    if command -v apt-get >/dev/null 2>&1; then \
        apt-get update; \
        apt-get install -y --no-install-recommends ${PKGS}; \
        rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache ${PKGS}; \
    fi
