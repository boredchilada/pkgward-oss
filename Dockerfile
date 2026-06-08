FROM python:3.11-slim

WORKDIR /app

# Base build deps + curl (opengrep/upx releases) + xz-utils (upx tarball is .tar.xz).
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ libc6-dev curl ca-certificates xz-utils && \
    rm -rf /var/lib/apt/lists/*

# --- UPX: static unpacking of UPX-packed payloads (analyze/unpack.py) ---
# `upx -d` is pure decompression and never executes the payload. Pinned for
# hermetic builds. Commercial protectors (Themida/VMProtect/...) are detected,
# not unpacked (no static unpacker exists).
ARG UPX_VERSION=4.2.4
RUN curl -fsSL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz" \
        -o /tmp/upx.tar.xz \
    && tar -xJf /tmp/upx.tar.xz -C /tmp \
    && cp "/tmp/upx-${UPX_VERSION}-amd64_linux/upx" /usr/local/bin/upx \
    && chmod +x /usr/local/bin/upx \
    && rm -rf /tmp/upx* \
    && upx --version | head -1

# --- opengrep static-analysis layer ---
# Self-contained binary (no Python deps). Pinned by version to keep image
# builds hermetic. Used by pkgward/analyze/opengrep_scan.py.
ARG OPENGREP_VERSION=1.21.0
RUN curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" \
        -o /usr/local/bin/opengrep \
    && chmod +x /usr/local/bin/opengrep \
    && /usr/local/bin/opengrep --version

# --- Node 22 + webcrack: npm-only JS deobfuscation pre-pass (analyze/webcrack_deobf.py) ---
# webcrack unminifies / unpacks webpack-browserify bundles / reverses obfuscator.io so
# the static analyzers run on readable code instead of an opaque blob. It evaluates some
# decoder snippets in isolated-vm (a hardened V8 isolate, no fs/net) — we run it bounded
# + fail-soft (analyze/webcrack_deobf.py). isolated-vm is a native addon, so the build
# needs make + g++ (g++ already installed above). Node 22 (even-numbered, per isolated-vm).
RUN apt-get update && apt-get install -y --no-install-recommends make \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g webcrack \
    && webcrack --version \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir py-tlsh && \
    python -c "import tlsh, yara, ppdeep"

COPY pyproject.toml .
COPY pkgward/ pkgward/
RUN pip install --no-cache-dir -e .

COPY tools/stats.py tools/stats.py
COPY tools/genome.py tools/genome.py

# Code version baked at build time for alert/node identification (node_id.py). Prod
# builds from a COPY (no .git), so it can't read a live SHA — pass it at build:
#   PKGWARD_BUILD_SHA=$(git rev-parse --short HEAD) docker compose build scanner
ARG PKGWARD_BUILD_SHA=unknown
ENV PKGWARD_BUILD_SHA=$PKGWARD_BUILD_SHA

VOLUME /data

ENTRYPOINT ["python", "-m", "pkgward"]
CMD ["run", "--workers", "4"]
