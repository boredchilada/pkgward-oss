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
# builds hermetic. Used by pkgsentry/analyze/opengrep_scan.py.
ARG OPENGREP_VERSION=1.21.0
RUN curl -fsSL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" \
        -o /usr/local/bin/opengrep \
    && chmod +x /usr/local/bin/opengrep \
    && /usr/local/bin/opengrep --version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir py-tlsh && \
    python -c "import tlsh, yara, ppdeep"

COPY pyproject.toml .
COPY pkgsentry/ pkgsentry/
RUN pip install --no-cache-dir -e .

COPY tools/stats.py tools/stats.py

VOLUME /data

ENTRYPOINT ["python", "-m", "pkgsentry"]
CMD ["run", "--workers", "4"]
