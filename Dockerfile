FROM python:3.11-slim

WORKDIR /app

# Base build deps + curl needed to pull the opengrep binary release.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

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
    pip install --no-cache-dir py-tlsh || true

COPY pyproject.toml .
COPY pkgsentry/ pkgsentry/
RUN pip install --no-cache-dir -e .

VOLUME /data

ENTRYPOINT ["python", "-m", "pkgsentry"]
CMD ["run", "--workers", "4"]
