"""Benign host bootstrap helpers (local-IP detection, GPU probe, launcher)."""
from __future__ import annotations

import socket
import subprocess
from pathlib import Path


def detect_local_ip() -> str:
    # Standard trick: open a UDP socket toward a public resolver and read our own
    # bound address. No packets are actually sent — this just resolves the LAN IP.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]


def gpu_info() -> str:
    try:
        return subprocess.run(["nvidia-smi"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return ""


def write_launcher(install_dir: Path) -> None:
    (install_dir / "run.sh").write_text(
        "#!/bin/bash\ncd %s\nexec python conny.py\n" % install_dir
    )
