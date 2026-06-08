# SPDX-License-Identifier: AGPL-3.0-or-later
"""Identify which scanner node + code version produced an alert.

Multiple hosts drain the same queue (the local scanner + the cloud worker) and both
post to Discord, so an alert must say which one fired it and what version it's on —
essential for tracing an incident (e.g. a FP flood) to a node still running old code.

``PKGWARD_NODE_NAME`` labels the node (e.g. ``prod`` / ``cloud``); version is the
running git short-SHA where available (the worker bind-mounts a git checkout at /app),
falling back to the SHA baked at image build (``PKGWARD_BUILD_SHA``) then the package
version."""
from __future__ import annotations

import functools
import os
import socket
from pathlib import Path


def node_name() -> str:
    return os.environ.get("PKGWARD_NODE_NAME") or socket.gethostname()


def _git_sha(repo: str = "/app") -> str | None:
    """Read the short SHA straight from .git — no `git` binary needed (the scanner
    image doesn't ship one). Works wherever a checkout is bind-mounted (the worker)."""
    try:
        g = Path(repo, ".git")
        head = (g / "HEAD").read_text().strip()
        if not head.startswith("ref:"):
            return head[:7]  # detached HEAD is the SHA itself
        ref = head[4:].strip()
        loose = g / ref
        if loose.exists():
            return loose.read_text().strip()[:7]
        packed = g / "packed-refs"
        if packed.exists():
            for line in packed.read_text().splitlines():
                if line.endswith(" " + ref):
                    return line.split(" ", 1)[0][:7]
    except Exception:
        pass
    return None


@functools.lru_cache(maxsize=1)
def node_version() -> str:
    sha = _git_sha()                               # worker: live SHA from the git-mount
    if sha:
        return sha
    baked = os.environ.get("PKGWARD_BUILD_SHA")  # prod: SHA baked at image build
    if baked and baked != "unknown":
        return baked
    try:
        from importlib.metadata import version
        return version("pkgward")
    except Exception:
        return "unknown"


def node_label() -> str:
    """``<name> @ <version>`` — for alert footers / logs."""
    return f"{node_name()} @ {node_version()}"
