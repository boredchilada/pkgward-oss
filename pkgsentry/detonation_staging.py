# SPDX-License-Identifier: AGPL-3.0-or-later
"""Staging for detonation archives — the single source of truth for the cross-uid
bind-mount permission contract.

The scanner writes the archive bytes (as **root**, inside its container); the
detonation service then bind-mounts them via **rootless Docker** as the
unprivileged ``detonation`` user (uid 979). Producer and consumer share neither
owner nor group, so the staged directory MUST be world-traversable (``o+rx``) and
the file world-readable (``o+r``) — otherwise the rootless daemon cannot enter the
staging dir and the mount fails with ``mkdir ...: permission denied`` (a ``mkdtemp``
dir is ``0700`` by default, which the detonation uid cannot traverse).

This contract was previously duplicated and *implicit* across every staging path
(each ecosystem ``fetch/download.py`` widened its own dir to ``0755`` and relied on
the process umask for the file mode), and the vault re-stage path
(``detonation_worker._stage_from_vault``) missed it entirely — so vault
re-detonation silently fell back to a re-fetch on every run. Route all
detonation-bound staging through here so the permissions are set explicitly (not
umask-dependent) and can never silently drift again.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

# The only directory bind-mounted into BOTH the scanner container and the
# detonation-service host, so it's the one place the service can read staged bytes.
STAGING_ROOT = Path(tempfile.gettempdir()) / "pkgsentry"

# Explicit modes for the cross-uid mount contract (see module docstring). Set
# explicitly rather than inherited from umask so a tighter worker umask can't
# silently reintroduce the unreadable-staging bug.
DIR_MODE = 0o755   # rwxr-xr-x — rootless detonation uid must traverse
FILE_MODE = 0o644  # rw-r--r-- — ...and read the archive bytes


def staging_dir(prefix: str) -> Path:
    """Create a fresh, detonation-readable staging directory under the shared root.

    ``mkdtemp`` forces ``0700``; we widen to ``DIR_MODE`` so the rootless detonation
    user can traverse it for the bind mount."""
    STAGING_ROOT.mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(dir=STAGING_ROOT, prefix=prefix))
    d.chmod(DIR_MODE)
    return d


def stage_bytes(data: bytes, inner_name: str, prefix: str) -> Path:
    """Write *data* as *inner_name* into a fresh detonation-readable staging dir and
    return the file path. Both the dir and the file are set to the mount-contract
    modes explicitly. *inner_name* is reduced to its basename (no traversal / nested
    dirs in the staging root)."""
    dest = staging_dir(prefix) / Path(inner_name).name
    dest.write_bytes(data)
    dest.chmod(FILE_MODE)
    return dest
