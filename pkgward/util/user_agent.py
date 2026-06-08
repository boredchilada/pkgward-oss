# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os

from pkgward import __version__

_PROJECT_URL = "https://github.com/boredchilada/pkgward-oss"


def user_agent() -> str:
    contact = os.environ.get("PKGWARD_CONTACT_EMAIL", "").strip()
    if contact:
        return f"pkgward/{__version__} (contact: {contact})"
    return f"pkgward/{__version__} (+{_PROJECT_URL})"
