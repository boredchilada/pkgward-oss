# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
from typing import Optional


def env_chain(*names: str, default: Optional[str] = None) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value != "":
            return value
    return default
