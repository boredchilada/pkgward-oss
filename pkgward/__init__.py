# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("pkgward")
except PackageNotFoundError:  # running from an uninstalled source tree
    __version__ = "0.5.3"
