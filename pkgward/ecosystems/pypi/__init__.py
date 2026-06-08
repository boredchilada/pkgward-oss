# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgward.adapter import register
from pkgward.ecosystems.pypi.adapter import PyPIAdapter

register(PyPIAdapter())
