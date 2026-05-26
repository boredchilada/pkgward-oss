# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pkgsentry.adapter import register
from pkgsentry.ecosystems.pypi.adapter import PyPIAdapter

register(PyPIAdapter())
