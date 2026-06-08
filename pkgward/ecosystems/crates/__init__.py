# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io ecosystem adapter."""
from pkgward.adapter import register
from pkgward.ecosystems.crates.adapter import CratesAdapter

register(CratesAdapter())
