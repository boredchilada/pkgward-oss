# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm (JavaScript) ecosystem adapter."""
from pkgward.adapter import register
from pkgward.ecosystems.npm.adapter import NpmAdapter

register(NpmAdapter())
