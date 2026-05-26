# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from pkgsentry.adapter import adapter_registry
import pkgsentry.ecosystems.pypi  # registers
from pkgsentry.ecosystems.pypi.adapter import PyPIAdapter


def test_pypi_adapter_registered():
    assert "pypi" in adapter_registry
    assert isinstance(adapter_registry["pypi"], PyPIAdapter)
    assert adapter_registry["pypi"].ecosystem_id == "pypi"
