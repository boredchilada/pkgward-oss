# SPDX-License-Identifier: AGPL-3.0-or-later
import structlog

from pkgsentry.logging_setup import configure_logging, get_logger


def test_configure_and_get_logger():
    configure_logging(level="DEBUG")
    log = get_logger("test")
    assert isinstance(log, structlog.stdlib.BoundLogger) or hasattr(log, "info")
    log.info("ping", k="v")  # should not raise
