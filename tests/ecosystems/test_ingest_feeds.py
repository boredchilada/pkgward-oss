# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from pkgsentry.ecosystems.pypi.ingest import feeds
from pkgsentry.store import session as sess


SAMPLE_UPDATES_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
 <item><title>requests 2.32.1</title><link>https://pypi.org/project/requests/2.32.1/</link></item>
 <item><title>numpy 2.1.0</title><link>https://pypi.org/project/numpy/2.1.0/</link></item>
 <item><title>broken-no-space</title><link>https://pypi.org/project/x/</link></item>
</channel></rss>"""


def test_parse_feed_extracts_name_version():
    items = feeds.parse_feed(SAMPLE_UPDATES_XML)
    assert ("requests", "2.32.1") in items
    assert ("numpy", "2.1.0") in items
    # broken entry without space is skipped
    assert all(v is not None for _, v in items)


@pytest.mark.asyncio
async def test_poll_feeds_once_enqueues(httpx_mock, tmp_path, monkeypatch):
    monkeypatch.setenv("PKGSENTRY_DB_URL", f"sqlite:///{tmp_path/'f.db'}")
    sess.reset_engine()
    sess.init_db()
    httpx_mock.add_response(url=feeds.UPDATES_URL, content=SAMPLE_UPDATES_XML)
    httpx_mock.add_response(url=feeds.PACKAGES_URL, content=SAMPLE_UPDATES_XML)
    items = await feeds.poll_feeds_once()
    assert any(it.name == "requests" for it in items)
