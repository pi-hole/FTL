"""
Pi-hole FTL query log in memory while queries arrive.

The test sends DNS queries, so the file is named ``test_m_*`` to run *after*
``test_api.py``, which asserts exact counts on the seed data.

Usage:
    pytest test/api/test_m_query_log.py -v
"""

import subprocess

FTL_URL = "http://127.0.0.1"
# Blocked by the test gravity database: FTL answers them itself, no upstream
# or DNSSEC query follows them
NAMES = ("first.special.gravity.ftl", "second.special.gravity.ftl")


def _ids(data):
    return [q["id"] for q in data["queries"]]


class TestQueriesArriving:

    def test_cursor_with_queries_arriving(self, api_session):
        """Page 2 with the cursor of page 1 shows none of the queries made in
        between and keeps the cursor. A request without a cursor shows them
        first as soon as FTL has answered them, with the newest as cursor"""
        page1 = api_session.get(f"{FTL_URL}/api/queries?length=5", timeout=5).json()
        cursor = page1["cursor"]
        for name in NAMES:
            subprocess.run(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", name],
                           capture_output=True, timeout=10, check=True)
        url = f"{FTL_URL}/api/queries?cursor={cursor}"
        page2 = api_session.get(f"{url}&start=5&length=5", timeout=5).json()
        both = api_session.get(f"{url}&length=10", timeout=5).json()
        assert page2["cursor"] == both["cursor"] == cursor
        assert _ids(page1) + _ids(page2) == _ids(both)

        latest = api_session.get(f"{FTL_URL}/api/queries", timeout=5).json()
        new = [q for q in latest["queries"] if q["id"] > cursor]
        assert [q["domain"] for q in new if q["domain"] in NAMES] == list(NAMES[::-1]), new
        assert latest["cursor"] == latest["queries"][0]["id"] == cursor + len(new)
        assert latest["recordsTotal"] == page1["recordsTotal"] + len(new)
