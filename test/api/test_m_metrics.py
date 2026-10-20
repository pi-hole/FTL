"""
Pi-hole FTL cache metrics.

The counters are read live. The cache content is walked on dnsmasq's main
thread, at most once a second, and the API serves the copy the walk left.
These tests send DNS queries, so the file is named ``test_m_*`` to run *after*
``test_api.py``, which asserts exact counts on the seed data.

Usage:
    pytest test/api/test_m_metrics.py -v
"""

import subprocess
import time

FTL_URL = "http://127.0.0.1"


def _dig(name):
    subprocess.run(["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", name],
                   capture_output=True, text=True, timeout=10)


def _dns_metrics(api_session):
    r = api_session.get(f"{FTL_URL}/api/info/metrics", timeout=5)
    assert r.status_code == 200, r.text
    return r.json()["metrics"]["dns"]


def _content_total(dns):
    return sum(c["count"]["valid"] + c["count"]["stale"] for c in dns["cache"]["content"])


def test_metrics_follow_dns_activity(api_session):
    """Replies count at once. The answers they cached show up in the content
    once the resolver walked the cache again, which it does on the next UDP
    query at least a second after the last walk.
    The unknown names get a cached negative answer from the ftl. zone"""
    before = _dns_metrics(api_session)
    assert before["cache"]["size"] > 0
    run = int(time.time())
    for i in range(3):
        time.sleep(1.1)
        _dig(f"metrics-walk-{run}-{i}.ftl")
    after = _dns_metrics(api_session)
    assert after["replies"]["sum"] > before["replies"]["sum"], \
        f"replies.sum {before['replies']['sum']} -> {after['replies']['sum']}"
    assert _content_total(after) > _content_total(before), \
        f"cache content {before['cache']['content']} -> {after['cache']['content']}"
