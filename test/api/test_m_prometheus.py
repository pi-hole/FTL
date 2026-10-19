"""
Pi-hole FTL API - Prometheus endpoint tests.

Exercises the full scrape-token procedure end-to-end:

  1. With no token configured (the default in test/pihole.toml, which ships
     with an empty ``webserver.api.prometheus.token``), the /api/metrics
     endpoint is inactive and returns HTTP 404.
  2. POST /api/auth/prometheus generates a token, stores its hash in the
     configuration automatically and returns the raw token exactly once.
  3. Scraping /api/metrics with that token returns a non-empty Prometheus
     exposition (HTTP 200, text/plain); a missing or wrong token returns 401.
  4. With perEntityMetrics on, crafted query names (quote, backslash, control
     characters, invalid UTF-8) still give an exposition a strict parser
     accepts, and the aggregate values match /api/stats/summary.

The file is named ``test_m_*`` so it runs alphabetically after
``test_api.py`` (which asserts exact counts on the seed data). The token is
reset to empty in a ``finally`` block so the configuration returns to its
baseline (disabled) state for subsequent tests.

Usage:
    pytest test/api/test_m_prometheus.py -v
"""

import math
import re
import subprocess
import time

import requests

FTL_URL = "http://127.0.0.1"
METRICS_URL = f"{FTL_URL}/api/metrics"


def _set_token(api_session, value):
    """Set webserver.api.prometheus.token via the config API."""
    return api_session.patch(
        f"{FTL_URL}/api/config",
        json={"config": {"webserver": {"api": {"prometheus": {"token": value}}}}},
        timeout=10,
    )


# Aggregate metrics that are always emitted (independent of perEntityMetrics),
# spanning every category of the exposition. The gravity metrics are left out,
# they are only emitted while the gravity database is readable
EXPECTED_METRICS = [
    "pihole_dns_queries_total",
    "pihole_queries",
    "pihole_queries_blocked",
    "pihole_queries_forwarded",
    "pihole_queries_cached",
    "pihole_query_frequency",
    "pihole_queries_by_type",
    "pihole_queries_by_status",
    "pihole_queries_by_reply",
    "pihole_clients",
    "pihole_clients_active",
    "pihole_domains",
    "pihole_upstreams",
    "pihole_dns_cache_size",
    "pihole_dns_cache_inserted_total",
    "pihole_dns_cache_expired",
    "pihole_dns_replies_total",
    "pihole_dns_upstream_sent_total",
    "pihole_dhcp_messages_total",
    "pihole_dhcp_leases_allocated_total",
    "pihole_dhcp_leases_pruned_total",
]

# Names sent as DNS queries in dig's escape syntax, and how each one has to
# appear (decoded) in the domain label: every byte that is not printable UTF-8,
# and the backslash, is written as visible \xHH text
CRAFTED_NAMES = {
    r'prom-a\"b.ftl': 'prom-a"b.ftl',
    r'prom-a\\b.ftl': r'prom-a\x5Cb.ftl',
    r'prom-a\010b.ftl': r'prom-a\x0Ab.ftl',
    r'prom-a\013b.ftl': r'prom-a\x0Db.ftl',
    r'prom-a\255b.ftl': r'prom-a\xFFb.ftl',
    # The literal text "\xff" (FTL lowercases names) must stay distinct from
    # the byte above
    r'prom-a\\xFFb.ftl': r'prom-a\x5Cxffb.ftl',
}


def _parse_samples(body):
    """Parse a Prometheus text exposition strictly.

    The body must be valid UTF-8, every sample must belong to a family
    declared by a TYPE line, label values may only use the backslash and
    double quote escapes (FTL never needs the newline one), and no series may
    appear twice. Returns a list of (name, labels, value) tuples with the
    label values decoded.
    """
    text = body.decode("utf-8")
    types = {}
    samples = []
    seen = set()
    label_re = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\[\\"])*)"(,|$)')
    for line in text.split("\n"):
        if not line:
            continue
        if line.startswith("# TYPE "):
            _, _, family, kind = line.split(" ", 3)
            types[family] = kind
            continue
        if line.startswith("#"):
            continue
        m = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (\S+)', line)
        assert m, f"malformed sample line: {line!r}"
        name, raw, value = m.groups()
        assert name in types, f"sample without TYPE line: {line!r}"
        labels = {}
        pos = 0
        raw = raw or ""
        while pos < len(raw):
            lm = label_re.match(raw, pos)
            assert lm, f"invalid label syntax or escape: {line!r}"
            labels[lm.group(1)] = re.sub(r'\\(.)', r'\1', lm.group(2))
            pos = lm.end()
        key = (name, tuple(sorted(labels.items())))
        assert key not in seen, f"duplicate series: {line!r}"
        seen.add(key)
        samples.append((name, labels, float(value)))
    return samples


def _summary_values(summary):
    """The /api/stats/summary values compared with the exposition"""
    queries = summary["queries"]
    return ([queries[k] for k in ("total", "blocked", "forwarded", "cached", "unique_domains")],
            summary["clients"])


def _scrape(token):
    r = requests.get(METRICS_URL, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200, f"scrape failed: {r.status_code} {r.text}"
    return _parse_samples(r.content)


class TestPrometheusEndpoint:
    def test_full_token_procedure(self, api_session):
        # 1. The endpoint is inactive while no token is configured -> 404.
        #    (No Authorization header is sent; the endpoint must not even
        #    reveal its existence when disabled.)
        r = requests.get(METRICS_URL, timeout=10)
        assert r.status_code == 404, \
            f"expected 404 while disabled, got {r.status_code}"

        try:
            # 2. Generate a token. This stores its hash in the config and
            #    returns the raw token exactly once.
            r = api_session.post(f"{FTL_URL}/api/auth/prometheus", timeout=10)
            assert r.status_code == 200, \
                f"token generation failed: {r.status_code} {r.text}"
            token = r.json().get("prometheus", {}).get("token")
            assert token, "no token returned by POST /api/auth/prometheus"

            # 3a. Now enabled, a request without a bearer token -> 401.
            r = requests.get(METRICS_URL, timeout=10)
            assert r.status_code == 401, \
                f"expected 401 without token, got {r.status_code}"

            # 3b. A wrong bearer token -> 401.
            r = requests.get(
                METRICS_URL,
                headers={"Authorization": "Bearer not-the-real-token"},
                timeout=10,
            )
            assert r.status_code == 401, \
                f"expected 401 with wrong token, got {r.status_code}"

            # 3c. The correct bearer token -> 200 with a non-empty
            #     text/plain Prometheus exposition.
            r = requests.get(
                METRICS_URL,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            assert r.status_code == 200, \
                f"scrape failed: {r.status_code} {r.text}"
            assert "text/plain" in r.headers.get("Content-Type", ""), \
                f"unexpected Content-Type: {r.headers.get('Content-Type')}"
            assert len(r.content.strip()) > 0, "metrics body is empty"

            # Parse the exposition strictly and check the aggregate metrics
            # are all present, spanning every category (queries/cache/DHCP/...)
            samples = _parse_samples(r.content)
            assert samples, "no metric samples parsed from response"
            names = {name for name, _, _ in samples}
            missing = [m for m in EXPECTED_METRICS if m not in names]
            assert not missing, f"expected metrics missing from response: {missing}"

            # Every emitted sample value must be a finite number. float()
            # happily parses "NaN"/"Inf", so assert finiteness explicitly.
            nonfinite = [(n, v) for n, _, v in samples if not math.isfinite(v)]
            assert not nonfinite, f"non-finite metric values emitted: {nonfinite}"

            # Values must be non-negative: these metrics are counts, sizes,
            # rates or a unix timestamp
            negative = [(n, v) for n, _, v in samples if v < 0]
            assert not negative, f"negative metric values emitted: {negative}"
        finally:
            # Reset to baseline (disabled) so later tests see the default.
            _set_token(api_session, "")

        # 4. After clearing the token, the endpoint is inactive again -> 404.
        r = requests.get(METRICS_URL, timeout=10)
        assert r.status_code == 404, \
            f"expected 404 after clearing token, got {r.status_code}"

    def test_per_entity_metrics(self, api_session):
        """Crafted names keep the exposition valid, values match the API"""
        r = api_session.post(f"{FTL_URL}/api/auth/prometheus", timeout=10)
        assert r.status_code == 200, f"token generation failed: {r.status_code} {r.text}"
        token = r.json()["prometheus"]["token"]
        try:
            r = api_session.patch(
                f"{FTL_URL}/api/config",
                json={"config": {"webserver": {"api": {"prometheus": {
                    "perEntityMetrics": True, "topN": 1000}}}}},
                timeout=10,
            )
            assert r.status_code == 200, f"enabling perEntityMetrics failed: {r.text}"

            for name in CRAFTED_NAMES:
                subprocess.run(["dig", "+time=2", "+tries=1", "@127.0.0.1", name],
                               capture_output=True, timeout=10)

            # The aggregate values have to match /api/stats/summary taken in
            # the same idle moment, retry if a query came in between
            for _ in range(5):
                before = api_session.get(f"{FTL_URL}/api/stats/summary", timeout=10).json()
                samples = _scrape(token)
                after = api_session.get(f"{FTL_URL}/api/stats/summary", timeout=10).json()
                if _summary_values(before) == _summary_values(after):
                    break
                time.sleep(1)
            values = {n: v for n, labels, v in samples if not labels}
            assert values["pihole_queries"] == after["queries"]["total"]
            assert values["pihole_queries_blocked"] == after["queries"]["blocked"]
            assert values["pihole_queries_forwarded"] == after["queries"]["forwarded"]
            assert values["pihole_queries_cached"] == after["queries"]["cached"]
            assert values["pihole_domains"] == after["queries"]["unique_domains"]
            assert values["pihole_clients"] == after["clients"]["total"]
            assert values["pihole_clients_active"] == after["clients"]["active"]
            assert values["pihole_dns_queries_total"] >= values["pihole_queries"]

            domains = {labels["domain"] for n, labels, _ in samples
                       if n == "pihole_top_domain_queries"}
            missing = [v for v in CRAFTED_NAMES.values() if v not in domains]
            assert not missing, f"crafted names missing or mangled: {missing}"

            clients = {labels["ip"] for n, labels, _ in samples
                       if n == "pihole_top_client_queries"}
            assert "127.0.0.1" in clients, f"localhost missing in {clients}"
        finally:
            api_session.patch(
                f"{FTL_URL}/api/config",
                json={"config": {"webserver": {"api": {"prometheus": {
                    "token": "", "perEntityMetrics": False, "topN": 100}}}}},
                timeout=10,
            )
