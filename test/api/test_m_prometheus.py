"""
Pi-hole FTL API - Prometheus/OpenMetrics endpoint tests.

Exercises the full scrape-token procedure end-to-end:

  1. With no token configured (the default in test/pihole.toml, which ships
     with an empty ``webserver.api.prometheus.token``), the /api/metrics
     endpoint is inactive and returns HTTP 404.
  2. POST /api/auth/prometheus generates a token, stores its hash in the
     configuration automatically and returns the raw token exactly once.
  3. Scraping /api/metrics with that token returns a non-empty Prometheus
     exposition (HTTP 200, text/plain); a missing or wrong token returns 401.

The file is named ``test_m_*`` so it runs alphabetically after
``test_api.py`` (which asserts exact counts on the seed data). The token is
reset to empty in a ``finally`` block so the configuration returns to its
baseline (disabled) state for subsequent tests.

Usage:
    pytest test/api/test_m_prometheus.py -v
"""

import math

import pytest
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
# spanning every category of the exposition.
EXPECTED_METRICS = [
    "pihole_queries",
    "pihole_queries_blocked",
    "pihole_queries_forwarded",
    "pihole_queries_cached",
    "pihole_query_frequency",
    "pihole_queries_by_type",
    "pihole_queries_by_status",
    "pihole_queries_by_reply",
    "pihole_clients_total",
    "pihole_clients_active",
    "pihole_domains_total",
    "pihole_upstreams_total",
    "pihole_gravity_domains",
    "pihole_gravity_last_update_timestamp_seconds",
    "pihole_dns_cache_size",
    "pihole_dns_cache_inserted_total",
    "pihole_dns_replies_total",
    "pihole_dhcp_messages_total",
    "pihole_dhcp_leases",
]


def _parse_samples(body):
    """Parse a Prometheus text exposition into a list of (name, value) tuples.

    Skips blank lines and ``#`` HELP/TYPE comment lines. For each sample line
    (``name[{labels}] value``) the value is the last whitespace-separated
    token; the name is everything before the first ``{`` or space.
    """
    samples = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.rsplit(None, 1)
        assert len(parts) == 2, f"malformed sample line: {line!r}"
        name_and_labels, value = parts
        name = name_and_labels.split("{", 1)[0]
        samples.append((name, float(value)))
    return samples


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
            body = r.text
            assert len(body.strip()) > 0, "metrics body is empty"

            # Parse the exposition and check the aggregate metrics are all
            # present, spanning every category (queries/cache/DHCP/gravity/...).
            samples = _parse_samples(body)
            assert samples, "no metric samples parsed from response"
            names = {name for name, _ in samples}
            missing = [m for m in EXPECTED_METRICS if m not in names]
            assert not missing, f"expected metrics missing from response: {missing}"

            # Every emitted sample value must be a finite number. float()
            # happily parses "NaN"/"Inf", so assert finiteness explicitly.
            nonfinite = [(n, v) for n, v in samples if not math.isfinite(v)]
            assert not nonfinite, f"non-finite metric values emitted: {nonfinite}"

            # Values must be non-negative: these metrics are counts, sizes,
            # rates or a unix timestamp. The only exception is
            # pihole_gravity_domains, which is -1 until the gravity list has
            # been loaded.
            negative = [
                (n, v) for n, v in samples
                if v < 0 and n != "pihole_gravity_domains"
            ]
            assert not negative, f"negative metric values emitted: {negative}"
        finally:
            # Reset to baseline (disabled) so later tests see the default.
            _set_token(api_session, "")

        # 4. After clearing the token, the endpoint is inactive again -> 404.
        r = requests.get(METRICS_URL, timeout=10)
        assert r.status_code == 404, \
            f"expected 404 after clearing token, got {r.status_code}"
