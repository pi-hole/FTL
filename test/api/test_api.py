"""
Pi-hole FTL API integration tests — stats, lists, search, history,
config validation (API-side), HTTP errors, and Lua server pages.

These tests replace the equivalent curl-based BATS tests with native
Python assertions against a live FTL instance.

Usage:
    pytest test/api/test_api.py -v
"""

import json
import re

import pytest

FTL_URL = "http://127.0.0.1"


# ---------------------------------------------------------------------------
# Expected query counters
# ---------------------------------------------------------------------------
# These counters must stay hermetic: every query the bats suite fires is served
# by the local PowerDNS instance, including a locally-signed root zone (see
# test/pdns/setup.sh and recursor.conf).  DNSSEC validation therefore never
# recurses to the public ICANN root, whose DNSKEY set drifts with key-signing-key
# rollovers - that used to change the number of root DNSKEY lookups and made the
# DNSSEC-dependent counters below flaky.  If you add or remove queries in
# test_suite.bats, update these.

TOTAL       = 131
FORWARDED   = 41
DNSKEY      = 4
TOP_DOMAIN  = "localhost"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _j(response, dump=None):
    """Return parsed JSON, stripping the volatile ``took`` field.

    If *dump* is given, write the full response to
    ``/tmp/ftl_test_<dump>.json`` (best-effort, ignored on failure)
    so the expected values can be inspected after a test run.
    """
    data = response.json()
    data.pop("took", None)
    if dump:
        try:
            with open(f"/tmp/ftl_test_{dump}.json", "w") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass
    return data


def set_config(api_session, dotted_key, value):
    """Set a FTL config item via the API.

    Builds the nested JSON payload from a dotted key, e.g.
    ``set_config(s, "webserver.serve_all", True)`` sends
    ``PATCH /api/config/webserver/serve_all``
    with ``{"config": {"webserver": {"serve_all": true}}}``.
    """
    parts = dotted_key.split(".")
    api_path = f"{FTL_URL}/api/config/" + "/".join(parts)

    payload = value
    for part in reversed(parts):
        payload = {part: payload}
    payload = {"config": payload}

    r = api_session.patch(api_path, json=payload, timeout=20)
    assert r.status_code == 200, \
        f"Failed to set {dotted_key}: {r.status_code} {r.text}"
    return r


# ---------------------------------------------------------------------------
# HTTP error responses
# ---------------------------------------------------------------------------

class TestHTTPErrors:

    def test_api_404_returns_json(self, api_session):
        """HTTP server responds with JSON error 404 to unknown API path."""
        data = _j(api_session.get(f"{FTL_URL}/api/undefined", timeout=5))
        assert data["error"] == {
            "key": "not_found",
            "message": "Not found",
            "hint": "/api/undefined",
        }, json.dumps(data, indent=2)

    def test_non_admin_path_returns_404(self, api_session):
        """HTTP server responds with 404 to path outside /admin."""
        r = api_session.head(f"{FTL_URL}/undefined", timeout=5)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# CORS headers for cross-origin web apps
# ---------------------------------------------------------------------------

class TestCORS:
    """Cross-origin requests must work for all methods.

    Browsers send a preflight OPTIONS request before "non-simple" cross-origin
    requests (DELETE, PUT, PATCH, JSON POST) and only send the real request if
    the preflight is answered with the matching Access-Control-Allow-* headers.
    The actual response must carry Access-Control-Allow-Origin as well.
    Regression test for https://github.com/pi-hole/FTL/issues/2261.
    """

    ORIGIN = "http://example.com"

    def test_preflight_returns_cors_headers(self, api_session):
        """OPTIONS preflight advertises the allowed origin and methods.

        A valid cross-origin preflight (carrying both Origin and
        Access-Control-Request-Method) is answered by civetweb's built-in CORS
        handler with a 200 response and the matching Access-Control-Allow-*
        headers, before the request reaches FTL's own OPTIONS branch.
        """
        r = api_session.options(
            f"{FTL_URL}/api/auth",
            headers={
                "Origin": self.ORIGIN,
                "Access-Control-Request-Method": "DELETE",
            },
            timeout=5,
        )
        assert r.status_code == 200
        assert "Access-Control-Allow-Origin" in r.headers
        assert "DELETE" in r.headers.get("Access-Control-Allow-Methods", "")

    def test_preflight_without_origin_omits_cors_headers(self, api_session):
        """A bare OPTIONS request (no Origin) is not a CORS preflight.

        Like civetweb's send_cors_header(), we only emit Access-Control-Allow-*
        when the request carries an Origin header, otherwise we answer with a
        plain 204 and just the RFC 7231 Allow header.
        """
        r = api_session.options(f"{FTL_URL}/api/auth", timeout=5)
        assert r.status_code == 204
        assert "Allow" in r.headers
        assert "Access-Control-Allow-Origin" not in r.headers

    def test_error_response_carries_cors_header(self, api_session):
        """Non-200 responses include Access-Control-Allow-Origin too.

        DELETE endpoints answer with 204 No Content, which - like this 404 - is
        sent via the same code path that previously omitted the CORS header.
        """
        r = api_session.get(
            f"{FTL_URL}/api/undefined",
            headers={"Origin": self.ORIGIN},
            timeout=5,
        )
        assert r.status_code == 404
        assert "Access-Control-Allow-Origin" in r.headers


# ---------------------------------------------------------------------------
# Config validation via API (type-based)
# ---------------------------------------------------------------------------

class TestConfigValidationAPIType:

    def test_CNAMEdeepInspect_rejects_float(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"CNAMEdeepInspect": 15.5}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item is invalid",
            "hint": "dns.CNAMEdeepInspect: not of type bool",
        }, json.dumps(data, indent=2)

    def test_piholePTR_rejects_invalid_option(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"piholePTR": "something_else"}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item is invalid",
            "hint": "dns.piholePTR: invalid option",
        }, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Config validation via API (validator-based)
# ---------------------------------------------------------------------------

class TestConfigValidationAPIValidator:

    def test_files_pcap_rejects_invalid_path(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"files": {"pcap": "%gh4b"}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item validation failed",
            "hint": 'files.pcap: not a valid file path ("%gh4b")',
        }, json.dumps(data, indent=2)

    def test_cnameRecords_rejects_too_few_elements(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"cnameRecords": ["a"]}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item validation failed",
            "hint": "dns.cnameRecords[0]: not a valid CNAME definition (too few elements)",
        }, json.dumps(data, indent=2)

    def test_cnameRecords_rejects_empty_string_position(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"cnameRecords": ["a,b,c", "a,b,c,,c"]}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item validation failed",
            "hint": "dns.cnameRecords[1]: contains an empty string at position 3",
        }, json.dumps(data, indent=2)

    def test_cnameRecords_rejects_non_string_element(self, api_session):
        data = _j(api_session.patch(f"{FTL_URL}/api/config",
                                    json={"config": {"dns": {"cnameRecords": ["a,b,c", "a,b,c", 5]}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config item is invalid",
            "hint": "dns.cnameRecords: array has invalid elements",
        }, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Envvar-protected config: cannot change via API
# ---------------------------------------------------------------------------

class TestEnvvarProtectedConfig:

    def test_api_rejects_envvar_override(self, api_session):
        """API cannot change misc.nice when set via FTLCONF_misc_nice."""
        data = _j(api_session.patch(f"{FTL_URL}/api/config/misc/nice",
                                    json={"config": {"misc": {"nice": -12}}}, timeout=20))
        assert data["error"] == {
            "key": "bad_request",
            "message": "Config items set via environment variables cannot be changed via the API",
            "hint": "misc.nice",
        }, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Domain search
# ---------------------------------------------------------------------------

class TestDomainSearch:

    def test_nonexistent_domain(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/search/non.existent", timeout=5))
        search = data["search"]
        assert search["domains"] == []
        assert search["gravity"] == []
        assert search["results"] == {
            "domains": {"exact": 0, "regex": 0},
            "gravity": {"allow": 0, "block": 0},
            "total": 0,
        }, json.dumps(data, indent=2)
        assert search["parameters"] == {
            "N": 20,
            "partial": False,
            "domain": "non.existent",
            "debug": False,
        }, json.dumps(data, indent=2)

    def test_antigravity_domain(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/search/antigravity.ftl", timeout=5))
        search = data["search"]
        assert search["results"] == {
            "domains": {"exact": 0, "regex": 0},
            "gravity": {"allow": 2, "block": 1},
            "total": 3,
        }, json.dumps(data, indent=2)
        assert search["domains"] == []

        gravity = search["gravity"]
        assert len(gravity) == 3, json.dumps(gravity, indent=2)

        # Block list match
        g0 = gravity[0]
        assert g0["domain"] == "antigravity.ftl"
        assert g0["type"] == "block"
        assert g0["address"] == "https://pi-hole.net/block.txt"
        assert g0["comment"] == "Fake block-list"
        assert g0["enabled"] is True
        assert g0["id"] == 1
        assert g0["number"] == 2000
        assert g0["invalid_domains"] == 2
        assert g0["groups"] == [0, 2]

        # Allow list match (exact domain)
        g1 = gravity[1]
        assert g1["domain"] == "antigravity.ftl"
        assert g1["type"] == "allow"
        assert g1["address"] == "https://pi-hole.net/allow.txt"
        assert g1["comment"] == "Fake allow-list"
        assert g1["id"] == 2
        assert g1["groups"] == [0]

        # Allow list match (ABP-style antigravity entry)
        g2 = gravity[2]
        assert g2["domain"] == "@@||antigravity.ftl^"
        assert g2["type"] == "allow"
        assert g2["id"] == 2

    def test_punycode_normalization(self, api_session):
        """Internationalized domain names should be normalized to punycode."""
        data = _j(api_session.get(f"{FTL_URL}/api/search/\u00e4BC.com",
                                  params={"debug": "true"}, timeout=5))
        assert data["search"]["debug"]["punycode"] == "xn--bc-uia.com", \
            json.dumps(data, indent=2)
        assert data["search"]["results"]["total"] == 0

    def test_punycode_domain_accepted(self, api_session):
        """Punycode domains (e.g. emoji IDNs) must not be rejected by the API.

        Regression test for https://github.com/pi-hole/FTL/issues/2837
        libidn2 rejects punycode for characters not in IDNA2008 (e.g. emoji),
        but the ASCII punycode form is a perfectly valid DNS name.
        xn--4ca0bs45142c.com is the punycode encoding of äöü😀.com.
        """
        data = _j(api_session.get(f"{FTL_URL}/api/search/xn--4ca0bs45142c.com",
                                  params={"debug": "true"}, timeout=5))
        assert data["search"]["debug"]["punycode"] == "xn--4ca0bs45142c.com", \
            json.dumps(data, indent=2)
        # The domain does not exist in gravity, so total should be 0
        assert data["search"]["results"]["total"] == 0

    def test_partial_matching(self, api_session):
        """Partial matching returns substring hits in gravity."""
        data = _j(api_session.get(f"{FTL_URL}/api/search/gravity",
                                  params={"partial": "true"}, timeout=5))
        search = data["search"]
        assert search["parameters"]["partial"] is True
        assert search["results"]["total"] > 0, \
            f"Expected partial matches for 'gravity':\n{json.dumps(data, indent=2)}"


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

class TestHistory:

    def test_history_returns_24h(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/history", timeout=5))
        assert len(data["history"]) == 145, \
            f"Expected 145 history entries (24h in 10-min slots), got {len(data['history'])}"
        # Verify each slot has the expected structure
        slot = data["history"][0]
        for key in ("timestamp", "total", "cached", "blocked", "forwarded"):
            assert key in slot, f"Missing key '{key}' in history slot: {slot}"

    def test_history_clients_returns_24h(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/history/clients", timeout=5))
        assert len(data["history"]) == 145, \
            f"Expected 145 history entries, got {len(data['history'])}"
        assert "clients" in data, f"Missing 'clients' key:\n{json.dumps(data, indent=2)}"


# ---------------------------------------------------------------------------
# Lists
# ---------------------------------------------------------------------------

class TestLists:

    def test_block_lists_only(self, api_session):
        lists = _j(api_session.get(f"{FTL_URL}/api/lists?type=block", timeout=5))["lists"]
        assert len(lists) == 1, f"Expected 1 block list:\n{json.dumps(lists, indent=2)}"
        bl = lists[0]
        assert bl["type"] == "block"
        assert bl["address"] == "https://pi-hole.net/block.txt"
        assert bl["comment"] == "Fake block-list"
        assert bl["enabled"] is True
        assert bl["id"] == 1
        assert bl["number"] == 2000
        assert bl["invalid_domains"] == 2
        assert bl["abp_entries"] == 0
        assert bl["status"] == 1
        assert bl["groups"] == [0, 2]

    def test_allow_lists_only(self, api_session):
        lists = _j(api_session.get(f"{FTL_URL}/api/lists?type=allow", timeout=5))["lists"]
        assert len(lists) == 1, f"Expected 1 allow list:\n{json.dumps(lists, indent=2)}"
        al = lists[0]
        assert al["type"] == "allow"
        assert al["address"] == "https://pi-hole.net/allow.txt"
        assert al["comment"] == "Fake allow-list"
        assert al["enabled"] is True
        assert al["id"] == 2
        assert al["number"] == 2000
        assert al["invalid_domains"] == 2
        assert al["abp_entries"] == 0
        assert al["status"] == 1
        assert al["groups"] == [0]

    def test_all_lists_includes_both_types(self, api_session):
        lists = _j(api_session.get(f"{FTL_URL}/api/lists", timeout=5))["lists"]
        assert len(lists) == 2, f"Expected 2 lists:\n{json.dumps(lists, indent=2)}"
        types = {lst["type"] for lst in lists}
        assert types == {"block", "allow"}


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

class TestQueries:

    def test_no_unknown_reply(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?reply=UNKNOWN", timeout=5))
        assert data["queries"] == []
        assert data["recordsFiltered"] == 0, json.dumps(data, indent=2)

    def test_no_unknown_status(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?status=UNKNOWN", timeout=5))
        assert data["queries"] == []
        assert data["recordsFiltered"] == 0, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Lua server pages
# ---------------------------------------------------------------------------

class TestLuaServerPages:

    def test_lua_page_outside_admin_not_served_by_default(self, api_session):
        """Lua server page outside /admin is not served when serve_all is off."""
        set_config(api_session, "webserver.serve_all", False)
        r = api_session.head(f"{FTL_URL}/broken_lua", timeout=5)
        assert r.status_code == 404

    def test_lua_page_generates_proper_backtrace(self, api_session):
        """Lua server page generates proper backtrace on error."""
        set_config(api_session, "webserver.serve_all", True)
        r = api_session.get(f"{FTL_URL}/broken_lua", timeout=5)
        lines = r.text.splitlines()
        assert lines[0] == "Hello, world 1!", f"Unexpected response:\n{r.text}"
        assert lines[1] == "Hello, world 2!"
        assert 'Cannot include [/var/www/html/does_not_exist.lp]: not found' in lines[2]
        assert lines[3] == "stack traceback:"

    def test_lua_page_outside_webhome_served_without_login(self, api_session):
        """After serve_all is enabled, Lua pages are served without login."""
        r = api_session.get(f"{FTL_URL}/broken_lua", timeout=5)
        lines = r.text.splitlines()
        assert lines[0] == "Hello, world 1!", f"Unexpected response:\n{r.text}"


# ---------------------------------------------------------------------------
# URI control-character / CRLF injection rejection
# ---------------------------------------------------------------------------


def _raw_http(request_bytes, host="127.0.0.1", port=80, timeout=5):
    """Send a raw HTTP request over a socket and return the raw response bytes.

    Used to smuggle bytes (e.g. a percent-encoded CR/LF in the path) that the
    requests library would normalise away before they reach FTL.
    """
    import socket
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(request_bytes)
        chunks = []
        try:
            while True:
                buf = sock.recv(4096)
                if not buf:
                    break
                chunks.append(buf)
        except socket.timeout:
            pass
    return b"".join(chunks)


class TestURIControlCharRejection:
    """An encoded CR/LF in the request path must never be reflected into a
    response header (HTTP response splitting / header injection).

    CivetWeb URL-decodes the path in place, so %0d%0a arrives as a literal
    CR/LF; the .lp redirect handler would otherwise copy it into the Location
    header verbatim.  FTL rejects any request whose decoded URI contains
    control characters with 400, before authentication and before any handler
    runs (see begin_request_handler in src/webserver/webserver.c).
    """

    def test_crlf_in_lp_path_is_rejected(self, api_session):
        req = (
            b"GET /admin/a%0d%0aSet-Cookie:%20injected=1.lp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = _raw_http(req)
        status_line = resp.split(b"\r\n", 1)[0]
        assert b" 400 " in status_line, f"Expected 400, got: {status_line!r}"
        # The smuggled header must not have been split out of the path into the
        # response headers.
        headers = resp.split(b"\r\n\r\n", 1)[0].lower()
        assert b"set-cookie: injected" not in headers, \
            f"CRLF was reflected into response headers:\n{resp!r}"

    def test_bare_control_char_in_uri_is_rejected(self, api_session):
        req = (
            b"GET /admin/%01%02.lp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = _raw_http(req)
        status_line = resp.split(b"\r\n", 1)[0]
        assert b" 400 " in status_line, f"Expected 400, got: {status_line!r}"

    def test_clean_lp_path_is_not_rejected(self, api_session):
        # A control-character-free .lp request must still be handled (the guard
        # must not over-block legitimate traffic).
        req = (
            b"GET /admin/index.lp HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        resp = _raw_http(req)
        status_line = resp.split(b"\r\n", 1)[0]
        assert b" 400 " not in status_line, \
            f"Legitimate .lp request was rejected: {status_line!r}"


# ---------------------------------------------------------------------------
# DNS blocking status
# ---------------------------------------------------------------------------

class TestDNSBlocking:

    def test_blocking_enabled(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/dns/blocking", timeout=5))
        assert data["blocking"] == "enabled"
        assert data["timer"] is None


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

class TestDomains:

    def test_allow_exact(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/domains/allow/exact", timeout=5))
        domains = data["domains"]
        names = [d["domain"] for d in domains]
        assert "allowed.ftl" in names, json.dumps(domains, indent=2)
        assert "regex1.ftl" in names
        assert "mask.icloud.com" in names
        for d in domains:
            assert d["type"] == "allow"
            assert d["kind"] == "exact"

    def test_allow_regex(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/domains/allow/regex", timeout=5))
        domains = data["domains"]
        assert len(domains) == 2, json.dumps(domains, indent=2)
        assert domains[0] == {
            "domain": "regex2", "unicode": "regex2",
            "type": "allow", "kind": "regex", "comment": "",
            "groups": [0], "enabled": True,
            "id": 3, "date_added": 1559928803, "date_modified": 1559928803,
        }
        assert domains[1]["domain"] == "^gravity-allowed"
        assert domains[1]["id"] == 4

    def test_deny_exact(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/domains/deny/exact", timeout=5))
        domains = data["domains"]
        names = [d["domain"] for d in domains]
        assert "denied.ftl" in names, json.dumps(domains, indent=2)
        assert "blacklisted-group-disabled.com" in names
        for d in domains:
            assert d["type"] == "deny"
            assert d["kind"] == "exact"

    def test_deny_regex(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/domains/deny/regex", timeout=5))
        domains = data["domains"]
        assert len(domains) == 11, \
            f"Expected 11 deny regex, got {len(domains)}:\n{json.dumps(domains, indent=2)}"
        assert domains[0]["domain"] == "regex[0-9].ftl"
        assert domains[0]["id"] == 6
        assert domains[0]["groups"] == [0, 2]
        for d in domains:
            assert d["type"] == "deny"
            assert d["kind"] == "regex"

    def test_all_domains(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/domains", timeout=5))
        domains = data["domains"]
        types = {d["type"] for d in domains}
        kinds = {d["kind"] for d in domains}
        assert types == {"allow", "deny"}
        assert kinds == {"exact", "regex"}

    def test_single_domain_lookup(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/domains/deny/exact/denied.ftl", timeout=5))
        domains = data["domains"]
        assert len(domains) == 1, json.dumps(domains, indent=2)
        assert domains[0]["domain"] == "denied.ftl"
        assert domains[0]["comment"] == "Migrated from /etc/pihole/blacklist.txt"


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

class TestGroups:

    def test_all_groups(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/groups", timeout=5))
        groups = data["groups"]
        assert len(groups) == 6, json.dumps(groups, indent=2)
        names = {g["name"] for g in groups}
        assert "Default" in names
        assert "Test group" in names
        assert "Second test group" in names

        default = next(g for g in groups if g["name"] == "Default")
        assert default["id"] == 0
        assert default["enabled"] is True
        assert default["comment"] == "The default group"

        disabled = next(g for g in groups if g["name"] == "Test group")
        assert disabled["id"] == 1
        assert disabled["enabled"] is False

    def test_single_group_lookup(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/groups/Default", timeout=5))
        groups = data["groups"]
        assert len(groups) == 1, json.dumps(groups, indent=2)
        assert groups[0]["name"] == "Default"
        assert groups[0]["id"] == 0


# ---------------------------------------------------------------------------
# Stats summary
# ---------------------------------------------------------------------------

class TestStatsSummary:

    def test_summary_structure(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/summary", timeout=5), dump="stats_summary")
        q = data["queries"]
        assert q["total"] == TOTAL, json.dumps(data, indent=2)
        assert q["blocked"] == 49
        assert q["forwarded"] == FORWARDED
        assert q["cached"] == 41
        assert q["unique_domains"] == 77
        assert q["status"]["UNKNOWN"] == 0
        assert q["status"]["GRAVITY"] == 7
        assert q["status"]["FORWARDED"] == FORWARDED
        assert q["status"]["CACHE"] == 41
        assert q["status"]["REGEX"] == 21
        assert q["status"]["DENYLIST"] == 4
        assert q["status"]["SPECIAL_DOMAIN"] == 2
        assert q["types"]["A"] == 69
        assert q["types"]["AAAA"] == 19

        assert data["clients"]["active"] == 11
        assert data["clients"]["total"] == 11
        assert data["gravity"]["domains_being_blocked"] == 8


# ---------------------------------------------------------------------------
# Stats: top domains
# ---------------------------------------------------------------------------

class TestStatsTopDomains:

    def test_top_domains_sorted_descending(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/top_domains", timeout=5), dump="top_domains")
        domains = data["domains"]
        assert len(domains) > 0
        counts = [d["count"] for d in domains]
        assert counts == sorted(counts, reverse=True), \
            f"Not sorted descending: {counts}"
        assert data["total_queries"] == TOTAL
        assert data["blocked_queries"] == 49

    def test_top_domains_blocked(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/top_domains?blocked=true", timeout=5))
        domains = data["domains"]
        names = [d["domain"] for d in domains]
        assert "gravity.ftl" in names, json.dumps(domains, indent=2)
        counts = [d["count"] for d in domains]
        assert counts == sorted(counts, reverse=True)

    def test_top_domains_permitted_excludes_gravity(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/top_domains?blocked=false", timeout=5))
        names = [d["domain"] for d in data["domains"]]
        assert "gravity.ftl" not in names, \
            f"gravity.ftl should not be in permitted domains:\n{json.dumps(data, indent=2)}"

    def test_top_domains_small_count_is_true_prefix(self, api_session):
        # Regression for #2946: the bounded top-K heap selection must return
        # the real top-K for small counts and must not drop legitimate
        # domains. A small count reduces the heap capacity to count*4, so any
        # entry that wrongly occupies a slot would evict a genuine domain and
        # shorten the result below the requested count.
        full = _j(api_session.get(f"{FTL_URL}/api/stats/top_domains?count=100", timeout=5),
                  dump="top_domains_full")["domains"]
        full_counts = [d["count"] for d in full]
        assert len(full) > 4, \
            f"test data must expose more than 4 domains to exercise heap eviction, got {len(full)}"
        for n in (1, 2, 3, 4):
            data = _j(api_session.get(f"{FTL_URL}/api/stats/top_domains?count={n}", timeout=5))
            counts = [d["count"] for d in data["domains"]]
            assert len(counts) == min(n, len(full)), \
                f"count={n} returned {len(counts)} domains, expected {min(n, len(full))}"
            assert counts == sorted(counts, reverse=True), \
                f"count={n} not sorted descending: {counts}"
            assert counts == full_counts[:n], \
                f"count={n} is not the top-{n} prefix: {counts} vs {full_counts[:n]}"

    def test_top_domains_exclude_filter_does_not_shorten(self, api_session):
        # Regression for #2946: excludeDomains must be applied before the
        # bounded top-K heap selection, not only at output. Excluded (usually
        # high-count) domains that reach the heap occupy slots and evict
        # genuine domains, so the result ends up shorter than requested. At
        # count=1 the heap capacity is 4, so excluding the four top domains
        # would empty a broken (output-only) filter's result entirely.
        full = _j(api_session.get(f"{FTL_URL}/api/stats/top_domains?count=100", timeout=5),
                  dump="top_domains_exclude_full")["domains"]
        names = [d["domain"] for d in full]
        full_counts = [d["count"] for d in full]
        assert len(names) > 5, \
            f"test data must expose more than 5 domains to exercise the filter, got {len(names)}"

        excluded = names[:4]
        try:
            set_config(api_session, "webserver.api.excludeDomains",
                       [f"^{re.escape(n)}$" for n in excluded])
            data = _j(api_session.get(f"{FTL_URL}/api/stats/top_domains?count=1", timeout=5))
            result = data["domains"]
            assert len(result) == 1, \
                f"excluding the top domains must not empty the result: {result}"
            assert result[0]["domain"] not in excluded, \
                f"an excluded domain leaked into the result: {result}"
            assert result[0]["count"] == full_counts[4], \
                f"expected the first non-excluded count {full_counts[4]}, got {result}"
        finally:
            set_config(api_session, "webserver.api.excludeDomains", [])


# ---------------------------------------------------------------------------
# Stats: top clients
# ---------------------------------------------------------------------------

class TestStatsTopClients:

    def test_top_clients_sorted_descending(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/top_clients", timeout=5), dump="top_clients")
        clients = data["clients"]
        assert len(clients) > 0
        assert clients[0]["ip"] == "127.0.0.1"
        counts = [c["count"] for c in clients]
        assert counts == sorted(counts, reverse=True), \
            f"Not sorted descending: {counts}"
        assert data["total_queries"] == TOTAL


# ---------------------------------------------------------------------------
# Stats: upstreams
# ---------------------------------------------------------------------------

class TestStatsUpstreams:

    def test_upstreams(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/upstreams", timeout=5), dump="upstreams")
        upstreams = data["upstreams"]
        assert len(upstreams) == 4, json.dumps(upstreams, indent=2)
        assert data["total_queries"] == TOTAL
        assert data["forwarded_queries"] == FORWARDED

        blocklist = next(u for u in upstreams if u["ip"] == "blocklist")
        assert blocklist["count"] == 49
        assert blocklist["port"] == -1

        cache = next(u for u in upstreams if u["ip"] == "cache")
        assert cache["count"] == 41
        assert cache["port"] == -1


# ---------------------------------------------------------------------------
# Stats: query types
# ---------------------------------------------------------------------------

class TestStatsQueryTypes:

    def test_query_types(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/query_types", timeout=5), dump="query_types")
        assert data["types"] == {
            "A": 69, "AAAA": 19, "ANY": 3, "SRV": 1, "SOA": 0,
            "PTR": 8, "TXT": 10, "NAPTR": 1, "MX": 1, "DS": 6,
            "RRSIG": 0, "DNSKEY": DNSKEY, "NS": 0, "SVCB": 3, "HTTPS": 3,
            "OTHER": 1,
        }, json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Stats: recent blocked
# ---------------------------------------------------------------------------

class TestStatsRecentBlocked:

    def test_recent_blocked(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/stats/recent_blocked", timeout=5))
        assert "denied.ftl" in data["blocked"], json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Stats: database endpoints (require from/until parameters)
# ---------------------------------------------------------------------------

class TestStatsDatabase:

    def test_database_endpoints_require_time_range(self, api_session):
        """Database stats endpoints return 400 without from/until."""
        for endpoint in ("query_types", "summary", "top_clients",
                         "top_domains", "upstreams"):
            data = _j(api_session.get(
                f"{FTL_URL}/api/stats/database/{endpoint}", timeout=5))
            assert data["error"]["key"] == "bad_request", \
                f"/api/stats/database/{endpoint}: {json.dumps(data, indent=2)}"
            assert "from" in data["error"]["message"]
            assert "until" in data["error"]["message"]

    def test_database_summary_with_range(self, api_session):
        data = _j(api_session.get(
            f"{FTL_URL}/api/stats/database/summary?from=1&until=9999999999",
            timeout=5))
        for key in ("sum_queries", "sum_blocked", "percent_blocked",
                     "total_clients"):
            assert key in data, f"Missing key '{key}' in database summary"

    def test_database_top_domains_with_range(self, api_session):
        data = _j(api_session.get(
            f"{FTL_URL}/api/stats/database/top_domains?from=1&until=9999999999",
            timeout=5))
        summary = _j(api_session.get(
            f"{FTL_URL}/api/stats/database/summary?from=1&until=9999999999",
            timeout=5))
        assert "domains" in data
        assert isinstance(data["domains"], list)
        assert data["total_queries"] == summary["sum_queries"]
        assert data["blocked_queries"] == summary["sum_blocked"]

    def test_database_top_clients_with_range(self, api_session):
        data = _j(api_session.get(
            f"{FTL_URL}/api/stats/database/top_clients?from=1&until=9999999999",
            timeout=5))
        summary = _j(api_session.get(
            f"{FTL_URL}/api/stats/database/summary?from=1&until=9999999999",
            timeout=5))
        assert "clients" in data
        assert isinstance(data["clients"], list)
        assert data["total_queries"] == summary["sum_queries"]
        assert data["blocked_queries"] == summary["sum_blocked"]

    def test_database_upstreams_with_range(self, api_session):
        data = _j(api_session.get(
            f"{FTL_URL}/api/stats/database/upstreams?from=1&until=9999999999",
            timeout=5))
        assert "upstreams" in data
        assert isinstance(data["upstreams"], list)

    def test_database_query_types_with_range(self, api_session):
        data = _j(api_session.get(
            f"{FTL_URL}/api/stats/database/query_types?from=1&until=9999999999",
            timeout=5))
        assert "types" in data
        assert isinstance(data["types"], dict)


# ---------------------------------------------------------------------------
# DHCP leases
# ---------------------------------------------------------------------------

class TestDHCPLeases:

    def test_no_leases(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/dhcp/leases", timeout=5))
        assert data["leases"] == []


# ---------------------------------------------------------------------------
# Endpoints listing
# ---------------------------------------------------------------------------

class TestEndpoints:

    def test_endpoints_has_all_methods(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/endpoints", timeout=5))
        eps = data["endpoints"]
        for method in ("get", "post", "put", "patch", "delete"):
            assert method in eps, f"Missing method '{method}':\n{json.dumps(eps.keys(), indent=2)}"
        # GET should have the most endpoints
        assert len(eps["get"]) > 20


# ---------------------------------------------------------------------------
# Info endpoints
# ---------------------------------------------------------------------------

class TestInfo:

    def test_info_ftl(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/ftl", timeout=5), dump="info_ftl")
        ftl = data["ftl"]
        db = ftl["database"]
        assert db["gravity"] == 8, json.dumps(db, indent=2)
        assert db["groups"] == 5
        assert db["lists"] == 2
        assert db["clients"] == 5
        assert db["domains"]["allowed"] == {"total": 3, "enabled": 3}
        assert db["domains"]["denied"] == {"total": 2, "enabled": 2}
        assert db["regex"]["allowed"] == {"total": 2, "enabled": 2}
        assert db["regex"]["denied"] == {"total": 11, "enabled": 11}
        assert ftl["privacy_level"] == 0
        assert ftl["clients"]["total"] == 11
        assert ftl["clients"]["active"] == 11

    def test_info_login(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/login", timeout=5))
        assert data["dns"] is True
        assert data["https_port"] == 443

    def test_info_version(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/version", timeout=5))
        v = data["version"]
        assert "ftl" in v
        assert "local" in v["ftl"]
        assert v["ftl"]["local"]["version"].startswith("v")
        assert "hash" in v["ftl"]["local"]

    def test_info_messages(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/messages", timeout=5))
        assert "messages" in data
        assert isinstance(data["messages"], list)

    def test_info_messages_count(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/messages/count", timeout=5))
        assert "count" in data
        assert isinstance(data["count"], int)

    def test_info_client(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/client", timeout=5))
        assert data["remote_addr"] == "127.0.0.1"
        assert data["http_version"] == "1.1"
        assert data["method"] == "GET"

    def test_info_database(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/database", timeout=5))
        assert data["type"] == "Regular file"
        assert data["mode"] == "rw-r-----"
        assert data["owner"]["user"]["name"] == "pihole"
        assert data["owner"]["group"]["name"] == "pihole"
        assert data["queries"] > 0
        assert data["sqlite_version"].startswith("3.")

    def test_info_system(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/system", timeout=5))
        s = data["system"]
        assert "uptime" in s
        assert s["memory"]["ram"]["total"] > 0
        assert s["cpu"]["nprocs"] > 0
        assert "ftl" in s
        assert "%mem" in s["ftl"]
        assert "%cpu" in s["ftl"]


# ---------------------------------------------------------------------------
# Auth (read-only)
# ---------------------------------------------------------------------------

class TestAuthReadOnly:

    def test_totp_suggestion(self, api_session):
        """GET /api/auth/totp returns TOTP credential suggestions."""
        data = _j(api_session.get(f"{FTL_URL}/api/auth/totp", timeout=5))
        totp = data["totp"]
        assert isinstance(totp["secret"], str)
        assert len(totp["secret"]) > 0
        assert totp["digits"] == 6
        assert totp["period"] == 30
        assert "algorithm" in totp
        assert isinstance(totp["codes"], list)


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

class TestNetwork:

    def test_network_devices(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/network/devices", timeout=5))
        devices = data["devices"]
        hwaddrs = [d["hwaddr"] for d in devices]
        assert "aa:bb:cc:dd:ee:ff" in hwaddrs, json.dumps(hwaddrs, indent=2)
        assert "ip-127.0.0.1" in hwaddrs

    def test_network_interfaces(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/network/interfaces", timeout=5))
        ifaces = data["interfaces"]
        names = [i["name"] for i in ifaces]
        assert "lo" in names, json.dumps(names, indent=2)


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

class TestLogs:

    def test_dnsmasq_log(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/logs/dnsmasq", timeout=5))
        assert len(data["log"]) > 0
        entry = data["log"][0]
        assert "timestamp" in entry
        assert "message" in entry

    def test_ftl_log(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/logs/ftl", timeout=5))
        assert len(data["log"]) > 0
        entry = data["log"][0]
        assert "timestamp" in entry
        assert "message" in entry
        assert "prio" in entry

    def test_webserver_log(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/logs/webserver", timeout=5))
        assert len(data["log"]) > 0


# ---------------------------------------------------------------------------
# PADD
# ---------------------------------------------------------------------------

class TestPADD:

    def test_padd(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/padd", timeout=5), dump="padd")
        assert data["blocking"] == "enabled"
        assert data["gravity_size"] == 8
        assert data["active_clients"] == 11
        assert data["top_domain"] == TOP_DOMAIN
        assert data["top_blocked"] == "gravity.ftl"
        assert data["top_client"] == "127.0.0.1"
        q = data["queries"]
        assert q["total"] == TOTAL, json.dumps(data, indent=2)
        assert q["blocked"] == 49
        cache = data["cache"]
        assert cache["size"] == 10000


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------

class TestClients:

    def test_all_clients(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/clients", timeout=5))
        clients = data["clients"]
        assert len(clients) == 5, \
            f"Expected 5 clients:\n{json.dumps(clients, indent=2)}"
        names = [c["client"] for c in clients]
        assert "127.0.0.1" in names
        assert "127.0.0.2" in names
        assert "aa:bb:cc:dd:ee:ff" in names
        assert ":enp0s123" in names

    def test_single_client_lookup(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/clients/127.0.0.1", timeout=5))
        clients = data["clients"]
        assert len(clients) == 1, json.dumps(clients, indent=2)
        c = clients[0]
        assert c["client"] == "127.0.0.1"
        assert c["groups"] == [0]

    def test_client_suggestions(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/clients/_suggestions", timeout=5))
        assert "clients" in data
        assert isinstance(data["clients"], list)


# ---------------------------------------------------------------------------
# Config (GET)
# ---------------------------------------------------------------------------

class TestConfigGet:

    def test_full_config(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/config", timeout=5))
        config = data["config"]
        assert "dns" in config
        assert "webserver" in config
        assert "misc" in config
        assert "debug" in config
        assert "database" in config
        assert config["dns"]["CNAMEdeepInspect"] is True
        assert config["dns"]["EDNS0ECS"] is True

    def test_config_element(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/config/dns/upstreams", timeout=5))
        config = data["config"]
        upstreams = config["dns"]["upstreams"]
        assert isinstance(upstreams, list)
        assert len(upstreams) > 0


# ---------------------------------------------------------------------------
# Network (additional)
# ---------------------------------------------------------------------------

class TestNetworkAdditional:

    def test_network_gateway(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/network/gateway", timeout=5))
        assert "gateway" in data
        assert isinstance(data["gateway"], list)

    def test_network_routes(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/network/routes", timeout=5))
        assert "routes" in data
        assert isinstance(data["routes"], list)


# ---------------------------------------------------------------------------
# Info (additional)
# ---------------------------------------------------------------------------

class TestInfoAdditional:

    def test_info_host(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/host", timeout=5))
        host = data["host"]
        uname = host["uname"]
        assert "sysname" in uname
        assert "nodename" in uname
        assert "release" in uname
        assert "machine" in uname

    def test_info_sensors(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/sensors", timeout=5))
        sensors = data["sensors"]
        assert "list" in sensors
        assert isinstance(sensors["list"], list)
        assert "unit" in sensors

    def test_info_metrics(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/info/metrics", timeout=5))
        m = data["metrics"]
        dns = m["dns"]
        assert dns["cache"]["size"] > 0
        assert "replies" in dns
        assert dns["replies"]["sum"] > 0
        assert "dhcp" in m


# ---------------------------------------------------------------------------
# Queries (additional)
# ---------------------------------------------------------------------------

class TestQueriesAdditional:

    def test_queries_default(self, api_session):
        """Default query (no filters) returns up to 100 results."""
        data = _j(api_session.get(f"{FTL_URL}/api/queries", timeout=5))
        assert "queries" in data
        queries = data["queries"]
        assert isinstance(queries, list)
        assert len(queries) > 0
        assert data["recordsTotal"] == TOTAL
        # Check structure of a query entry
        q = queries[0]
        assert "id" in q
        assert "time" in q
        assert "type" in q
        assert "domain" in q
        assert "status" in q
        assert "client" in q
        assert "ip" in q["client"]
        assert "reply" in q
        assert "type" in q["reply"]

    def test_queries_with_length(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?length=5", timeout=5))
        assert len(data["queries"]) == 5

    def test_queries_length_is_capped(self, api_session):
        """Regression: an unbounded 'length' must not build the whole history.

        /api/queries caps the number of rows materialized at
        API_QUERIES_MAX_ROWS (10000) regardless of the requested length,
        including the documented length<=0 ("all") case. The fixed test
        database holds far fewer rows than the cap, so this exercises the
        clamp's contract - a huge or negative length is accepted, saturated,
        and never rejected or overflowed - rather than the 10000-row boundary
        itself.
        """
        CAP = 10000
        # A huge length must be accepted (not rejected) and stay bounded
        huge = _j(api_session.get(f"{FTL_URL}/api/queries?length=999999999", timeout=10))
        assert len(huge["queries"]) <= CAP
        # length=-1 is the documented "all"; it must still return everything
        all_rows = _j(api_session.get(f"{FTL_URL}/api/queries?length=-1", timeout=10))
        assert len(all_rows["queries"]) <= CAP
        # An oversized length saturates to the same bounded result as "all" ...
        assert len(huge["queries"]) == len(all_rows["queries"])
        # ... which, below the cap, is the full unfiltered history
        assert len(all_rows["queries"]) == all_rows["recordsTotal"]

    def test_queries_filter_by_type(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?type=AAAA", timeout=5))
        for q in data["queries"]:
            assert q["type"] == "AAAA", \
                f"Expected type AAAA, got {q['type']}"

    def test_queries_filter_by_status(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?status=GRAVITY", timeout=5))
        assert data["recordsFiltered"] > 0
        for q in data["queries"]:
            assert q["status"] == "GRAVITY"

    def test_queries_filter_by_domain(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?domain=gravity.ftl", timeout=5))
        assert data["recordsFiltered"] > 0
        for q in data["queries"]:
            assert q["domain"] == "gravity.ftl"

    def test_queries_filter_by_client_ip(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries?client_ip=127.0.0.1", timeout=5))
        assert data["recordsFiltered"] > 0
        for q in data["queries"]:
            assert q["client"]["ip"] == "127.0.0.1"

    def test_queries_filter_by_upstream_blocklist(self, api_session):
        """upstream=blocklist is a pseudo-upstream that matches all blocked queries."""
        data = _j(api_session.get(f"{FTL_URL}/api/queries?upstream=blocklist", timeout=5))
        assert data["recordsFiltered"] > 0
        blocked_statuses = {"GRAVITY", "REGEX", "DENYLIST", "SPECIAL_DOMAIN",
                            "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
                            "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL",
                            "EXTERNAL_BLOCKED_NXRA", "EXTERNAL_BLOCKED_EDE15",
                            "DBBUSY"}
        for q in data["queries"]:
            assert q["status"] in blocked_statuses, \
                f"Expected blocked status, got {q['status']}"

    def test_queries_filter_by_upstream_address(self, api_session):
        """Filtering by an actual upstream address."""
        data = _j(api_session.get(
            f"{FTL_URL}/api/queries?upstream=127.0.0.1%235555", timeout=5))
        assert data["recordsFiltered"] > 0
        for q in data["queries"]:
            assert q["upstream"] == "127.0.0.1#5555"

    def test_queries_cursor_pagination(self, api_session):
        """Cursor + start offset returns non-overlapping pages."""
        page1 = _j(api_session.get(f"{FTL_URL}/api/queries?length=5", timeout=5))
        assert len(page1["queries"]) == 5
        cursor = page1["cursor"]
        assert isinstance(cursor, int)

        # Page 2: same cursor, offset by start=5
        page2 = _j(api_session.get(
            f"{FTL_URL}/api/queries?length=5&cursor={cursor}&start=5", timeout=5))
        assert len(page2["queries"]) == 5

        ids1 = {q["id"] for q in page1["queries"]}
        ids2 = {q["id"] for q in page2["queries"]}
        assert ids1.isdisjoint(ids2), \
            f"Pages overlap: {ids1 & ids2}"

    def test_queries_suggestions(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/queries/suggestions", timeout=5))
        s = data["suggestions"]
        assert "domain" in s
        assert "client_ip" in s
        assert "type" in s
        assert "status" in s
        assert "reply" in s
        assert isinstance(s["domain"], list)
        assert len(s["domain"]) > 0
        assert "127.0.0.1" in s["client_ip"]
        assert "A" in s["type"]
        assert "AAAA" in s["type"]


# ---------------------------------------------------------------------------
# History (additional -- database endpoints)
# ---------------------------------------------------------------------------

class TestHistoryDatabase:

    def test_history_database_requires_params(self, api_session):
        """Database history endpoints return 400 without from/until."""
        data = _j(api_session.get(f"{FTL_URL}/api/history/database", timeout=5))
        assert data["error"]["key"] == "bad_request"

    def test_history_database_with_range(self, api_session):
        data = _j(api_session.get(
            f"{FTL_URL}/api/history/database?from=0&until=9999999999", timeout=5))
        assert "history" in data
        assert isinstance(data["history"], list)

    def test_history_database_clients_requires_params(self, api_session):
        data = _j(api_session.get(f"{FTL_URL}/api/history/database/clients", timeout=5))
        assert data["error"]["key"] == "bad_request"

    def test_history_database_clients_with_range(self, api_session):
        data = _j(api_session.get(
            f"{FTL_URL}/api/history/database/clients?from=1&until=9999999999", timeout=5))
        assert "history" in data
        assert "clients" in data


# ---------------------------------------------------------------------------
# NTP server (protocol-level, not HTTP)
# ---------------------------------------------------------------------------

class TestNTP:

    def test_ntp_server_responds(self, api_session):
        """FTL's built-in NTP server returns a valid NTPv4 response."""
        import socket
        import struct

        # NTP v3 client request
        request = b'\x1b' + 47 * b'\0'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.sendto(request, ('127.0.0.1', 123))
            data, _ = sock.recvfrom(1024)
        finally:
            sock.close()

        assert len(data) == 48, f"Expected 48-byte NTP packet, got {len(data)}"

        # LI/VN/Mode byte: mode should be 4 (server)
        mode = data[0] & 0x7
        version = (data[0] >> 3) & 0x7
        assert mode == 4, f"Expected NTP mode 4 (server), got {mode}"
        assert version == 4, f"Expected NTPv4, got v{version}"

        # Transmit timestamp (bytes 40-47): seconds since 1900-01-01
        # should be close to current time (within 2 seconds)
        import time
        ntp_epoch_offset = 2208988800  # seconds between 1900 and 1970
        tx_seconds = struct.unpack('!I', data[40:44])[0]
        now_ntp = int(time.time()) + ntp_epoch_offset
        drift = abs(tx_seconds - now_ntp)
        assert drift <= 2, \
            f"NTP transmit timestamp off by {drift}s (expected ≤2s)"
