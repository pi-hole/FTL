"""
Pi-hole FTL OpenAPI specification validation tests.

Verifies that FTL's API implementation matches the OpenAPI specs:
- Endpoint coverage (OpenAPI ↔ FTL cross-check)
- Response schema validation (types, formats, examples)
- Teleporter export/import round-trip

Ported from checkAPI.py. Reuses the existing libs/ utilities.

Usage:
    pytest test/api/test_openapi.py -v
"""

import pytest
from libs.FTLAPI import FTLAPI, AuthenticationMethods
from libs.openAPI import openApi
from libs.responseVerifyer import ResponseVerifyer


# ---------------------------------------------------------------------------
# Helpers for parametrize — collect endpoint lists at import time is not
# possible (needs fixtures). Instead, tests iterate inside the body and
# use subtests-style assertions, or we use indirect fixtures.
# We use a hybrid: fixtures provide the data, tests iterate with clear
# error messages per endpoint.
# ---------------------------------------------------------------------------


class TestEndpointCoverage:
    """Cross-check that OpenAPI specs and FTL agree on available endpoints."""

    def test_openapi_get_endpoints_exist_in_ftl(self, openapi, ftl):
        """Every GET endpoint in the OpenAPI specs is implemented in FTL."""
        missing = []
        for path in openapi.endpoints["get"]:
            if path not in ftl.endpoints["get"]:
                missing.append(path)
        assert missing == [], \
            "GET endpoints in OpenAPI specs but not in FTL:\n" + \
            "\n".join(f"  {p}" for p in missing)

    def test_ftl_get_endpoints_exist_in_openapi(self, openapi, ftl):
        """Every GET endpoint in FTL is documented in the OpenAPI specs."""
        # /api/docs is intentionally undocumented
        skip = {"/api/docs"}
        missing = []
        for path in ftl.endpoints["get"]:
            if path in skip:
                continue
            if path not in openapi.endpoints["get"]:
                missing.append(path)
        assert missing == [], \
            "GET endpoints in FTL but not in OpenAPI specs:\n" + \
            "\n".join(f"  {p}" for p in missing)

    def test_all_endpoints_cross_check(self, openapi, ftl):
        """Full bidirectional check across all HTTP methods."""
        with ResponseVerifyer(ftl, openapi) as verifyer:
            errors, checked = verifyer.verify_endpoints()
        assert errors == [], \
            f"Endpoint cross-check errors ({checked} checked):\n" + \
            "\n".join(f"  {e}" for e in errors)


class TestEndpointResponses:
    """Validate each GET endpoint's response against its OpenAPI schema."""

    def test_get_endpoint_responses(self, openapi, ftl):
        """Each GET endpoint's response matches its OpenAPI spec.

        Skips /api/action/* endpoints (would trigger unwanted actions).
        Reports all failures with the endpoint path for easy identification.
        """
        all_errors = {}
        teleporter_archive = None

        for path in openapi.endpoints["get"]:
            if path.startswith("/api/action"):
                continue
            with ResponseVerifyer(ftl, openapi) as verifyer:
                errors = verifyer.verify_endpoint(path)
                if verifyer.teleporter_archive is not None:
                    teleporter_archive = verifyer.teleporter_archive
                if len(errors) > 0:
                    all_errors[path] = (verifyer.auth_method, errors)

        # Store teleporter archive for the teleporter tests
        TestEndpointResponses._teleporter_archive = teleporter_archive

        assert all_errors == {}, \
            "Endpoint response validation errors:\n" + \
            "\n".join(
                f"  GET {path} ({auth} auth):\n" +
                "\n".join(f"    - {e}" for e in errs)
                for path, (auth, errs) in all_errors.items()
            )

    # Store across test instances
    _teleporter_archive = None


class TestTeleporter:
    """Teleporter export/import round-trip via API."""

    def test_teleporter_v5_domainlist_groups(self, ftl):
        """A v5 archive keeps the group assignments of all four domain lists.

        The tr_domainlist_add trigger puts every imported domain into the
        Default group (0); the archived domainlist_by_group has to replace
        that for allow and deny entries alike. This import overwrites the
        group and domainlist tables and pihole.toml, test_teleporter_import
        below restores both from the ZIP exported earlier.
        """
        import io
        import json
        import sqlite3
        import tarfile
        import time
        import requests

        now = int(time.time())
        def entry(id, domain, type):
            return {"id": id, "domain": domain, "enabled": 1,
                    "date_added": now, "date_modified": now,
                    "comment": "v5 import test", "type": type}
        files = {
            "group.json": [
                {"id": 0, "enabled": 1, "name": "Default", "date_added": now,
                 "date_modified": now, "description": "The default group"},
                {"id": 1, "enabled": 1, "name": "iot", "date_added": now,
                 "date_modified": now, "description": None}],
            "whitelist.exact.json": [entry(9001, "allowiot.example", 0)],
            "whitelist.regex.json": [entry(9002, "allowre\\.example$", 2)],
            "blacklist.exact.json": [entry(9003, "denyiot.example", 1)],
            "blacklist.regex.json": [entry(9004, "denyre\\.example$", 3)],
            "domainlist_by_group.json": [
                {"group_id": 1, "domainlist_id": id}
                for id in (9001, 9002, 9003, 9004)],
            # The config migration warns if there is no legacy file to read
            "pihole-FTL.conf": b"# v5 import test\n",
        }
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, content in files.items():
                data = content if isinstance(content, bytes) else json.dumps(content).encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

        with open("/var/log/pihole/FTL.log", "r") as f:
            f.seek(0, 2)
            log_pos = f.tell()

        response = ftl.POST("/api/teleporter", None, AuthenticationMethods.HEADER,
                            {"file": ("pi-hole-teleporter.tar.gz", buf.getvalue(),
                                      "application/gzip")})
        assert response is not None and "domainlist_by_group.json" in response.get("files", []), \
            f"v5 Teleporter import failed: {response} {ftl.errors}"

        # The import is written before the reply, the restart follows it
        with sqlite3.connect("file:/etc/pihole/gravity.db?mode=ro", uri=True) as db:
            rows = db.execute("SELECT d.domain, group_concat(g.group_id) "
                              "FROM domainlist d JOIN domainlist_by_group g "
                              "ON g.domainlist_id = d.id WHERE d.id >= 9001 "
                              "GROUP BY d.id ORDER BY d.id").fetchall()
        expected = [("allowiot.example", "1"), ("allowre\\.example$", "1"),
                    ("denyiot.example", "1"), ("denyre\\.example$", "1")]
        assert rows == expected, f"domainlist groups after v5 import: {rows}"

        # Wait for the restarted FTL to serve the API again
        for _ in range(60):
            time.sleep(0.5)
            with open("/var/log/pihole/FTL.log", "r") as f:
                f.seek(log_pos)
                if "FTL started on" not in f.read():
                    continue
            try:
                r = requests.get("http://127.0.0.1/api/auth", timeout=2)
                if r.status_code in (200, 401):
                    return
            except requests.ConnectionError:
                continue
        pytest.fail("FTL did not come back after v5 teleporter import")

    def test_teleporter_import(self, openapi, ftl):
        """Re-import the teleporter ZIP archive exported during response tests.

        Teleporter import triggers an internal FTL restart (gravity
        database reload, exit code 22). We wait for FTL to come back
        afterwards so subsequent tests (auth, rate limiting) have a
        working API. Teleporter imports are the only API calls that
        restart FTL - password hashing (BALLOON-SHA256) and all other
        config changes are fully synchronous and do not restart FTL.
        """
        import time
        import requests

        archive = TestEndpointResponses._teleporter_archive
        if archive is None:
            pytest.skip("No teleporter archive captured during response tests")

        with ResponseVerifyer(ftl, openapi) as verifyer:
            errors = verifyer.verify_teleporter_zip(archive)
        assert errors == [], \
            "Teleporter import errors:\n" + \
            "\n".join(f"  - {e}" for e in errors)

        # Wait for FTL to complete its internal restart after teleporter import
        for _ in range(30):
            time.sleep(0.5)
            try:
                r = requests.get("http://127.0.0.1/api/auth", timeout=2)
                if r.status_code in (200, 401):
                    return
            except requests.ConnectionError:
                continue
        pytest.fail("FTL did not come back after teleporter import")
