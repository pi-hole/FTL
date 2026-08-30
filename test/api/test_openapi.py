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

    def test_teleporter_export_entry_names(self, ftl):
        """Exported archives must use the canonical etc/pihole/... entry names.

        The names are independent of PIHOLE_INSTALL_DIR and of the runtime
        files.gravity / files.database values, so that archives stay portable
        between differently configured installations and the import side
        (which matches fixed names) keeps accepting them.
        """
        import io
        import zipfile

        archive = ftl.GET("/api/teleporter", [], "application/zip",
                          AuthenticationMethods.HEADER)
        assert archive is not None, \
            "Teleporter export failed:\n" + \
            "\n".join(f"  - {e}" for e in ftl.errors)

        names = zipfile.ZipFile(io.BytesIO(archive)).namelist()
        for expected in ("etc/pihole/pihole.toml", "etc/pihole/gravity.db",
                         "etc/pihole/pihole-FTL.db"):
            assert expected in names, \
                f"Teleporter archive does not contain {expected}:\n" + \
                "\n".join(f"  - {n}" for n in names)
        leases = [n for n in names if n.endswith("dhcp.leases")]
        assert leases in ([], ["etc/pihole/dhcp.leases"]), \
            f"Teleporter archive stores DHCP leases under {leases}, " \
            "expected etc/pihole/dhcp.leases"

    def test_teleporter_import(self, openapi, ftl):
        """Re-import the teleporter ZIP archive exported during response tests.

        Teleporter import triggers an internal FTL restart (gravity
        database reload, exit code 22). We wait for FTL to come back
        afterwards so subsequent tests (auth, rate limiting) have a
        working API.  Note: this is the only API call that causes an
        FTL restart — password hashing (BALLOON-SHA256) and all other
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
