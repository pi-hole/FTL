"""
Pi-hole FTL API mutation tests -- PUT (create) and DELETE operations.

These tests verify that creating and deleting items via the API works
correctly.  Every test is self-contained: it creates a temporary item,
verifies it exists, deletes it, asserts 204, and verifies it is gone.

The file is named ``test_m_*`` so it runs alphabetically *after*
``test_api.py`` (which asserts exact counts on the seed data) but
*before* ``test_openapi.py`` and ``test_z_auth.py``.

Usage:
    pytest test/api/test_m_mutations.py -v
"""

import json
from urllib.parse import quote

import pytest

FTL_URL = "http://127.0.0.1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _j(response):
    """Return parsed JSON, stripping the volatile ``took`` field."""
    data = response.json()
    data.pop("took", None)
    return data


# ---------------------------------------------------------------------------
# DELETE groups
# ---------------------------------------------------------------------------

class TestDeleteGroups:

    def test_delete_group_returns_204(self, api_session):
        name = "_pytest_del_group"
        url = f"{FTL_URL}/api/groups/{name}"

        # Create
        r = api_session.put(url, json={"comment": "pytest temp"}, timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"

        # Verify exists
        r = api_session.get(url, timeout=5)
        assert r.status_code == 200
        groups = _j(r)["groups"]
        assert any(g["name"] == name for g in groups), \
            f"Group {name} not found after PUT"

        # Delete
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"
        assert r.content == b"", "Expected empty body on 204"

        # Verify gone
        r = api_session.get(url, timeout=5)
        assert r.status_code == 404 or _j(r).get("groups", []) == []

    def test_delete_nonexistent_group_returns_404(self, api_session):
        r = api_session.delete(
            f"{FTL_URL}/api/groups/_pytest_no_such_group", timeout=5)
        assert r.status_code == 404, \
            f"Expected 404, got {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# DELETE domains
# ---------------------------------------------------------------------------

class TestDeleteDomains:

    def test_delete_domain_returns_204(self, api_session):
        domain = "_pytest-del.example.com"
        url = f"{FTL_URL}/api/domains/allow/exact/{domain}"

        # Create
        r = api_session.put(url,
                            json={"comment": "pytest temp", "groups": [0],
                                  "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"

        # Verify exists
        r = api_session.get(url, timeout=5)
        assert r.status_code == 200
        domains = _j(r)["domains"]
        assert any(d["domain"] == domain for d in domains), \
            f"Domain {domain} not found after PUT"

        # Delete
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"
        assert r.content == b""

        # Verify gone
        r = api_session.get(url, timeout=5)
        assert r.status_code == 404 or _j(r).get("domains", []) == []

    def test_delete_nonexistent_domain_returns_404(self, api_session):
        r = api_session.delete(
            f"{FTL_URL}/api/domains/allow/exact/_pytest-nosuch.invalid",
            timeout=5)
        assert r.status_code == 404, \
            f"Expected 404, got {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# DELETE clients
# ---------------------------------------------------------------------------

class TestDeleteClients:

    def test_delete_client_returns_204(self, api_session):
        client = "192.168.255.250"
        url = f"{FTL_URL}/api/clients/{client}"

        # Create
        r = api_session.put(url,
                            json={"comment": "pytest temp", "groups": [0]},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"

        # Verify exists
        r = api_session.get(url, timeout=5)
        assert r.status_code == 200
        clients = _j(r)["clients"]
        assert any(c["client"] == client for c in clients), \
            f"Client {client} not found after PUT"

        # Delete
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"
        assert r.content == b""

        # Verify gone
        r = api_session.get(url, timeout=5)
        assert r.status_code == 404 or _j(r).get("clients", []) == []

    def test_delete_nonexistent_client_returns_404(self, api_session):
        r = api_session.delete(
            f"{FTL_URL}/api/clients/192.168.255.251", timeout=5)
        assert r.status_code == 404, \
            f"Expected 404, got {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# DELETE lists
# ---------------------------------------------------------------------------

class TestDeleteLists:

    def test_delete_list_returns_204(self, api_session):
        address = "https://pytest-temp.example.com/block.txt"
        encoded = quote(address, safe="")
        url = f"{FTL_URL}/api/lists/{encoded}"

        # Create
        r = api_session.put(f"{url}?type=block",
                            json={"comment": "pytest temp", "groups": [0],
                                  "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"

        # Verify exists
        r = api_session.get(f"{url}?type=block", timeout=5)
        assert r.status_code == 200
        lists = _j(r)["lists"]
        assert any(lst["address"] == address for lst in lists), \
            f"List {address} not found after PUT"

        # Delete
        r = api_session.delete(f"{url}?type=block", timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"
        assert r.content == b""

        # Verify gone
        r = api_session.get(f"{url}?type=block", timeout=5)
        assert r.status_code == 404 or _j(r).get("lists", []) == []

    def test_delete_nonexistent_list_returns_404(self, api_session):
        encoded = quote("https://no-such.invalid/block.txt", safe="")
        r = api_session.delete(
            f"{FTL_URL}/api/lists/{encoded}?type=block", timeout=5)
        assert r.status_code == 404, \
            f"Expected 404, got {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# DELETE config array items
# ---------------------------------------------------------------------------

class TestDeleteConfigArrayItem:

    def test_delete_config_item_returns_204(self, api_session):
        value = quote("192.168.255.99 pytest-temp-host", safe="")
        base = f"{FTL_URL}/api/config/dns/hosts"
        url = f"{base}/{value}"

        # Add item to array
        r = api_session.put(f"{url}?restart=false", timeout=10)
        assert r.status_code in (200, 201, 204), \
            f"PUT failed: {r.status_code} {r.text}"

        # Delete item from array
        r = api_session.delete(f"{url}?restart=false", timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"
        assert r.content == b""

    def test_delete_nonexistent_config_item_returns_404(self, api_session):
        value = quote("192.168.255.99 no_such_host", safe="")
        r = api_session.delete(
            f"{FTL_URL}/api/config/dns/hosts/{value}?restart=false",
            timeout=5)
        assert r.status_code == 404, \
            f"Expected 404, got {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# DELETE network devices (404 only -- deleting real devices would break
# other tests)
# ---------------------------------------------------------------------------

class TestDeleteNetworkDevice:

    def test_delete_nonexistent_device_returns_404(self, api_session):
        r = api_session.delete(
            f"{FTL_URL}/api/network/devices/99999", timeout=5)
        assert r.status_code == 404, \
            f"Expected 404, got {r.status_code} {r.text}"


# ---------------------------------------------------------------------------
# DELETE info messages (404 only -- cannot easily create a message to delete)
# ---------------------------------------------------------------------------

class TestDeleteInfoMessage:

    def test_delete_nonexistent_message_returns_404(self, api_session):
        r = api_session.delete(
            f"{FTL_URL}/api/info/messages/99999", timeout=5)
        assert r.status_code == 404, \
            f"Expected 404, got {r.status_code} {r.text}"


# ===========================================================================
# PUT (create/replace) tests
# ===========================================================================


# ---------------------------------------------------------------------------
# PUT groups
# ---------------------------------------------------------------------------

class TestPutGroups:

    def test_put_creates_group(self, api_session):
        """PUT /api/groups/{name} creates a new group and returns it."""
        name = "_pytest_put_group"
        url = f"{FTL_URL}/api/groups/{name}"

        r = api_session.put(url,
                            json={"comment": "pytest created", "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"
        data = _j(r)
        groups = data["groups"]
        assert len(groups) == 1
        assert groups[0]["name"] == name
        assert groups[0]["comment"] == "pytest created"
        assert groups[0]["enabled"] is True

        # Clean up
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204

    def test_put_replaces_group(self, api_session):
        """PUT to an existing group replaces its attributes."""
        name = "_pytest_replace_group"
        url = f"{FTL_URL}/api/groups/{name}"

        # Create
        r = api_session.put(url,
                            json={"comment": "original", "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201)

        # Replace
        r = api_session.put(url,
                            json={"comment": "replaced", "enabled": False},
                            timeout=10)
        assert r.status_code == 200
        groups = _j(r)["groups"]
        assert groups[0]["comment"] == "replaced"
        assert groups[0]["enabled"] is False

        # Clean up
        api_session.delete(url, timeout=10)


# ---------------------------------------------------------------------------
# PUT domains
# ---------------------------------------------------------------------------

class TestPutDomains:

    def test_put_creates_domain(self, api_session):
        domain = "_pytest-put.example.com"
        url = f"{FTL_URL}/api/domains/deny/exact/{domain}"

        r = api_session.put(url,
                            json={"comment": "pytest created", "groups": [0],
                                  "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"
        data = _j(r)
        domains = data["domains"]
        assert len(domains) == 1
        assert domains[0]["domain"] == domain
        assert domains[0]["type"] == "deny"
        assert domains[0]["kind"] == "exact"
        assert domains[0]["comment"] == "pytest created"

        # Clean up
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204

    def test_put_replaces_domain(self, api_session):
        domain = "_pytest-replace.example.com"
        url = f"{FTL_URL}/api/domains/allow/exact/{domain}"

        r = api_session.put(url,
                            json={"comment": "original", "groups": [0],
                                  "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201)

        r = api_session.put(url,
                            json={"comment": "replaced", "groups": [0],
                                  "enabled": False},
                            timeout=10)
        assert r.status_code == 200
        domains = _j(r)["domains"]
        assert domains[0]["comment"] == "replaced"
        assert domains[0]["enabled"] is False

        # Clean up
        api_session.delete(url, timeout=10)

    def test_put_punycode_domain(self, api_session):
        """Punycode domains with IDNA2008-disallowed chars must be accepted.

        Regression test for https://github.com/pi-hole/FTL/issues/2837
        xn--4ca0bs45142c.com encodes äöü😀.com — the emoji makes libidn2 reject
        it under IDNA2008 even though the ASCII punycode form is a perfectly
        valid DNS name.
        """
        domain = "xn--4ca0bs45142c.com"
        url = f"{FTL_URL}/api/domains/deny/exact/{domain}"

        r = api_session.put(url,
                            json={"comment": "pytest punycode", "groups": [0],
                                  "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), \
            f"PUT punycode domain failed: {r.status_code} {r.text}"
        data = _j(r)
        domains = data["domains"]
        assert len(domains) == 1
        assert domains[0]["domain"] == domain
        assert domains[0]["type"] == "deny"
        assert domains[0]["kind"] == "exact"

        # Clean up
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204


# ---------------------------------------------------------------------------
# PUT clients
# ---------------------------------------------------------------------------

class TestPutClients:

    def test_put_creates_client(self, api_session):
        client = "192.168.255.240"
        url = f"{FTL_URL}/api/clients/{client}"

        r = api_session.put(url,
                            json={"comment": "pytest created", "groups": [0]},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"
        data = _j(r)
        clients = data["clients"]
        assert len(clients) == 1
        assert clients[0]["client"] == client
        assert clients[0]["comment"] == "pytest created"

        # Clean up
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204

    def test_put_replaces_client(self, api_session):
        client = "192.168.255.241"
        url = f"{FTL_URL}/api/clients/{client}"

        r = api_session.put(url,
                            json={"comment": "original", "groups": [0]},
                            timeout=10)
        assert r.status_code in (200, 201)

        r = api_session.put(url,
                            json={"comment": "replaced", "groups": [0]},
                            timeout=10)
        assert r.status_code == 200
        clients = _j(r)["clients"]
        assert clients[0]["comment"] == "replaced"

        # Clean up
        api_session.delete(url, timeout=10)


# ---------------------------------------------------------------------------
# PUT lists
# ---------------------------------------------------------------------------

class TestPutLists:

    def test_put_creates_list(self, api_session):
        address = "https://pytest-put.example.com/block.txt"
        encoded = quote(address, safe="")
        url = f"{FTL_URL}/api/lists/{encoded}"

        r = api_session.put(f"{url}?type=block",
                            json={"comment": "pytest created", "groups": [0],
                                  "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"
        data = _j(r)
        lists = data["lists"]
        assert len(lists) == 1
        assert lists[0]["address"] == address
        assert lists[0]["type"] == "block"
        assert lists[0]["comment"] == "pytest created"

        # Clean up
        r = api_session.delete(f"{url}?type=block", timeout=10)
        assert r.status_code == 204

    def test_put_replaces_list(self, api_session):
        address = "https://pytest-replace.example.com/allow.txt"
        encoded = quote(address, safe="")
        url = f"{FTL_URL}/api/lists/{encoded}"

        r = api_session.put(f"{url}?type=allow",
                            json={"comment": "original", "groups": [0],
                                  "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201)

        r = api_session.put(f"{url}?type=allow",
                            json={"comment": "replaced", "groups": [0],
                                  "enabled": False},
                            timeout=10)
        assert r.status_code == 200
        lists = _j(r)["lists"]
        assert lists[0]["comment"] == "replaced"
        assert lists[0]["enabled"] is False

        # Clean up
        api_session.delete(f"{url}?type=allow", timeout=10)


# ===========================================================================
# Error-case tests
# ===========================================================================


class TestPutErrors:

    def test_put_group_without_body_returns_400(self, api_session):
        """PUT with no JSON body should return 400."""
        r = api_session.put(
            f"{FTL_URL}/api/groups/_pytest_err_nobody",
            data=b"", timeout=5)
        assert r.status_code == 400, \
            f"Expected 400, got {r.status_code} {r.text}"

    def test_put_domain_invalid_type_returns_400(self, api_session):
        """PUT domain with invalid type/kind in path should return 400."""
        r = api_session.put(
            f"{FTL_URL}/api/domains/invalid/invalid/_pytest-err.example.com",
            json={"comment": "err"},
            timeout=5)
        assert r.status_code == 400, \
            f"Expected 400, got {r.status_code} {r.text}"

    def test_put_and_delete_group_via_item_query(self, api_session):
        """A name browsers strip from the path is carried by ?item=."""
        name = "."
        url = f"{FTL_URL}/api/groups?item={quote(name)}"

        r = api_session.put(url,
                            json={"comment": "pytest dot", "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"
        groups = _j(r)["groups"]
        assert len(groups) == 1
        assert groups[0]["name"] == name

        # Clean up
        r = api_session.delete(url, timeout=10)
        assert r.status_code == 204

    def test_put_group_with_agreeing_item_query(self, api_session):
        """The path and ?item= may both be given if they are identical."""
        name = "_pytest_agree_group"
        url = f"{FTL_URL}/api/groups/{name}?item={name}"

        r = api_session.put(url,
                            json={"comment": "pytest agree", "enabled": True},
                            timeout=10)
        assert r.status_code in (200, 201), f"PUT failed: {r.status_code} {r.text}"
        assert _j(r)["groups"][0]["name"] == name

        # Clean up
        r = api_session.delete(f"{FTL_URL}/api/groups/{name}", timeout=10)
        assert r.status_code == 204

    def test_put_group_with_conflicting_item_query_returns_400(self, api_session):
        """A path item disagreeing with ?item= is rejected, not resolved."""
        r = api_session.put(
            f"{FTL_URL}/api/groups/_pytest_path_group?item=_pytest_query_group",
            json={"comment": "err"},
            timeout=5)
        assert r.status_code == 400, \
            f"Expected 400, got {r.status_code} {r.text}"


# ===========================================================================
# Batch delete tests
# ===========================================================================


class TestBatchDeleteGroups:

    def test_batch_delete_groups(self, api_session):
        names = ["_pytest_batch_g1", "_pytest_batch_g2"]
        for name in names:
            r = api_session.put(f"{FTL_URL}/api/groups/{name}",
                                json={"comment": "batch test"}, timeout=10)
            assert r.status_code in (200, 201), f"PUT {name} failed: {r.status_code}"

        r = api_session.post(
            f"{FTL_URL}/api/groups:batchDelete",
            json=[{"item": n} for n in names],
            timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"

        for name in names:
            r = api_session.get(f"{FTL_URL}/api/groups/{name}", timeout=5)
            assert r.status_code == 404 or _j(r).get("groups", []) == [], \
                f"Group {name} still exists after batch delete"


class TestBatchDeleteDomains:

    def test_batch_delete_domains(self, api_session):
        items = [
            {"domain": "_pytest-batch1.example.com", "type": "allow", "kind": "exact"},
            {"domain": "_pytest-batch2.example.com", "type": "deny", "kind": "exact"},
        ]
        for it in items:
            r = api_session.put(
                f"{FTL_URL}/api/domains/{it['type']}/{it['kind']}/{it['domain']}",
                json={"comment": "batch test", "groups": [0], "enabled": True},
                timeout=10)
            assert r.status_code in (200, 201), \
                f"PUT {it['domain']} failed: {r.status_code}"

        r = api_session.post(
            f"{FTL_URL}/api/domains:batchDelete",
            json=[{"item": it["domain"], "type": it["type"], "kind": it["kind"]}
                  for it in items],
            timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"

        for it in items:
            r = api_session.get(
                f"{FTL_URL}/api/domains/{it['type']}/{it['kind']}/{it['domain']}",
                timeout=5)
            assert r.status_code == 404 or _j(r).get("domains", []) == [], \
                f"Domain {it['domain']} still exists after batch delete"


class TestBatchDeleteClients:

    def test_batch_delete_clients(self, api_session):
        clients = ["192.168.255.230", "192.168.255.231"]
        for c in clients:
            r = api_session.put(f"{FTL_URL}/api/clients/{c}",
                                json={"comment": "batch test", "groups": [0]},
                                timeout=10)
            assert r.status_code in (200, 201), f"PUT {c} failed: {r.status_code}"

        r = api_session.post(
            f"{FTL_URL}/api/clients:batchDelete",
            json=[{"item": c} for c in clients],
            timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"

        for c in clients:
            r = api_session.get(f"{FTL_URL}/api/clients/{c}", timeout=5)
            assert r.status_code == 404 or _j(r).get("clients", []) == [], \
                f"Client {c} still exists after batch delete"


class TestBatchDeleteLists:

    def test_batch_delete_lists(self, api_session):
        items = [
            {"address": "https://pytest-batch1.example.com/list.txt", "type": "block"},
            {"address": "https://pytest-batch2.example.com/list.txt", "type": "block"},
        ]
        for it in items:
            encoded = quote(it["address"], safe="")
            r = api_session.put(
                f"{FTL_URL}/api/lists/{encoded}?type={it['type']}",
                json={"comment": "batch test", "groups": [0], "enabled": True},
                timeout=10)
            assert r.status_code in (200, 201), \
                f"PUT {it['address']} failed: {r.status_code}"

        r = api_session.post(
            f"{FTL_URL}/api/lists:batchDelete",
            json=[{"item": it["address"], "type": it["type"]} for it in items],
            timeout=10)
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"

        for it in items:
            encoded = quote(it["address"], safe="")
            r = api_session.get(
                f"{FTL_URL}/api/lists/{encoded}?type={it['type']}", timeout=5)
            assert r.status_code == 404 or _j(r).get("lists", []) == [], \
                f"List {it['address']} still exists after batch delete"


# ===========================================================================
# DNS blocking toggle
# ===========================================================================


class TestDNSBlockingToggle:

    def test_disable_and_reenable_blocking(self, api_session):
        """POST /api/dns/blocking toggles blocking on and off."""
        # Disable
        r = api_session.post(f"{FTL_URL}/api/dns/blocking",
                             json={"blocking": False}, timeout=10)
        assert r.status_code == 200, f"Disable failed: {r.status_code} {r.text}"
        data = _j(r)
        assert data["blocking"] == "disabled"

        # Verify via GET
        data = _j(api_session.get(f"{FTL_URL}/api/dns/blocking", timeout=5))
        assert data["blocking"] == "disabled"

        # Re-enable
        r = api_session.post(f"{FTL_URL}/api/dns/blocking",
                             json={"blocking": True}, timeout=10)
        assert r.status_code == 200, f"Enable failed: {r.status_code} {r.text}"
        data = _j(r)
        assert data["blocking"] == "enabled"

        # Verify via GET
        data = _j(api_session.get(f"{FTL_URL}/api/dns/blocking", timeout=5))
        assert data["blocking"] == "enabled"


# ===========================================================================
# Config PATCH round-trip
# ===========================================================================


class TestConfigPatchRoundTrip:

    def test_patch_bool_config_round_trip(self, api_session):
        """PATCH a boolean config value, verify, then restore."""
        url = f"{FTL_URL}/api/config/dns/blockESNI"

        # Read original
        original = _j(api_session.get(url, timeout=5))
        orig_val = original["config"]["dns"]["blockESNI"]

        # Change to opposite
        new_val = not orig_val
        r = api_session.patch(url,
                              json={"config": {"dns": {"blockESNI": new_val}}},
                              timeout=20)
        assert r.status_code == 200, f"PATCH failed: {r.status_code} {r.text}"
        assert _j(r)["config"]["dns"]["blockESNI"] == new_val

        # Verify via GET
        data = _j(api_session.get(url, timeout=5))
        assert data["config"]["dns"]["blockESNI"] == new_val

        # Restore
        r = api_session.patch(url,
                              json={"config": {"dns": {"blockESNI": orig_val}}},
                              timeout=20)
        assert r.status_code == 200
        assert _j(r)["config"]["dns"]["blockESNI"] == orig_val

    def test_patch_integer_config_round_trip(self, api_session):
        """PATCH an integer config value, verify, then restore."""
        url = f"{FTL_URL}/api/config/dns/blockTTL"

        # Read original
        original = _j(api_session.get(url, timeout=5))
        orig_val = original["config"]["dns"]["blockTTL"]

        # Change
        new_val = orig_val + 10
        r = api_session.patch(url,
                              json={"config": {"dns": {"blockTTL": new_val}}},
                              timeout=20)
        assert r.status_code == 200, f"PATCH failed: {r.status_code} {r.text}"
        assert _j(r)["config"]["dns"]["blockTTL"] == new_val

        # Verify via GET
        data = _j(api_session.get(url, timeout=5))
        assert data["config"]["dns"]["blockTTL"] == new_val

        # Restore
        r = api_session.patch(url,
                              json={"config": {"dns": {"blockTTL": orig_val}}},
                              timeout=20)
        assert r.status_code == 200
        assert _j(r)["config"]["dns"]["blockTTL"] == orig_val
