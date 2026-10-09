"""
Pi-hole FTL API tests -- password-protected Teleporter archives.

POST /api/teleporter/export returns the archive encrypted with a key derived
from the given password. POST /api/teleporter recognizes such an archive by its
content and needs the same password to import it.

Only the group table is imported, so the round-trip does not write pihole.toml
and leaves the write count checked by test_final.bats unchanged.

Usage:
    pytest test/api/test_n_teleporter_encryption.py -v
"""

import json

import pytest

from test_n_teleporter_validation import _log_end, _wait_for_restart

PASSWORD = "correct horse battery staple"
MAGIC = b"PIHOLETP"
IMPORT_GROUPS_ONLY = json.dumps({
    "config": False,
    "dhcp_leases": False,
    "gravity": {
        "group": True,
        "adlist": False,
        "adlist_by_group": False,
        "domainlist": False,
        "domainlist_by_group": False,
        "client": False,
        "client_by_group": False,
    },
})


@pytest.fixture(scope="module")
def encrypted(api_session, ftl_url):
    r = api_session.post(f"{ftl_url}/api/teleporter/export",
                         json={"password": PASSWORD}, timeout=30)
    assert r.status_code == 200, r.text
    return r


def _import(api_session, ftl_url, data, password=None):
    form = {"import": IMPORT_GROUPS_ONLY}
    if password is not None:
        form["password"] = password
    return api_session.post(f"{ftl_url}/api/teleporter", data=form, timeout=30,
                            files={"file": ("backup.zip.enc", data, "application/octet-stream")})


@pytest.mark.parametrize("body", [None, {}, {"password": ""}, {"Password": PASSWORD}],
                         ids=["no body", "empty object", "empty password", "wrong key case"])
def test_export_requires_password(api_session, ftl_url, body):
    """Without a usable password there is no export, encrypted or not."""
    r = api_session.post(f"{ftl_url}/api/teleporter/export", json=body, timeout=30)
    assert r.status_code == 400, r.text
    assert "error" in r.json()


def test_password_length_limit(api_session, ftl_url, encrypted):
    """Export and import share the CLI's limit, so every archive stays importable."""
    r = api_session.post(f"{ftl_url}/api/teleporter/export",
                         json={"password": "x" * 1025}, timeout=30)
    assert r.status_code == 400, r.text
    r = _import(api_session, ftl_url, encrypted.content, "x" * 1025)
    assert r.status_code == 400, r.text
    assert r.json()["error"]["message"] == "Password too long"


def test_long_password_round_trip(api_session, ftl_url):
    """A password at the limit is accepted and used in full."""
    password = "p" * 1024
    r = api_session.post(f"{ftl_url}/api/teleporter/export",
                         json={"password": password}, timeout=30)
    assert r.status_code == 200, r.text
    # A wrong password of the same length must fail, so the whole one is used
    r2 = _import(api_session, ftl_url, r.content, "p" * 1023 + "q")
    assert r2.json()["error"]["hint"] == "Wrong password or corrupted archive"
    pos = _log_end()
    r2 = _import(api_session, ftl_url, r.content, password)
    assert r2.status_code == 200, r2.text
    _wait_for_restart(pos)


def test_export_is_encrypted(encrypted):
    assert encrypted.headers["Content-Type"] == "application/octet-stream"
    assert 'filename="' in encrypted.headers["Content-Disposition"]
    assert encrypted.headers["Content-Disposition"].endswith('.zip.enc"')
    assert encrypted.content.startswith(MAGIC)
    # Nothing of the archive is readable without the password
    assert b"etc/pihole" not in encrypted.content
    assert b"PK\x03\x04" not in encrypted.content


def test_import_without_password(api_session, ftl_url, encrypted):
    r = _import(api_session, ftl_url, encrypted.content)
    assert r.status_code == 400, r.text
    assert r.json()["error"]["key"] == "password_required"


def test_import_wrong_password(api_session, ftl_url, encrypted):
    r = _import(api_session, ftl_url, encrypted.content, "wrong")
    assert r.status_code == 400, r.text
    assert r.json()["error"]["hint"] == "Wrong password or corrupted archive"


def test_import_tampered(api_session, ftl_url, encrypted):
    data = bytearray(encrypted.content)
    data[len(data) // 2] ^= 0x01
    r = _import(api_session, ftl_url, bytes(data), PASSWORD)
    assert r.status_code == 400, r.text
    assert r.json()["error"]["hint"] == "Wrong password or corrupted archive"


def test_import_round_trip(api_session, ftl_url, encrypted):
    pos = _log_end()
    r = _import(api_session, ftl_url, encrypted.content, PASSWORD)
    assert r.status_code == 200, r.text
    assert r.json()["files"] == ["etc/pihole/gravity.db->group"]
    _wait_for_restart(pos)
