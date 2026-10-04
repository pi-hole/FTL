"""
Pi-hole FTL per-client blocking decisions after group or list changes.

These tests send DNS queries and change the domain lists through the API, so
the file is named ``test_m_*`` to run *after* ``test_api.py``, which asserts
exact counts on the seed data. Every list change is undone at the end.

The test gravity database assigns MAC aa:bb:cc:dd:ee:ff to group 4, which
holds no lists, while the default group 0 denies regex[0-9].ftl. Blocked
answers are compared against gravity.ftl's, as earlier tests change the
blocking mode.

Usage:
    pytest test/api/test_m_client_policy.py -v
"""

import socket
import struct
import subprocess
import time
from urllib.parse import quote

FTL_URL = "http://127.0.0.1"
MAC_GROUP4 = "+ednsopt=65001:aabbccddeeff"


def _dig(name, source=None, *opts):
    """First line of a short dig answer from the given source address."""
    cmd = ["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", name]
    if source:
        cmd += ["-b", source]
    cmd += list(opts)
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    return out.splitlines()[0] if out else ""


def _blocked():
    """The answer a blocked A query gets in the current blocking mode"""
    answer = _dig("gravity.ftl")
    assert answer not in ("", "192.168.1.2"), answer
    return answer


def _tcp_query(sock, name):
    """Send an A query over an open TCP connection, return the first address."""
    msg = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
    msg += b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    msg += b"\0" + struct.pack(">HH", 1, 1)
    sock.sendall(struct.pack(">H", len(msg)) + msg)
    length = struct.unpack(">H", sock.recv(2))[0]
    reply = b""
    while len(reply) < length:
        reply += sock.recv(length - len(reply))
    if struct.unpack(">H", reply[6:8])[0] == 0:
        return ""
    return ".".join(str(b) for b in reply[-4:])


def _info_domains(api_session):
    r = api_session.get(f"{FTL_URL}/api/info/ftl", timeout=5)
    assert r.status_code == 200, r.text
    return r.json()["ftl"]["database"]["domains"]


def _wait_for(api_session, kind, enabled):
    """Wait until the reload shows the given number of enabled exact entries.

    /api/info/ftl reads these counters under the lock the whole reload holds,
    so seeing the new value means the reload has finished.
    """
    for _ in range(100):
        if _info_domains(api_session)[kind]["enabled"] == enabled:
            return
        time.sleep(0.1)
    raise AssertionError(f"lists not reloaded: {_info_domains(api_session)}")


def _put_allow(api_session, entry, enabled):
    url = f"{FTL_URL}/api/domains/allow/exact/{quote(entry['domain'], safe='')}"
    r = api_session.put(url, json={"comment": entry["comment"],
                                   "groups": entry["groups"],
                                   "enabled": enabled}, timeout=10)
    assert r.status_code == 200, f"PUT failed: {r.status_code} {r.text}"


class TestClientGroupChange:

    def test_cached_decision_follows_new_groups(self):
        """A domain blocked for the default group is re-checked once the
        client's MAC moves it into group 4"""
        assert _dig("regex5.ftl", "127.0.0.7") == _blocked()
        assert _dig("regex5.ftl", "127.0.0.7", MAC_GROUP4) == "192.168.2.3"

    def test_known_mac_beats_network_table(self):
        """The network table still maps 127.0.0.9 to aa:bb:cc:dd:ee:ff, the
        MAC the query carries has no client entry (default group)"""
        sql = "INSERT INTO network_addresses (network_id, ip) VALUES (0, '127.0.0.9');"
        subprocess.run(["./pihole-FTL", "sqlite3", "/etc/pihole/pihole-FTL.db", sql],
                       check=True, capture_output=True, timeout=10)
        assert _dig("regex5.ftl", "127.0.0.9", "+ednsopt=65001:020000000099") == _blocked()


class TestEmptyExactAllowlist:
    """Both checks need an exact allowlist without enabled entries"""

    def test_groups_and_workers_follow_changes(self, api_session):
        r = api_session.get(f"{FTL_URL}/api/domains/allow/exact", timeout=5)
        assert r.status_code == 200, r.text
        entries = [d for d in r.json()["domains"] if d["enabled"]]
        allowed = next(d for d in entries if d["domain"] == "allowed.ftl")
        before = _info_domains(api_session)["allowed"]["enabled"]
        denied = _info_domains(api_session)["denied"]["enabled"]
        deny_url = f"{FTL_URL}/api/domains/deny/exact/regex2.ftl"
        worker = None
        try:
            for entry in entries:
                _put_allow(api_session, entry, False)
            r = api_session.put(deny_url, json={"comment": "group 4 only",
                                                "groups": [4],
                                                "enabled": True}, timeout=10)
            assert r.status_code in (200, 201), r.text
            _wait_for(api_session, "allowed", before - len(entries))
            _wait_for(api_session, "denied", denied + 1)

            # regex2.ftl is allowed by a regex of the default group and
            # exactly denied for group 4, the client's group once its MAC
            # is known
            assert _dig("a.ftl", "127.0.0.8") == "192.168.1.1"
            assert _dig("regex2.ftl", "127.0.0.8", MAC_GROUP4) == _blocked()

            # A TCP worker forked now sees the empty exact allowlist.
            # allowed.ftl is in gravity and becomes exactly allowed again
            worker = socket.create_connection(("127.0.0.1", 53), timeout=5)
            assert _tcp_query(worker, "a.ftl") == "192.168.1.1"
            _put_allow(api_session, allowed, True)
            _wait_for(api_session, "allowed", before - len(entries) + 1)
            assert _tcp_query(worker, "allowed.ftl") == "192.168.1.4"
            assert _dig("allowed.ftl") == "192.168.1.4"
        finally:
            if worker is not None:
                worker.close()
            api_session.delete(deny_url, timeout=10)
            for entry in entries:
                _put_allow(api_session, entry, True)
            _wait_for(api_session, "allowed", before)
            _wait_for(api_session, "denied", denied)
