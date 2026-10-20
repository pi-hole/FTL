"""
Pi-hole FTL cluster API integration tests.

A cluster needs several Pi-holes, but the part worth guarding does not: a peer
authenticates with a signature rather than a session, and a single node can be
asked to accept or refuse one. These tests speak the peer protocol to a live
FTL and check what it does with a good signature, a bad one, a replayed one and
one that arrives too late - and what comes back in the answer.

Switching clustering on restarts FTL, which ends every session and resets what
the counters in test_api.py expect - hence the `y` in the name. Like the `s` and
`z` files, this one runs after the tests that need an undisturbed instance.

Usage:
    pytest test/api/test_y_cluster.py -v
"""

import hashlib
import hmac
import http.server
import json
import os
import socket
import sqlite3
import subprocess
import threading
import time

import pytest
import requests
import urllib3

# The certificate is FTL's own, and what is being checked here is the body
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FTL_URL = "http://127.0.0.1"

# Credentials only ever cross an encrypted connection, so the test that checks
# they do not come back has to ask over one - over http the answer withholds
# them whatever the code does, and the test would pass without meaning anything
FTL_URL_TLS = "https://127.0.0.1"

SECRET_FILE = "/etc/pihole/cluster_secret"

# Mirrors src/cluster/auth.{c,h}. Kept here rather than derived, so that a
# change to the wire format has to be made twice on purpose
SIG_VERSION = "FTLCLUSTER1"
REQUEST_KEY = "FTL cluster request v1"
RESPONSE_KEY = "FTL cluster response v1"
ANY_NODE = "*"
SIG_WINDOW = 30

HDR_FROM = "X-FTL-Cluster"
HDR_TO = "X-FTL-Cluster-To"
HDR_SEQ = "X-FTL-Cluster-Seq"
HDR_SIG = "X-FTL-Cluster-Sig"

# Any well-formed identity that is not this node's
OTHER_NODE = "aaaaaaaaaaaaaaaa"

# The identity of the stand-in peer below. Below any identity FTL mints, so
# this node is the one that hands over a starting point both of them hold
FAKE_NODE = "0000000000000001"

# What the rest of the suite logs in with, and what this file sets while it runs
PASSWORD = "ABC"


def _answering(session):
    try:
        return session.get(f"{FTL_URL}/api/auth", timeout=2).status_code in (200, 401)
    except requests.RequestException:
        return False


def _wait_for_ftl(session, timeout=90):
    """Waits for the API to answer."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _answering(session):
            return True
        time.sleep(1)
    return False


def _wait_for_restart(session, timeout=90):
    """Waits for a restart to have happened, which is not the same as waiting
    for an answer.

    `FLAG_RESTART_FTL` sends the signal only after the response has been
    written, so the daemon goes on answering for about a second. Watching for
    the first 200 reads the process that is about to die, and everything after
    it - the cluster secret, this node's identity - is then read too early and
    found missing. Wait for it to go away, then for it to come back."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _answering(session):
            break
        time.sleep(0.2)

    return _wait_for_ftl(session, timeout)


def _relogin(session, password=None):
    """Takes a fresh session. Anything that touches a credential carries
    FLAG_INVALIDATE_SESSIONS, and this session is shared with every other test
    in the run - leaving it dead would fail all of them, somewhere else."""
    r = session.post(f"{FTL_URL}/api/auth",
                     json={"password": PASSWORD if password is None else password}, timeout=10)
    valid = r.json().get("session", {})
    sid = valid.get("sid")
    if sid:
        session.headers["X-FTL-SID"] = sid
    else:
        session.headers.pop("X-FTL-SID", None)

    # A node with no password answers valid with no SID, which is a working
    # session rather than a failure
    return bool(sid) or valid.get("valid") is True


def _j(response):
    try:
        return response.json()
    except ValueError:
        pytest.fail(f"Not JSON: {response.text[:200]}")


def _sign(secret, method, uri, sender, recipient, seq, body):
    key = hmac.new(secret.encode(), REQUEST_KEY.encode(), hashlib.sha256).digest()
    bodyhash = hashlib.sha256(body.encode()).hexdigest()
    canonical = "\n".join([SIG_VERSION, method, uri, sender, recipient, str(seq), bodyhash])
    return hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()


def _headers(secret, method, uri, recipient, seq=None, body="", sender=OTHER_NODE):
    seq = int(time.time() * 1e6) if seq is None else seq
    return {
        HDR_FROM: sender,
        HDR_TO: recipient,
        HDR_SEQ: str(seq),
        HDR_SIG: _sign(secret, method, uri, sender, recipient, seq, body),
    }


def _read_secret():
    try:
        with open(SECRET_FILE, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


class _FakePeer(http.server.BaseHTTPRequestHandler):
    """A second member that never configured anything, so the node under test
    hands it its configuration - the one path that builds the cluster document
    without a connection behind it."""

    pushes = []
    node_id = ""
    node_url = ""
    # The item stamps it publishes, and whether its fingerprint moves with
    # every poll - which has the node compare what it holds against it again
    items = {}
    hash_moves = False
    polls = 0

    def log_message(self, *args):
        pass

    def _answer(self, document):
        secret = _read_secret()
        seq = self.headers.get(HDR_SEQ, "")
        if not secret or not seq:
            self.send_response(500)
            self.end_headers()
            return
        body = json.dumps(document).encode()
        key = hmac.new(secret.encode(), RESPONSE_KEY.encode(), hashlib.sha256).digest()
        canonical = "\n".join([SIG_VERSION + "-R", FAKE_NODE, seq,
                               hashlib.sha256(body).hexdigest()])
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(HDR_SIG, hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest())
        self.send_header("X-FTL-Cluster-By", FAKE_NODE)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.path.startswith("/api/cluster/status"):
            self.send_response(404)
            self.end_headers()
            return
        sender = self.headers.get(HDR_FROM, "")
        _FakePeer.polls += 1
        confhash = f"{_FakePeer.polls:016x}" if _FakePeer.hash_moves else "0000000000000000"
        self._answer({"cluster": {
            "enabled": True,
            "node": {
                "name": "fake", "id": FAKE_NODE, "time": time.time(), "interval": 10,
                "resolving": True, "vip_capable": False,
                "dhcp": {"active": False, "failover": False, "capable": False,
                         "configured": False},
                "vip": {"address": "", "held": False},
                "sync": {
                    "config": {"changed": 0, "hash": confhash, "credentials": "",
                               "accepts_credentials": False, "wants_credentials": False,
                               "pinned": "", "pinned_credentials": "",
                               "items": _FakePeer.items},
                    "gravity": {"changed": 0, "hash": "", "owed": False},
                },
            },
            "peers": [{"id": sender, "url": _FakePeer.node_url, "reachable": True,
                       "last_seen": time.time()}],
        }})

    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        _FakePeer.pushes.append((self.path, body))
        self._answer({"config": {}})


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _patch(api_session, body, expect_restart=False):
    """One configuration change, and a check that it happened.

    Nothing here is allowed to fail quietly: a fixture that swallows a refused
    PATCH leaves the tests skipping over a node that was never set up, and
    reports it as a pass."""
    try:
        r = api_session.patch(f"{FTL_URL}/api/config", json={"config": body}, timeout=25)
        status = r.status_code
    except requests.RequestException:
        # A setting that restarts FTL can take the answer with it
        status = None

    if expect_restart:
        assert _wait_for_restart(api_session), "FTL did not come back"
    assert status in (None, 200), f"PATCH {body} answered {status}"


def _push(config, changed):
    """The body a peer hands this node: items, and when each was changed."""
    return json.dumps({"config": config, "changed": changed})


def _signed_patch(addressed, body):
    uri = "/api/config"
    headers = _headers(addressed["secret"], "PATCH", uri, addressed["id"], body=body)
    headers["Content-Type"] = "application/json"
    return requests.patch(f"{FTL_URL}{uri}", headers=headers, data=body, timeout=20)


def _disk(cluster):
    """misc.check.disk, once this node holds a version of it. Before the first
    round dated it, any push is newer than what is here."""
    deadline = time.time() + 60
    while time.time() < deadline:
        status = _j(cluster["session"].get(f"{FTL_URL}/api/cluster/status", timeout=10))
        items = status["cluster"]["node"]["sync"]["config"].get("items", {})
        if items.get("misc.check.disk", 0) >= 1:
            break
        time.sleep(1)
    else:
        pytest.fail("this node never dated misc.check.disk")

    r = cluster["session"].get(f"{FTL_URL}/api/config/misc/check/disk", timeout=10)
    return _j(r)["config"]["misc"]["check"]["disk"]


@pytest.fixture(scope="module")
def cluster(api_session):
    """Switches clustering on, sets a password, and puts both back afterwards.

    The password is not incidental. With `webserver.api.pwhash` empty,
    `check_client_auth()` answers every request with `API_AUTH_EMPTYPASS` and
    serves it - so a request carrying a wrong, tampered or replayed signature
    comes back 200, and every refusal below would be asserting nothing. FTL's
    own suite runs password-less at this point, which is the state this file has
    to create for itself, exactly as `test_s_auth_stress.py` does.

    Each change is its own request, and each answer is checked. Not because one
    document could not carry both - it can - but so that a step that is refused
    says which one it was. An earlier version put them together and swallowed
    the answer, and a node that was never set up then produced twelve skipped
    tests and a green file.
    """
    # A node with no password answers /api/auth as a valid session
    no_password = _j(api_session.get(f"{FTL_URL}/api/auth", timeout=10))
    no_password = no_password.get("session", {}).get("valid") is True

    if no_password:
        _patch(api_session, {"webserver": {"api": {"password": PASSWORD}}})
        assert _relogin(api_session), "could not log in with the password just set"

    before = _j(api_session.get(f"{FTL_URL}/api/config/cluster", timeout=10))
    before = before.get("config", {}).get("cluster", {})
    was_enabled = before.get("enabled", False)
    was_members = before.get("members", [])
    was_credentials = before.get("sync", {}).get("credentials", True)

    fake = None
    if not was_enabled:
        # A second member that answers like a node with no configuration, so
        # this node pushes its own to it
        self_url = FTL_URL.replace("http://", "https://")
        _FakePeer.pushes = []
        _FakePeer.node_url = self_url
        fake = http.server.ThreadingHTTPServer(("127.0.0.1", _free_port()), _FakePeer)
        threading.Thread(target=fake.serve_forever, daemon=True).start()

        # A member list as well as the switch: a node with nobody to talk to
        # does not start the cluster thread at all, and so never mints the
        # identity these tests address it by. The stand-in peer speaks http,
        # which credentials never cross
        _patch(api_session, {"cluster": {
            "enabled": True,
            "members": [self_url, f"http://127.0.0.1:{fake.server_address[1]}"],
            "sync": {"credentials": False},
        }}, expect_restart=True)
        assert _relogin(api_session), "could not log in after the restart"

    # The secret is written and the identity minted by the cluster thread, not
    # by the request that switched clustering on, so both appear a moment after
    # the daemon is answering again. Reading them straight away finds neither,
    # and every test that needs one would skip while the file reported green
    node_id = ""
    deadline = time.time() + 60
    while time.time() < deadline:
        status = _j(api_session.get(f"{FTL_URL}/api/cluster/status", timeout=10))
        node_id = status.get("cluster", {}).get("node", {}).get("id", "") or ""
        if node_id:
            break
        time.sleep(2)

    assert node_id, ("this node has no cluster identity, so the cluster thread never started - "
                     "the signature tests would all skip and this file would report green")

    # What a peer must never be handed back. Read rather than planted as a
    # canary: setting one would be another write for test_final.bats to account
    # for, and the real hash is a better thing to look for than an invented one
    pwhash = _j(api_session.get(f"{FTL_URL}/api/config/webserver/api/pwhash", timeout=10))
    pwhash = pwhash.get("config", {}).get("webserver", {}).get("api", {}).get("pwhash", "")

    # Not read leniently. A node with an identity has a running cluster thread,
    # and that thread writes the secret before it mints one - so an absent file
    # here is something wrong, not something to step around
    secret = None
    try:
        with open(SECRET_FILE, encoding="utf-8") as handle:
            secret = handle.read().strip()
    except PermissionError:
        # ...except for the one case that is somebody else's business: a run
        # that is not the user FTL writes as can check everything here but the
        # signatures
        pass
    except FileNotFoundError:
        raise AssertionError(
            f"{SECRET_FILE} is missing although this node has an identity ({node_id})"
        ) from None

    assert secret is None or secret, f"{SECRET_FILE} is empty"

    yield {"secret": secret, "id": node_id, "pwhash": pwhash, "fake": fake, "session": api_session}

    # Put back what was found, member list included - emptying it would be this
    # file deciding the configuration of a node it was only visiting
    if not was_enabled:
        _patch(api_session, {"cluster": {"enabled": False, "members": was_members,
                                         "sync": {"credentials": was_credentials}}},
               expect_restart=True)
        _relogin(api_session)
        fake.shutdown()
        fake.server_close()

    if no_password:
        _patch(api_session, {"webserver": {"api": {"password": ""}}})
        _relogin(api_session, "")


@pytest.fixture()
def signed(cluster):
    """As above, but skips outright when nothing can be signed."""
    if not cluster["secret"]:
        pytest.skip(f"Cannot read {SECRET_FILE}")
    return cluster


@pytest.fixture()
def addressed(signed):
    """For the requests that have to name this node rather than any node."""
    if not signed["id"]:
        pytest.skip("This node has no cluster identity yet")
    return signed


# ---------------------------------------------------------------------------
# The status document
# ---------------------------------------------------------------------------

class TestClusterJoin:
    """Before any test switches clustering on: a node in a cluster refuses to
    join another one before it looks at the pin."""

    def test_join_without_a_pin_is_refused_before_connecting(self, api_session):
        """Without a pin or cluster.tls.ca nothing checks the other node's
        certificate, so the password must not be sent at all."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.5)
        try:
            port = listener.getsockname()[1]
            r = api_session.post(f"{FTL_URL_TLS}/api/cluster/join",
                                 json={"url": f"https://127.0.0.1:{port}", "password": "x"},
                                 timeout=30, verify=False)
            assert r.status_code == 400, r.text[:300]
            assert "pin" in _j(r)["error"]["hint"], r.text[:300]
            with pytest.raises(socket.timeout):
                listener.accept()
        finally:
            listener.close()


class TestClusterStatus:

    def test_status_is_well_formed(self, api_session):
        """Answered on a node that is in no cluster, and answered fully."""
        data = _j(api_session.get(f"{FTL_URL}/api/cluster/status", timeout=10))
        assert "cluster" in data, json.dumps(data)[:300]
        cluster = data["cluster"]
        for key in ("enabled", "node", "peers"):
            assert key in cluster, f"{key} missing: {json.dumps(cluster)[:300]}"
        assert isinstance(cluster["peers"], list)

    def test_node_reports_what_it_pins(self, cluster, api_session):
        """An item pinned through the environment can never be synchronized, so
        every node says which of its items are - the page has no other way to
        explain a difference that never closes."""
        data = _j(api_session.get(f"{FTL_URL}/api/cluster/status", timeout=10))
        conf = data["cluster"]["node"]["sync"]["config"]
        assert "pinned" in conf
        assert isinstance(conf["pinned"], str)
        assert isinstance(conf["refused"], str)
        assert "wants_credentials" in conf
        assert "accepts_credentials" in conf

    def test_node_reports_conflicts(self, cluster, api_session):
        """Two DHCP servers or two holders of the virtual IP are shown on the
        page of the node that sees them. This node serves neither."""
        data = _j(api_session.get(f"{FTL_URL}/api/cluster/status", timeout=10))
        node = data["cluster"]["node"]
        assert node["dhcp"]["conflict"] is False, json.dumps(node["dhcp"])
        assert node["vip"]["conflict"] is False, json.dumps(node["vip"])

    def test_lists_say_whether_a_rebuild_is_owed(self, cluster, api_session):
        """The list fingerprint names the tables on disk, which after a pull are
        the peer's - so it cannot say whether this node has built anything from
        them. This flag can."""
        data = _j(api_session.get(f"{FTL_URL}/api/cluster/status", timeout=10))
        gravity = data["cluster"]["node"]["sync"]["gravity"]
        assert "owed" in gravity
        assert isinstance(gravity["owed"], bool)


# ---------------------------------------------------------------------------
# What a signature does and does not open
# ---------------------------------------------------------------------------

class TestClusterSignature:

    def test_valid_signature_is_accepted_without_a_session(self, signed):
        """This is the whole authentication story between nodes: no session, no
        cookie, nothing on the wire that can be replayed elsewhere."""
        uri = "/api/cluster/status"
        r = requests.get(f"{FTL_URL}{uri}",
                         headers=_headers(signed["secret"], "GET", uri, ANY_NODE),
                         timeout=10)
        assert r.status_code == 200, r.text[:200]

    def test_wrong_secret_is_refused(self, signed):
        uri = "/api/cluster/status"
        r = requests.get(f"{FTL_URL}{uri}",
                         headers=_headers("not-the-secret-at-all", "GET", uri, ANY_NODE),
                         timeout=10)
        assert r.status_code == 401, r.text[:200]

    def test_tampered_signature_is_refused(self, signed):
        uri = "/api/cluster/status"
        headers = _headers(signed["secret"], "GET", uri, ANY_NODE)
        # One hex digit, which is the whole point of a MAC
        headers[HDR_SIG] = ("0" if headers[HDR_SIG][0] != "0" else "1") + headers[HDR_SIG][1:]
        r = requests.get(f"{FTL_URL}{uri}", headers=headers, timeout=10)
        assert r.status_code == 401, r.text[:200]

    def test_signature_of_another_uri_is_refused(self, signed):
        """The URI is signed, so a signature taken for one endpoint does not
        open another."""
        headers = _headers(signed["secret"], "GET", "/api/cluster/lists", ANY_NODE)
        r = requests.get(f"{FTL_URL}/api/cluster/status", headers=headers, timeout=10)
        assert r.status_code == 401, r.text[:200]

    def test_replay_is_refused(self, signed):
        """A signed request is valid once. Replaying the identical bytes is the
        cheapest attack there is against a scheme like this."""
        uri = "/api/cluster/status"
        headers = _headers(signed["secret"], "GET", uri, ANY_NODE)
        first = requests.get(f"{FTL_URL}{uri}", headers=headers, timeout=10)
        assert first.status_code == 200, first.text[:200]
        second = requests.get(f"{FTL_URL}{uri}", headers=headers, timeout=10)
        assert second.status_code == 401, second.text[:200]

    @pytest.mark.parametrize("offset", [-(SIG_WINDOW + 60), SIG_WINDOW + 60])
    def test_outside_the_window_is_refused(self, signed, offset):
        """Signed correctly, but too old or too far ahead to be current."""
        uri = "/api/cluster/status"
        seq = int((time.time() + offset) * 1e6)
        r = requests.get(f"{FTL_URL}{uri}",
                         headers=_headers(signed["secret"], "GET", uri, ANY_NODE, seq=seq),
                         timeout=10)
        assert r.status_code == 401, r.text[:200]

    def test_addressed_to_another_node_is_refused_for_writes(self, addressed):
        """A GET may be addressed to anybody - reading a status document
        somewhere else gains nothing. Anything that writes may not."""
        uri = "/api/config"
        body = json.dumps({"config": {}})
        headers = _headers(addressed["secret"], "PATCH", uri, OTHER_NODE, body=body)
        headers["Content-Type"] = "application/json"
        r = requests.patch(f"{FTL_URL}{uri}", headers=headers, data=body, timeout=10)
        assert r.status_code == 401, r.text[:200]

    def test_sent_under_our_own_identity_is_refused(self, addressed):
        """Taking a configuration from ourselves over the network is not a thing
        that should ever happen, and it is how an answer of ours handed back
        would look."""
        uri = "/api/config"
        body = json.dumps({"config": {}})
        headers = _headers(addressed["secret"], "PATCH", uri, addressed["id"],
                           body=body, sender=addressed["id"])
        headers["Content-Type"] = "application/json"
        r = requests.patch(f"{FTL_URL}{uri}", headers=headers, data=body, timeout=10)
        assert r.status_code == 401, r.text[:200]


# ---------------------------------------------------------------------------
# What a peer is allowed to read
# ---------------------------------------------------------------------------

class TestClusterCredentials:

    def test_patch_answer_carries_no_credentials(self, addressed):
        """A peer that pushes a configuration is answered, and the answer used
        to carry this node's password hash and its unmasked second-factor
        secret - which a stolen cluster secret is explicitly not meant to
        reach.

        Asked over TLS and on both answers a push can get. Over `http` the
        answer withholds credentials whatever the code does, and the two answers
        are built by different lines - a version of this test that got either
        wrong passed against the bug it was written for."""
        pwhash = addressed["pwhash"]
        assert pwhash, "no password is set, so there is no credential to look for"

        disk = _disk(addressed)
        for changed, what in ((0.5, "a push that was turned away"),
                              (time.time(), "a push that was taken")):
            body = _push({"misc": {"check": {"disk": disk}}}, {"misc.check.disk": changed})
            uri = "/api/config"
            headers = _headers(addressed["secret"], "PATCH", uri, addressed["id"], body=body)
            headers["Content-Type"] = "application/json"
            # Not skipped when TLS is missing. This is the one test in the file
            # whose worth was measured by reverting the fix and watching it
            # fail, and a silent skip is how it would stop meaning anything
            try:
                answer = requests.patch(f"{FTL_URL_TLS}{uri}", headers=headers, data=body,
                                        timeout=20, verify=False)
            except requests.RequestException as err:
                raise AssertionError(
                    f"cannot reach {FTL_URL_TLS} - credentials only travel over TLS, so "
                    f"without it this test cannot check anything: {err}"
                ) from None
            assert answer.status_code == 200, answer.text[:200]
            assert pwhash not in answer.text, f"the password hash came back in {what}"
            assert "totp_secret" not in answer.text, f"the second factor came back in {what}"
            assert "app_pwhash" not in answer.text, f"the application passwords came back in {what}"


class TestClusterPushAnswer:

    @pytest.mark.parametrize("older", [True, False])
    def test_answer_says_whether_the_push_was_taken(self, addressed, older):
        """A push older than what this node holds is kept out, and the sender
        has to learn that rather than believe it caught this node up. The newer
        one carries the value this node already has, so taking it changes
        nothing but the version."""
        disk = _disk(addressed)
        body = _push({"misc": {"check": {"disk": disk + 1 if older else disk}}},
                     {"misc.check.disk": 0.5 if older else time.time()})
        r = _signed_patch(addressed, body)
        assert r.status_code == 200, r.text[:200]
        assert _j(r).get("taken") is (not older), r.text[:200]
        assert _disk(addressed) == disk

    def test_each_item_is_judged_by_its_own_stamp(self, addressed):
        """Two nodes that were apart can each hold the newest version of a
        different item. A push carrying both is taken for the item it holds
        the newer version of and refused for the other, rather than taken or
        refused as a whole."""
        disk = _disk(addressed)
        load = _j(addressed["session"].get(f"{FTL_URL}/api/config/misc/check/load", timeout=10))
        load = load["config"]["misc"]["check"]["load"]
        body = _push({"misc": {"check": {"disk": disk + 1, "load": not load}}},
                     {"misc.check.disk": 0.5, "misc.check.load": time.time()})
        r = _signed_patch(addressed, body)
        assert r.status_code == 200, r.text[:200]
        assert _j(r).get("taken") is True, r.text[:200]
        after = _j(addressed["session"].get(f"{FTL_URL}/api/config/misc/check", timeout=10))
        assert after["config"]["misc"]["check"]["disk"] == disk, "an older item was taken"
        assert after["config"]["misc"]["check"]["load"] is (not load), "a newer item was refused"

        # ...and the node says which item it kept, and why
        status = _j(addressed["session"].get(f"{FTL_URL}/api/cluster/status", timeout=10))
        refused = status["cluster"]["node"]["sync"]["config"]["refused"]
        assert "misc.check.disk (not newer" in refused, refused
        assert "misc.check.load" not in refused, refused

        # Put back, again as the newer version
        r = _signed_patch(addressed, _push({"misc": {"check": {"load": load}}},
                                           {"misc.check.load": time.time()}))
        assert r.status_code == 200, r.text[:200]

    def test_push_larger_than_any_other_request_is_read(self, addressed):
        """A push carries whole items, and dns.hosts on its own outgrows what
        any other request may send. Dated before what this node holds, so it is
        read, judged and kept out without changing anything."""
        _disk(addressed)
        hosts = [f"10.{1 + i // 65025}.{(i // 255) % 255}.{1 + i % 255} host-{i}.example.lan"
                 for i in range(3000)]
        body = _push({"dns": {"hosts": hosts}}, {"dns.hosts": 0.5})
        assert len(body) > 64 * 1024
        r = _signed_patch(addressed, body)
        assert r.status_code == 200, r.text[:200]
        assert _j(r).get("taken") is False, r.text[:200]
        # ...and answered with that alone, however large the document is
        assert "config" not in _j(r), r.text[:200]

    def test_push_not_written_is_not_taken(self, addressed):
        """A push this node cannot write to pihole.toml would be gone at its
        next restart, so it is answered as a failure the sender tries again -
        not as taken. The temporary file the configuration is written through
        is made unusable for the one write."""
        if os.geteuid() != 0:
            pytest.skip("making pihole.toml unwritable needs root")
        disk = _disk(addressed)
        tmp = "/etc/pihole/pihole.toml.tmp"
        if os.path.lexists(tmp):
            os.remove(tmp)
        os.symlink("/nonexistent", tmp)
        try:
            r = _signed_patch(addressed, _push({"misc": {"check": {"disk": disk + 1}}},
                                               {"misc.check.disk": time.time()}))
        finally:
            os.remove(tmp)
        assert r.status_code == 500, r.text[:200]
        assert "taken" not in r.text, r.text[:200]

        # The value went live all the same. Put back as the newer version
        r = _signed_patch(addressed, _push({"misc": {"check": {"disk": disk}}},
                                           {"misc.check.disk": time.time()}))
        assert r.status_code == 200, r.text[:200]
        assert _j(r).get("taken") is True, r.text[:200]
        assert _disk(addressed) == disk

    def test_local_items_carry_no_stamp(self, addressed):
        """An item that never leaves a node is never dated: a change to it is
        not a newer version of anything the cluster holds."""
        data = _j(addressed["session"].get(f"{FTL_URL}/api/cluster/status", timeout=10))
        items = data["cluster"]["node"]["sync"]["config"]["items"]
        assert items, "this node dates none of its items"
        for key in ("dns.port", "webserver.port", "cluster.name", "debug.api", "dhcp.active"):
            assert key not in items, f"{key} carries a cluster stamp"


# ---------------------------------------------------------------------------
# Handing a cluster over
# ---------------------------------------------------------------------------

class TestClusterEnrolment:

    def test_enroll_refuses_an_unencrypted_connection(self, api_session):
        """The secret and the password both cross this connection. A signature
        would keep them from being changed, not from being read."""
        r = api_session.post(f"{FTL_URL}/api/cluster/enroll",
                             json={"port": 443}, timeout=10)
        assert r.status_code == 403, r.text[:200]

    def test_enroll_refuses_a_peer(self, addressed):
        """A cluster identity may read what the cluster publishes. The secret is
        what made it a peer in the first place."""
        uri = "/api/cluster/enroll"
        body = json.dumps({"port": 443})
        headers = _headers(addressed["secret"], "POST", uri, addressed["id"], body=body)
        headers["Content-Type"] = "application/json"
        r = requests.post(f"{FTL_URL}{uri}", headers=headers, data=body, timeout=10)
        assert r.status_code in (401, 403), r.text[:200]

    def test_leave_refuses_a_peer(self, addressed):
        """Leaving is an administrator's decision, not a peer's."""
        uri = "/api/cluster/leave"
        body = ""
        headers = _headers(addressed["secret"], "POST", uri, addressed["id"], body=body)
        r = requests.post(f"{FTL_URL}{uri}", headers=headers, timeout=10)
        assert r.status_code in (401, 403), r.text[:200]


# ---------------------------------------------------------------------------
# Handing the configuration to a peer
# ---------------------------------------------------------------------------

class TestClusterPush:

    def test_node_pushes_to_a_peer_and_survives(self, signed, api_session):
        """The document a node hands to its peers is built by the cluster
        thread, with no connection behind it. A peer that holds no
        configuration is caught up within a round or two."""
        if signed["fake"] is None:
            pytest.skip("clustering was already on, so there is no stand-in peer")

        deadline = time.time() + 60
        while time.time() < deadline and not _FakePeer.pushes:
            time.sleep(1)

        assert _FakePeer.pushes, "the node never handed its configuration to the peer"
        assert _answering(api_session), "the node stopped answering after the push"

        path, body = _FakePeer.pushes[0]
        document = json.loads(body)
        assert "config" in document, body[:200]
        # Every item goes with the time it was changed at
        assert document.get("changed"), body[:200]
        assert all(stamp > 0.0 for stamp in document["changed"].values()), body[:200]
        # Credentials only travel to https:// members
        assert signed["pwhash"] not in body

    def test_starting_points_are_handed_over_once(self, signed, api_session):
        """Two nodes holding the same starting point of an item settle it by
        identity: the higher one hands its value over, and the peer holds it at
        the same stamp afterwards. Handing it over again at every catch-up
        rewrote the peer's state for nothing, so it is sent once per value.

        The stand-in publishes this node's stamps and a fingerprint that moves
        with every poll, so this node keeps comparing and finds nothing to send."""
        if signed["fake"] is None:
            pytest.skip("clustering was already on, so there is no stand-in peer")
        assert signed["id"] > FAKE_NODE, "this node does not rank above the stand-in"

        # Handed over once already, as in the test above
        deadline = time.time() + 60
        while time.time() < deadline and not _FakePeer.pushes:
            time.sleep(1)
        assert _FakePeer.pushes, "the node never handed its configuration to the peer"

        status = _j(api_session.get(f"{FTL_URL}/api/cluster/status", timeout=10))
        items = status["cluster"]["node"]["sync"]["config"]["items"]
        baseline = {key for key, stamp in items.items() if stamp <= 1.0}
        if not baseline:
            pytest.skip("this node holds no starting point")

        _FakePeer.items = dict(items)
        _FakePeer.hash_moves = True
        start = len(_FakePeer.pushes)
        try:
            # Two rounds at the default interval, each seeing another fingerprint
            polls = _FakePeer.polls
            deadline = time.time() + 45
            while time.time() < deadline and _FakePeer.polls < polls + 3:
                time.sleep(1)
            assert _FakePeer.polls >= polls + 3, "the node stopped polling the stand-in"
            sent = [set(json.loads(body).get("changed", {})) & baseline
                    for _, body in _FakePeer.pushes[start:]]
        finally:
            _FakePeer.items = {}
            _FakePeer.hash_moves = False

        assert not any(sent), f"starting points handed over again: {sorted(set().union(*sent))[:10]}"


# ---------------------------------------------------------------------------
# The lists
# ---------------------------------------------------------------------------

GRAVITY_DB = "/etc/pihole/gravity.db"


def _swap_gravity():
    """What gravity.sh does at the end of every run: the lists copied into a new
    file, which takes the place of the old one. The old one is kept beside it,
    as gravity.sh does, and FTL reads that as the file being renamed."""
    st = os.stat(GRAVITY_DB)
    new = GRAVITY_DB + ".swap"
    src = sqlite3.connect(f"file:{GRAVITY_DB}?mode=ro", uri=True)
    dst = sqlite3.connect(new)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.chown(new, st.st_uid, st.st_gid)
    os.chmod(new, st.st_mode & 0o777)
    os.rename(GRAVITY_DB, "/etc/pihole/gravity_old.db")
    os.rename(new, GRAVITY_DB)


def _gravity_state(session):
    status = _j(session.get(f"{FTL_URL}/api/cluster/status", timeout=10))
    return status["cluster"]["node"]["sync"]["gravity"]


class TestClusterLists:

    def test_list_edit_survives_a_swapped_database(self, cluster, api_session):
        """A list edit made through the API is dated as an edit made here, also
        when a gravity run swaps gravity.db before the next round looks: the
        tables in the new file are the ones the edit left. Only tables nothing
        explains count as a database restored or copied in, which the cluster's
        lists replace."""
        if os.geteuid() != 0:
            pytest.skip("swapping gravity.db needs root")

        before = _gravity_state(api_session)
        domain = "swapped.cluster.example"
        r = api_session.post(f"{FTL_URL}/api/domains/deny/exact",
                             json={"domain": domain}, timeout=10)
        assert r.status_code == 201, r.text[:200]
        written = time.time()
        try:
            _swap_gravity()

            # Judged by the next round
            deadline = time.time() + 40
            after = before
            while time.time() < deadline and after["hash"] == before["hash"]:
                time.sleep(1)
                after = _gravity_state(api_session)
            assert after["hash"] != before["hash"], "no round recorded the edit"
            assert after["changed"] >= written - 5, \
                f"the edit was not dated as one made here: {json.dumps(after)}"
        finally:
            r = api_session.delete(f"{FTL_URL}/api/domains/deny/exact/{domain}", timeout=10)
            assert r.status_code == 204, r.text[:200]


# ---------------------------------------------------------------------------
# The virtual IP address
# ---------------------------------------------------------------------------

def _own_subnet_addresses():
    """This machine's addresses that belong to a subnet, read from `ip`."""
    try:
        out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True,
                             timeout=5, check=True).stdout
        links = json.loads(out)
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    found = []
    for link in links:
        for addr in link.get("addr_info", []):
            full = 32 if addr.get("family") == "inet" else 128
            if addr.get("scope") == "global" and addr.get("prefixlen", full) < full:
                found.append(addr["local"])
    return found


class TestClusterVip:

    @pytest.mark.parametrize("address", [
        "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255",
        "::", "::1", "ff02::1", "fe80::1", "::ffff:192.168.0.1",
    ])
    def test_address_that_cannot_be_shared_is_refused(self, api_session, address):
        """Every DHCP client is handed this address, and the elected node adds it
        to its interface, so it has to be a unicast address of the network."""
        r = api_session.patch(f"{FTL_URL}/api/config",
                              json={"config": {"cluster": {"vip": {"address": address}}}},
                              timeout=10)
        assert r.status_code == 400, r.text[:200]

    def test_own_address_is_refused(self, api_session):
        """A node's own address would be taken away from it by whichever
        node is elected to hold the virtual one."""
        own = _own_subnet_addresses()
        if not own:
            pytest.skip("this machine has no address on a subnet")
        r = api_session.patch(f"{FTL_URL}/api/config",
                              json={"config": {"cluster": {"vip": {"address": own[0]}}}},
                              timeout=10)
        assert r.status_code == 400, r.text[:200]
