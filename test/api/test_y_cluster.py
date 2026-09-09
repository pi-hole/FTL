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
import json
import os
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
ANY_NODE = "*"
SIG_WINDOW = 30

HDR_FROM = "X-FTL-Cluster"
HDR_TO = "X-FTL-Cluster-To"
HDR_SEQ = "X-FTL-Cluster-Seq"
HDR_SIG = "X-FTL-Cluster-Sig"

# Any well-formed identity that is not this node's
OTHER_NODE = "aaaaaaaaaaaaaaaa"

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

    if not was_enabled:
        # A member list as well as the switch: a node with nobody to talk to
        # does not start the cluster thread at all, and so never mints the
        # identity these tests address it by. One member, this node itself, is
        # what a cluster looks like before anybody has joined it
        _patch(api_session, {"cluster": {
            "enabled": True,
            "members": [FTL_URL.replace("http://", "https://")],
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

    yield {"secret": secret, "id": node_id, "pwhash": pwhash}

    # Put back what was found, member list included - emptying it would be this
    # file deciding the configuration of a node it was only visiting
    if not was_enabled:
        _patch(api_session, {"cluster": {"enabled": False, "members": was_members}},
               expect_restart=True)
        _relogin(api_session)

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
        assert "wants_credentials" in conf
        assert "accepts_credentials" in conf

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
        uri = "/api/config?changed=0.000000"
        body = json.dumps({"config": {}})
        headers = _headers(addressed["secret"], "PATCH", uri, OTHER_NODE, body=body)
        headers["Content-Type"] = "application/json"
        r = requests.patch(f"{FTL_URL}{uri}", headers=headers, data=body, timeout=10)
        assert r.status_code == 401, r.text[:200]

    def test_sent_under_our_own_identity_is_refused(self, addressed):
        """Taking a configuration from ourselves over the network is not a thing
        that should ever happen, and it is how an answer of ours handed back
        would look."""
        uri = "/api/config?changed=0.000000"
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

        body = json.dumps({"config": {}})
        for changed, what in ((0.0, "a push that was turned away"),
                              (time.time(), "a push that was taken")):
            uri = f"/api/config?changed={changed:.6f}"
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
