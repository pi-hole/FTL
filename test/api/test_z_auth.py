
"""
Pi-hole FTL API integration tests -- authentication workflow.

These tests are ORDER-DEPENDENT: the application password must be created
and set before the regular password tests can run. Method names are
numbered (test_01_ ... test_10_) to guarantee deterministic ordering
inside the single class.

The password is removed at the end (test_10_) so there is no net state
change after the test suite completes.

Usage:
    pytest test/api/test_z_auth.py -v
"""

import base64
import os
import stat
import time

import pytest
import requests

FTL_URL = "http://127.0.0.1"


class TestAuthWorkflow:
    """Order-dependent authentication tests.

    01: no password set => session valid without login
    02-04: application password creation and usage
    04b: CLI password file validation
    05: setting a regular password via API
    06: incorrect password is rejected
    07: correct password is accepted
    08: rate limiting is enforced after many wrong attempts
    09: removing the password via API
    10: no password set => session valid again
    """

    # ---- shared state across ordered tests ----
    _app_password = None
    _app_pwhash = None

    # -- 01: no password set => session valid without login --

    def test_01_no_password_means_session_valid(self):
        """API authorization (without password): No login required."""
        r = requests.get(f"{FTL_URL}/api/auth", timeout=5)
        assert r.status_code == 200
        data = r.json()
        session = data["session"]
        assert session["valid"] is True
        assert session["totp"] is False
        assert session["sid"] is None
        assert session["validity"] == -1
        assert session["message"] == "no password set"

    # -- 02: create application password --

    def test_02_create_app_password(self):
        """Create application password and extract password + hash."""
        r = requests.get(f"{FTL_URL}/api/auth/app", timeout=5)
        assert r.status_code == 200
        data = r.json()

        assert "app" in data
        assert "password" in data["app"]
        assert "hash" in data["app"]

        TestAuthWorkflow._app_password = data["app"]["password"]
        TestAuthWorkflow._app_pwhash = data["app"]["hash"]

        assert len(TestAuthWorkflow._app_password) > 0
        assert len(TestAuthWorkflow._app_pwhash) > 0

    # -- 03: set application password hash via API --

    def test_03_set_app_password_hash(self):
        """Set app password hash via PATCH /api/config."""
        assert TestAuthWorkflow._app_pwhash is not None, \
            "test_02 must run first to generate the hash"

        pwhash = TestAuthWorkflow._app_pwhash
        r = requests.patch(
            f"{FTL_URL}/api/config/webserver/api/app_pwhash",
            json={"config": {"webserver": {"api": {"app_pwhash": pwhash}}}},
            timeout=20,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["config"]["webserver"]["api"]["app_pwhash"] == pwhash

    # -- 04: login with application password succeeds --

    def test_04_login_with_app_password(self):
        """Login using the application password is successful."""
        assert TestAuthWorkflow._app_password is not None, \
            "test_02 must run first to generate the password"

        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": TestAuthWorkflow._app_password},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["session"]["valid"] is True

    # -- 04b: CLI password file is correct --

    def test_04b_cli_password_file(self):
        """CLI password file (/etc/pihole/cli_pw) is well-formed."""
        cli_pw_path = "/etc/pihole/cli_pw"

        assert os.path.isfile(cli_pw_path), f"{cli_pw_path} does not exist"

        with open(cli_pw_path, "rb") as f:
            raw = f.read()

        assert len(raw) > 0, "cli_pw file is empty"

        content = raw.decode("utf-8")
        lines = content.splitlines()

        assert len(lines) == 1, f"Expected 1 line, got {len(lines)}"

        try:
            base64.b64decode(lines[0], validate=True)
        except Exception as exc:
            pytest.fail(f"cli_pw content is not valid base64: {exc}")

        mode = stat.S_IMODE(os.stat(cli_pw_path).st_mode)
        assert mode == 0o640, f"Expected permissions 0640, got {oct(mode)}"

    # -- 05: set a regular password --

    def test_05_set_password(self):
        """API authorization: Setting password via API (password: ABC).

        Password hashing (BALLOON-SHA256) is synchronous — the API only
        responds after the hash is computed, sessions are invalidated,
        and the config is written to disk.
        """
        r = requests.patch(
            f"{FTL_URL}/api/config/webserver/api/password",
            json={"config": {"webserver": {"api": {"password": "ABC"}}}},
            timeout=20,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["config"]["webserver"]["api"]["password"] == "********"

    # -- 06: incorrect password is rejected --

    def test_06_incorrect_password_rejected(self):
        """API authorization (with password): Incorrect password is rejected."""
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": "XXX"},
            timeout=5,
        )
        assert r.status_code == 401
        data = r.json()
        session = data["session"]
        assert session["valid"] is False
        assert session["totp"] is False
        assert session["sid"] is None
        assert session["validity"] == -1
        assert session["message"] == "password incorrect"

    # -- 07: correct password is accepted --

    def test_07_correct_password_accepted(self):
        """API authorization (with password): Correct password is accepted."""
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": "ABC"},
            timeout=5,
        )
        assert r.status_code == 200
        data = r.json()
        session = data["session"]
        assert session["valid"] is True
        assert session["totp"] is False
        assert session["validity"] == 300
        assert session["message"] == "password correct"
        assert isinstance(session["sid"], str) and len(session["sid"]) > 0
        assert isinstance(session["csrf"], str) and len(session["csrf"]) > 0

    # -- 07b: explicit logout deletes session --

    def test_07b_explicit_logout(self):
        """DELETE /api/auth invalidates the current session (returns 204)."""
        # Login to get a valid session
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": "ABC"},
            timeout=5,
        )
        assert r.status_code == 200
        sid = r.json()["session"]["sid"]
        assert sid is not None

        # Logout via DELETE
        r = requests.delete(
            f"{FTL_URL}/api/auth",
            headers={"X-FTL-SID": sid},
            timeout=5,
        )
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"

        # Verify session is no longer valid
        r = requests.get(
            f"{FTL_URL}/api/auth",
            headers={"X-FTL-SID": sid},
            timeout=5,
        )
        assert r.status_code == 401, \
            f"Expected 401 after logout, got {r.status_code}"

    # -- 07c: delete session by ID --

    def test_07c_delete_session_by_id(self):
        """DELETE /api/auth/session/{id} removes a specific session."""
        # Login to get a session
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": "ABC"},
            timeout=5,
        )
        assert r.status_code == 200
        sid = r.json()["session"]["sid"]

        # List sessions to find the ID
        r = requests.get(
            f"{FTL_URL}/api/auth/sessions",
            headers={"X-FTL-SID": sid},
            timeout=5,
        )
        assert r.status_code == 200
        sessions = r.json()["sessions"]
        # Find our current session
        current = next(
            (s for s in sessions if s.get("current_session")), None)
        assert current is not None, \
            f"No current session found in {sessions}"
        session_id = current["id"]

        # Delete by ID
        r = requests.delete(
            f"{FTL_URL}/api/auth/session/{session_id}",
            headers={"X-FTL-SID": sid},
            timeout=5,
        )
        assert r.status_code == 204, \
            f"Expected 204, got {r.status_code} {r.text}"


    # -- 07f: an app session without app_sudo cannot read the secrets --

    def test_07f_app_session_cannot_read_secrets(self):
        """An app session without app_sudo cannot export the config or read the password hashes."""
        # An app-password login is checked against both hashes, which counts
        # two attempts against the per-second rate limit, so start in a
        # second the logins above have not used
        time.sleep(1.1)
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": TestAuthWorkflow._app_password},
            timeout=10,
        )
        assert r.status_code == 200
        sid = r.json()["session"]["sid"]
        assert isinstance(sid, str) and len(sid) > 0
        headers = {"X-FTL-SID": sid}
        try:
            r = requests.get(f"{FTL_URL}/api/teleporter", headers=headers, timeout=20)
            assert r.status_code == 403
            assert r.json()["error"]["key"] == "forbidden"

            r = requests.get(f"{FTL_URL}/api/config/webserver/api", headers=headers, timeout=10)
            assert r.status_code == 200
            api = r.json()["config"]["webserver"]["api"]
            assert api["pwhash"] == "********"
            assert api["app_pwhash"] == "********"
        finally:
            requests.delete(f"{FTL_URL}/api/auth", headers=headers, timeout=5)

    # -- 08: rate limiting enforced --

    def test_08_rate_limiting_enforced(self):
        """Sending many wrong passwords triggers rate limiting (HTTP 429)."""
        import random
        import string
        import time

        for i in range(100):
            pw = "".join(random.choices(string.printable, k=random.randint(1, 64)))
            try:
                r = requests.post(
                    f"{FTL_URL}/api/auth",
                    json={"password": pw},
                    timeout=5,
                )
            except requests.ConnectionError:
                # FTL may forcefully close the connection when rate limiting
                # Wait for FTL to recover before subsequent tests
                time.sleep(2)
                return
            if r.status_code == 429:
                # Wait for FTL to recover from rate limiting
                time.sleep(2)
                return

        pytest.fail("Rate limiting was not enforced after 100 login attempts")

    # -- 09: remove the password --

    def test_09_remove_password(self):
        """Remove the password so FTL returns to unauthenticated state.

        We first need to log in to get a valid session, then use that
        session to remove the password.
        """
        # Login first
        r = requests.post(
            f"{FTL_URL}/api/auth",
            json={"password": "ABC"},
            timeout=10,
        )
        assert r.status_code == 200
        sid = r.json()["session"]["sid"]

        # Remove password using the session
        r = requests.patch(
            f"{FTL_URL}/api/config/webserver/api/password",
            json={"config": {"webserver": {"api": {"password": ""}}}},
            headers={"X-FTL-SID": sid},
            timeout=20,
        )
        assert r.status_code == 200

        # Also clear the app password hash
        r = requests.patch(
            f"{FTL_URL}/api/config/webserver/api/app_pwhash",
            json={"config": {"webserver": {"api": {"app_pwhash": ""}}}},
            timeout=20,
        )
        assert r.status_code == 200

    # -- 10: no password set again --

    def test_10_no_password_after_removal(self):
        """After password removal, session is valid without login."""
        r = requests.get(f"{FTL_URL}/api/auth", timeout=5)
        assert r.status_code == 200
        data = r.json()
        session = data["session"]
        assert session["valid"] is True
        assert session["message"] == "no password set"
