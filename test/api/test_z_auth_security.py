"""
Pi-hole FTL API security regression tests.

These guard three hardening fixes and are intentionally isolated in their own
module (with a self-contained password/TOTP lifecycle) so they do not disturb
the order-dependent workflow in test_z_auth.py:

1. Session cookies carry the Secure attribute only over TLS. A TLS session's
   SID must not be settable over plaintext HTTP (that would allow it to be
   captured on a single http:// request), and Secure must NOT be added over
   plain HTTP (that would make browsers drop the cookie and break LAN setups).

2. An accepted TOTP code cannot be replayed. Replay protection tracks the
   accepted RFC 6238 time-step counter, so once a step has been accepted the
   same code can no longer be reused.

3. A legacy password hash is still upgraded at login once the stored hash
   is compared under the lock.

Usage:
    pytest test/api/test_z_auth_security.py -v
"""

import base64
import hashlib
import hmac
import time
import warnings

import pytest
import requests

# The TLS test talks to FTL's self-signed cert with verify=False. Resolve the
# InsecureRequestWarning category so that test can silence it locally: pytest
# resets warning filters per test, so a module-level disable_warnings() is not
# enough - the test wraps its request in a catch_warnings() block.
try:
    from urllib3.exceptions import InsecureRequestWarning
except ImportError:  # pragma: no cover - fallback for bundled urllib3
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

FTL_URL = "http://127.0.0.1"
FTL_URL_TLS = "https://127.0.0.1"
PASSWORD = "sec-regress-pw"
# Valid base32 TOTP secret (same shape as the stress-test suite)
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


# -- helpers ----------------------------------------------------------------

def _set_password(pw, sid=None):
    headers = {"X-FTL-SID": sid} if sid else {}
    return requests.patch(
        f"{FTL_URL}/api/config/webserver/api/password",
        json={"config": {"webserver": {"api": {"password": pw}}}},
        headers=headers, timeout=20)


def _set_totp_secret(secret, sid):
    return requests.patch(
        f"{FTL_URL}/api/config/webserver/api/totp_secret",
        json={"config": {"webserver": {"api": {"totp_secret": secret}}}},
        headers={"X-FTL-SID": sid}, timeout=20)


def _login(pw, totp=None, base=FTL_URL, verify=True, timeout=10):
    payload = {"password": pw}
    if totp is not None:
        payload["totp"] = totp
    return requests.post(f"{base}/api/auth", json=payload,
                         timeout=timeout, verify=verify)


def _login_rate_limited(pw, totp=None, base=FTL_URL, verify=True, attempts=6):
    """Login, tolerating the login rate limiter (HTTP 429) with short waits.

    Kept short so a TOTP code stays within its 30 s validity window.
    """
    r = _login(pw, totp=totp, base=base, verify=verify)
    for _ in range(attempts):
        if r.status_code != 429:
            return r
        time.sleep(0.5)
        r = _login(pw, totp=totp, base=base, verify=verify)
    return r


def _totp_code(secret, now=None):
    if now is None:
        now = time.time()
    key = base64.b32decode(secret, casefold=True)
    counter = int(now // 30)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = ((digest[offset] & 0x7F) << 24) | (
        (digest[offset + 1] & 0xFF) << 16) | (
        (digest[offset + 2] & 0xFF) << 8) | (
        digest[offset + 3] & 0xFF)
    return binary % 1_000_000


def _admin_sid():
    """Obtain an authenticated SID via a password-only login.

    Only used while no TOTP secret is configured (module setup/teardown and
    before the replay test enables TOTP), so a plain password login is enough
    and never triggers a "no 2FA token" warning.
    """
    return _login_rate_limited(PASSWORD).json().get("session", {}).get("sid")


# -- module lifecycle -------------------------------------------------------

def setup_module(_mod):
    # Wait until the API is reachable, then set a known password
    for _ in range(40):
        try:
            if requests.get(f"{FTL_URL}/api/auth", timeout=5).status_code in (200, 401):
                break
        except requests.ConnectionError:
            time.sleep(0.25)
    r = _set_password(PASSWORD)
    assert r.status_code == 200, f"set password: {r.status_code} {r.text}"


def teardown_module(_mod):
    time.sleep(1)
    try:
        sid = _admin_sid()
        if sid:
            # Clear any TOTP secret first so a plain password login works again
            _set_totp_secret("", sid)
            _set_password("", sid=sid)
    except Exception:
        pass  # best-effort cleanup


# -- tests ------------------------------------------------------------------

class TestSessionCookieSecure:
    """The Secure cookie attribute must track the transport."""

    def test_http_login_cookie_has_no_secure_attribute(self):
        r = _login_rate_limited(PASSWORD, base=FTL_URL)
        assert r.status_code == 200, f"HTTP login failed: {r.status_code} {r.text}"
        set_cookie = r.headers.get("Set-Cookie", "")
        assert "sid=" in set_cookie, f"no session cookie set: {set_cookie!r}"
        # Secure over plain HTTP would make the browser drop the cookie
        assert "secure" not in set_cookie.lower(), \
            f"Secure attribute wrongly set over HTTP: {set_cookie!r}"

    def test_https_login_cookie_has_secure_attribute(self):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                r = _login_rate_limited(PASSWORD, base=FTL_URL_TLS, verify=False)
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError) as e:
            pytest.skip(f"HTTPS endpoint not available: {e}")
        assert r.status_code == 200, f"HTTPS login failed: {r.status_code} {r.text}"
        set_cookie = r.headers.get("Set-Cookie", "")
        assert "sid=" in set_cookie, f"no session cookie set: {set_cookie!r}"
        assert "secure" in set_cookie.lower(), \
            f"Secure attribute missing over HTTPS: {set_cookie!r}"


class TestTOTPReplay:
    """An accepted TOTP code must not be replayable."""

    def test_accepted_totp_code_cannot_be_replayed(self):
        # Obtain a session before enabling TOTP (plain password login), then
        # configure the shared TOTP secret.
        sid = _admin_sid()
        assert sid, "could not obtain an admin session to configure TOTP"
        assert _set_totp_secret(TOTP_SECRET, sid).status_code == 200

        first_sid = None
        try:
            # Advance into a fresh 30 s time step that no earlier login has
            # consumed, so the first code is accepted (the replay guard rejects
            # any step counter <= the last accepted one).
            time.sleep(30 - (time.time() % 30) + 1)
            code = _totp_code(TOTP_SECRET)

            first = _login_rate_limited(PASSWORD, totp=code)
            assert first.status_code == 200, \
                f"valid TOTP code was not accepted: {first.status_code} {first.text}"
            session = first.json().get("session", {})
            first_sid = session.get("sid")
            assert session.get("valid") is True

            # Replay the exact same code: must be rejected as reused
            replay = _login_rate_limited(PASSWORD, totp=code)
            assert replay.status_code != 200, \
                f"replayed TOTP code was accepted: {replay.status_code} {replay.text}"
            assert replay.json().get("session", {}).get("valid") is not True
        finally:
            # Clear the secret using the session created by the accepted login:
            # it is valid under the 2FA regime, so this avoids a password-only
            # login (which would emit a "no 2FA token" warning) and the replay
            # guard (which would reject a freshly computed code in this window).
            if first_sid:
                _set_totp_secret("", first_sid)


class TestLegacyPasswordUpgrade:
    """A login with a legacy SHA256^2 password rewrites the stored hash as a
    BALLOON one, but only while the stored hash is still that legacy one."""

    OLD = "legacy-old-pw"

    @staticmethod
    def _patch(api, sid):
        return requests.patch(f"{FTL_URL}/api/config",
                              json={"config": {"webserver": {"api": api}}},
                              headers={"X-FTL-SID": sid}, timeout=20)

    def test_legacy_hash_is_upgraded_at_login(self):
        sid = _admin_sid()
        assert sid, "could not obtain an admin session"
        legacy = hashlib.sha256(hashlib.sha256(self.OLD.encode()).hexdigest().encode()).hexdigest()
        assert self._patch({"pwhash": legacy}, sid).status_code == 200

        time.sleep(1.1)
        r = _login_rate_limited(self.OLD)
        session = r.json().get("session", {})
        assert session.get("valid") is True, r.text[:200]
        sid = session.get("sid")
        try:
            r = requests.get(f"{FTL_URL}/api/config/webserver/api/pwhash",
                             headers={"X-FTL-SID": sid}, timeout=20)
            pwhash = r.json()["config"]["webserver"]["api"]["pwhash"]
            assert pwhash.startswith("$BALLOON-SHA256$"), pwhash
        finally:
            self._patch({"password": PASSWORD}, sid)
