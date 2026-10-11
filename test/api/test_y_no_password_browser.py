"""
Pi-hole FTL API tests -- no password set, requests from a browser.

Without a password, FTL authorizes every request that could also reach it
directly, but not requests another website sends through a browser on the
network (cross-site requests and DNS rebinding).

Usage:
    pytest test/api/test_y_no_password_browser.py -v
"""

import socket

import pytest
import requests

FTL_URL = "http://127.0.0.1"
EVIL = "https://evil.example"


def _auth(headers=None, method="GET", data=None):
    return requests.request(method, f"{FTL_URL}/api/auth", headers=headers or {},
                            data=data, timeout=5)


@pytest.fixture(autouse=True, scope="module")
def no_password():
    r = _auth()
    assert r.status_code == 200 and r.json()["session"]["message"] == "no password set", \
        f"tests need an install without a password: {r.status_code} {r.text}"


class TestCrossSite:
    """Requests sent through a browser on behalf of another website"""

    def test_script_without_browser_headers_is_authorized(self):
        assert _auth().status_code == 200

    def test_cross_origin_read_is_refused(self):
        r = requests.get(f"{FTL_URL}/api/queries?length=1",
                         headers={"Origin": EVIL}, timeout=5)
        assert r.status_code == 401

    def test_cross_site_fetch_metadata_is_refused(self):
        r = requests.get(f"{FTL_URL}/api/queries?length=1",
                         headers={"Origin": EVIL, "Sec-Fetch-Site": "cross-site",
                                  "Sec-Fetch-Mode": "cors"}, timeout=5)
        assert r.status_code == 401

    def test_same_site_is_refused(self):
        r = requests.get(f"{FTL_URL}/api/queries?length=1",
                         headers={"Origin": "http://127.0.0.1:8080",
                                  "Sec-Fetch-Site": "same-site",
                                  "Sec-Fetch-Mode": "cors"}, timeout=5)
        assert r.status_code == 401

    def test_simple_post_cannot_disable_blocking(self):
        r = requests.post(f"{FTL_URL}/api/dns/blocking",
                          headers={"Origin": EVIL, "Content-Type": "text/plain",
                                   "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"},
                          data='{"blocking":false,"timer":30}', timeout=5)
        assert r.status_code == 401
        assert requests.get(f"{FTL_URL}/api/dns/blocking", timeout=5).json()["blocking"] == "enabled"

    def test_cross_site_login_is_refused(self):
        for method in ("GET", "POST"):
            r = _auth({"Origin": EVIL, "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors",
                       "Content-Type": "text/plain"}, method=method, data='{"password":""}')
            assert r.status_code == 401, method
            assert r.json()["session"]["sid"] is None
            assert r.json()["session"]["valid"] is False

    def test_null_origin_is_refused(self):
        assert _auth({"Origin": "null"}).status_code == 401

    def test_same_origin_is_authorized(self):
        r = _auth({"Origin": "http://127.0.0.1", "Sec-Fetch-Site": "same-origin",
                   "Sec-Fetch-Mode": "cors"})
        assert r.status_code == 200

    def test_matching_origin_without_fetch_metadata_is_authorized(self):
        assert _auth({"Origin": "http://127.0.0.1"}).status_code == 200

    def test_typed_url_is_authorized(self):
        assert _auth({"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"}).status_code == 200

    def test_link_from_another_site_is_authorized(self):
        r = _auth({"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"})
        assert r.status_code == 200

    def test_navigating_post_is_refused(self):
        r = _auth({"Origin": EVIL, "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
                   "Content-Type": "text/plain"}, method="POST", data='{"password":""}')
        assert r.status_code == 401

    @pytest.mark.parametrize("origin", ["chrome-extension://abcdefghijklmnop",
                                        "moz-extension://0a1b2c3d-4e5f",
                                        "safari-web-extension://0A1B2C3D"])
    def test_browser_extension_is_authorized(self, origin):
        r = _auth({"Origin": origin, "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"})
        assert r.status_code == 200


class TestHost:
    """DNS rebinding reaches the API under a name that is not the Pi-hole's"""

    @pytest.mark.parametrize("host", ["rebind.evil.example", "rebind.evil.example:80",
                                      "127.0.0.1.nip.io", "pi.hole.evil.example"])
    def test_unknown_host_is_refused(self, host):
        assert _auth({"Host": host}).status_code == 401

    def test_rebinding_with_same_origin_is_refused(self):
        r = _auth({"Host": "rebind.evil.example", "Origin": "http://rebind.evil.example",
                   "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"})
        assert r.status_code == 401

    @pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.1:80", "[::1]", "[::1]:80",
                                      "localhost", "LOCALHOST:80", "pi.hole", "pi.hole.",
                                      "Pi.Hole:80"])
    def test_known_host_is_authorized(self, host):
        assert _auth({"Host": host}).status_code == 200

    def test_api_refusal_explains_itself(self):
        r = requests.get(f"{FTL_URL}/api/queries?length=1",
                         headers={"Host": "rebind.evil.example"}, timeout=5)
        assert r.status_code == 401
        assert "webserver.domain" in r.json()["error"]["hint"]

    def test_dashboard_refusal_explains_itself(self):
        r = requests.get(f"{FTL_URL}/admin/", headers={"Host": "rebind.evil.example"},
                         allow_redirects=False, timeout=5)
        assert r.status_code == 403
        assert "webserver.domain" in r.text
        r = requests.get(f"{FTL_URL}/admin/", allow_redirects=False, timeout=5)
        assert r.status_code != 403

    def test_machine_hostname_is_authorized(self):
        name = socket.gethostname()
        for host in (name, f"{name}.lan", f"{name}.local", f"{name}:80"):
            assert _auth({"Host": host}).status_code == 200, host
        assert _auth({"Host": f"{name}.evil.example"}).status_code == 401
