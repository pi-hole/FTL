"""
Pi-hole FTL API tests -- what a Teleporter archive may and may not carry.

An imported archive contains a complete pihole.toml and is installed as the
running configuration.  Parsing it is not the same as accepting it: every value
has to pass the validator its config item declares, exactly as it would when set
through PATCH /api/config, the CLI or an environment variable.  Otherwise the
import is a way to put a value into the configuration that every other path
refuses - an embedded newline in a dnsmasq-bound option, for instance, carries a
second directive into the generated dnsmasq configuration.

Separately, an item the API may not set is not settable by uploading a file
through the API either: the archive is imported, but that one value stays as it
is configured on this host.

Each test builds an archive from the configuration currently in effect and
changes a single value in it.

The file is named ``test_n_*`` so it runs after ``test_m_mutations.py`` and
before ``test_openapi.py``, whose teleporter round-trip expects an importable
archive.

Usage:
    pytest test/api/test_n_teleporter_validation.py -v
"""

import io
import re
import time
import zipfile

import pytest

from libs.FTLAPI import AuthenticationMethods

PIHOLE_TOML = "/etc/pihole/pihole.toml"
FTL_LOG = "/var/log/pihole/FTL.log"
RESTART_MARKER = "CLI password set and stored in file"


def _log_end():
    """Byte offset of the end of FTL.log."""
    try:
        with open(FTL_LOG, "r") as f:
            f.seek(0, 2)
            return f.tell()
    except FileNotFoundError:
        return 0


def _wait_for_restart(start_pos, timeout=30):
    """Block until a restarted FTL has re-initialised.

    An accepted import sets restart_ftl(). Probing the API is no good, it
    can answer from the process that is going away, so watch the log for
    the marker the new one writes.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(FTL_LOG, "r") as f:
                f.seek(start_pos)
                for line in f:
                    if RESTART_MARKER in line:
                        return
        except FileNotFoundError:
            pass
        time.sleep(0.25)
    raise AssertionError("FTL did not come back within %ds of an import" % timeout)


def _archive(toml_text: str) -> bytes:
    """Pack a pihole.toml into a Teleporter ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("etc/pihole/pihole.toml", toml_text)
    return buf.getvalue()


def _current_toml() -> str:
    with open(PIHOLE_TOML, "r", encoding="utf-8") as fp:
        return fp.read()


def _replace(toml_text: str, key: str, value: str) -> str:
    """Replace the value of ``key`` in the TOML text, keeping its indentation.

    Arrays are written across several lines, so an assignment opening with "["
    consumes the following lines up to the one closing it. Replacing only the
    first line would leave a stray "]" behind and the archive would be rejected
    as malformed TOML rather than by the validator under test.
    """
    lines = toml_text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines)
                  if re.match(r"^\s*" + re.escape(key) + r"\s*=", line)), None)
    assert start is not None, f"{key} not found in {PIHOLE_TOML}"

    end = start
    if re.match(r"^\s*" + re.escape(key) + r"\s*=\s*\[", lines[start]) and \
       "]" not in lines[start].split("=", 1)[1]:
        while "]" not in lines[end]:
            end += 1
            assert end < len(lines), f"unterminated array for {key}"

    indent = re.match(r"^\s*", lines[start]).group(0)
    return "".join(lines[:start] + [f"{indent}{key} = {value}\n"] + lines[end + 1:])


def _import(ftl, toml_text: str):
    return ftl.POST("/api/teleporter", None, AuthenticationMethods.HEADER,
                    {"file": ("teleporter.zip", _archive(toml_text), "application/zip")})


# Each entry is a value no other way of configuring FTL would accept.
INVALID_VALUES = [
    # An embedded newline carries a second directive into dnsmasq.conf
    ("hostRecord", '"pi.hole,127.0.0.1\\nlog-queries"', "dns.hostRecord"),
    # Same, in an array
    ("cnameRecords", '[ "a.com,b.com\\nlog-queries" ]', "dns.cnameRecords"),
    # Not a valid IP/hostname pair
    ("hosts", '[ "not-an-ip somehost" ]', "dns.hosts"),
]


@pytest.mark.parametrize("key,value,expected_item", INVALID_VALUES,
                         ids=[v[2] for v in INVALID_VALUES])
def test_invalid_value_is_refused(ftl, key, value, expected_item):
    """An archive carrying an invalid value is refused, naming the item."""
    before = _current_toml()

    # The import stops at the first item that does not validate, so the archive
    # must contain exactly one. The shipped test configuration carries an
    # internationalized host name in dns.hosts which our own validator rejects,
    # and that would otherwise be reported instead of the value under test.
    archive = before if key == "hosts" else _replace(before, "hosts", "[]")
    response = _import(ftl, _replace(archive, key, value))

    assert "error" in response, \
        f"{expected_item}: archive was accepted, response: {response}"
    hint = str(response["error"].get("hint", ""))
    assert expected_item in hint, \
        f"{expected_item}: not named in the rejection, hint was: {hint}"

    # A refused import must not have changed anything
    assert _current_toml() == before, \
        f"{expected_item}: configuration was modified by a refused import"




def test_migrated_value_is_validated(ftl):
    """A value a migration produces is checked like any other.

    The migrations run once the whole file has been read, so a check sitting
    with the config items would not see what they assign. dns.revServer is the
    legacy form of dns.revServers[0] and is built by joining four strings.
    """
    before = _current_toml()
    archive = _replace(before, "hosts", "[]") + (
        "\n[dns.revServer]\n"
        "active = true\n"
        'cidr = "192.168.0.0/24"\n'
        'target = "192.168.0.1"\n'
        'domain = "local\\nlog-queries"\n'
    )

    response = _import(ftl, archive)

    assert "error" in response, f"the migrated value was accepted: {response}"
    hint = str(response["error"].get("hint", ""))
    assert "dns.revServers" in hint, f"not named in the rejection, hint was: {hint}"

    assert _current_toml() == before, \
        "configuration was modified by a refused import"


# Items the API may not set are not settable by uploading a file through the
# API either, otherwise the archive would be the way around that restriction.
LOCKED_ITEMS = [
    ("dnsmasq_lines", '[ "log-queries" ]', "misc.dnsmasq_lines"),
    ("advancedOpts", '[ "put_delete_auth_file", "/etc/pihole/pihole.toml" ]',
     "webserver.advancedOpts"),
    # Relocating the document root is host-only; "/" would serve the filesystem
    ("webroot", '"/"', "webserver.paths.webroot"),
]


@pytest.mark.parametrize("key,value,dotted", LOCKED_ITEMS,
                         ids=[i[2] for i in LOCKED_ITEMS])
def test_locked_item_is_not_carried_over(ftl, key, value, dotted):
    """An archive changing a host-only item is imported without that change."""
    def _value():
        node = ftl.GET("/api/config/" + dotted.replace(".", "/"))["config"]
        for part in dotted.split("."):
            node = node[part]
        return node

    before = _value()

    pos = _log_end()
    response = _import(ftl, _replace(_current_toml(), key, value))
    assert "error" not in response, f"{dotted}: refused: {response}"
    _wait_for_restart(pos)

    assert _value() == before, \
        f"{dotted}: archive changed it"
