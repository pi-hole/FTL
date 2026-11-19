#!/usr/bin/env python3
"""The webserver must come back after renewing its TLS certificate while a
dnsmasq TCP worker is alive (#3368).

dnsmasq forks a worker for every TCP DNS connection. A worker that keeps a
copy of the webserver's listening sockets keeps the ports bound, so the
restart that follows the renewal fails with EADDRINUSE.

test/expired.pem is a certificate issued by "CN=pi.hole, O=Pi-hole" that
expired in 2020, so FTL treats it as its own and renews it two seconds after
the webserver starts. Switching webserver.tls.cert to a copy of it restarts
FTL. As soon as the new webserver is up, a TCP DNS connection is opened and
kept open across the renewal.

Prints "up" or "down". Restores webserver.tls.cert afterwards, through the
API if the webserver is up and by restarting FTL by hand if it is not, so
later tests run against a working FTL either way. Writes pihole.toml twice."""

import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import time
import urllib.request

FTL_LOG = "/var/log/pihole/FTL.log"
WEB_LOG = "/var/log/pihole/webserver.log"
TOML = "/etc/pihole/pihole.toml"
CERT = "/etc/pihole/renew.pem"
TEST_CERT = "/etc/pihole/test.pem"
URL = "http://127.0.0.1"


def patch_cert(path):
    data = json.dumps({"config": {"webserver": {"tls": {"cert": path}}}}).encode()
    req = urllib.request.Request(URL + "/api/config", data=data, method="PATCH")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except OSError:
        # FTL may restart before the reply is complete
        pass


def log_since(path, offset):
    with open(path, errors="replace") as f:
        f.seek(offset)
        return f.read()


def wait_for(cond, what, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.05)
    raise SystemExit(f"timed out waiting for {what}")


def port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
        return True
    except OSError:
        return False


def web_up():
    try:
        with urllib.request.urlopen(URL + "/api/info/login", timeout=5) as r:
            return r.status == 200
    except OSError:
        return False


def ftl_pid():
    with open("/run/pihole-FTL.pid") as f:
        return int(f.read())


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def ftl_processes():
    pids = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm") as f:
                if f.read().strip() == "pihole-FTL" and alive(int(entry)):
                    pids.append(int(entry))
        except OSError:
            pass
    return pids


def restart_with(path):
    """Switch webserver.tls.cert through the API, which restarts FTL"""
    ftl_off = os.path.getsize(FTL_LOG)
    web_off = os.path.getsize(WEB_LOG)
    patch_cert(path)
    wait_for(lambda: "########## FTL started" in log_since(FTL_LOG, ftl_off), "FTL to restart")
    return web_off


def restore_by_hand():
    """Without a webserver there is no API: stop FTL, restore the setting in
    pihole.toml and start FTL again the way test/run.sh does"""
    pid = ftl_pid()
    os.kill(pid, signal.SIGTERM)
    # Including its TCP workers, which still hold the webserver ports
    wait_for(lambda: not ftl_processes(), "FTL and its TCP workers to exit")
    with open(TOML) as f:
        toml = f.read()
    with open(TOML, "w") as f:
        f.write(toml.replace(f'"{CERT}"', f'"{TEST_CERT}"'))
    ftl_off = os.path.getsize(FTL_LOG)
    subprocess.run(["su", "pihole", "-s", "/bin/sh", "-c", "/home/pihole/pihole-FTL"], check=True)
    wait_for(lambda: "########## FTL started" in log_since(FTL_LOG, ftl_off), "FTL to start")


shutil.copy("test/expired.pem", CERT)
shutil.chown(CERT, "pihole", "pihole")
os.chmod(CERT, 0o600)

web_off = restart_with(CERT)
conn = None
try:
    wait_for(lambda: port_open(80), "the webserver to listen on port 80")

    # Keep a TCP DNS connection open, so dnsmasq forks a worker that stays alive
    conn = socket.create_connection(("127.0.0.1", 53), timeout=10)
    name = b"".join(bytes([len(label)]) + label for label in b"pi.hole".split(b".")) + b"\0"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    conn.sendall(struct.pack("!H", len(query)) + query)
    conn.recv(4096)
    if "Restarting HTTP server" in log_since(WEB_LOG, web_off):
        raise SystemExit("the worker was forked only after the renewal, cannot test")

    wait_for(lambda: "The new certificate is valid" in log_since(WEB_LOG, web_off),
             "the certificate renewal")
    log = log_since(WEB_LOG, web_off)
    up = web_up() and "cannot bind" not in log
    print("up" if up else "down")
    if not up:
        print(log)
finally:
    if conn is not None:
        conn.close()
    if web_up():
        restart_with(TEST_CERT)
    else:
        restore_by_hand()
    os.remove(CERT)
