#!/usr/bin/env python3
"""A dnsmasq TCP worker forked during a config write must not keep
pihole.toml.lock once the write is done.

The lock is taken here first, so the config write FTL starts next waits in
flock() with the lock file open. A TCP connection opened meanwhile makes
dnsmasq fork a worker. After the write, a non-blocking flock() on the lock
file has to succeed while that worker is still alive.

Prints "free" or "held". The PATCH flips webserver.interface.boxed, a second
one restores it, so this writes pihole.toml twice."""

import fcntl
import json
import os
import socket
import threading
import time
import urllib.request

LOCK = "/etc/pihole/pihole.toml.lock"
URL = "http://127.0.0.1/api/config/webserver/interface/boxed"


def get_boxed():
    with urllib.request.urlopen(URL, timeout=30) as r:
        return json.load(r)["config"]["webserver"]["interface"]["boxed"]


def patch_boxed(boxed):
    data = json.dumps({"config": {"webserver": {"interface": {"boxed": boxed}}}}).encode()
    req = urllib.request.Request("http://127.0.0.1/api/config", data=data, method="PATCH")
    with urllib.request.urlopen(req, timeout=120) as r:
        r.read()


def lock_waiter():
    """True once some process waits in flock() for the lock file. /proc/locks
    is readable without CAP_SYS_PTRACE, FTL's /proc/<pid>/fd is not"""
    ino = os.stat(LOCK).st_ino
    with open("/proc/locks") as f:
        for line in f:
            fields = line.split()
            # "1: -> FLOCK  ADVISORY  WRITE <pid> <maj>:<min>:<inode> 0 EOF"
            if "->" in fields and "FLOCK" in fields and fields[-3].endswith(f":{ino}"):
                return True
    return False


def children(pid):
    kids = set()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as f:
                # The command name in field 2 may contain spaces, ppid follows it
                if int(f.read().rsplit(")", 1)[1].split()[1]) == pid:
                    kids.add(int(entry))
        except (OSError, IndexError, ValueError):
            pass
    return kids


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def wait_for(cond, what, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.05)
    raise SystemExit(f"timed out waiting for {what}")


with open("/run/pihole-FTL.pid") as f:
    pid = int(f.read())
boxed = get_boxed()

holder = open(LOCK, "r")
fcntl.flock(holder, fcntl.LOCK_EX)

writer = threading.Thread(target=patch_boxed, args=(not boxed,))
writer.start()
wait_for(lock_waiter, "FTL to wait for " + LOCK)

before = children(pid)
conn = socket.create_connection(("127.0.0.1", 53), timeout=30)
wait_for(lambda: children(pid) - before, "dnsmasq to fork a TCP worker")
worker = min(children(pid) - before)

fcntl.flock(holder, fcntl.LOCK_UN)
holder.close()
writer.join()

if not alive(worker):
    raise SystemExit("the TCP worker exited before the check")

with open(LOCK, "r") as probe:
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print("free")
    except BlockingIOError:
        print("held")

# The worker exits with its connection, and with it any lock it holds
conn.close()
wait_for(lambda: not alive(worker), "the TCP worker to exit")
patch_boxed(boxed)
