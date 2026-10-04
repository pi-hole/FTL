#!/usr/bin/env python3
# Minimal NTP server answering correctly while advertising a chosen precision
# (log2 seconds), e.g. -9 for about 2 ms. Usage: fakentp.py <address> <precision>
import socket, struct, sys, time

ADDR, RHO = sys.argv[1], int(sys.argv[2])
EPOCH = 2208988800


def ts(t):
    return int(t) + EPOCH, int((t - int(t)) * (1 << 32))


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((ADDR, 123))
print("ready", flush=True)
while True:
    d, a = s.recvfrom(512)
    if len(d) < 48:
        continue
    xs, xf = struct.unpack("!II", d[40:48])
    rs, rf = ts(time.time())
    ref = ts(time.time() - 60)
    tx = ts(time.time())
    s.sendto(struct.pack("!BBbb", 0x24, 2, 0, RHO) + struct.pack("!II", 0, 0) + b"LOCL"
             + struct.pack("!II", *ref) + struct.pack("!II", xs, xf)
             + struct.pack("!II", rs, rf) + struct.pack("!II", *tx), a)
