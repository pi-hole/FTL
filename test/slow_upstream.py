#!/usr/bin/env python3
# Minimal DNS server answering every query after a delay, A queries with
# 192.168.7.1 and all others without records. Usage: slow_upstream.py <port> <seconds>
import socket, struct, sys, time

PORT, DELAY = int(sys.argv[1]), float(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", PORT))
print("ready", flush=True)
while True:
    d, a = s.recvfrom(4096)
    # The question ends with the root label, the type and the class
    end = d.find(b"\x00", 12) + 5
    if end < 17 or end > len(d):
        continue
    qtype = struct.unpack("!H", d[end - 4:end - 2])[0]
    answer = b"\xc0\x0c" + struct.pack("!HHIH4B", 1, 1, 60, 4, 192, 168, 7, 1) if qtype == 1 else b""
    time.sleep(DELAY)
    s.sendto(d[:2] + struct.pack("!HHHHH", 0x8180, 1, 1 if answer else 0, 0, 0) + d[12:end] + answer, a)
