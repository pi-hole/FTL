#!/usr/bin/env python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Encrypted-upstream DoT/DoH test shim
#
# A tiny, self-contained DoT + DoH server used only by the encrypted-upstream
# E2E tests. It terminates TLS with the repository test certificate (CN/SAN
# "pi.hole", signed by test/test_ca.crt) and forwards the decrypted DNS wire
# message to the local plaintext PowerDNS recursor, returning its answer. Using
# a shim keeps the recursor config untouched and also covers DoH, which the CI
# recursor is not built with.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
#   DoT  : TLS  on 127.0.0.1:8853 (2-byte length-prefixed DNS)
#   DoH  : HTTPS on 127.0.0.1:8443 (HTTP/1.1 POST /dns-query)
#   backend: 127.0.0.1:5555 (pdns_recursor, UDP)

import os
import socket
import ssl
import struct
import sys
import threading
import time

BACKEND = ("127.0.0.1", 5555)
CERT = os.environ.get("SHIM_CERT", "test/test.pem")
DOT_ADDR = ("127.0.0.1", 8853)
DOH_ADDR = ("127.0.0.1", 8443)
# When set, append the on-the-wire length of every decrypted query here so the
# padding E2E test can confirm FTL padded it. FTL pads encrypted queries to a
# 128-octet boundary (RFC 8467), so a padded query arrives as a multiple of 128.
PAD_LOG = os.environ.get("SHIM_PAD_LOG", "")
_pad_lock = threading.Lock()
# Optional per-response delay (ms). When set, each backend resolution sleeps this
# long before replying, so a concurrency test can make in-flight exchanges
# overlap (a serial client would take N*delay, a parallel one ~delay).
try:
    DELAY_S = float(os.environ.get("SHIM_DELAY_MS", "0")) / 1000.0
except ValueError:
    DELAY_S = 0.0


def note_query(transport, query):
    if not PAD_LOG:
        return
    with _pad_lock:
        with open(PAD_LOG, "a") as fh:
            fh.write("%s %d\n" % (transport, len(query)))


def resolve(wire):
    """Forward a DNS wire message to the plaintext backend and return the reply."""
    if DELAY_S > 0:
        time.sleep(DELAY_S)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(wire, BACKEND)
        data, _ = s.recvfrom(65535)
        return data
    finally:
        s.close()


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT)
    return ctx


def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def dot_handle(ctx, raw):
    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        raw.close()
        return
    try:
        while True:
            hdr = recvall(conn, 2)
            if not hdr:
                break
            (qlen,) = struct.unpack("!H", hdr)
            query = recvall(conn, qlen)
            if query is None:
                break
            note_query("dot", query)
            answer = resolve(query)
            conn.sendall(struct.pack("!H", len(answer)) + answer)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def doh_handle(ctx, raw):
    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        raw.close()
        return
    # Persistent HTTP/1.1 keep-alive, like a real DoH resolver (Cloudflare/Google
    # keep the connection open for a long time): serve request after request on the
    # same connection so FTL's connection pool actually reuses it. An idle timeout
    # eventually closes it, matching a real server.
    conn.settimeout(30)
    buf = b""
    try:
        while True:
            # Read up to the end of the request headers, keeping any bytes that
            # belong to the following pipelined request in buf.
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) > 65536:
                    return
            head, _, rest = buf.partition(b"\r\n\r\n")

            # Require a valid, positive Content-Length and read exactly that many
            # body bytes. A malformed request fails closed (connection dropped, no
            # answer) instead of being resolved with an empty or partial body.
            content_len = None
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        content_len = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        return
            if content_len is None or content_len <= 0:
                return
            body = rest
            while len(body) < content_len:
                chunk = conn.recv(content_len - len(body))
                if not chunk:
                    return  # connection closed before the full body arrived
                body += chunk
            buf = body[content_len:]  # leftover -> start of the next request
            body = body[:content_len]

            note_query("doh", body)
            answer = resolve(body)
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/dns-message\r\n"
                b"Content-Length: " + str(len(answer)).encode() + b"\r\n"
                b"Connection: keep-alive\r\n\r\n" + answer
            )
            conn.sendall(resp)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def make_listener(addr):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(addr)
    srv.listen(16)
    return srv


def accept_loop(srv, ctx, handler):
    while True:
        raw, _ = srv.accept()
        threading.Thread(target=handler, args=(ctx, raw), daemon=True).start()


if __name__ == "__main__":
    ctx = tls_context()
    # Bind both listeners up front so a port clash (e.g. a stale shim from an
    # interrupted run) makes us exit immediately instead of lingering half-alive.
    try:
        dot_srv = make_listener(DOT_ADDR)
        doh_srv = make_listener(DOH_ADDR)
    except OSError as exc:
        print("dotdoh_shim: could not bind (%s); is another shim running?" % exc,
              file=sys.stderr)
        sys.exit(1)
    threading.Thread(target=accept_loop, args=(dot_srv, ctx, dot_handle), daemon=True).start()
    threading.Thread(target=accept_loop, args=(doh_srv, ctx, doh_handle), daemon=True).start()
    while True:
        time.sleep(3600)
