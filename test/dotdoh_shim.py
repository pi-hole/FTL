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
#   DoT   : TLS   on 127.0.0.1:8853 (2-byte length-prefixed DNS)
#   DoH   : HTTPS on 127.0.0.1:8443 (HTTP/2 via ALPN "h2", else HTTP/1.1)
#   DoH1  : HTTPS on 127.0.0.1:8445 (HTTP/1.1 only - ALPN offers "http/1.1")
#   DoH3  : QUIC  on 127.0.0.1:8444 (HTTP/3, only if aioquic is installed)
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
DOH_ADDR = ("127.0.0.1", 8443)     # HTTP/2-capable DoH (auto-negotiates via ALPN)
DOH_H1_ADDR = ("127.0.0.1", 8445)  # HTTP/1.1-only DoH (exercises the h1 fallback)
DOH3_ADDR = ("127.0.0.1", 8444)    # HTTP/3 (QUIC) DoH, optional (needs aioquic)
# When set, append the on-the-wire length of every decrypted query here so the
# padding E2E test can confirm FTL padded it. FTL pads encrypted queries to a
# 128-octet boundary (RFC 8467), so a padded query arrives as a multiple of 128.
PAD_LOG = os.environ.get("SHIM_PAD_LOG", "")
_pad_lock = threading.Lock()
# Touched once the (optional) HTTP/3 listener is actually bound and accepting, so
# the bats suite can skip the DoH3 test cleanly when aioquic is not installed.
H3_READY = os.environ.get("SHIM_H3_READY", "/tmp/dotdoh_h3_ready")
# Optional per-response delay (ms): each backend resolution sleeps this long
# before replying, so a concurrency test can overlap in-flight exchanges.
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


def note_proto(transport, proto):
    # Record the wire protocol a request arrived on (e.g. "HTTP/1.1") so the test
    # suite can assert the DoH transport. Written with a distinct "<t>-proto"
    # label so it never collides with the "<t> <len>" padding records above.
    if not PAD_LOG:
        return
    with _pad_lock:
        with open(PAD_LOG, "a") as fh:
            fh.write("%s-proto %s\n" % (transport, proto))


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


def tls_context(alpn=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT)
    if alpn:
        ctx.set_alpn_protocols(alpn)
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
    """Terminate TLS for a DoH connection and dispatch on the negotiated ALPN.

    If the client selected "h2" we serve the exchange over a minimal HTTP/2
    session; otherwise we fall back to the HTTP/1.1 framing. FTL's DoH client
    offers "h2,http/1.1", so an h2-capable context here upgrades it to HTTP/2,
    while the http/1.1-only context keeps exercising the fallback path.
    """
    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        raw.close()
        return
    try:
        if conn.selected_alpn_protocol() == "h2":
            doh_http2(conn)
        else:
            doh_http1(conn)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def doh_http1(conn):
    # Persistent HTTP/1.1 keep-alive, like a real DoH resolver: serve request
    # after request on the same connection so FTL's connection pool reuses it.
    # An idle timeout eventually closes it, matching a real server.
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

            # Record the request-line HTTP version (FTL's HTTP/1.1 DoH client
            # sends "HTTP/1.1") so the suite can assert the DoH transport.
            try:
                req_line = head.split(b"\r\n", 1)[0].decode("latin-1")
                note_proto("doh", req_line.rsplit(" ", 1)[-1])
            except Exception:
                pass

            # Require a valid, positive Content-Length and read exactly that many
            # body bytes. A malformed request fails closed instead of resolving.
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


# --- Minimal HTTP/2 server -------------------------------------------------
#
# Just enough of RFC 7540 to serve the DoH exchange to FTL's nghttp2 client with
# no third-party dependency. We never decode the request HPACK header block (we
# only need the DATA payload) and hand-encode the response headers, which avoids
# any HPACK dynamic-table state.

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# Frame types
H2_DATA, H2_HEADERS, H2_RST_STREAM = 0x0, 0x1, 0x3
H2_SETTINGS, H2_PING, H2_GOAWAY, H2_CONTINUATION = 0x4, 0x6, 0x7, 0x9
# Frame flags
H2_END_STREAM, H2_END_HEADERS, H2_PADDED, H2_ACK = 0x1, 0x4, 0x8, 0x1


def h2_encode_int(value, prefix_bits, first_byte):
    """HPACK integer with the high (8 - prefix_bits) bits taken from first_byte."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([first_byte | value])
    out = bytearray([first_byte | max_prefix])
    value -= max_prefix
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def h2_encode_str(s):
    b = s.encode("latin-1")
    return h2_encode_int(len(b), 7, 0x00) + b  # H=0 (no Huffman)


def h2_literal_header(name, value):
    # Literal header field without indexing, new name (first byte 0x00).
    return b"\x00" + h2_encode_str(name) + h2_encode_str(value)


def h2_frame(ftype, flags, stream_id, payload=b""):
    return (struct.pack("!I", len(payload))[1:] +
            bytes([ftype, flags]) +
            struct.pack("!I", stream_id & 0x7fffffff) +
            payload)


def h2_respond(conn, stream_id, body):
    note_query("doh", body)
    answer = resolve(body)
    headers = (b"\x88" +  # indexed :status 200 (static table index 8)
               h2_literal_header("content-type", "application/dns-message") +
               h2_literal_header("content-length", str(len(answer))))
    conn.sendall(h2_frame(H2_HEADERS, H2_END_HEADERS, stream_id, headers))
    conn.sendall(h2_frame(H2_DATA, H2_END_STREAM, stream_id, answer))


def doh_http2(conn):
    conn.settimeout(30)
    pre = recvall(conn, len(H2_PREFACE))
    if pre != H2_PREFACE:
        return
    # Server connection preface: an (empty) SETTINGS frame must come first.
    conn.sendall(h2_frame(H2_SETTINGS, 0x0, 0))
    proto_recorded = False
    bodies = {}  # stream_id -> bytearray (accumulated request body)
    try:
        while True:
            hdr = recvall(conn, 9)
            if not hdr:
                return
            length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
            ftype, flags = hdr[3], hdr[4]
            stream_id = struct.unpack("!I", hdr[5:9])[0] & 0x7fffffff
            payload = recvall(conn, length) if length else b""
            if length and payload is None:
                return

            if ftype == H2_SETTINGS:
                if not (flags & H2_ACK):
                    conn.sendall(h2_frame(H2_SETTINGS, H2_ACK, 0))
            elif ftype == H2_PING:
                if not (flags & H2_ACK):
                    conn.sendall(h2_frame(H2_PING, H2_ACK, 0, payload))
            elif ftype == H2_GOAWAY:
                return
            elif ftype == H2_RST_STREAM:
                bodies.pop(stream_id, None)
            elif ftype == H2_HEADERS:
                if not proto_recorded:
                    note_proto("doh", "HTTP/2")
                    proto_recorded = True
                bodies.setdefault(stream_id, bytearray())
                # We do not decode the header block; if it spans CONTINUATION
                # frames, drain them until END_HEADERS so the framing stays in
                # sync (their payloads are irrelevant to us).
                if not (flags & H2_END_HEADERS):
                    while True:
                        chdr = recvall(conn, 9)
                        if not chdr:
                            return
                        clen = (chdr[0] << 16) | (chdr[1] << 8) | chdr[2]
                        ctype, cflags = chdr[3], chdr[4]
                        if clen and recvall(conn, clen) is None:
                            return
                        if ctype == H2_CONTINUATION and (cflags & H2_END_HEADERS):
                            break
                if flags & H2_END_STREAM:  # request with no body (unusual for DoH)
                    h2_respond(conn, stream_id, bytes(bodies.pop(stream_id, b"")))
            elif ftype == H2_DATA:
                data = payload
                if flags & H2_PADDED and data:
                    pad_len = data[0]
                    data = data[1:len(data) - pad_len] if pad_len <= len(data) - 1 else data[1:]
                bodies.setdefault(stream_id, bytearray()).extend(data)
                if flags & H2_END_STREAM:
                    h2_respond(conn, stream_id, bytes(bodies.pop(stream_id, b"")))
            # WINDOW_UPDATE / PRIORITY / unknown frames are ignored: our response
            # is small enough that no flow-control bookkeeping is needed.
    except Exception:
        pass


# --- Optional HTTP/3 (QUIC) server via aioquic -----------------------------

try:
    import asyncio
    from aioquic.asyncio import serve as quic_serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ProtocolNegotiated
    HAVE_AIOQUIC = True
    AIOQUIC_IMPORT_ERROR = None
except Exception as exc:
    HAVE_AIOQUIC = False
    # Keep the reason so the disabled message can tell "aioquic not installed"
    # apart from "installed but a submodule/API import failed".
    AIOQUIC_IMPORT_ERROR = repr(exc)


def start_h3_listener():
    """Bring up the HTTP/3 DoH listener if aioquic is available.

    Returns True once bound (and touches H3_READY), or False if aioquic is not
    installed - in which case the DoH3 E2E test skips cleanly.
    """
    if not HAVE_AIOQUIC:
        return False

    class DoH3Protocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._http = None
            self._bodies = {}

        def quic_event_received(self, event):
            if isinstance(event, ProtocolNegotiated):
                self._http = H3Connection(self._quic)
            if self._http is None:
                return
            for h3_event in self._http.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    self._bodies.setdefault(h3_event.stream_id, bytearray())
                    note_proto("doh3", "HTTP/3")
                    if h3_event.stream_ended:
                        self._reply(h3_event.stream_id)
                elif isinstance(h3_event, DataReceived):
                    self._bodies.setdefault(h3_event.stream_id, bytearray()).extend(h3_event.data)
                    if h3_event.stream_ended:
                        self._reply(h3_event.stream_id)

        def _reply(self, stream_id):
            body = bytes(self._bodies.pop(stream_id, b""))
            note_query("doh3", body)
            answer = resolve(body)
            self._http.send_headers(stream_id, [
                (b":status", b"200"),
                (b"content-type", b"application/dns-message"),
            ])
            self._http.send_data(stream_id, answer, end_stream=True)
            self.transmit()

    async def _serve():
        config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        config.load_cert_chain(CERT, CERT)
        await quic_serve(DOH3_ADDR[0], DOH3_ADDR[1],
                         configuration=config, create_protocol=DoH3Protocol)

    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_serve())
        except Exception as exc:
            print("dotdoh_shim: HTTP/3 listener failed to start (%s)" % exc,
                  file=sys.stderr)
            return
        try:
            with open(H3_READY, "w") as fh:
                fh.write("1\n")
        except Exception:
            pass
        loop.run_forever()

    threading.Thread(target=_run, daemon=True).start()
    return True


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
    # A stale readiness marker from an earlier run must not fool the suite into
    # thinking HTTP/3 is up; drop it and only re-create it once we actually bind.
    try:
        os.unlink(H3_READY)
    except OSError:
        pass

    dot_ctx = tls_context()                          # DoT: no ALPN
    doh_ctx = tls_context(["h2", "http/1.1"])        # DoH: prefer HTTP/2
    doh_h1_ctx = tls_context(["http/1.1"])           # DoH: HTTP/1.1 only

    # Bind the TCP listeners up front so a port clash (e.g. a stale shim from an
    # interrupted run) makes us exit immediately instead of lingering half-alive.
    try:
        dot_srv = make_listener(DOT_ADDR)
        doh_srv = make_listener(DOH_ADDR)
        doh_h1_srv = make_listener(DOH_H1_ADDR)
    except OSError as exc:
        print("dotdoh_shim: could not bind (%s); is another shim running?" % exc,
              file=sys.stderr)
        sys.exit(1)

    # HTTP/3 needs aioquic. dotdoh.bats requires DoH3, so surface the exact
    # reason (import error) rather than a bare "not available".
    if not start_h3_listener():
        print("dotdoh_shim: HTTP/3 (DoH3) listener disabled, aioquic import failed: %s"
              % AIOQUIC_IMPORT_ERROR, file=sys.stderr)

    threading.Thread(target=accept_loop, args=(dot_srv, dot_ctx, dot_handle), daemon=True).start()
    threading.Thread(target=accept_loop, args=(doh_srv, doh_ctx, doh_handle), daemon=True).start()
    threading.Thread(target=accept_loop, args=(doh_h1_srv, doh_h1_ctx, doh_handle), daemon=True).start()
    while True:
        time.sleep(3600)
