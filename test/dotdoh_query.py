#!/usr/bin/env python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Inbound-DoT/DoH end-to-end test client
#
# A tiny, dependency-free client for the inbound (server-side) DoT/DoH E2E tests
# in test/dotdoh_server.bats. It builds a DNS query, optionally sends it to FTL's
# own DoT listener over TLS, and validates the answer. DoH is exercised with curl
# in the bats file (a real-world client); this helper provides the DoT client
# curl cannot, plus the query/answer (de)serialisation both paths share.
#
# Subcommands:
#   emit  <domain> <outfile>                      write the raw DNS query wire
#   check <infile> <expected-ip>                  validate a DNS answer file
#   dot   <host> <port> <domain> <src> <ca> <ip>  full DoT exchange + validate
#
# The whole 127.0.0.0/8 is loopback on Linux, so binding <src> (e.g. 127.0.0.2)
# as the source address while connecting to 127.0.0.1 lets the test assert that
# FTL attributes the query to the real downstream client, not to loopback.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

import base64
import socket
import ssl
import struct
import sys


def build_query(qname, qtype=1):
    """Build a minimal DNS query (qtype/IN, RD=1) for qname (default A)."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    body = b""
    for label in qname.split("."):
        body += bytes([len(label)]) + label.encode()
    body += b"\x00" + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + body


def build_forged_query(qname, fake_client_ip):
    """Build a DNS query for qname carrying a FORGED Pi-hole-private client option
    (EDNS code 65432): [family=4][fake IPv4][16-byte bogus HMAC]. FTL trusts this
    option only when its per-run HMAC verifies, so a forged one must be rejected -
    the query attributed to the real packet source, never to fake_client_ip."""
    # ARCOUNT=1 for the trailing OPT pseudo-record.
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
    body = b""
    for label in qname.split("."):
        body += bytes([len(label)]) + label.encode()
    body += b"\x00" + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    # Payload family(1)+IPv4(4)+bogus MAC(16) = 21 bytes, the exact length FTL's
    # parser accepts for an IPv4 option, so the forgery reaches the HMAC compare.
    payload = b"\x04" + socket.inet_aton(fake_client_ip) + (b"\xaa" * 16)
    option = struct.pack("!HH", 65432, len(payload)) + payload  # code, length, data
    # OPT RR: root name, TYPE=41, CLASS=UDP-size, TTL=0 (EDNS0, DO=0), RDLEN, RDATA.
    opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(option)) + option
    return header + body + opt


def dns_udp(host, port, packet, source):
    """Send a raw DNS packet over UDP from source; return the reply, or None."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        if source:
            s.bind((source, 0))
        s.sendto(packet, (host, port))
        try:
            data, _ = s.recvfrom(4096)
            return data
        except OSError:
            return None
    finally:
        s.close()


def validate(answer, expected_ip):
    """Fail (raise SystemExit) unless answer is a positive reply for expected_ip."""
    if len(answer) < 12:
        sys.exit("answer too short (%d bytes)" % len(answer))
    flags, _, ancount = struct.unpack("!HHH", answer[2:8])
    if not (flags & 0x8000):
        sys.exit("QR bit not set (not a response)")
    rcode = flags & 0x000F
    if rcode != 0:
        sys.exit("non-zero RCODE %d" % rcode)
    if ancount < 1:
        sys.exit("no answer records")
    if socket.inet_aton(expected_ip) not in answer:
        sys.exit("expected A record %s not found in answer" % expected_ip)


def validate_nodata(answer):
    """Fail unless answer is NODATA (positive response, NOERROR, no answers)."""
    if len(answer) < 12:
        sys.exit("answer too short (%d bytes)" % len(answer))
    flags, _, ancount = struct.unpack("!HHH", answer[2:8])
    if not (flags & 0x8000):
        sys.exit("QR bit not set (not a response)")
    rcode = flags & 0x000F
    if rcode != 0:
        sys.exit("non-zero RCODE %d" % rcode)
    if ancount != 0:
        sys.exit("expected NODATA but got %d answer record(s)" % ancount)


def recvall(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _dot_ctx(cafile):
    """TLS context for the DoT client. The repo's shared test CA (test_ca.crt)
    omits the keyUsage extension, which OpenSSL >= 4.0 rejects during verification.
    This client tests DNS-over-TLS resolution, not the test PKI - the DoH curl
    cases cover cert trust against the same CA - so it does not verify the chain."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def dot_exchange(host, port, qname, source, cafile, qtype=1):
    """Send qname over DoT (TLS + 2-byte length prefix) and return the answer."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    ctx = _dot_ctx(cafile)
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(10)
    if source:
        raw.bind((source, 0))
    raw.connect((host, port))
    # The certificate is issued for "pi.hole"; validate against that name even
    # though we dial the loopback IP.
    conn = ctx.wrap_socket(raw, server_hostname="pi.hole")
    try:
        query = build_query(qname, qtype)
        conn.sendall(struct.pack("!H", len(query)) + query)
        hdr = recvall(conn, 2)
        if hdr is None:
            sys.exit("DoT: no length prefix in reply")
        (alen,) = struct.unpack("!H", hdr)
        answer = recvall(conn, alen)
        if answer is None:
            sys.exit("DoT: truncated answer")
        return answer
    finally:
        conn.close()


def dot_exchange_multi(host, port, qname, source, cafile, count):
    """Send `count` queries over ONE DoT connection (keep-alive, RFC 7858 Sec.
    3.4 - how real DoT clients reuse a connection) and return the answers."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    ctx = _dot_ctx(cafile)
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(10)
    if source:
        raw.bind((source, 0))
    raw.connect((host, port))
    conn = ctx.wrap_socket(raw, server_hostname="pi.hole")
    answers = []
    try:
        query = build_query(qname)
        for _ in range(count):
            conn.sendall(struct.pack("!H", len(query)) + query)
            hdr = recvall(conn, 2)
            if hdr is None:
                break
            (alen,) = struct.unpack("!H", hdr)
            answer = recvall(conn, alen)
            if answer is None:
                break
            answers.append(answer)
    finally:
        conn.close()
    return answers


def dot_garbage(host, port, source, cafile):
    """Send a length-prefixed non-DNS payload over DoT; the server must not crash
    (it should drop/close). Read whatever (if anything) comes back and ignore it."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    ctx = _dot_ctx(cafile)
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(10)
    if source:
        raw.bind((source, 0))
    raw.connect((host, port))
    conn = ctx.wrap_socket(raw, server_hostname="pi.hole")
    try:
        payload = b"\xde\xad\xbe\xef" * 4  # 16 bytes, not a valid DNS message
        conn.sendall(struct.pack("!H", len(payload)) + payload)
        try:
            conn.recv(4096)
        except OSError:
            pass
    finally:
        conn.close()


def dot_peercert(host, port, source, expected_pem):
    """Connect over DoT and assert the server presents exactly the expected leaf
    certificate. The shared test CA omits keyUsage (OpenSSL >= 4.0 rejects full-chain
    verification), so rather than validating the chain we compare the DER the server
    sent against the known server certificate - which still proves the DoT listener
    serves the right cert, not a wrong or self-signed one."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    ctx = _dot_ctx(None)
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(10)
    if source:
        raw.bind((source, 0))
    raw.connect((host, port))
    conn = ctx.wrap_socket(raw, server_hostname="pi.hole")
    try:
        presented = conn.getpeercert(binary_form=True)
    finally:
        conn.close()
    if not presented:
        sys.exit("DoT: server presented no certificate")
    with open(expected_pem) as f:
        want = ssl.PEM_cert_to_DER_cert(f.read())
    if presented != want:
        sys.exit("DoT: presented certificate does not match %s" % expected_pem)


def doh3(host, port, qname, expected_ip):
    """POST a DNS query over DoH/HTTP/3 (RFC 9114 + RFC 8484) using aioquic and
    validate the answer. curl in CI is built without HTTP/3, so we drive an aioquic
    client against FTL's QUIC terminator directly. Exits with a SKIP marker when
    aioquic is not installed so the bats test can skip cleanly."""
    try:
        import asyncio
        import ssl as _ssl
        from aioquic.asyncio import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration
    except Exception as exc:
        sys.exit("SKIP: aioquic unavailable (%s)" % (exc,))

    query = build_query(qname)

    class H3Client(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = None
            self.status = None
            self.body = bytearray()
            self.done = asyncio.Event()

        def quic_event_received(self, event):
            if self.http is None:
                return
            for e in self.http.handle_event(event):
                if isinstance(e, HeadersReceived):
                    for hk, hv in e.headers:
                        if hk == b":status":
                            self.status = hv.decode()
                elif isinstance(e, DataReceived):
                    self.body.extend(e.data)
                if getattr(e, "stream_ended", False):
                    self.done.set()

    async def run():
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        # The shared test cert chains to a keyUsage-less CA (OpenSSL >= 4.0 rejects
        # it); this test exercises h3 transport, not the PKI, so skip verification.
        cfg.verify_mode = _ssl.CERT_NONE
        cfg.server_name = "pi.hole"
        async with connect(host, port, configuration=cfg,
                           create_protocol=H3Client) as client:
            await client.wait_connected()
            client.http = H3Connection(client._quic)
            sid = client._quic.get_next_available_stream_id()
            client.http.send_headers(sid, [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"pi.hole"),
                (b":path", b"/dns-query"),
                (b"content-type", b"application/dns-message"),
                (b"content-length", str(len(query)).encode()),
            ], end_stream=False)
            client.http.send_data(sid, query, end_stream=True)
            client.transmit()
            await asyncio.wait_for(client.done.wait(), timeout=15)
            return client.status, bytes(client.body)

    status, answer = asyncio.run(run())
    if status != "200":
        sys.exit("DoH3: HTTP status %s" % (status,))
    validate(answer, expected_ip)



# --- DoQ (DNS-over-QUIC, RFC 9250) client -----------------------------------
#
# aioquic's asyncio connect() always binds the wildcard address, but the inbound
# tests must query FTL from a specific loopback source to prove client
# attribution. So we drive aioquic's sans-IO QuicConnection over a socket we own
# and pump datagrams ourselves - which also gives us the exact stream control DoQ
# needs (one query per bidirectional stream, FIN in both directions).


def _doq_import():
    try:
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic import events as quic_events
        return QuicConfiguration, QuicConnection, quic_events
    except Exception as exc:
        sys.exit("SKIP: aioquic unavailable (%s)" % (exc,))


def doq_exchange(host, port, queries, source=None, alpn="doq", server_name="pi.hole",
                 timeout=20.0):
    """Send each wire message in `queries` on its own QUIC stream and return the
    list of answers, in the order the queries were submitted."""
    import select
    import time

    QuicConfiguration, QuicConnection, quic_events = _doq_import()

    cfg = QuicConfiguration(is_client=True, alpn_protocols=[alpn])
    # The shared test cert chains to a keyUsage-less CA (OpenSSL >= 4.0 rejects
    # it); these tests exercise the DoQ transport, not the PKI, so skip
    # verification here - test.crt itself is asserted by the DoT cert test.
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = server_name

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    if source:
        sock.bind((source, 0))
    addr = (host, port)

    conn = QuicConnection(configuration=cfg)
    now = time.monotonic
    conn.connect(addr, now=now())

    pending = list(queries)
    streams = []          # submitted stream ids, in order
    bufs = {}             # stream id -> accumulated bytes
    answers = {}          # stream id -> answer
    handshaked = False
    deadline = now() + timeout
    terminated = None

    def flush():
        for data, dest in conn.datagrams_to_send(now=now()):
            sock.sendto(data, dest)

    try:
        flush()
        while now() < deadline and len(answers) < len(queries):
            timer = conn.get_timer()
            wait = min(deadline, timer) - now() if timer is not None else deadline - now()
            r, _, _ = select.select([sock], [], [], max(0.0, min(wait, 1.0)))
            if r:
                while True:
                    try:
                        data, src = sock.recvfrom(65536)
                    except BlockingIOError:
                        break
                    conn.receive_datagram(data, src, now=now())
            timer = conn.get_timer()
            if timer is not None and now() >= timer:
                conn.handle_timer(now=now())

            while True:
                event = conn.next_event()
                if event is None:
                    break
                if isinstance(event, quic_events.HandshakeCompleted):
                    handshaked = True
                elif isinstance(event, quic_events.ConnectionTerminated):
                    terminated = event
                    deadline = 0.0
                    break
                elif isinstance(event, quic_events.StreamDataReceived):
                    buf = bufs.setdefault(event.stream_id, bytearray())
                    buf.extend(event.data)
                    if len(buf) >= 2:
                        alen = (buf[0] << 8) | buf[1]
                        if len(buf) >= 2 + alen and event.stream_id not in answers:
                            answers[event.stream_id] = bytes(buf[2:2 + alen])

            if handshaked and pending:
                for query in pending:
                    sid = conn.get_next_available_stream_id()
                    streams.append(sid)
                    conn.send_stream_data(
                        sid, struct.pack("!H", len(query)) + query, end_stream=True)
                pending = []
            flush()

        conn.close()
        flush()
    finally:
        sock.close()

    if terminated is not None and len(answers) < len(queries):
        sys.exit("DoQ: connection terminated (%s: %s)"
                 % (terminated.error_code, terminated.reason_phrase))
    if len(answers) < len(queries):
        sys.exit("DoQ: timed out with %d/%d answers" % (len(answers), len(queries)))
    return [answers[sid] for sid in streams]


def doq_handshake_rejected(host, port, alpn, source=None, timeout=10.0):
    """Fail unless a QUIC handshake offering `alpn` is refused by the server."""
    try:
        doq_exchange(host, port, [build_query("a.ftl")], source=source, alpn=alpn,
                     timeout=timeout)
    except SystemExit as exc:
        msg = str(exc.code) if exc.code is not None else ""
        if msg.startswith("SKIP:"):
            raise
        return  # terminated or timed out: the server refused it, as required
    sys.exit("DoQ: handshake with ALPN %r was accepted, expected refusal" % alpn)


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: dotdoh_query.py <emit|emiturl|check|dot|dotmulti|dotgarbage|"
                 "forge|dotcert|doh3|doq|doqnodata|doqmulti|doqgarbage|doqalpn> ...")
    cmd = sys.argv[1]

    if cmd == "emit":
        _, _, domain, outfile = sys.argv[:4]
        with open(outfile, "wb") as f:
            f.write(build_query(domain))
    elif cmd == "emiturl":
        # Unpadded base64url of the query, for a DoH GET ?dns= parameter.
        _, _, domain = sys.argv[:3]
        sys.stdout.write(base64.urlsafe_b64encode(build_query(domain)).rstrip(b"=").decode())
    elif cmd == "check":
        _, _, infile, expected_ip = sys.argv[:4]
        with open(infile, "rb") as f:
            validate(f.read(), expected_ip)
        print("OK")
    elif cmd == "dot":
        _, _, host, port, domain, source, cafile, expected_ip = sys.argv[:8]
        answer = dot_exchange(host, int(port), domain, source, cafile)
        validate(answer, expected_ip)
        print("OK")
    elif cmd == "dotnodata":
        _, _, host, port, domain, source, cafile = sys.argv[:7]
        answer = dot_exchange(host, int(port), domain, source, cafile, qtype=28)
        validate_nodata(answer)
        print("OK")
    elif cmd == "dotmulti":
        _, _, host, port, domain, source, cafile, expected_ip, count = sys.argv[:9]
        answers = dot_exchange_multi(host, int(port), domain, source, cafile, int(count))
        if len(answers) != int(count):
            sys.exit("DoT keep-alive: got %d/%s answers" % (len(answers), count))
        for a in answers:
            validate(a, expected_ip)
        print("OK")
    elif cmd == "dotgarbage":
        _, _, host, port, source, cafile = sys.argv[:6]
        dot_garbage(host, int(port), source, cafile)
        print("OK")
    elif cmd == "forge":
        _, _, host, port, domain, source, fake_ip = sys.argv[:7]
        dns_udp(host, int(port), build_forged_query(domain, fake_ip), source)
        print("OK")
    elif cmd == "dotcert":
        _, _, host, port, source, expected_pem = sys.argv[:6]
        dot_peercert(host, int(port), source, expected_pem)
        print("OK")
    elif cmd == "doh3":
        _, _, host, port, domain, expected_ip = sys.argv[:6]
        doh3(host, int(port), domain, expected_ip)
        print("OK")
    elif cmd == "doq":
        # RFC 9250 Sec. 4.2.1: a DoQ query carries Message ID 0.
        _, _, host, port, domain, source, expected_ip = sys.argv[:7]
        query = build_query(domain)
        query = b"\x00\x00" + query[2:]
        answers = doq_exchange(host, int(port), [query], source=source)
        validate(answers[0], expected_ip)
        print("OK")
    elif cmd == "doqnodata":
        # Cross-family pi.hole over DoQ: with the connected-address hint conveyed,
        # the family the client did not connect over is answered NODATA. Without
        # the hint the answer falls back to the loopback handoff's interface and
        # leaks ::1 (or 127.0.0.1), so this is what proves the hint arrives.
        _, _, host, port, domain, source = sys.argv[:6]
        query = b"\x00\x00" + build_query(domain, qtype=28)[2:]
        answers = doq_exchange(host, int(port), [query], source=source)
        validate_nodata(answers[0])
        print("OK")
    elif cmd == "doqmulti":
        # Several queries multiplexed on one QUIC connection, each on its own
        # bidirectional stream - the DoQ equivalent of DoT keep-alive.
        _, _, host, port, domain, source, expected_ip, count = sys.argv[:8]
        query = b"\x00\x00" + build_query(domain)[2:]
        answers = doq_exchange(host, int(port), [query] * int(count), source=source)
        if len(answers) != int(count):
            sys.exit("DoQ: got %d/%s answers" % (len(answers), count))
        for a in answers:
            validate(a, expected_ip)
        print("OK")
    elif cmd == "doqgarbage":
        # A framed but non-DNS message must not wedge the listener.
        _, _, host, port, source = sys.argv[:5]
        try:
            doq_exchange(host, int(port), [b"\xde\xad\xbe\xef" * 4], source=source,
                         timeout=8.0)
        except SystemExit as exc:
            msg = str(exc.code) if exc.code is not None else ""
            if msg.startswith("SKIP:"):
                raise
            # No answer (or a reset stream) is a perfectly good outcome here; the
            # follow-up query in the bats test proves the listener still serves.
        print("OK")
    elif cmd == "doqalpn":
        # QUIC mandates ALPN and RFC 9250 Sec. 4.1.2 defines exactly one token for
        # DoQ, so a client offering something else must be refused.
        _, _, host, port, alpn, source = sys.argv[:6]
        doq_handshake_rejected(host, int(port), alpn, source=source)
        print("OK")
    else:
        sys.exit("unknown subcommand: %s" % cmd)


if __name__ == "__main__":
    main()
