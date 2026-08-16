#!/usr/bin/env python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# HTTP(S) test shim for pihole.download()
#
# Serves the response shapes FTL's own web server cannot produce on demand:
# chunked bodies, redirects and a body that never ends. Listens on 8099 (plain)
# and 8098 (TLS, using the repo test certificate). See test/test_suite.bats.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

import gzip
import http.server
import ssl
import threading
import time

PLAIN_PORT = 8099
TLS_PORT = 8098
# Comfortably above the 16 MiB cap in src/webserver/http-client.h
HUGE_BLOCKS = 400
BLOCK = b"x" * 65536


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _chunks(self, parts):
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for part in parts:
                self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            # Expected once FTL aborts an oversized transfer
            pass

    def do_GET(self):
        if self.path == "/chunked":
            self._chunks([b"AAA", b"BBB", b"CCC"])
        elif self.path == "/chunked-huge":
            # No Content-Length, so CURLOPT_MAXFILESIZE_LARGE cannot see this
            # coming - only the write callback can stop it
            self._chunks(BLOCK for _ in range(HUGE_BLOCKS))
        elif self.path == "/redirect":
            self._redirect("/final")
        elif self.path == "/redirect-relative":
            self._redirect("a/../final")
        elif self.path == "/redirect-loop":
            self._redirect("/redirect-loop")
        elif self.path == "/downgrade":
            self._redirect("http://127.0.0.1:%d/final" % PLAIN_PORT)
        elif self.path == "/to-file":
            # A server must not be able to talk us into reading a local file
            self._redirect("file:///etc/passwd")
        elif self.path == "/gzip":
            body = gzip.compress(b"GZIPPED" * 1000)
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/gzip-bomb":
            # ~64 MiB of zeroes in a handful of KB: only a cap counting
            # decompressed bytes stops this
            body = gzip.compress(b"\0" * (64 * 1024 * 1024))
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/slow":
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                for _ in range(1000):
                    self.wfile.write(b"z")
                    self.wfile.flush()
                    time.sleep(1)
            except (BrokenPipeError, ConnectionResetError):
                pass
        elif self.path == "/final":
            body = b"FINAL"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


def main():
    plain = http.server.ThreadingHTTPServer(("127.0.0.1", PLAIN_PORT), Handler)
    tls = http.server.ThreadingHTTPServer(("127.0.0.1", TLS_PORT), Handler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("test/test.pem")
    tls.socket = context.wrap_socket(tls.socket, server_side=True)

    threading.Thread(target=plain.serve_forever, daemon=True).start()
    tls.serve_forever()


if __name__ == "__main__":
    main()
