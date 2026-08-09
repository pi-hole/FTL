/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  In-process TLS front terminator (HTTP/1.1, HTTP/2, HTTP/3)
*
*  Terminates TLS on the public port and forwards plain HTTP/1.1 to the CivetWeb
*  backend on the loopback interface. HTTP/2 (nghttp2) and HTTP/3 (nghttp3/QUIC)
*  are bridged to the same backend; CivetWeb itself stays HTTP/1.1-only.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef WEBSERVER_TERMINATOR_H
#define WEBSERVER_TERMINATOR_H

#include <stdbool.h>
#include <stddef.h> // size_t

// Upper bound on the public TLS ports the terminator serves at once. More
// secure entries than this in webserver.port are reported and ignored.
#define TERMINATOR_MAX_LISTENERS 8

// One public TLS listener: the port and the address it is scoped to (NULL or ""
// for all interfaces, else an IPv4/IPv6 literal).
struct terminator_listener {
	const char *addr;
	int port;
};

// Start the TLS terminator on every entry of listeners: terminate TLS with the
// PEM (cert + key) at cert_path and forward accepted connections as plain
// HTTP/1.1 to 127.0.0.1:backend_port. Spawns one accept thread serving all of
// them. HTTP/3 is served on the first entry only. Returns true if at least one
// listener came up; on total failure nothing is left running.
bool terminator_start(const struct terminator_listener *listeners, unsigned n_listeners,
                      int backend_port, const char *cert_path);

// Stop the terminator and free all resources. Safe to call if never started or already stopped.
void terminator_stop(void);

// Hex-encode the per-boot token (generating it if needed) into out, which must
// hold at least 33 bytes. webserver.c passes it to the loopback CivetWeb backend
// as "proxy_protocol_secret", the shared secret the backend uses to authenticate
// our PROXY v2 headers. Returns false if out is too small or the RNG fails.
bool terminator_proxy_token_hex(char *out, size_t outsz);

#endif // WEBSERVER_TERMINATOR_H
