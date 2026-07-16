/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  In-process TLS front terminator (HTTP/1.1)
*
*  Terminates TLS on the public port and forwards plain HTTP/1.1 to the CivetWeb
*  backend on the loopback interface. This is milestone M1 (HTTP/1.1 only); the
*  terminator is the foundation for HTTP/2 (nghttp2) and HTTP/3 (nghttp3/QUIC),
*  which are added in later milestones. CivetWeb itself stays HTTP/1.1-only.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef WEBSERVER_TERMINATOR_H
#define WEBSERVER_TERMINATOR_H

#include <stdbool.h>

// Start the TLS terminator: bind public_port on all interfaces, terminate TLS
// using the certificate (PEM with certificate and private key) at cert_path,
// and forward accepted connections as plain HTTP/1.1 to 127.0.0.1:backend_port
// (the CivetWeb backend). Spawns its own accept thread. Returns true on
// success; on failure nothing is left running.
bool terminator_start(int public_port, int backend_port, const char *cert_path);

// Stop the terminator and release all resources. Safe to call even if the
// terminator was never started or already stopped.
void terminator_stop(void);

#endif // WEBSERVER_TERMINATOR_H
