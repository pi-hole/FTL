/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  HTTP server prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <stdbool.h>
// in_port_t
#include <netinet/in.h>
// struct sockaddr_storage
#include <sys/socket.h>
// struct mg_connection
#include "webserver/civetweb/civetweb.h"

void http_init(void);
void http_terminate(void);
void *webserver_thread(void *val);
void get_all_supported_ciphersuites(void);

int ftl_http_redirect(struct mg_connection *conn, const int code, const char *format, ...) __attribute__((format(printf, 3, 4), nonnull(1, 3)));
in_port_t get_https_port(void) __attribute__((pure));
unsigned int get_https_ports(in_port_t *ports, unsigned int max_ports,
                             const struct in_addr *local_addr_v4,
                             const struct in6_addr *local_addr_v6,
                             sa_family_t query_family);
// Whether webserver.acl admits the client address sa (true when no ACL is set).
// An IPv4-mapped IPv6 address is matched as the IPv4 address it carries
bool webserver_acl_allows(const struct sockaddr_storage *sa);
unsigned short get_api_string(char **buf, int *bufflen, const bool domain);
char *get_prefix_webhome(void) __attribute__((pure));
char *get_api_uri(void) __attribute__((pure));

// Compile-time protocol capabilities of the advanced TLS backend, exposed so
// --version (compiled in core, which lacks the HTTP/2 and HTTP/3 build flags)
// can report them.
bool webserver_have_http2(void) __attribute__((const));
bool webserver_have_http3(void) __attribute__((const));

// Runtime listener state: whether HTTP/2 or HTTP/3 is actually being served
bool webserver_http2_active(void);
bool webserver_http3_active(void);
bool webserver_http3_active_on_port(const in_port_t port);

#endif // WEBSERVER_H
