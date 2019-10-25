/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Socket prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SOCKET_H
#define SOCKET_H

void close_telnet_socket(void);
void seom(const int sock);
void ssend(const int sock, const char *format, ...) __attribute__ ((format (gnu_printf, 2, 3)));
void swrite(const int sock, const void* value, const size_t size);
void *telnet_listening_thread_IPv4(void *args);
void *telnet_listening_thread_IPv6(void *args);
bool ipv6_available(void);
void bind_sockets(void);

extern bool ipv4telnet, ipv6telnet;
extern bool istelnet[MAXCONNS];

#endif //SOCKET_H
