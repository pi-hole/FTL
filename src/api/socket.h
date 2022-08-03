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

// enum telnet_type
#include "../enums.h"

struct thread_info {
	int fd;
	int tid;
	bool istelnet;
	const char *stype;
};

void saveport(int port);
void close_unix_socket(bool unlink_file);
void seom(const int sock, const bool istelnet);
#define ssend(sock, format, ...) _ssend(sock, __FILE__, __FUNCTION__,  __LINE__, format, ##__VA_ARGS__)
bool _ssend(const int sock, const char *file, const char *func, const int line, const char *format, ...) __attribute__ ((format (gnu_printf, 5, 6)));
void listen_telnet(const enum telnet_type type);

#endif //SOCKET_H
