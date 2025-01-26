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

// Hard-coded maximum number of allowed web server threads
#define MAX_WEBTHREADS 64
// Macro to limiting a numeric value to a certain minimum and maximum
#define LIMIT_MIN_MAX(a, b, c) ((a) < (b) ? (b) : (a) > (c) ? (c) : (a))

void http_init(void);
void http_terminate(void);

in_port_t get_https_port(void) __attribute__((pure));
unsigned short get_api_string(char **buf, const bool domain);

#endif // WEBSERVER_H
