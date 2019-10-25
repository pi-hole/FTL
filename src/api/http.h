/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  HTTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef HTTP_H
#define HTTP_H

// External components
#include "../civetweb/civetweb.h"
#include "../cJSON/cJSON.h"

// strlen()
#include <string.h>

// FTLfree()
#include "../memory.h"

void http_init(void);
void http_terminate(void);
void http_send(struct mg_connection *conn, bool chunk, const char *format, ...) __attribute__ ((format (gnu_printf, 3, 4)));

#endif // HTTP_H