/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Lua-related webserver prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LUA_WEB_H
#define LUA_WEB_H

// definition of struct mg_connection
#include "http-common.h"

void allocate_lua(void);
void free_lua(void);
void init_lua(const struct mg_connection *conn, void *L, unsigned context_flags);
int request_handler(struct mg_connection *conn, void *cbdata);

#endif // LUA_WEB_H