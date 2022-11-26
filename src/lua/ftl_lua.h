/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  LUA prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_LUA_H
#define FTL_LUA_H

#include "lua.h"
#include <stdbool.h>

#define LUA_HISTORY_FILE "~/.pihole_lua_history"

int run_lua_interpreter(const int argc, char **argv, bool dnsmasq_debug);
int run_luac(const int argc, char **argv);

int lua_main (int argc, char **argv);
int luac_main (int argc, char **argv);

extern int dolibrary (lua_State *L, char *name);

void print_embedded_scripts(void);
void ftl_lua_init(lua_State *L);

#endif //FTL_LUA_H