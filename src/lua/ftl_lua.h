/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  LUA prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LUA_H
#define LUA_H

#include "lua.h"

#define LUA_HISTORY_FILE "~/.pihole_lua_history"

int lua_main (int argc, char **argv);
int luac_main (int argc, char **argv);

extern int dolibrary (lua_State *L, const char *name);

void ftl_lua_init(lua_State *L);

#endif //LUA_H