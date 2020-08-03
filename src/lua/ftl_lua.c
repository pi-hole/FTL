/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  LUA routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "ftl_lua.h"
// struct luaL_Reg
#include "lauxlib.h"
// get_FTL_version()
#include "../log.h"

// pihole.ftl_version()
static int pihole_ftl_version(lua_State *L) {
	lua_pushstring(L, get_FTL_version());
	return 1;
}

static const luaL_Reg piholelib[] = {
	{"ftl_version", pihole_ftl_version},
	{NULL, NULL}
};

// Register pihole library
LUAMOD_API int luaopen_pihole(lua_State *L) {
	luaL_newlib(L, piholelib);
	return LUA_YIELD;
}

// Load bundled libraries and make the available globally
void ftl_lua_init(lua_State *L)
{
	dolibrary(L, "inspect");
}
