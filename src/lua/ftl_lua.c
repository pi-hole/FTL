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
// init_shmem
#include "../shmem.h"
#include "../datastructure.h"

/*
** Variations of 'lua_settable', used by 'db_getinfo' to put results
** from 'lua_getinfo' into result table. Key is always a string;
** value can be a string, an int, or a boolean.
*/
static void settabss (lua_State *L, const char *k, const char *v) {
  lua_pushstring(L, v);
  lua_setfield(L, -2, k);
}

static void settabsi (lua_State *L, const char *k, int v) {
  lua_pushinteger(L, v);
  lua_setfield(L, -2, k);
}

static void settabsb (lua_State *L, const char *k, int v) {
  lua_pushboolean(L, v);
  lua_setfield(L, -2, k);
}

static bool shm_connected = false;

static int pihole_ftl_version(lua_State *L) {
	lua_pushstring(L, get_FTL_version());
	return 1;
}

static int _pihole_connect(lua_State *L) {
	if(!init_shmem(false))
	{
		luaL_pushfail(L);
		lua_insert(L, -2);
		lua_pushliteral(L, "Cannot connect to running FTL");
		shm_connected = false;
		return LUA_ERRRUN;
	}
	shm_connected = true;
	return LUA_OK;
}

static int pihole_connect(lua_State *L) {
	return _pihole_connect(L);
}

static int pihole_counters(lua_State *L) {
	if(!shm_connected)
	{
		int ret = _pihole_connect(L);
		if(ret != LUA_OK)
			return ret;
	}
	lua_newtable(L);  /* table to collect results */
	settabsi(L, "queries", counters->queries);
	settabsi(L, "blocked", counters->blocked);
	settabsi(L, "cached", counters->cached);
	settabsi(L, "clients", counters->clients);
	settabsi(L, "domains", counters->domains);
	settabsi(L, "forwarded", counters->forwarded);
	settabsi(L, "gravity", counters->gravity);
	settabsi(L, "num_regex_white", counters->num_regex[0]);
	settabsi(L, "num_regex_black", counters->num_regex[1]);
	settabsi(L, "unknown", counters->unknown);
	settabsi(L, "upstreams", counters->upstreams);
	settabsi(L, "unknown", counters->unknown);
	return LUA_YIELD;
}

static const luaL_Reg piholelib[] = {
	{"ftl_version", pihole_ftl_version},
	{"connect", pihole_connect},
	{"counters", pihole_counters},
	{NULL, NULL}
};

LUAMOD_API int luaopen_pihole(lua_State *L) {
	luaL_newlib(L, piholelib);
	return LUA_YIELD;
}