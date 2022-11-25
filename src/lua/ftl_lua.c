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
#include <readline/history.h>
#include <wordexp.h>
#include "scripts/scripts.h"

int run_lua_interpreter(const int argc, char **argv, bool dnsmasq_debug)
{
	if(argc == 1) // No arguments after this one
		printf("Pi-hole FTL %s\n", get_FTL_version());
#if defined(LUA_USE_READLINE)
	wordexp_t word;
	wordexp(LUA_HISTORY_FILE, &word, WRDE_NOCMD);
	const char *history_file = NULL;
	if(word.we_wordc == 1)
	{
		history_file = word.we_wordv[0];
		const int ret_r = read_history(history_file);
		if(dnsmasq_debug)
		{
			printf("Reading history ... ");
			if(ret_r == 0)
				printf("success\n");
			else
				printf("error - %s: %s\n", history_file, strerror(ret_r));
		}

		// The history file may not exist, try to create an empty one in this case
		if(ret_r == ENOENT)
		{
			if(dnsmasq_debug)
			{
				printf("Creating new history file: %s\n", history_file);
			}
			FILE *history = fopen(history_file, "w");
			if(history != NULL)
				fclose(history);
		}
	}
#else
	if(dnsmasq_debug)
		printf("No readline available!\n");
#endif
	const int ret = lua_main(argc, argv);
#if defined(LUA_USE_READLINE)
	if(history_file != NULL)
	{
		const int ret_w = write_history(history_file);
		if(dnsmasq_debug)
		{
			printf("Writing history ... ");
			if(ret_w == 0)
				printf("success\n");
			else
				printf("error - %s: %s\n", history_file, strerror(ret_w));
		}

		wordfree(&word);
	}
#endif
	return ret;
}

int run_luac(const int argc, char **argv)
{
	if(argc == 1) // No arguments after this one
		printf("Pi-hole FTL %s\n", get_FTL_version());
	return luac_main(argc, argv);
}

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

static bool ftl_lua_load_embedded_script(lua_State *L, const char *name, const char *script, const size_t script_len, const bool make_global)
{
	// Explanation:
	// luaL_dostring(L, script)   expands to   (luaL_loadstring(L, script) || lua_pcall(L, 0, LUA_MULTRET, 0))
	// luaL_loadstring(L, script)   calls   luaL_loadbuffer(L, s, strlen(s), s)
	if (luaL_loadbufferx(L, script, script_len, name, NULL) || lua_pcall(L, 0, LUA_MULTRET, 0) != 0)
	{
		const char *lua_err = lua_tostring(L, -1);
		printf("LUA error while trying to import %s.lua: %s\n", name, lua_err);
		return false;
	}

	if(make_global)
	{
		/* Set global[name] = luaL_dostring return */
		lua_setglobal(L, name);
	}

	return true;
}

struct {
	const char *name;
	const char *content;
	const size_t contentlen;
	const bool global;
} scripts[] =
{
	{"inspect", inspect_lua, sizeof(inspect_lua), true},
};

// Loop over bundled LUA libraries and print their names on the console
void print_embedded_scripts(void)
{
	for(unsigned int i = 0; i < sizeof(scripts)/sizeof(scripts[0]); i++)
	{
		char prefix[2] = { 0 };
		double formatted = 0.0;
		format_memory_size(prefix, scripts[i].contentlen, &formatted);

		printf("%s.lua (%.2f %sB) ", scripts[i].name, formatted, prefix);
	}
}

// Loop over bundled LUA libraries and load them
void ftl_lua_init(lua_State *L)
{
	for(unsigned int i = 0; i < sizeof(scripts)/sizeof(scripts[0]); i++)
		ftl_lua_load_embedded_script(L, scripts[i].name, scripts[i].content, scripts[i].contentlen, scripts[i].global);
}
