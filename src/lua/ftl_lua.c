/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  LUA routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "ftl_lua.h"

#include "FTL.h"
// struct luaL_Reg
#include "lauxlib.h"
// get_FTL_version()
#include "log.h"
// config struct
#include "config/config.h"
// file_exists
#include "files.h"
// get_web_theme_str
#include "datastructure.h"
#include "api/api.h"
#include "scripts/scripts.h"
// get_prefix_webhome(), get_api_uri()
#include "webserver/webserver.h"

// prototype for luaopen_pihole()
#include "lualib.h"

#if defined(LUA_USE_READLINE)
# include <readline/history.h>
#endif
#include <wordexp.h>

// hostname()
#include "daemon.h"


int run_lua_interpreter(const int argc, char **argv, bool debug)
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
		if(debug)
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
			if(debug)
			{
				printf("Creating new history file: %s\n", history_file);
			}
			FILE *history = fopen(history_file, "w");
			if(history != NULL)
				fclose(history);
		}
	}
#else
	if(debug)
		printf("No readline available!\n");
#endif
	const int ret = lua_main(argc, argv);
#if defined(LUA_USE_READLINE)
	if(history_file != NULL)
	{
		const int ret_w = write_history(history_file);
		if(debug)
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
	const char *version = get_FTL_version();
	lua_pushexternalstring(L, version, strlen(version), NULL, NULL);
	return 1; // number of results
}

// pihole.hostname()
static int pihole_hostname(lua_State *L) {
	// Get and immediately push host name
	const char *hname = hostname();
	lua_pushexternalstring(L, hname, strlen(hname), NULL, NULL);
	return 1; // number of results
}

static void get_abspath(char abs_filename[1024], char rel_filename[1024], const char *filename)
{
	size_t abs_filename_len = 1023;
	size_t rel_filename_len = 1023;
	if(config.webserver.paths.webroot.v.s != NULL)
	{
		strncpy(abs_filename, config.webserver.paths.webroot.v.s, abs_filename_len);
		abs_filename_len -= strlen(config.webserver.paths.webroot.v.s);
	}

	// Add prefix to rel_filename if applicable
	if(rel_filename != NULL && config.webserver.paths.prefix.v.s[0] != '\0')
	{
		strncpy(rel_filename, config.webserver.paths.prefix.v.s, rel_filename_len);
		rel_filename_len -= strlen(config.webserver.paths.prefix.v.s);
	}

	// Add webhome to abs_filename and rel_filename if applicable
	if(config.webserver.paths.webhome.v.s != NULL)
	{
		strncat(abs_filename, config.webserver.paths.webhome.v.s, abs_filename_len);
		abs_filename_len -= strlen(config.webserver.paths.webhome.v.s);

		// Add webhome to rel_filename
		if(rel_filename != NULL)
		{
			strncat(rel_filename, config.webserver.paths.webhome.v.s, rel_filename_len);
			rel_filename_len -= strlen(config.webserver.paths.webhome.v.s);
		}
	}
	strncat(abs_filename, filename, abs_filename_len);
	if(rel_filename != NULL)
		strncat(rel_filename, filename, rel_filename_len);
}

// pihole.fileversion(<filename:str>)
// Avoid browser caching old versions of a file, using the last modification time
//   Receive the file URL (without "/admin/");
//   Return the string containin URL + "?v=xxx", where xxx is the last modified time of the file.
static int pihole_fileversion(lua_State *L) {
	// Get filename (first argument to LUA function)
	const char *filename = luaL_checkstring(L, 1);

	// Construct full filename if webroot/webhome are available
	char abspath[1024] = { 0 };
	char relpath[1024] = { 0 };
	get_abspath(abspath, relpath, filename);

	// Check if file exists
	if(!file_exists(abspath))
	{
		// File does not exist, return filename.
		log_warn("Requested file \"%s\" does not exist",
		         abspath);
		lua_pushstring(L, relpath);
		return 1; // number of results
	}

	// Get last modification time
	struct stat filestat;
	if (stat(abspath, &filestat) == -1)
	{
		log_warn("Could not get file modification time for \"%s\": %s",
		         abspath, strerror(errno));
		lua_pushstring(L, relpath);
		return 1; // number of results
	}

	// Cast to long long to avoid warnings on 32-bit systems
	log_debug(DEBUG_API, "File \"%s\" -> \"%s\" last modified at %lld",
	          abspath, relpath, (long long)filestat.st_mtime);

	// Return filename + modification time
	lua_pushfstring(L, "%s?v=%d", relpath, filestat.st_mtime);
	return 1; // number of results
}

// pihole.webtheme()
static int pihole_webtheme(lua_State *L) {
	// Get currently configured webtheme
	const struct web_themes this_theme = webthemes[config.webserver.interface.theme.v.web_theme];
	// Create a Lua table
	lua_newtable(L);

	// Set table["name"] = this_theme.name (string)
	lua_pushliteral(L, "name");
	lua_pushstring(L, this_theme.name);
	lua_settable(L, -3);

	// Set table["dark"] = this_theme.dark (boolean)
	lua_pushliteral(L, "dark");
	lua_pushboolean(L, this_theme.dark);
	lua_settable(L, -3);

	// Set table["color"] = this_theme.color (string)
	lua_pushliteral(L, "color");
	lua_pushstring(L, this_theme.color);
	lua_settable(L, -3);

	// Return there is one result on the stack
	return 1;
}

// pihole.webhome()
static int pihole_webhome(lua_State *L) {
	// Get name of currently set webhome
	lua_pushstring(L, get_prefix_webhome());
	return 1; // number of results
}

// pihole.include(<filename:str>)
static int pihole_include(lua_State *L) {
	// Get filename (first argument to LUA function)
	const char *filename = luaL_checkstring(L, 1);

	// Construct full filename if webroot/webhome are available
	char abspath[1024] = { 0 };
	get_abspath(abspath, NULL, filename);

	// Load and execute file
	luaL_dofile(L, abspath);

	return 0; // number of results
}

// pihole.boxedlayout()
static int pihole_boxedlayout(lua_State *L) {
	lua_pushboolean(L, config.webserver.interface.boxed.v.b);
	return 1; // number of results
}

// pihole.needLogin()
static int pihole_needLogin(lua_State *L) {
	// Check if password is set
	const bool has_password = config.webserver.api.pwhash.v.s != NULL &&
	                          config.webserver.api.pwhash.v.s[0] != '\0';

	lua_pushboolean(L, has_password);
	return 1; // number of results
}

// pihole.api_url()
static int pihole_api_url(lua_State *L) {
	// Return API URL
	lua_pushstring(L, get_api_uri());

	return 1; // number of results
}

// pihole.format_path()
static int pihole_format_path(lua_State *L) {
	// Get current page (first argument to LUA function)
	const char *page = luaL_checkstring(L, 1);

	// Duplicate string to modify it
	char *page_copy = strdup(page);
	if (page_copy == NULL)
	{
		// Memory allocation error
		lua_pushnil(L);
		return 1; // number of results
	}

	// Strip leading webhome from page_copy (if it exists)
	char *page_copy_start = page_copy;
	if (config.webserver.paths.webhome.v.s != NULL)
	{
		const size_t webhome_len = strlen(config.webserver.paths.webhome.v.s);
		if (strncmp(page_copy, config.webserver.paths.webhome.v.s, webhome_len) == 0)
			page_copy += webhome_len;
	}

	// Convert all / to -
	for (char *p = (char *)page_copy; *p != '\0'; p++)
		if (*p == '/')
			*p = '-';

	if (page_copy[0] == '\0')
	{
		// Substitute "index" for empty string (dashboard landing page)
		lua_pushstring(L, "index");
	}
	else
	{
		// Return the formatted page string
		lua_pushstring(L, page_copy);
	}

	// Free originally allocated memory (page_copy may have been modified)
	free(page_copy_start);

	return 1; // number of results
}

static const luaL_Reg piholelib[] = {
	{"ftl_version", pihole_ftl_version},
	{"hostname", pihole_hostname},
	{"fileversion", pihole_fileversion},
	{"webtheme", pihole_webtheme},
	{"webhome", pihole_webhome},
	{"include", pihole_include},
	{"boxedlayout", pihole_boxedlayout},
	{"needLogin", pihole_needLogin},
	{"api_url", pihole_api_url},
	{"format_path", pihole_format_path},
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
