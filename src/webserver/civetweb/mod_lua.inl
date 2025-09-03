/* This file is part of the CivetWeb web server.
 * See https://github.com/civetweb/civetweb/
 */

#if !defined(_WIN32)
#include <dlfcn.h>
#include <sys/mman.h>
#endif

#include "civetweb_lua.h"
#include "civetweb_private_lua.h"

/* Prototypes */
static int lua_error_handler(lua_State *L);

#if defined(_WIN32)
static void *
mmap(void *addr, int64_t len, int prot, int flags, int fd, int offset)
{
	/* TODO (low): This is an incomplete implementation of mmap for windows.
	 * Currently it is sufficient, but there are a lot of unused parameters.
	 * Better use a function "mg_map" which only has the required parameters,
	 * and implement it using mmap in Linux and CreateFileMapping in Windows.
	 * No one should expect a full mmap for Windows here.
	 */
	HANDLE fh = (HANDLE)_get_osfhandle(fd);
	HANDLE mh = CreateFileMapping(fh, 0, PAGE_READONLY, 0, 0, 0);
	void *p = MapViewOfFile(mh, FILE_MAP_READ, 0, 0, (size_t)len);
	CloseHandle(mh);

	/* unused parameters */
	(void)addr;
	(void)prot;
	(void)flags;
	(void)offset;

	return p;
}


static void
munmap(void *addr, int64_t length)
{
	/* unused parameters */
	(void)length;

	UnmapViewOfFile(addr);
}


#define MAP_PRIVATE (0)
#define PROT_READ (0)
#endif


static const char *const LUASOCKET = "luasocket";
static const char lua_regkey_ctx = 1;
static const char lua_regkey_connlist = 2;
static const char lua_regkey_lsp_include_history = 3;
static const char lua_regkey_environment_type = 4;
static const char lua_regkey_dtor = 5;


/* Limit nesting depth of mg.include.
 * This takes a lot of stack (~10 kB per recursion),
 * so do not use a too high limit. */
#if !defined(LSP_INCLUDE_MAX_DEPTH)
#define LSP_INCLUDE_MAX_DEPTH (10)
#endif


/* Forward declarations */
static int handle_lsp_request(struct mg_connection *,
                              const char *,
                              struct mg_file *,
                              struct lua_State *);


static void
reg_lstring(struct lua_State *L,
            const char *name,
            const void *buffer,
            size_t buflen)
{
	if (name != NULL && buffer != NULL) {
		lua_pushstring(L, name);
		lua_pushlstring(L, (const char *)buffer, buflen);
		lua_rawset(L, -3);
	}
}


static void
reg_llstring(struct lua_State *L,
             const void *buffer1,
             size_t buflen1,
             const void *buffer2,
             size_t buflen2)
{
	if (buffer1 != NULL && buffer2 != NULL) {
		lua_pushlstring(L, (const char *)buffer1, buflen1);
		lua_pushlstring(L, (const char *)buffer2, buflen2);
		lua_rawset(L, -3);
	}
}


#define reg_string(L, name, val)                                               \
	reg_lstring(L, name, val, (val != NULL) ? strlen(val) : 0)


static void
reg_int(struct lua_State *L, const char *name, int val)
{
	if (name != NULL) {
		lua_pushstring(L, name);
		lua_pushinteger(L, val);
		lua_rawset(L, -3);
	}
}


static void
reg_i64(struct lua_State *L, const char *name, int64_t val)
{
	if (name == NULL) {
		return;
	}
	lua_pushstring(L, name);
	if (sizeof(lua_Integer) >= sizeof(val)) {
		lua_pushinteger(L, (lua_Integer)val);
	} else {
		double d = (double)val;
		lua_pushnumber(L, d);
	}
	lua_rawset(L, -3);
}


static void
reg_double(struct lua_State *L, const char *name, double val)
{
	if (name != NULL) {
		lua_pushstring(L, name);
		lua_pushnumber(L, val);
		lua_rawset(L, -3);
	}
}


static void
reg_boolean(struct lua_State *L, const char *name, int val)
{
	if (name != NULL) {
		lua_pushstring(L, name);
		lua_pushboolean(L, val != 0);
		lua_rawset(L, -3);
	}
}


static void
reg_conn_function(struct lua_State *L,
                  const char *name,
                  lua_CFunction func,
                  struct mg_connection *conn)
{
	if (name != NULL && func != NULL && conn != NULL) {
		lua_pushstring(L, name);
		lua_pushlightuserdata(L, conn);
		lua_pushcclosure(L, func, 1);
		lua_rawset(L, -3);
	}
}


static void
reg_function(struct lua_State *L, const char *name, lua_CFunction func)
{
	if (name != NULL && func != NULL) {
		lua_pushstring(L, name);
		lua_pushcclosure(L, func, 0);
		lua_rawset(L, -3);
	}
}


static void
lua_cry(const struct mg_connection *conn,
        int err,
        lua_State *L,
        const char *lua_title,
        const char *lua_operation)
{
	DEBUG_TRACE("lua_cry (err=%i): %s: %s", err, lua_title, lua_operation);

	switch (err) {
	case LUA_OK:
	case LUA_YIELD:
		break;
	case LUA_ERRRUN:
		mg_cry_internal(conn,
		                "%s: %s failed: runtime error: %s",
		                lua_title,
		                lua_operation,
		                lua_tostring(L, -1));
		break;
	case LUA_ERRSYNTAX:
		mg_cry_internal(conn,
		                "%s: %s failed: syntax error: %s",
		                lua_title,
		                lua_operation,
		                lua_tostring(L, -1));
		break;
	case LUA_ERRMEM:
		mg_cry_internal(conn,
		                "%s: %s failed: out of memory",
		                lua_title,
		                lua_operation);
		break;
#if LUA_VERSION_NUM < 504
	/* LUA_ERRGCMM has been removed in Lua 5.4.
	 * See https://www.lua.org/manual/5.4/manual.html#8.3 */
	case LUA_ERRGCMM:
		mg_cry_internal(conn,
		                "%s: %s failed: error during garbage collection",
		                lua_title,
		                lua_operation);
		break;
#endif
	case LUA_ERRERR:
		mg_cry_internal(conn,
		                "%s: %s failed: error in error handling: %s",
		                lua_title,
		                lua_operation,
		                lua_tostring(L, -1));
		break;
	default:
		mg_cry_internal(
		    conn, "%s: %s failed: error %i", lua_title, lua_operation, err);
		break;
	}
}


static int
lsp_sock_close(lua_State *L)
{
	int num_args = lua_gettop(L);
	size_t s;
	SOCKET *psock;

	if ((num_args == 1) && lua_istable(L, 1)) {
		lua_getfield(L, -1, "sock");
		psock = (SOCKET *)lua_tolstring(L, -1, &s);
		if (s != sizeof(SOCKET)) {
			return luaL_error(L, "invalid internal state in :close() call");
		}
		/* Do not closesocket(*psock); here, close it in __gc */
		(void)psock;
	} else {
		return luaL_error(L, "invalid :close() call");
	}
	return 0;
}


static int
lsp_sock_recv(lua_State *L)
{
	int num_args = lua_gettop(L);
	char buf[2000];
	int n;
	size_t s;
	SOCKET *psock;

	if ((num_args == 1) && lua_istable(L, 1)) {
		lua_getfield(L, -1, "sock");
		psock = (SOCKET *)lua_tolstring(L, -1, &s);
		if (s != sizeof(SOCKET)) {
			return luaL_error(L, "invalid internal state in :recv() call");
		}
		n = recv(*psock, buf, sizeof(buf), 0);
		if (n <= 0) {
			lua_pushnil(L);
		} else {
			lua_pushlstring(L, buf, n);
		}
	} else {
		return luaL_error(L, "invalid :recv() call");
	}
	return 1;
}


static int
lsp_sock_send(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *buf;
	size_t len, sent = 0;
	int n = 0;
	size_t s;
	SOCKET *psock;

	if ((num_args == 2) && lua_istable(L, -2) && lua_isstring(L, -1)) {
		buf = lua_tolstring(L, -1, &len);
		lua_getfield(L, -2, "sock");
		psock = (SOCKET *)lua_tolstring(L, -1, &s);
		if (s != sizeof(SOCKET)) {
			return luaL_error(L, "invalid internal state in :close() call");
		}

		while (sent < len) {
			if ((n = send(*psock, buf + sent, (int)(len - sent), 0)) <= 0) {
				break;
			}
			sent += n;
		}
		lua_pushnumber(L, n);
	} else {
		return luaL_error(L, "invalid :close() call");
	}
	return 1;
}


static int
lsp_sock_gc(lua_State *L)
{
	int num_args = lua_gettop(L);
	size_t s;
	SOCKET *psock;

	if ((num_args == 1) && lua_istable(L, 1)) {
		lua_getfield(L, -1, "sock");
		psock = (SOCKET *)lua_tolstring(L, 1, &s);
		if (s != sizeof(SOCKET)) {
			return luaL_error(
			    L,
			    "invalid internal state in __gc for object created by connect");
		}
		closesocket(*psock);
	} else {
		return luaL_error(L, "__gc for object created by connect failed");
	}
	return 0;
}


/* Methods and meta-methods supported by the object returned by connect.
 * For meta-methods, see http://lua-users.org/wiki/MetatableEvents */
static const struct luaL_Reg luasocket_methods[] = {{"close", lsp_sock_close},
                                                    {"send", lsp_sock_send},
                                                    {"recv", lsp_sock_recv},
                                                    {"__gc", lsp_sock_gc},
                                                    {NULL, NULL}};


static int
lsp_connect(lua_State *L)
{
	int num_args = lua_gettop(L);
	struct mg_error_data error;
	char ebuf[128];
	SOCKET sock;
	union usa sa;
	int ok;

	memset(&error, 0, sizeof(error));
	error.text = ebuf;
	error.text_buffer_size = sizeof(ebuf);

	if ((num_args == 3) && lua_isstring(L, 1) && lua_isnumber(L, 2)
	    && lua_isnumber(L, 3)) {

		const char *host = lua_tostring(L, 1);
		const int port = (int)lua_tointeger(L, 2);
		const int is_ssl = (int)lua_tointeger(L, 3);

		ok = connect_socket(NULL, host, port, is_ssl, &error, &sock, &sa);
		if (!ok) {
			return luaL_error(L, error.text);
		} else {
			set_blocking_mode(sock);
			lua_newtable(L);
			reg_lstring(L, "sock", (const char *)&sock, sizeof(SOCKET));
			reg_string(L, "host", lua_tostring(L, -4));
			luaL_getmetatable(L, LUASOCKET);
			lua_setmetatable(L, -2);
		}
	} else {
		return luaL_error(
		    L, "connect(host,port,is_ssl): invalid parameter given.");
	}
	return 1;
}


static int
lsp_error(lua_State *L)
{
	DEBUG_TRACE("%s", "lsp_error");
	lua_getglobal(L, "mg");
	lua_getfield(L, -1, "onerror");
	lua_pushvalue(L, -3);
	lua_pcall(L, 1, 0, 0);
	return 0;
}


/* Silently stop processing chunks. */
static void
lsp_abort(lua_State *L)
{
	int top = lua_gettop(L);
	DEBUG_TRACE("%s", "lsp_abort");
	lua_getglobal(L, "mg");
	lua_pushnil(L);
	lua_setfield(L, -2, "onerror");
	lua_settop(L, top);
	lua_pushstring(L, "aborting");
	lua_error(L);
}


struct lsp_var_reader_data {
	int64_t len;
	int64_t consumed;
	const char *begin;
	unsigned char state;
	char tag;
};


/* Helper function to read the content of variable values */
static const char *
lsp_var_reader(lua_State *L, void *ud, size_t *sz)
{
	struct lsp_var_reader_data *reader = (struct lsp_var_reader_data *)ud;
	const char *ret;
	(void)(L); /* unused */

	/* This reader is called multiple times, to fetch the full Lua script */
	switch (reader->state) {
	case 0:
		/* First call: what function to call */
		reader->consumed = 0;
		ret = "mg.write(";
		*sz = strlen(ret);
		break;
	case 1:
		/* Second call: forward variable name */
		ret = reader->begin;
		*sz = (size_t)reader->len;
		reader->consumed += reader->len;
		break;
	case 2:
		/* Third call: close function call */
		ret = ")";
		*sz = strlen(ret);
		break;
	default:
		/* Forth/Final call: tell Lua we got the entire script */
		ret = 0;
		*sz = 0;
	}

	/* Step to the next state for the next call */
	reader->state++;
	return ret;
}


static const char *
lsp_kepler_reader(lua_State *L, void *ud, size_t *sz)
{
	struct lsp_var_reader_data *reader = (struct lsp_var_reader_data *)ud;
	const char *ret;
	int64_t i;
	int64_t left;

	(void)(L); /* unused */

	/* This reader is called multiple times, to fetch the full Lua script */

	if (reader->state == 0) {
		/* First call: Send opening tag - what function to call */
		ret = "mg.write([=======[";
		*sz = strlen(ret);
		reader->state = 1;
		reader->consumed = 0;
		return ret;
	}

	if (reader->state == 4) {
		/* Final call: Tell Lua reader, we reached the end */
		*sz = 0;
		return 0;
	}

	left = reader->len - reader->consumed;
	if (left == 0) {
		/* We reached the end of the file/available data. */
		/* Send closing tag. */
		ret = "]=======]);\n";
		*sz = strlen(ret);
		reader->state = 4; /* Next will be the final call */
		return ret;
	}
	if (left > MG_BUF_LEN / 100) {
		left = MG_BUF_LEN / 100; /* TODO XXX */
	}
	i = 0;

	if (reader->state == 1) {
		/* State 1: plain text - put inside mg.write(...) */
		for (;;) {
			/* Find next tag */
			while ((i < left) && (reader->begin[i + reader->consumed] != '<')) {
				i++;
			}
			if (i > 0) {
				/* Forward all data until the next tag */
				int64_t j = reader->consumed;
				reader->consumed += i;
				*sz = (size_t)i; /* cast is ok, i is limited to MG_BUF_LEN */
				return reader->begin + j;
			}

			/* assert (reader->begin[reader->state] == '<') */
			/* assert (i == 0) */
			if (0 == memcmp(reader->begin + reader->consumed, "<?lua", 5)) {
				/* kepler <?lua syntax */
				i = 5;
				reader->tag = '?';
				break;
			} else if (0 == memcmp(reader->begin + reader->consumed, "<%", 2)) {
				/* kepler <% syntax */
				i = 2;
				reader->tag = '%';
				break;
			} else if (0 == memcmp(reader->begin + reader->consumed, "<?", 2)) {
				/* civetweb <? syntax */
				i = 2;
				reader->tag = '?';
				break;
			} else {
				i = 1;
			}
		}
		/* We found an opening or closing tag, or we reached the end of the
		 * file/data block */
		if (reader->begin[reader->consumed + i] == '=') {
			/* Lua= tag - Lua expression to print */
			ret = "]=======]);\nmg.write(";
			reader->state = 3;
			i++;
		} else {
			/* Normal Lua tag - Lua chunk */
			ret = "]=======]);\n";
			reader->state = 2;
		}
		*sz = strlen(ret);
		reader->consumed += i; /* length of <?lua or <% tag */
		return ret;
	}

	if ((reader->state == 2) || (reader->state == 3)) {
		/* State 2: Lua chunkg - keep outside mg.write(...) */
		/* State 3: Lua expression - inside mg.write(...) */

		for (;;) {
			int close_tag_found = 0;

			/* Find end tag */
			while ((i < left)
			       && (reader->begin[i + reader->consumed] != reader->tag)) {
				i++;
			}
			if (i > 0) {
				/* Forward all data inside the Lua script tag */
				int64_t j = reader->consumed;
				reader->consumed += i;
				*sz = (size_t)i; /* cast is ok, i is limited to MG_BUF_LEN */

				return reader->begin + j;
			}

			/* Is this the closing tag we are looking for? */
			close_tag_found =
			    ((i + 1 < left)
			     && (reader->begin[i + 1 + reader->consumed] == '>'));

			if (close_tag_found) {
				/* Drop close tag */
				reader->consumed += 2;

				if (reader->state == 2) {
					/* Send a new opening tag to Lua */
					ret = ";\nmg.write([=======[";
				} else {
					ret = ");\nmg.write([=======[";
				}
				*sz = strlen(ret);
				reader->state = 1;
				return ret;
			} else {
				/* Not a close tag, continue searching */
				i++;
			}
		}
	}


	/* Must never be reached */
	*sz = 0;
	return 0;
}


static int
run_lsp_kepler(struct mg_connection *conn,
               const char *path,
               const char *p,
               int64_t len,
               lua_State *L,
               int depth)
{

	int lua_ok;
	struct lsp_var_reader_data data;
	char date[64];
	time_t curtime = time(NULL);

	gmt_time_string(date, sizeof(date), &curtime);

	if (depth == 1) {
		/* Top level page assumes keep_alive is disabled.
		 * Do not overwrite this setting for included pages. */
		conn->must_close = 1;

		/* Only send a HTML header, if this is the top level page.
		 * If this page is included by some mg.include calls, do not add a
		 * header. */

		/* Initialize a new HTTP response, either with some-predefined
		 * status code (e.g. 404 if this is called from an error
		 * handler) or with 200 OK */
		mg_response_header_start(conn,
		                         conn->status_code > 0 ? conn->status_code
		                                               : 200);

		/* Add additional headers */
		send_no_cache_header(conn);
		send_additional_header(conn);

		/* Add content type */
		mg_response_header_add(conn,
		                       "Content-Type",
		                       "text/html; charset=utf-8",
		                       -1);

		/* Send the HTTP response (status and all headers) */
		mg_response_header_send(conn);
	}

	data.begin = p;
	data.len = len;
	data.state = 0;
	data.consumed = 0;
	data.tag = 0;
	lua_ok = mg_lua_load(L, lsp_kepler_reader, &data, path, NULL);

	if (lua_ok) {
		/* Syntax error or OOM.
		 * Error message is pushed on stack. */
		lua_pcall(L, 1, 0, 0);
		lua_cry(conn, lua_ok, L, "LSP Kepler", "execute");
		lua_error_handler(L);
		return 1;

	} else {
		/* Success loading chunk. Call it. */
		lua_ok = lua_pcall(L, 0, 0, 0);
		if (lua_ok != LUA_OK) {
			lua_cry(conn, lua_ok, L, "LSP Kepler", "call");
			lua_error_handler(L);
			return 1;
		}
	}
	return 0;
}


static int
run_lsp_civetweb(struct mg_connection *conn,
                 const char *path,
                 const char *p,
                 int64_t len,
                 lua_State *L,
                 int depth)
{
	int i, j, s, pos = 0, lines = 1, lualines = 0, is_var, lua_ok;
	char chunkname[MG_BUF_LEN];
	struct lsp_var_reader_data data;
	const char lsp_mark1 = '?'; /* Use <? code ?> */
	const char lsp_mark2 = '%'; /* Use <% code %> */

	if (depth == 1) {
		/* Assume the script does not support keep_alive. The script may change
		 * this by calling mg.keep_alive(true). */
		conn->must_close = 1;
	}

	for (i = 0; i < len; i++) {
		if (p[i] == '\n') {
			lines++;
		}

		/* Lua pages are normal text, unless there is a "<?" or "<%" tag. */
		if (((i + 1) < len) && (p[i] == '<')
		    && ((p[i + 1] == lsp_mark1) || (p[i + 1] == lsp_mark2))) {

			/* Opening tag way "<?" or "<%", closing tag must be the same. */
			char lsp_mark_used = p[i + 1];

			/* <?= var ?> or <%= var %> means a variable is enclosed and its
			 * value should be printed */
			if (0 == memcmp("lua", p + i + 2, 3)) {
				/* Syntax: <?lua code ?> or <?lua= var ?> */
				/* This is added for compatibility to other LSP syntax
				 * definitions. */
				/* Skip 3 letters ("lua"). */
				s = 3;
			} else {
				/* no additional letters to skip, only "<?" */
				s = 0;
			}

			/* Check for '=' in "<?= ..." or "<%= ..." or "<?lua= ..." */
			is_var = (((i + s + 2) < len) && (p[i + s + 2] == '='));
			if (is_var) {
				/* use variable value (print it later) */
				j = i + 2;
			} else {
				/* execute script code */
				j = i + 1;
			}

			while (j < len) {

				if (p[j] == '\n') {
					/* Add line (for line number offset) */
					lualines++;
				}

				/* Check for closing tag. */
				if (((j + 1) < len) && (p[j] == lsp_mark_used)
				    && (p[j + 1] == '>')) {
					/* We found the closing tag of the Lua tag. */

					/* Print everything before the Lua opening tag. */
					mg_write(conn, p + pos, i - pos);

					/* Set a name for debugging purposes */
					mg_snprintf(conn,
					            NULL, /* ignore truncation for debugging */
					            chunkname,
					            sizeof(chunkname),
					            "@%s+%i",
					            path,
					            lines);

					/* Prepare data for Lua C functions */
					lua_pushlightuserdata(L, conn);
					lua_pushcclosure(L, lsp_error, 1);

					/* Distinguish between <? script ?> (is_var == 0)
					 * and <?= expression ?> (is_var != 0). */
					if (is_var) {
						/* For variables: Print the value */
						/* Note: <?= expression ?> is equivalent to
						 * <? mg.write( expression ) ?> */
						data.begin = p + (i + 3 + s);
						data.len = j - (i + 3 + s);
						data.state = 0;
						data.consumed = 0;
						data.tag = 0;
						lua_ok = mg_lua_load(
						    L, lsp_var_reader, &data, chunkname, NULL);
					} else {
						/* For scripts: Execute them */
						lua_ok = luaL_loadbuffer(L,
						                         p + (i + 2 + s),
						                         j - (i + 2 + s),
						                         chunkname);
					}

					if (lua_ok) {
						/* Syntax error or OOM.
						 * Error message is pushed on stack. */
						lua_pcall(L, 1, 0, 0);
						lua_cry(conn, lua_ok, L, "LSP", "execute");
						lua_error_handler(L);
						return 1;
					} else {
						/* Success loading chunk. Call it. */
						lua_ok = lua_pcall(L, 0, 0, 0);
						if (lua_ok != LUA_OK) {
							lua_cry(conn, lua_ok, L, "LSP", "call");
							lua_error_handler(L);
							return 1;
						}
					}

					/* Progress until after the Lua closing tag. */
					pos = j + 2;
					i = pos - 1;
					break;
				}
				j++;
			}

			/* Line number for debugging/error logging. */
			if (lualines > 0) {
				lines += lualines;
				lualines = 0;
			}
		}
	}

	/* Print everything after the last Lua closing tag. */
	if (i > pos) {
		mg_write(conn, p + pos, i - pos);
	}

	return 0;
}


/* mg.write: Send data to the client */
static int
lsp_write(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	const char *str;
	size_t size;
	int i;
	int rv = 1;

	for (i = 1; i <= num_args; i++) {
		if (lua_isstring(L, i)) {
			str = lua_tolstring(L, i, &size);
			if (mg_write(conn, str, size) != (int)size) {
				rv = 0;
			}
		}
	}
	lua_pushboolean(L, rv);

	return 1;
}


/* mg.read: Read data from the client (e.g., from a POST request) */
static int
lsp_read(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	char buf[1024];
	int len = mg_read(conn, buf, sizeof(buf));

	if (len <= 0)
		return 0;
	lua_pushlstring(L, buf, len);

	return 1;
}


/* mg.keep_alive: Allow Lua pages to use the http keep-alive mechanism */
static int
lsp_keep_alive(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);

	/* This function may be called with one parameter (boolean) to set the
	keep_alive state.
	Or without a parameter to just query the current keep_alive state. */
	if ((num_args == 1) && lua_isboolean(L, 1)) {
		conn->must_close = !lua_toboolean(L, 1);
	} else if (num_args != 0) {
		/* Syntax error */
		return luaL_error(L, "invalid keep_alive() call");
	}

	/* Return the current "keep_alive" state. This may be false, even it
	 * keep_alive(true) has been called. */
	lua_pushboolean(L, should_keep_alive(conn));
	return 1;
}


/* Stack of includes */
struct lsp_include_history {
	int depth;
	const char *script[LSP_INCLUDE_MAX_DEPTH + 1];
};


/* mg.include: Include another .lp file */
static int
lsp_include(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	struct mg_file file = STRUCT_FILE_INITIALIZER;
	const char *file_name = (num_args >= 1) ? lua_tostring(L, 1) : NULL;
	const char *path_type = (num_args >= 2) ? lua_tostring(L, 2) : NULL;
	struct lsp_include_history *include_history;

	if (path_type == NULL) {
		/* default to "absolute" */
		path_type = "a";
	}

	if ((file_name != NULL) && (num_args <= 2)) {

		lua_pushlightuserdata(L, (void *)&lua_regkey_lsp_include_history);
		lua_gettable(L, LUA_REGISTRYINDEX);
		include_history = (struct lsp_include_history *)lua_touserdata(L, -1);

		if (include_history->depth >= ((int)(LSP_INCLUDE_MAX_DEPTH))) {
			mg_cry_internal(
			    conn,
			    "lsp max include depth of %i reached while including %s",
			    (int)(LSP_INCLUDE_MAX_DEPTH),
			    file_name);
		} else {
			char file_name_path[512];
			char *p;
			size_t len;
			int truncated = 0;

			file_name_path[511] = 0;

			if (*path_type == 'v') {
				/* "virtual" = relative to document root. */
				(void)mg_snprintf(conn,
				                  &truncated,
				                  file_name_path,
				                  sizeof(file_name_path),
				                  "%s/%s",
				                  conn->dom_ctx->config[DOCUMENT_ROOT],
				                  file_name);

			} else if (*path_type == 'a') {
				/* "absolute" = file name is relative to the
				 * webserver working directory
				 * or it is absolute system path. */
				/* path_type==NULL is the legacy use case with 1 argument */
				(void)mg_snprintf(conn,
				                  &truncated,
				                  file_name_path,
				                  sizeof(file_name_path),
				                  "%s",
				                  file_name);

			} else if ((*path_type == 'r') || (*path_type == 'f')) {
				/* "relative" = file name is relative to the
				 * current document */
				(void)mg_snprintf(
				    conn,
				    &truncated,
				    file_name_path,
				    sizeof(file_name_path),
				    "%s",
				    include_history->script[include_history->depth]);

				if (!truncated) {
					if ((p = strrchr(file_name_path, '/')) != NULL) {
						p[1] = '\0';
					}
					len = strlen(file_name_path);
					(void)mg_snprintf(conn,
					                  &truncated,
					                  file_name_path + len,
					                  sizeof(file_name_path) - len,
					                  "%s",
					                  file_name);
				}

			} else {
				return luaL_error(
				    L,
				    "invalid path_type in include(file_name, path_type) call");
			}

			if (handle_lsp_request(conn, file_name_path, &file, L)) {
				/* handle_lsp_request returned an error code, meaning an error
				 * occurred in the included page and mg.onerror returned
				 * non-zero.
				 * Stop processing.
				 */

				lsp_abort(L);
			}
		}

	} else {
		/* Syntax error */
		return luaL_error(L, "invalid include() call");
	}
	return 0;
}


/* mg.cry: Log an error. Default value for mg.onerror. */
static int
lsp_cry(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	const char *text = (num_args == 1) ? lua_tostring(L, 1) : NULL;

	if (text) {
		mg_cry_internal(conn, "%s", lua_tostring(L, -1));
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid cry() call");
	}
	return 0;
}


/* mg.redirect: Redirect the request (internally). */
static int
lsp_redirect(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	const char *target = (num_args == 1) ? lua_tostring(L, 1) : NULL;

	if (target) {
		conn->request_info.local_uri = target;
		handle_request(conn);
		lsp_abort(L);
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid redirect() call");
	}
	return 0;
}


/* mg.send_file */
static int
lsp_send_file(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	const char *filename = (num_args == 1) ? lua_tostring(L, 1) : NULL;

	if (filename) {
		mg_send_file(conn, filename);
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid send_file() call");
	}
	return 0;
}


/* mg.mg_send_file_body */
static int
lsp_send_file_body(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	const char *filename = (num_args == 1) ? lua_tostring(L, 1) : NULL;
	int ret;

	if (filename) {
		ret = mg_send_file_body(conn, filename);
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid send_file_body() call");
	}

	lua_pushboolean(L, ret >= 0);
	return 1;
}


/* mg.send_http_error */
static int
lsp_send_http_error(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	int status = (num_args >= 1) ? (int)lua_tonumber(L, 1) : -1;
	const char *auxText = (num_args >= 2) ? lua_tostring(L, 2) : NULL;
	int ret;

	if ((status >= 100) && (status <= 999)) {
		ret = mg_send_http_error(conn,
		                         status,
		                         "%s",
		                         (auxText != NULL) ? auxText : "");
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid send_http_error() call");
	}

	lua_pushnumber(L, ret);
	return 1;
}


/* mg.send_http_ok */
static int
lsp_send_http_ok(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	int type1, type2;
	const char *content_type = NULL;
	const char *content = NULL;
	int64_t content_len = 0;
	int ret;

	if (num_args < 2) {
		/* Syntax error */
		return luaL_error(L, "invalid send_http_ok() call");
	}
	type1 = lua_type(L, 1);
	type2 = lua_type(L, 2);
	if (type1 == LUA_TSTRING) {
		content_type = lua_tostring(L, 1);
	} else if (type1 != LUA_TNIL) {
		/* Syntax error */
		return luaL_error(L, "invalid send_http_ok() call");
	}
	if (type2 == LUA_TSTRING) {
		size_t len;
		content = lua_tolstring(L, 2, &len);
		content_len = (int64_t)len;
	} else if (type2 == LUA_TNUMBER) {
		content_len = (int64_t)lua_tonumber(L, 2);
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid send_http_ok() call");
	}

	ret = mg_send_http_ok(conn, content_type, content_len);

	if ((ret == 0) && (content != NULL) && (content_len > 0)) {
		mg_write(conn, content, (size_t)content_len);
	}

	lua_pushnumber(L, ret);
	return 1;
}


/* mg.mg_send_http_redirect */
static int
lsp_send_http_redirect(lua_State *L)
{
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));
	int num_args = lua_gettop(L);
	int type1, type2;
	const char *target_url = NULL;
	int redirect_code = 300;
	int ret;

	if (num_args < 2) {
		/* Syntax error */
		return luaL_error(L, "invalid send_http_redirect() call");
	}
	type1 = lua_type(L, 1);
	type2 = lua_type(L, 2);
	if (type1 == LUA_TSTRING) {
		target_url = lua_tostring(L, 1);
	} else if (type1 != LUA_TNIL) {
		/* Syntax error */
		return luaL_error(L, "invalid send_http_redirect() call");
	}
	if (type2 == LUA_TNUMBER) {
		redirect_code = (int)lua_tonumber(L, 2);
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid send_http_redirect() call");
	}

	ret = mg_send_http_redirect(conn, target_url, redirect_code);

	lua_pushnumber(L, ret);
	return 1;
}


/* mg.get_time */
static int
lsp_get_time(lua_State *L)
{
	int num_args = lua_gettop(L);
	int monotonic = (num_args > 0) ? lua_toboolean(L, 1) : 0;
	struct timespec ts;
	double d;

	clock_gettime(monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME, &ts);
	d = (double)ts.tv_sec + ((double)ts.tv_nsec * 1.0E-9);
	lua_pushnumber(L, d);
	return 1;
}


/* mg.get_var */
static int
lsp_get_var(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *data, *var_name;
	size_t data_len, occurrence;
	int ret;
	struct mg_context *ctx;

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	if ((num_args >= 2) && (num_args <= 3)) {
		char *dst;
		data = lua_tolstring(L, 1, &data_len);
		var_name = lua_tostring(L, 2);
		occurrence = (num_args > 2) ? (long)lua_tonumber(L, 3) : 0;

		/* Allocate dynamically, so there is no internal limit for get_var */
		dst = (char *)mg_malloc_ctx(data_len + 1, ctx);
		if (!dst) {
			return luaL_error(L, "out of memory in get_var() call");
		}

		ret = mg_get_var2(data, data_len, var_name, dst, data_len, occurrence);
		if (ret >= 0) {
			/* Variable found: return value to Lua */
			lua_pushstring(L, dst);
		} else {
			/* Variable not found */
			lua_pushnil(L);
		}
		mg_free(dst);
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid get_var() call");
	}
	return 1;
}


#define MG_MAX_FORM_FIELDS (64)

/* mg.split_form_data */
static int
lsp_split_form_urlencoded(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *in;
	size_t len;
	char *buf;
	struct mg_context *ctx;

	struct mg_header form_fields[MG_MAX_FORM_FIELDS] = {0};
	int ret, i;

	if (num_args != 1) {
		return luaL_error(L, "invalid split_form_data() call");
	}

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	/* Get input (const string) */
	in = lua_tolstring(L, 1, &len);

	/* Create a modifiable copy */
	buf = (char *)mg_malloc_ctx(len + 1, ctx);
	if (buf == NULL) {
		return luaL_error(L, "out of memory in invalid split_form_data() call");
	}
	memcpy(buf, in, len + 1);

	/* mg_split_form_urlencoded does the real work */
	ret = mg_split_form_urlencoded(buf, form_fields, MG_MAX_FORM_FIELDS);

	if (ret < 0) {
		return luaL_error(L, "error in invalid split_form_data() call");
	}

	/* return a table */
	lua_newtable(L);
	for (i = 0; i < ret; i++) {

		lua_newtable(L);
		if (form_fields[i].name) {
			lua_pushstring(L, form_fields[i].name);
		} else {
			lua_pushnil(L);
		}
		lua_setfield(L, -2, "name");
		if (form_fields[i].value) {
			lua_pushstring(L, form_fields[i].value);
		} else {
			lua_pushnil(L);
		}
		lua_setfield(L, -2, "value");

		lua_rawseti(L, -2, i + 1);
	}

	mg_free(buf);

	return 1;
}


/* mg.get_mime_type */
static int
lsp_get_mime_type(lua_State *L)
{
	int num_args = lua_gettop(L);
	struct vec mime_type = {0, 0};
	const char *text;

	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));

	if (num_args == 1) {
		text = lua_tostring(L, 1);
		if (text) {
			if (conn) {
				get_mime_type(conn, text, &mime_type);
				lua_pushlstring(L, mime_type.ptr, mime_type.len);
			} else {
				text = mg_get_builtin_mime_type(text);
				lua_pushstring(L, text);
			}
		} else {
			/* Syntax error */
			return luaL_error(L, "invalid argument for get_mime_type() call");
		}
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid get_mime_type() call");
	}
	return 1;
}


/* mg.get_cookie */
static int
lsp_get_cookie(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *cookie;
	const char *var_name;
	int ret;
	struct mg_context *ctx;

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	if (num_args == 2) {
		/* Correct number of arguments */
		size_t data_len;
		char *dst;

		cookie = lua_tolstring(L, 1, &data_len);
		var_name = lua_tostring(L, 2);

		if (cookie == NULL || var_name == NULL) {
			/* Syntax error */
			return luaL_error(L, "invalid get_cookie() call");
		}

		dst = (char *)mg_malloc_ctx(data_len + 1, ctx);
		if (!dst) {
			return luaL_error(L, "out of memory in get_cookie() call");
		}

		ret = mg_get_cookie(cookie, var_name, dst, data_len);

		if (ret >= 0) {
			lua_pushlstring(L, dst, ret);
		} else {
			lua_pushnil(L);
		}
		mg_free(dst);

	} else {
		/* Syntax error */
		return luaL_error(L, "invalid get_cookie() call");
	}
	return 1;
}


/* mg.md5 */
static int
lsp_md5(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *text;
	md5_byte_t hash[16];
	md5_state_t ctx;
	size_t text_len;
	char buf[40];

	if (num_args == 1) {
		text = lua_tolstring(L, 1, &text_len);
		if (text) {
			md5_init(&ctx);
			md5_append(&ctx, (const md5_byte_t *)text, text_len);
			md5_finish(&ctx, hash);
			bin2str(buf, hash, sizeof(hash));
			lua_pushstring(L, buf);
		} else {
			lua_pushnil(L);
		}
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid md5() call");
	}
	return 1;
}


/* mg.url_encode */
static int
lsp_url_encode(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *text;
	size_t text_len;
	char *dst;
	int dst_len;
	struct mg_context *ctx;

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	if (num_args == 1) {
		text = lua_tolstring(L, 1, &text_len);
		if (text) {
			dst_len = 3 * (int)text_len + 1;
			dst = ((text_len < 0x2AAAAAAA) ? (char *)mg_malloc_ctx(dst_len, ctx)
			                               : (char *)NULL);
			if (dst) {
				mg_url_encode(text, dst, dst_len);
				lua_pushstring(L, dst);
				mg_free(dst);
			} else {
				return luaL_error(L, "out of memory in url_encode() call");
			}
		} else {
			lua_pushnil(L);
		}
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid url_encode() call");
	}
	return 1;
}


/* mg.url_decode */
static int
lsp_url_decode(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *text;
	size_t text_len;
	int is_form;
	char *dst;
	int dst_len;
	struct mg_context *ctx;

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	if (num_args == 1 || (num_args == 2 && lua_isboolean(L, 2))) {
		text = lua_tolstring(L, 1, &text_len);
		is_form = (num_args == 2) ? lua_isboolean(L, 2) : 0;
		if (text) {
			dst_len = (int)text_len + 1;
			dst = ((text_len < 0x7FFFFFFF) ? (char *)mg_malloc_ctx(dst_len, ctx)
			                               : (char *)NULL);
			if (dst) {
				mg_url_decode(text, (int)text_len, dst, dst_len, is_form);
				lua_pushstring(L, dst);
				mg_free(dst);
			} else {
				return luaL_error(L, "out of memory in url_decode() call");
			}
		} else {
			lua_pushnil(L);
		}
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid url_decode() call");
	}
	return 1;
}


/* mg.base64_encode */
static int
lsp_base64_encode(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *text;
	size_t text_len;
	struct mg_context *ctx;

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	if (num_args == 1) {
		text = lua_tolstring(L, 1, &text_len);
		if (text) {
			/* Base 64 encodes 8 bits into 6 */
			size_t dst_len = text_len * 8 / 6 + 4;
			char *dst = (char *)mg_malloc_ctx(dst_len, ctx);
			if (dst) {
				mg_base64_encode((const unsigned char *)text,
				                 (int)text_len,
				                 dst,
				                 &dst_len);
				lua_pushstring(L, dst);
				mg_free(dst);
			} else {
				return luaL_error(L, "out of memory in base64_encode() call");
			}
		} else {
			lua_pushnil(L);
		}
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid base64_encode() call");
	}
	return 1;
}


/* mg.base64_encode */
static int
lsp_base64_decode(lua_State *L)
{
	int num_args = lua_gettop(L);
	const char *text;
	size_t text_len, dst_len;
	int ret;
	unsigned char *dst;
	struct mg_context *ctx;

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	if (num_args == 1) {
		text = lua_tolstring(L, 1, &text_len);
		if (text) {
			dst = (unsigned char *)mg_malloc_ctx(text_len, ctx);
			if (dst) {
				ret = mg_base64_decode(text, (int)text_len, dst, &dst_len);
				if (ret != -1) {
					mg_free(dst);
					return luaL_error(
					    L, "illegal character in lsp_base64_decode() call");
				} else {
					lua_pushlstring(L, (char *)dst, dst_len);
					mg_free(dst);
				}
			} else {
				return luaL_error(L,
				                  "out of memory in lsp_base64_decode() call");
			}
		} else {
			lua_pushnil(L);
		}
	} else {
		/* Syntax error */
		return luaL_error(L, "invalid lsp_base64_decode() call");
	}
	return 1;
}


/* mg.get_response_code_text */
static int
lsp_get_response_code_text(lua_State *L)
{
	int num_args = lua_gettop(L);
	int type1;
	double code;
	const char *text;

	if (num_args == 1) {
		type1 = lua_type(L, 1);
		if (type1 == LUA_TNUMBER) {
			/* If the first argument is a number,
			   convert it to the corresponding text. */
			code = lua_tonumber(L, 1);
			text = mg_get_response_code_text(NULL, (int)code);
			if (text) { /* <-- should be always true */
				lua_pushstring(L, text);
			}
			return text ? 1 : 0;
		}
	}

	/* Syntax error */
	return luaL_error(L, "invalid get_response_code_text() call");
}


/* mg.random - might be better than math.random on some systems */
static int
lsp_random(lua_State *L)
{
	int num_args = lua_gettop(L);
	if (num_args == 0) {
		/* The civetweb internal random number generator will generate
		 * a 64 bit random number. */
		uint64_t r = get_random();
		/* Lua "number" is a IEEE 754 double precision float:
		 * https://en.wikipedia.org/wiki/Double-precision_floating-point_format
		 * Thus, mask with 2^53-1 to get an integer with the maximum
		 * precision available. */
		r &= ((((uint64_t)1) << 53) - 1);
		lua_pushnumber(L, (double)r);
		return 1;
	}

	/* Syntax error */
	return luaL_error(L, "invalid random() call");
}


/* mg.get_info */
static int
lsp_get_info(lua_State *L)
{
	int num_args = lua_gettop(L);
	int type1, type2;
	const char *arg1;
	double arg2;
	int len;
	char *buf;

	if (num_args == 1) {
		type1 = lua_type(L, 1);
		if (type1 == LUA_TSTRING) {
			arg1 = lua_tostring(L, 1);
			/* Get info according to argument */
			if (!mg_strcasecmp(arg1, "system")) {
				/* Get system info */
				len = mg_get_system_info(NULL, 0);
				if (len > 0) {
					buf = (char *)mg_malloc(len + 64);
					if (!buf) {
						return luaL_error(L, "OOM in get_info() call");
					}
					len = mg_get_system_info(buf, len + 63);
					lua_pushlstring(L, buf, len);
					mg_free(buf);
				} else {
					lua_pushstring(L, "");
				}
				return 1;
			}
			if (!mg_strcasecmp(arg1, "context")) {
				/* Get context */
				struct mg_context *ctx;
				lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
				lua_gettable(L, LUA_REGISTRYINDEX);
				ctx = (struct mg_context *)lua_touserdata(L, -1);

				/* Get context info for server context */
				len = mg_get_context_info(ctx, NULL, 0);
				if (len > 0) {
					buf = (char *)mg_malloc(len + 64);
					if (!buf) {
						return luaL_error(L, "OOM in get_info() call");
					}
					len = mg_get_context_info(ctx, buf, len + 63);
					lua_pushlstring(L, buf, len);
					mg_free(buf);
				} else {
					lua_pushstring(L, "");
				}
				return 1;
			}
			if (!mg_strcasecmp(arg1, "common")) {
				/* Get context info for NULL context */
				len = mg_get_context_info(NULL, NULL, 0);
				if (len > 0) {
					buf = (char *)mg_malloc(len + 64);
					if (!buf) {
						return luaL_error(L, "OOM in get_info() call");
					}
					len = mg_get_context_info(NULL, buf, len + 63);
					lua_pushlstring(L, buf, len);
					mg_free(buf);
				} else {
					lua_pushstring(L, "");
				}
				return 1;
			}
			return 0;
		}
	}

	if (num_args == 2) {
		type1 = lua_type(L, 1);
		type2 = lua_type(L, 2);
		if ((type1 == LUA_TSTRING) && (type2 == LUA_TNUMBER)) {
			arg1 = lua_tostring(L, 1);
			arg2 = lua_tonumber(L, 2);

			/* Get info according to argument */
			if (!mg_strcasecmp(arg1, "connection")) {
				int idx;

				/* Get context */
				struct mg_context *ctx;
				lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
				lua_gettable(L, LUA_REGISTRYINDEX);
				ctx = (struct mg_context *)lua_touserdata(L, -1);

				/* Get connection info for connection idx */
				idx = (int)(arg2 + 0.5);

				/* Lua uses 1 based index, C uses 0 based index */
				idx--;

#if defined(MG_EXPERIMENTAL_INTERFACES)
				len = mg_get_connection_info(ctx, idx, NULL, 0);
				if (len > 0) {
					buf = (char *)mg_malloc(len + 64);
					if (!buf) {
						return luaL_error(L, "OOM in get_info() call");
					}
					len = mg_get_connection_info(ctx, idx, buf, len + 63);
					lua_pushlstring(L, buf, len);
					mg_free(buf);
				} else {
					lua_pushstring(L, "");
				}
#else
				(void)ctx;
				(void)idx;
				lua_pushstring(L, "");
#endif

				return 1;
			}
			return 0;
		}
	}

	/* Syntax error */
	return luaL_error(L, "invalid get_info() call");
}


/* mg.get_option */
static int
lsp_get_option(lua_State *L)
{
	int num_args = lua_gettop(L);
	int type1;
	const char *arg1;
	const char *data;
	int optidx;

	/* Get connection */
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));

	if (num_args == 0) {
		const struct mg_option *opts = mg_get_valid_options();

		if (!opts) { /* <-- should be always false */
			return 0;
		}

		lua_newtable(L);
		while (opts->name) {
			optidx = get_option_index(opts->name);
			if (optidx >= 0) {
				data = conn->dom_ctx->config[optidx];
				if (data) {
					reg_string(L, opts->name, data);
				}
			}
			opts++;
		}

		return 1;
	}

	if (num_args == 1) {
		type1 = lua_type(L, 1);
		if (type1 == LUA_TSTRING) {
			arg1 = lua_tostring(L, 1);
			/* Get option according to argument */
			optidx = get_option_index(arg1);
			if (optidx >= 0) {
				data = conn->dom_ctx->config[optidx];
				if (data) {
					lua_pushstring(L, data);
					return 1;
				}
			}
			return 0;
		}
	}

	/* Syntax error */
	return luaL_error(L, "invalid get_option() call");
}


static int s_lua_traceLevel = 1;
static FILE *s_lua_traceFile = NULL;
static pthread_mutex_t s_lua_traceMutex;


/* mg.trace */
static int
lsp_trace(lua_State *L)
{
	int num_args = lua_gettop(L);
	int arg_type[8];
	int trace_level = 0;
	int firstarg = 1;
	int i;

	for (i = 0; i < 8; i++) {
		if (num_args >= (i + 1)) {
			arg_type[i] = lua_type(L, (i + 1));
		} else {
			arg_type[i] = LUA_TNIL;
		}
	}

	if (arg_type[0] == LUA_TNUMBER) {
		trace_level = (int)lua_tointeger(L, 1);
		if (num_args == 1) {
			/* Set a new trace level, return the current one. */
			lua_pushinteger(L, s_lua_traceLevel);
			s_lua_traceLevel = trace_level;
			if (s_lua_traceFile) {
				pthread_mutex_lock(&s_lua_traceMutex);
				fflush(s_lua_traceFile);
				pthread_mutex_unlock(&s_lua_traceMutex);
			}
			return 1;
		}
		firstarg = 2;
	}

	if (trace_level > s_lua_traceLevel) {
		/* If this trace request has a higher trace level than the global trace
		 * level, do not trace. */
		lua_pushboolean(L, 0);
		return 1;
	}

	/* Print to file */
	if (s_lua_traceFile) {
		pthread_mutex_lock(&s_lua_traceMutex);
		for (i = firstarg; i <= num_args; i++) {
			if (arg_type[i - 1] == LUA_TSTRING) {
				const char *arg = lua_tostring(L, i);
				fprintf(s_lua_traceFile, "%s\n", arg);
			}
		}
		pthread_mutex_unlock(&s_lua_traceMutex);
	}
	lua_pushboolean(L, 1);
	return 1;
}


/* UUID library and function pointer */
union {
	void *p;
	void (*f)(unsigned char uuid[16]);
} pf_uuid_generate;


/* mg.uuid */
static int
lsp_uuid(lua_State *L)
{
	union {
		unsigned char uuid_array[16];
		struct uuid_struct_type {
			uint32_t data1;
			uint16_t data2;
			uint16_t data3;
			uint8_t data4[8];
		} uuid_struct;
	} uuid;

	char uuid_str[40];
	int num_args = lua_gettop(L);

	memset(&uuid, 0, sizeof(uuid));
	memset(uuid_str, 0, sizeof(uuid_str));

	if (num_args == 0) {

		pf_uuid_generate.f(uuid.uuid_array);

		sprintf(uuid_str,
		        "{%08lX-%04X-%04X-%02X%02X-"
		        "%02X%02X%02X%02X%02X%02X}",
		        (unsigned long)uuid.uuid_struct.data1,
		        (unsigned)uuid.uuid_struct.data2,
		        (unsigned)uuid.uuid_struct.data3,
		        (unsigned)uuid.uuid_struct.data4[0],
		        (unsigned)uuid.uuid_struct.data4[1],
		        (unsigned)uuid.uuid_struct.data4[2],
		        (unsigned)uuid.uuid_struct.data4[3],
		        (unsigned)uuid.uuid_struct.data4[4],
		        (unsigned)uuid.uuid_struct.data4[5],
		        (unsigned)uuid.uuid_struct.data4[6],
		        (unsigned)uuid.uuid_struct.data4[7]);

		lua_pushstring(L, uuid_str);
		return 1;
	}

	/* Syntax error */
	return luaL_error(L, "invalid uuid() call");
}


#if defined(USE_WEBSOCKET)
struct lua_websock_data {
	lua_State *state;
	char *script;
	unsigned references;
	struct mg_connection *conn[MAX_WORKER_THREADS];
	pthread_mutex_t ws_mutex;
};
#endif


/* mg.write for websockets */
static int
lwebsock_write(lua_State *L)
{
#if defined(USE_WEBSOCKET)
	int num_args = lua_gettop(L);
	struct lua_websock_data *ws;
	const char *str;
	size_t size;
	int opcode = -1;
	unsigned i;
	struct mg_connection *client = NULL;

	lua_pushlightuserdata(L, (void *)&lua_regkey_connlist);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ws = (struct lua_websock_data *)lua_touserdata(L, -1);

	(void)pthread_mutex_lock(&(ws->ws_mutex));

	if (num_args == 1) {
		/* just one text: send it to all client */
		if (lua_isstring(L, 1)) {
			opcode = MG_WEBSOCKET_OPCODE_TEXT;
		}
	} else if (num_args == 2) {
		if (lua_isnumber(L, 1)) {
			/* opcode number and message text */
			opcode = (int)lua_tointeger(L, 1);
		} else if (lua_isstring(L, 1)) {
			/* opcode string and message text */
			str = lua_tostring(L, 1);
			if (!mg_strncasecmp(str, "text", 4))
				opcode = MG_WEBSOCKET_OPCODE_TEXT;
			else if (!mg_strncasecmp(str, "bin", 3))
				opcode = MG_WEBSOCKET_OPCODE_BINARY;
			else if (!mg_strncasecmp(str, "close", 5))
				opcode = MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE;
			else if (!mg_strncasecmp(str, "ping", 4))
				opcode = MG_WEBSOCKET_OPCODE_PING;
			else if (!mg_strncasecmp(str, "pong", 4))
				opcode = MG_WEBSOCKET_OPCODE_PONG;
			else if (!mg_strncasecmp(str, "cont", 4))
				opcode = MG_WEBSOCKET_OPCODE_CONTINUATION;
		} else if (lua_isuserdata(L, 1)) {
			/* client id and message text */
			client = (struct mg_connection *)lua_touserdata(L, 1);
			opcode = MG_WEBSOCKET_OPCODE_TEXT;
		}
	} else if (num_args == 3) {
		if (lua_isuserdata(L, 1)) {
			client = (struct mg_connection *)lua_touserdata(L, 1);
			if (lua_isnumber(L, 2)) {
				/* client id, opcode number and message text */
				opcode = (int)lua_tointeger(L, 2);
			} else if (lua_isstring(L, 2)) {
				/* client id, opcode string and message text */
				str = lua_tostring(L, 2);
				if (!mg_strncasecmp(str, "text", 4))
					opcode = MG_WEBSOCKET_OPCODE_TEXT;
				else if (!mg_strncasecmp(str, "bin", 3))
					opcode = MG_WEBSOCKET_OPCODE_BINARY;
				else if (!mg_strncasecmp(str, "close", 5))
					opcode = MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE;
				else if (!mg_strncasecmp(str, "ping", 4))
					opcode = MG_WEBSOCKET_OPCODE_PING;
				else if (!mg_strncasecmp(str, "pong", 4))
					opcode = MG_WEBSOCKET_OPCODE_PONG;
				else if (!mg_strncasecmp(str, "cont", 4))
					opcode = MG_WEBSOCKET_OPCODE_CONTINUATION;
			}
		}
	}

	if (opcode >= 0 && opcode < 16 && lua_isstring(L, num_args)) {
		str = lua_tolstring(L, num_args, &size);
		if (client) {
			for (i = 0; i < ws->references; i++) {
				if (client == ws->conn[i]) {
					mg_lock_connection(ws->conn[i]);
					mg_websocket_write(ws->conn[i], opcode, str, size);
					mg_unlock_connection(ws->conn[i]);
				}
			}
		} else {
			for (i = 0; i < ws->references; i++) {
				mg_lock_connection(ws->conn[i]);
				mg_websocket_write(ws->conn[i], opcode, str, size);
				mg_unlock_connection(ws->conn[i]);
			}
		}
	} else {
		(void)pthread_mutex_unlock(&(ws->ws_mutex));
		return luaL_error(L, "invalid websocket write() call");
	}

	(void)pthread_mutex_unlock(&(ws->ws_mutex));

#else
	(void)(L);           /* unused */
#endif
	return 0;
}


struct laction_string_arg {
	lua_State *L;
	const char *script;
	pthread_mutex_t *pmutex;
	char txt[1];
};

struct laction_funcref_arg {
	lua_State *L;
	const char *script;
	pthread_mutex_t *pmutex;
	int funcref;
};


static int
lua_action_string(struct laction_string_arg *arg)
{
	int err, ok;
	struct mg_context *ctx;

	(void)pthread_mutex_lock(arg->pmutex);

	lua_pushlightuserdata(arg->L, (void *)&lua_regkey_ctx);
	lua_gettable(arg->L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(arg->L, -1);
	lua_pop(arg->L, 1);

	err = luaL_loadstring(arg->L, arg->txt);
	if (err != 0) {
		struct mg_connection fc;
		lua_cry(fake_connection(&fc, ctx), err, arg->L, arg->script, "timer");
		(void)pthread_mutex_unlock(arg->pmutex);
		return 0;
	}
	err = lua_pcall(arg->L, 0, 1, 0);
	if (err != 0) {
		struct mg_connection fc;
		lua_cry(fake_connection(&fc, ctx), err, arg->L, arg->script, "timer");
		(void)pthread_mutex_unlock(arg->pmutex);
		return 0;
	}

	ok = lua_type(arg->L, -1);
	if (lua_isboolean(arg->L, -1)) {
		ok = lua_toboolean(arg->L, -1);
	} else {
		ok = 0;
	}
	lua_pop(arg->L, 1);

	(void)pthread_mutex_unlock(arg->pmutex);

	return ok;
}


static int
lua_action_funcref(struct laction_funcref_arg *arg)
{
	int err, ok;
	struct mg_context *ctx;

	(void)pthread_mutex_lock(arg->pmutex);

	lua_pushlightuserdata(arg->L, (void *)&lua_regkey_ctx);
	lua_gettable(arg->L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(arg->L, -1);
	lua_pop(arg->L, 1);

	lua_rawgeti(arg->L, LUA_REGISTRYINDEX, arg->funcref);
	err = lua_pcall(arg->L, 0, 1, 0);
	if (err != 0) {
		struct mg_connection fc;
		lua_cry(fake_connection(&fc, ctx), err, arg->L, arg->script, "timer");
		(void)pthread_mutex_unlock(arg->pmutex);
		return 0;
	}

	ok = lua_type(arg->L, -1);
	if (lua_isboolean(arg->L, -1)) {
		ok = lua_toboolean(arg->L, -1);
	} else {
		ok = 0;
	}
	lua_pop(arg->L, 1);

	(void)pthread_mutex_unlock(arg->pmutex);

	return ok;
}


static void
lua_action_string_cancel(struct laction_string_arg *arg)
{
	mg_free(arg);
}


static void
lua_action_funcref_cancel(struct laction_funcref_arg *arg)
{
	luaL_unref(arg->L, LUA_REGISTRYINDEX, arg->funcref);
	mg_free(arg);
}


static int
lwebsocket_set_timer(lua_State *L, int is_periodic)
{
#if defined(USE_TIMERS) && defined(USE_WEBSOCKET)
	int num_args = lua_gettop(L);
	struct lua_websock_data *ws;
	int type1, type2, type3, ok = 0;
	double delay, interval;
	struct mg_context *ctx;

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	lua_pushlightuserdata(L, (void *)&lua_regkey_connlist);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ws = (struct lua_websock_data *)lua_touserdata(L, -1);

	if (num_args < 2) {
		return luaL_error(L,
		                  "not enough arguments for set_timer/interval() call");
	}

	type1 = lua_type(L, 1);
	type2 = lua_type(L, 2);
	type3 = lua_type(L, 3);

	/* Must have at least two arguments, ant the first one has to be some text
	 */
	if ((num_args < 2) || (num_args > 3)) {
		return luaL_error(L, "invalid arguments for set_timer/interval() call");
	}

	/* Second argument is the delay (and interval) */
	if (type2 != LUA_TNUMBER) {
		return luaL_error(L, "invalid arguments for set_timer/interval() call");
	}
	delay = (double)lua_tonumber(L, 2);
	interval = (is_periodic ? delay : 0.0);

	/* Third argument (optional) could be an interval */
	if (num_args > 2) {
		if (is_periodic || (type3 != LUA_TNUMBER)) {
			return luaL_error(
			    L, "invalid arguments for set_timer/interval() call");
		}
		interval = (double)lua_tonumber(L, 3);
	}

	/* Check numbers */
	if ((delay < 0.0) || (interval < 0.0)) {
		return luaL_error(L, "invalid arguments for set_timer/interval() call");
	}

	/* First value specifies the action */
	if (type1 == LUA_TSTRING) {

		/* Action could be passed as a string value */
		struct laction_string_arg *arg;
		const char *action_txt;
		size_t action_txt_len;

		action_txt = lua_tostring(L, 1);
		if ((action_txt == NULL) || (action_txt[0] == 0)) {
			return luaL_error(
			    L, "invalid arguments for set_timer/interval() call");
		}
		action_txt_len = strlen(action_txt);

		/* Create timer data structure and schedule timer */
		arg = (struct laction_string_arg *)mg_malloc_ctx(
		    sizeof(struct laction_string_arg) + action_txt_len + 10, ctx);
		if (!arg) {
			return luaL_error(L, "out of memory");
		}

		/* Argument for timer */
		arg->L = L;
		arg->script = (ws ? ws->script : NULL);
		arg->pmutex = (ws ? &(ws->ws_mutex) : &(ctx->lua_bg_mutex));
		memcpy(arg->txt, "return(", 7);
		memcpy(arg->txt + 7, action_txt, action_txt_len);
		arg->txt[action_txt_len + 7] = ')';
		arg->txt[action_txt_len + 8] = 0;
		if (0
		    == timer_add(ctx,
		                 delay,
		                 interval,
		                 1,
		                 (taction)lua_action_string,
		                 (void *)arg,
		                 (tcancelaction)lua_action_string_cancel)) {
			/* Timer added successfully */
			ok = 1;
		}
	} else if (type1 == LUA_TFUNCTION) {

		/* Action could be passed as a function */
		int funcref;
		struct laction_funcref_arg *arg;

		lua_pushvalue(L, 1);
		funcref = luaL_ref(L, LUA_REGISTRYINDEX);

		/* Create timer data structure and schedule timer */
		arg = (struct laction_funcref_arg *)
		    mg_malloc_ctx(sizeof(struct laction_funcref_arg), ctx);
		if (!arg) {
			return luaL_error(L, "out of memory");
		}

		/* Argument for timer */
		arg->L = L;
		arg->script = (ws ? ws->script : NULL);
		arg->pmutex = (ws ? &(ws->ws_mutex) : &(ctx->lua_bg_mutex));
		arg->funcref = funcref;
		if (0
		    == timer_add(ctx,
		                 delay,
		                 interval,
		                 1,
		                 (taction)lua_action_funcref,
		                 (void *)arg,
		                 (tcancelaction)lua_action_funcref_cancel)) {
			/* Timer added successfully */
			ok = 1;
		}
	} else {
		return luaL_error(L, "invalid arguments for set_timer/interval() call");
	}

	lua_pushboolean(L, ok);
	return 1;

#else
	(void)(L);           /* unused */
	(void)(is_periodic); /* unused */
	return 0;
#endif
}


/* mg.set_timeout for websockets */
static int
lwebsocket_set_timeout(lua_State *L)
{
	return lwebsocket_set_timer(L, 0);
}


/* mg.set_interval for websockets */
static int
lwebsocket_set_interval(lua_State *L)
{
	return lwebsocket_set_timer(L, 1);
}


/* mg.response.send() */
static int
lsp_response_send(lua_State *L)
{
	int http_status;
	int ret1, ret2, ret3;

	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));

	/* Get mg.response - table */
	lua_getglobal(L, "mg");
	if (!lua_istable(L, -1)) {
		return luaL_error(L, "table mg not available");
	}
	lua_pushstring(L, "response");
	lua_rawget(L, -2); /* rawget: no metatable */
	if (!lua_istable(L, -1)) {
		return luaL_error(L, "table mg.response not available");
	}

	/* Get element: status code  */
	lua_pushstring(L, "status");
	lua_gettable(L, -2); /* get .. could use metatable */
	if (!lua_isnumber(L, -1)) {
		return luaL_error(L, "number mg.response.status not available");
	}
	http_status = (int)lua_tonumber(L, -1);
	lua_pop(L, 1); /* remove number "status" */

	/* Get element: table of http response headers */
	lua_pushstring(L, "http_headers");
	lua_gettable(L, -2); /* get .. could use metatable */
	if (!lua_istable(L, -1)) {
		return luaL_error(L, "table mg.response.http_headers not available");
	}

	/* Parameter checks passed, initiate response */
	ret1 = mg_response_header_start(conn, http_status);
	if (ret1 != 0) {
		lua_pushboolean(L, 0); /* false */
		lua_pushinteger(L, ret1);
		return 2;
	}

	/* Iterate table of http response headers */
	ret2 = 0;
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		int retadd = 0;
		int key_type = lua_type(L, -2);
		int value_type = lua_type(L, -1);
		if ((key_type == LUA_TSTRING) && (value_type == LUA_TSTRING)) {
			size_t key_len = 0, value_len = 0;
			const char *key = lua_tolstring(L, -2, &key_len);
			const char *value = lua_tolstring(L, -1, &value_len);
			retadd = mg_response_header_add(conn, key, value, (int)value_len);
		} else if ((key_type == LUA_TNUMBER) && (value_type == LUA_TSTRING)) {
			const char *value = lua_tostring(L, -1);
			retadd = mg_response_header_add_lines(conn, value);
		}
		if ((retadd != 0) && (ret2 == 0)) {
			/* Store first error */
			ret2 = retadd;
		}
		lua_pop(L, 1);
	}

	/* Finalize */
	ret3 = mg_response_header_send(conn);
	if (ret3 == 0) {
		lua_pushboolean(L, 1);    /* TRUE */
		lua_pushinteger(L, ret2); /* Error/Warning from header_add */
	} else {
		lua_pushboolean(L, 0);    /* FALSE */
		lua_pushinteger(L, ret3); /* Error from header_send */
	}
	return 2;
}


/* Debug hook */
static void
lua_debug_hook(lua_State *L, lua_Debug *ar)
{
	int i;
	int stack_len = lua_gettop(L);

	lua_getinfo(L, "nSlu", ar);

	if (ar->event == LUA_HOOKCALL) {
		printf("call\n");
	} else if (ar->event == LUA_HOOKRET) {
		printf("ret\n");
#if defined(LUA_HOOKTAILRET)
	} else if (ar->event == LUA_HOOKTAILRET) {
		printf("tail ret\n");
#endif
#if defined(LUA_HOOKTAILCALL)
	} else if (ar->event == LUA_HOOKTAILCALL) {
		printf("tail call\n");
#endif
	} else if (ar->event == LUA_HOOKLINE) {
		printf("line\n");
	} else if (ar->event == LUA_HOOKCOUNT) {
		printf("count\n");
	} else {
		printf("unknown (%i)\n", ar->event);
	}

	if (ar->currentline >= 0) {
		printf("%s:%i\n", ar->source, ar->currentline);
	}

	printf("%s (%s)\n", ar->name, ar->namewhat);


	for (i = 1; i <= stack_len; i++) { /* repeat for each level */
		int val_type = lua_type(L, i);
		const char *s;
		size_t n;

		switch (val_type) {

		case LUA_TNIL:
			/* nil value  on the stack */
			printf("nil\n");
			break;

		case LUA_TBOOLEAN:
			/* boolean (true / false) */
			printf("boolean: %s\n", lua_toboolean(L, i) ? "true" : "false");
			break;

		case LUA_TNUMBER:
			/* number */
			printf("number: %g\n", lua_tonumber(L, i));
			break;

		case LUA_TSTRING:
			/* string with limited length */
			s = lua_tolstring(L, i, &n);
			printf("string: '%.*s%s\n",
			       ((n > 30) ? 28 : (int)n),
			       s,
			       ((n > 30) ? ".." : "'"));
			break;

		default:
			/* other values */
			printf("%s\n", lua_typename(L, val_type));
			break;
		}
	}

	printf("\n");
}


/* Lua Environment */
enum {
	LUA_ENV_TYPE_LUA_SERVER_PAGE = 0, /* page.lp */
	LUA_ENV_TYPE_PLAIN_LUA_PAGE = 1,  /* script.lua */
	LUA_ENV_TYPE_LUA_WEBSOCKET = 2,   /* websock.lua */
	LUA_ENV_TYPE_BACKGROUND = 9 /* Lua background script or exec from cmdline */
};


static void
push_lua_response_log_data(const struct mg_connection *conn, lua_State *L)
{
	int i;
	const char *s;

	lua_newtable(L);

	/* request status */
	reg_int(L, "status", conn->status_code);

	/* protocol (http, https, ws, wss) */
	s = get_proto_name(conn);
	reg_string(L, "protocol", s);

	/* request counter */
	reg_int(L, "handled_requests", conn->handled_requests);

	/* data read and written */
	reg_i64(L, "read", conn->consumed_content);
	reg_i64(L, "written", conn->num_bytes_sent);

#if !defined(NO_RESPONSE_BUFFERING)
	lua_pushstring(L, "http_headers");
	lua_newtable(L);
	for (i = 0; i < conn->response_info.num_headers; i++) {
		reg_string(L,
		           conn->response_info.http_headers[i].name,
		           conn->response_info.http_headers[i].value);
	}
	lua_rawset(L, -3);
#endif

#if defined(USE_SERVER_STATS)
	reg_double(L, "processing_time", conn->processing_time);
#endif
}


static void
prepare_lua_request_info_inner(const struct mg_connection *conn, lua_State *L)
{
	const char *s;
	int i;

	lua_newtable(L);
	reg_string(L, "request_method", conn->request_info.request_method);
	reg_string(L, "request_uri", conn->request_info.request_uri);
	reg_string(L, "uri", conn->request_info.local_uri);
	reg_string(L, "uri_raw", conn->request_info.local_uri_raw);
	reg_string(L, "http_version", conn->request_info.http_version);
	reg_string(L, "query_string", conn->request_info.query_string);
	reg_string(L, "remote_addr", conn->request_info.remote_addr);
	/* TODO (high): ip version */
	reg_int(L, "remote_port", conn->request_info.remote_port);
	reg_int(L, "server_port", conn->request_info.server_port);
	reg_int(L, "num_headers", conn->request_info.num_headers);

	if (conn->path_info != NULL) {
		reg_string(L, "path_info", conn->path_info);
	}

	{
		char buf[2048];
		if (0 == mg_get_request_link(conn, buf, sizeof(buf))) {
			reg_string(L, "request_link", buf);
		}
	}

	if (conn->request_info.content_length >= 0) {
		/* reg_int64: content_length */
		lua_pushstring(L, "content_length");
		lua_pushnumber(
		    L,
		    (lua_Number)conn->request_info
		        .content_length); /* lua_Number may be used as 52 bit integer */
		lua_rawset(L, -3);
	}
	if ((s = mg_get_header(conn, "Content-Type")) != NULL) {
		reg_string(L, "content_type", s);
	}

	if (conn->request_info.remote_user != NULL) {
		reg_string(L, "remote_user", conn->request_info.remote_user);
		reg_string(L, "auth_type", "Digest");
	}

	reg_boolean(L, "https", conn->ssl != NULL);

	if (conn->status_code > 0) {
		/* Lua error handler should show the status code */
		reg_int(L, "status", conn->status_code);
	}

	/* Table "HTTP headers" */
	lua_pushstring(L, "http_headers");
	lua_newtable(L);
	for (i = 0; i < conn->request_info.num_headers; i++) {
		reg_string(L,
		           conn->request_info.http_headers[i].name,
		           conn->request_info.http_headers[i].value);
	}
	lua_rawset(L, -3);

	/* Table "Client Certificate" */
	if (conn->request_info.client_cert) {
		lua_pushstring(L, "client_cert");
		lua_newtable(L);
		reg_string(L, "subject", conn->request_info.client_cert->subject);
		reg_string(L, "issuer", conn->request_info.client_cert->issuer);
		reg_string(L, "serial", conn->request_info.client_cert->serial);
		reg_string(L, "finger", conn->request_info.client_cert->finger);
		lua_rawset(L, -3);
	}

	/* Pi-hole addition */
	reg_string(L, "csrf_token", conn->request_info.csrf_token);
	reg_boolean(L, "is_authenticated", conn->request_info.is_authenticated != 0);
}


static void
prepare_lua_request_info(const struct mg_connection *conn, lua_State *L)
{
	/* Export mg.request_info */
	lua_pushstring(L, "request_info");
	prepare_lua_request_info_inner(conn, L);

	/* End of request_info */
	lua_rawset(L, -3);
}


static void
prepare_lua_response_table(struct mg_connection *conn, lua_State *L)
{
	/* Export mg.request_info */
	lua_pushstring(L, "response");
	lua_newtable(L);

	/* Add table elements */

	/* HTTP status code (default to 200 OK) */
	reg_int(L, "status", 200);

	/* Table "HTTP headers" */
	lua_pushstring(L, "http_headers");
	lua_newtable(L);
	/* Initially empty */
	lua_rawset(L, -3);

	/* mg_response_header_send wrapper */
	reg_conn_function(L, "send", lsp_response_send, conn);

	/* End of response table */
	lua_rawset(L, -3);
}


static void *
lua_allocator(void *ud, void *ptr, size_t osize, size_t nsize)
{
	(void)osize; /* not used */
	struct mg_context *ctx = (struct mg_context *)ud;
	if (nsize == 0) {
		mg_free(ptr);
		return NULL;
	}
	return mg_realloc_ctx(ptr, nsize, ctx);
}


/* In CivetWeb, Lua-Shared is used as *.inl file */
#define LUA_SHARED_INTERFACE static
#include "mod_lua_shared.inl"


static void
civetweb_open_lua_libs(lua_State *L)
{
	{
		extern void luaL_openlibs(lua_State *);
		luaL_openlibs(L);
	}
#if defined(USE_LUA_SQLITE3)
	{
		extern int luaopen_lsqlite3(lua_State *);
		luaopen_lsqlite3(L);
	}
#endif
#if defined(USE_LUA_LUAXML)
	{
		extern int luaopen_LuaXML_lib(lua_State *);
		luaopen_LuaXML_lib(L);
		lua_setglobal(L, "xml");
	}
#endif
#if defined(USE_LUA_FILE_SYSTEM)
	{
		extern int luaopen_lfs(lua_State *);
		luaopen_lfs(L);
	}
#endif
#if defined(USE_LUA_STRUCT)
	{
		int luaopen_struct(lua_State * L);
		luaopen_struct(L);
	}
#endif
#if defined(USE_LUA_SHARED_MEMORY)
	{
		extern int luaopen_lsh(lua_State *);
		luaopen_lsh(L);
	}
#endif
}


/* garbage collect "mg"
 * this indicates when a Lua state is closed
 */
static int
lsp_mg_gc(lua_State *L)
{
	int context_flags;
	struct mg_context *ctx;
	struct mg_connection *conn =
	    (struct mg_connection *)lua_touserdata(L, lua_upvalueindex(1));

	lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
	lua_gettable(L, LUA_REGISTRYINDEX);
	ctx = (struct mg_context *)lua_touserdata(L, -1);

	lua_pushlightuserdata(L, (void *)&lua_regkey_environment_type);
	lua_gettable(L, LUA_REGISTRYINDEX);
	context_flags = (int)lua_tointeger(L, -1);

	if (ctx != NULL) {
		if (ctx->callbacks.exit_lua != NULL) {
			ctx->callbacks.exit_lua(conn, L, (unsigned)context_flags);
		}
	}

	return 0;
}


static void
reg_gc(lua_State *L, void *conn)
{
	/* Key element */
	lua_pushlightuserdata(L, (void *)&lua_regkey_dtor);

	/* Value element */
	lua_newuserdata(L, 0);

	/* Prepare metatable for value element */
	lua_newtable(L);

	/* Add garbage collector key to metatable */
	lua_pushliteral(L, "__gc");

	/* Add garbage collector function with one upvalue (conn) */
	lua_pushlightuserdata(L, conn);
	lua_pushcclosure(L, lsp_mg_gc, 1);

	/* Set __gc = function lsp_mg_gc in metatable */
	lua_rawset(L, -3);

	/* Set metatable for "value element" */
	lua_setmetatable(L, -2);

	/* Add key (lightuserdata) = value (userdata with metatable) */
	lua_settable(L, LUA_REGISTRYINDEX);
}


static int
lua_error_handler(lua_State *L)
{
	const char *error_msg = lua_isstring(L, -1) ? lua_tostring(L, -1) : "?\n";

	lua_getglobal(L, "mg");
	if (!lua_isnil(L, -1)) {
		/* Write the error message to the error log */
		lua_getfield(L, -1, "write");
		lua_pushstring(L, error_msg);
		lua_pushliteral(L, "\n");
		lua_call(L, 2, 0); /* call mg.write(error_msg + \n) */
		lua_pop(L, 1);     /* pop mg */

		/* Get Lua traceback */
		lua_getglobal(L, "debug");
		lua_getfield(L, -1, "traceback");
		lua_call(L, 0, 1); /* call debug.traceback() */
		lua_remove(L, -2); /* remove debug */

		/* Write the Lua traceback to the error log */
		lua_getglobal(L, "mg");
		lua_getfield(L, -1, "write");
		lua_pushvalue(L, -3); /* push the traceback */

		/* Only print the traceback if it is not empty */
		if (strcmp(lua_tostring(L, -1), "stack traceback:") != 0) {
			lua_pushliteral(L, "\n"); /* append a newline */
			lua_call(L, 2, 0);        /* call mg.write(traceback + \n) */
			lua_pop(L, 2);            /* pop mg and traceback */
		} else {
			lua_pop(L, 3); /* pop mg, traceback and error message */
		}

	} else {
		printf("Lua error: [%s]\n", error_msg);
		IGNORE_UNUSED_RESULT(
		    luaL_dostring(L, "print(debug.traceback(), '\\n')"));
	}
	lua_pop(L, 1); /* pop error message */

	return 0;
}


static void
prepare_lua_environment(struct mg_context *ctx,
                        struct mg_connection *conn,
                        struct lua_websock_data *ws_conn_list,
                        lua_State *L,
                        const char *script_name,
                        int lua_env_type)
{
	const char *preload_file_name = NULL;
	const char *debug_params = NULL;

	int lua_context_flags = lua_env_type;

	DEBUG_TRACE("Lua environment type %i: %p, connection %p, script %s",
	            lua_env_type,
	            L,
	            conn,
	            script_name);

	civetweb_open_lua_libs(L);

#if defined(MG_EXPERIMENTAL_INTERFACES)
	/* Check if debugging should be enabled */
	if ((conn != NULL) && (conn->dom_ctx != NULL)) {
		debug_params = conn->dom_ctx->config[LUA_DEBUG_PARAMS];
	}
#endif

#if LUA_VERSION_NUM == 502
	/* Keep the "connect" method for compatibility,
	 * but do not backport it to Lua 5.1.
	 * TODO: Redesign the interface.
	 */
	luaL_newmetatable(L, LUASOCKET);
	/* self.__index = self */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_setfuncs(L, luasocket_methods, 0);
	lua_pop(L, 1);
	lua_register(L, "connect", lsp_connect);
#endif

	/* Store context in the registry */
	if (ctx != NULL) {
		lua_pushlightuserdata(L, (void *)&lua_regkey_ctx);
		lua_pushlightuserdata(L, (void *)ctx);
		lua_settable(L, LUA_REGISTRYINDEX);
	}
	if (ws_conn_list != NULL) {
		lua_pushlightuserdata(L, (void *)&lua_regkey_connlist);
		lua_pushlightuserdata(L, (void *)ws_conn_list);
		lua_settable(L, LUA_REGISTRYINDEX);
	}
	lua_pushlightuserdata(L, (void *)&lua_regkey_environment_type);
	lua_pushinteger(L, lua_context_flags);
	lua_settable(L, LUA_REGISTRYINDEX);

	/* State close function */
	reg_gc(L, conn);

	/* Lua server pages store the depth of mg.include, in order
	 * to detect recursions and prevent stack overflows. */
	if (lua_env_type == LUA_ENV_TYPE_LUA_SERVER_PAGE) {
		struct lsp_include_history *h;
		lua_pushlightuserdata(L, (void *)&lua_regkey_lsp_include_history);
		h = (struct lsp_include_history *)
		    lua_newuserdata(L, sizeof(struct lsp_include_history));
		lua_settable(L, LUA_REGISTRYINDEX);
		memset(h, 0, sizeof(struct lsp_include_history));
	}

	/* Register mg module */
	lua_newtable(L);

	switch (lua_env_type) {
	case LUA_ENV_TYPE_LUA_SERVER_PAGE:
		reg_string(L, "lua_type", "page");
		break;
	case LUA_ENV_TYPE_PLAIN_LUA_PAGE:
		reg_string(L, "lua_type", "script");
		break;
	case LUA_ENV_TYPE_LUA_WEBSOCKET:
		reg_string(L, "lua_type", "websocket");
		break;
	case LUA_ENV_TYPE_BACKGROUND:
		reg_string(L, "lua_type", "background");
		break;
	}

	if ((lua_env_type == LUA_ENV_TYPE_LUA_SERVER_PAGE)
	    || (lua_env_type == LUA_ENV_TYPE_PLAIN_LUA_PAGE)) {
		reg_conn_function(L, "cry", lsp_cry, conn);
		reg_conn_function(L, "read", lsp_read, conn);
		reg_conn_function(L, "write", lsp_write, conn);
		reg_conn_function(L, "keep_alive", lsp_keep_alive, conn);
		reg_conn_function(L, "send_file", lsp_send_file, conn);
		reg_conn_function(L, "send_file_body", lsp_send_file_body, conn);
		reg_conn_function(L, "send_http_error", lsp_send_http_error, conn);
		reg_conn_function(L, "send_http_ok", lsp_send_http_ok, conn);
		reg_conn_function(L,
		                  "send_http_redirect",
		                  lsp_send_http_redirect,
		                  conn);
		reg_conn_function(L, "redirect", lsp_redirect, conn);
	}

	if (lua_env_type == LUA_ENV_TYPE_LUA_SERVER_PAGE) {
		reg_conn_function(L, "include", lsp_include, conn);
	}

	if (lua_env_type == LUA_ENV_TYPE_LUA_WEBSOCKET) {
		reg_function(L, "write", lwebsock_write);
	}

#if defined(USE_TIMERS)
	if ((lua_env_type == LUA_ENV_TYPE_LUA_WEBSOCKET)
	    || (lua_env_type == LUA_ENV_TYPE_BACKGROUND)) {
		reg_function(L, "set_timeout", lwebsocket_set_timeout);
		reg_function(L, "set_interval", lwebsocket_set_interval);
	}
#endif

	reg_conn_function(L, "get_mime_type", lsp_get_mime_type, conn);
	reg_conn_function(L, "get_option", lsp_get_option, conn);

	reg_function(L, "time", lsp_get_time);
	reg_function(L, "get_var", lsp_get_var);
	reg_function(L, "split_form_data", lsp_split_form_urlencoded);
	reg_function(L, "get_cookie", lsp_get_cookie);
	reg_function(L, "md5", lsp_md5);
	reg_function(L, "url_encode", lsp_url_encode);
	reg_function(L, "url_decode", lsp_url_decode);
	reg_function(L, "base64_encode", lsp_base64_encode);
	reg_function(L, "base64_decode", lsp_base64_decode);
	reg_function(L, "get_response_code_text", lsp_get_response_code_text);
	reg_function(L, "random", lsp_random);
	reg_function(L, "get_info", lsp_get_info);
	reg_function(L, "trace", lsp_trace);

	if (pf_uuid_generate.f) {
		reg_function(L, "uuid", lsp_uuid);
	}

	reg_string(L, "version", CIVETWEB_VERSION);

	reg_string(L, "script_name", script_name);

	if ((conn != NULL) && (conn->dom_ctx != NULL)) {
		reg_string(L, "document_root", conn->dom_ctx->config[DOCUMENT_ROOT]);
		if (conn->dom_ctx->config[FALLBACK_DOCUMENT_ROOT]) {
			reg_string(L,
			           "fallback_document_root",
			           conn->dom_ctx->config[FALLBACK_DOCUMENT_ROOT]);
		}
		reg_string(L,
		           "auth_domain",
		           conn->dom_ctx->config[AUTHENTICATION_DOMAIN]);
#if defined(USE_WEBSOCKET)
		if (conn->dom_ctx->config[WEBSOCKET_ROOT]) {
			reg_string(L,
			           "websocket_root",
			           conn->dom_ctx->config[WEBSOCKET_ROOT]);
			if (conn->dom_ctx->config[FALLBACK_WEBSOCKET_ROOT]) {
				reg_string(L,
				           "fallback_websocket_root",
				           conn->dom_ctx->config[FALLBACK_WEBSOCKET_ROOT]);
			}
		} else {
			reg_string(L,
			           "websocket_root",
			           conn->dom_ctx->config[DOCUMENT_ROOT]);
		}
#endif

		if ((ctx != NULL) && (ctx->systemName != NULL)) {
			reg_string(L, "system", ctx->systemName);
		}
	}

	/* Export connection specific info */
	if (conn != NULL) {
		/* mg.request_info.* available for all environments */
		prepare_lua_request_info(conn, L);

		if (lua_env_type == LUA_ENV_TYPE_PLAIN_LUA_PAGE) {
			/* mg.response.* available only for *.lua scripts */
			prepare_lua_response_table(conn, L);
		}
	}

	/* Store as global table "mg" */
	lua_setglobal(L, "mg");

	/* Register "shared" table */
	lua_shared_register(L);

	/* Register default mg.onerror function */
	IGNORE_UNUSED_RESULT(
	    luaL_dostring(L,
	                  "mg.onerror = function(e) mg.write('\\nLua error:\\n', "
	                  "debug.traceback(e, 1)) end"));

	/* Check if a preload file is available */
	if ((conn != NULL) && (conn->dom_ctx != NULL)) {
		preload_file_name = conn->dom_ctx->config[LUA_PRELOAD_FILE];
	}

	/* Call user init function */
	if (ctx != NULL) {
		if (ctx->callbacks.init_lua != NULL) {
			ctx->callbacks.init_lua(conn, L, lua_context_flags);
		}
	}

	/* Preload file into new Lua environment */
	if (preload_file_name) {
		int ret = luaL_loadfile(L, preload_file_name);
		if (ret != 0) {
			lua_error_handler(L);
		} else {
			ret = lua_pcall(L, 0, 1, 0);
		}
	}

	/* If debugging is enabled, add a hook */
	if (debug_params) {
		int mask = 0;
		if (0 != strchr(debug_params, 'c')) {
			mask |= LUA_MASKCALL;
		}
		if (0 != strchr(debug_params, 'r')) {
			mask |= LUA_MASKRET;
		}
		if (0 != strchr(debug_params, 'l')) {
			mask |= LUA_MASKLINE;
		}
		lua_sethook(L, lua_debug_hook, mask, 0);
	}
}


static void
mg_exec_lua_script(struct mg_connection *conn,
                   const char *path,
                   const void **exports)
{
	int i;
	lua_State *L;

	/* Assume the script does not support keep_alive. The script may change this
	 * by calling mg.keep_alive(true). */
	conn->must_close = 1;

	/* Execute a plain Lua script. */
	if (path != NULL
	    && (L = lua_newstate(lua_allocator, (void *)(conn->phys_ctx)))
	           != NULL) {
		prepare_lua_environment(
		    conn->phys_ctx, conn, NULL, L, path, LUA_ENV_TYPE_PLAIN_LUA_PAGE);
		lua_pushcclosure(L, &lua_error_handler, 0);

		if (exports != NULL) {
#if LUA_VERSION_NUM > 501
			lua_pushglobaltable(L);
			for (i = 0; exports[i] != NULL && exports[i + 1] != NULL; i += 2) {
				lua_CFunction func;
				lua_pushstring(L, (const char *)(exports[i]));
				*(const void **)(&func) = exports[i + 1];
				lua_pushcclosure(L, func, 0);
				lua_rawset(L, -3);
			}
#else
			for (i = 0; exports[i] != NULL && exports[i + 1] != NULL; i += 2) {
				lua_CFunction func;
				const char *name = (const char *)(exports[i]);
				*(const void **)(&func) = exports[i + 1];
				lua_register(L, name, func);
			}
#endif
		}

		if (luaL_loadfile(L, path) != 0) {
			mg_send_http_error(conn, 500, "Lua error:\r\n");
			lua_error_handler(L);
		} else {
			int call_status = lua_pcall(L, 0, 0, 0);
			if (call_status != 0) {
				mg_send_http_error(conn, 500, "Lua error:\r\n");
				lua_error_handler(L);
			}
		}
		DEBUG_TRACE("Close Lua environment %p", L);
		lua_close(L);
	}
}


static int
handle_lsp_request(struct mg_connection *conn,
                   const char *path,
                   struct mg_file *filep,
                   struct lua_State *ls)
{
	void *p = NULL;
	lua_State *L = NULL;
	struct lsp_include_history *include_history;
	int error = 1;
	int (*run_lsp)(struct mg_connection *,
	               const char *,
	               const char *,
	               int64_t,
	               lua_State *,
	               int);
	const char *addr;

	/* mg_fopen opens the file and sets the size accordingly */
	if (!mg_fopen(conn, path, MG_FOPEN_MODE_READ, filep)) {

		/* File not found or not accessible */
		if (ls == NULL) {
			mg_send_http_error(conn,
			                   500,
			                   "Error: Cannot open script file %s",
			                   path);
		} else {
			luaL_error(ls, "Cannot include [%s]: not found", path);
		}

		goto cleanup_handle_lsp_request;
	}

	/* Map file in memory (size is known). */
	if ((p = mmap(NULL,
	              (size_t)filep->stat.size,
	              PROT_READ,
	              MAP_PRIVATE,
	              fileno(filep->access.fp),
	              0))
	    == NULL) {

		/* File was not already in memory, and mmap failed now.
		 * Since wi have no data, show an error. */
		if (ls == NULL) {
			/* No open Lua state - use generic error function */
			mg_send_http_error(
			    conn,
			    500,
			    "Error: Cannot open script\nFile %s can not be mapped",
			    path);
		} else {
			/* Lua state exists - use Lua error function */
			luaL_error(ls,
			           "mmap(%s, %zu, %d): %s",
			           path,
			           (size_t)filep->stat.size,
			           fileno(filep->access.fp),
			           strerror(errno));
		}

		goto cleanup_handle_lsp_request;
	}

	/* File content is now memory mapped. Get mapping address. */
	addr = (const char *)p;

	/* Get a Lua state */
	if (ls != NULL) {
		/* We got a Lua state as argument. Use it! */
		L = ls;
	} else {
		/* We need to create a Lua state. */
		L = lua_newstate(lua_allocator, (void *)(conn->phys_ctx));
		if (L == NULL) {
			/* We neither got a Lua state from the command line,
			 * nor did we succeed in creating our own state.
			 * Show an error, and stop further processing of this request. */
			mg_send_http_error(
			    conn,
			    500,
			    "%s",
			    "Error: Cannot execute script\nlua_newstate failed");

			goto cleanup_handle_lsp_request;
		}

		/* New Lua state needs CivetWeb functions (e.g., the "mg" library). */
		prepare_lua_environment(
		    conn->phys_ctx, conn, NULL, L, path, LUA_ENV_TYPE_LUA_SERVER_PAGE);
	}

	/* Get LSP include history table */
	lua_pushlightuserdata(L, (void *)&lua_regkey_lsp_include_history);
	lua_gettable(L, LUA_REGISTRYINDEX);
	include_history = (struct lsp_include_history *)lua_touserdata(L, -1);

	/* Store script name and increment depth */
	include_history->depth++;
	include_history->script[include_history->depth] = path;

	/* Lua state is ready to use now. */
	/* Currently we have two different syntax options:
	 * Either "classic" CivetWeb syntax:
	 *    <? code ?>
	 *    <?= expression ?>
	 * Or "Kepler Syntax"
	 * https://keplerproject.github.io/cgilua/manual.html#templates
	 *    <?lua chunk ?>
	 *    <?lua= expression ?>
	 *    <% chunk %>
	 *    <%= expression %>
	 *
	 * Two important differences are:
	 * - In the "classic" CivetWeb syntax, the Lua Page had to send the HTTP
	 *   response headers itself. So the first lines are usually something like
	 *   HTTP/1.0 200 OK
	 *   Content-Type: text/html
	 *   followed by additional headers and an empty line, before the actual
	 *   Lua page in HTML syntax with <? code ?> tags.
	 *   The "Kepler"Syntax" does not send any HTTP header from the Lua Server
	 *   Page, but starts directly with <html> code - so it cannot influence
	 *   the HTTP response code, e.g., to send a 301 Moved Permanently.
	 *   Due to this difference, the same *.lp file cannot be used with the
	 *   same algorithm.
	 * - The "Kepler Syntax" used to allow mixtures of Lua and HTML inside an
	 *   incomplete Lua block, e.g.:
	 *   <lua? for i=1,10 do ?><li><%= key %></li><lua? end ?>
	 *   This was not provided in "classic" CivetWeb syntax, but you had to use
	 *   <? for i=1,10 do mg.write("<li>"..i.."</li>") end ?>
	 *   instead. The parsing algorithm for "Kepler syntax" is more complex
	 *   than for "classic" CivetWeb syntax - TODO: check timing/performance.
	 *
	 * CivetWeb now can use both parsing methods, but needs to know what
	 * parsing algorithm should be used.
	 * Idea: Files starting with '<' are HTML files in "Kepler Syntax", except
	 * "<?" which means "classic CivetWeb Syntax".
	 *
	 */
	run_lsp = run_lsp_civetweb;
	if ((addr[0] != 'H')) { // Pi-hole change: Check if file starts with "H" for HTTP
		run_lsp = run_lsp_kepler;
	}

	/* We're not sending HTTP headers here, Lua page must do it. */
	error =
	    run_lsp(conn, path, addr, filep->stat.size, L, include_history->depth);

	/* pop from stack */
	include_history->depth--;

cleanup_handle_lsp_request:

	if (L != NULL && ls == NULL) {
		DEBUG_TRACE("Close Lua environment %p", L);
		lua_close(L);
	}
	if (p != NULL) {
		munmap(p, filep->stat.size);
	}
	(void)mg_fclose(&filep->access);

	return error;
}


#if defined(USE_WEBSOCKET)
struct mg_shared_lua_websocket_list {
	struct lua_websock_data ws;
	struct mg_shared_lua_websocket_list *next;
};


static void *
lua_websocket_new(const char *script, struct mg_connection *conn)
{
	struct mg_shared_lua_websocket_list **shared_websock_list =
	    &(conn->dom_ctx->shared_lua_websockets);
	struct lua_websock_data *ws;
	int err, ok = 0;

	DEBUG_ASSERT(conn->lua_websocket_state == NULL);

	/* lock list (mg_context global) */
	mg_lock_context(conn->phys_ctx);
	while (*shared_websock_list) {
		/* check if ws already in list */
		if (0 == strcmp(script, (*shared_websock_list)->ws.script)) {
			break;
		}
		shared_websock_list = &((*shared_websock_list)->next);
	}

	if (*shared_websock_list == NULL) {
		/* add ws to list */
		*shared_websock_list =
		    (struct mg_shared_lua_websocket_list *)mg_calloc_ctx(
		        sizeof(struct mg_shared_lua_websocket_list), 1, conn->phys_ctx);
		if (*shared_websock_list == NULL) {
			conn->must_close = 1;
			mg_unlock_context(conn->phys_ctx);
			mg_cry_internal(conn,
			                "%s",
			                "Cannot create shared websocket struct, OOM");
			return NULL;
		}
		/* init ws list element */
		ws = &(*shared_websock_list)->ws;
		ws->script = mg_strdup_ctx(script, conn->phys_ctx);
		if (!ws->script) {
			conn->must_close = 1;
			mg_unlock_context(conn->phys_ctx);
			mg_cry_internal(conn,
			                "%s",
			                "Cannot create shared websocket script, OOM");
			return NULL;
		}
		pthread_mutex_init(&(ws->ws_mutex), &pthread_mutex_attr);
		(void)pthread_mutex_lock(&(ws->ws_mutex));
		ws->state = lua_newstate(lua_allocator, (void *)(conn->phys_ctx));
		ws->conn[0] = conn;
		ws->references = 1;
		prepare_lua_environment(conn->phys_ctx,
		                        conn,
		                        ws,
		                        ws->state,
		                        script,
		                        LUA_ENV_TYPE_LUA_WEBSOCKET);
		err = luaL_loadfile(ws->state, script);
		if (err != 0) {
			lua_cry(conn, err, ws->state, script, "load");
		}
		err = lua_pcall(ws->state, 0, 0, 0);
		if (err != 0) {
			lua_cry(conn, err, ws->state, script, "init");
		}
	} else {
		/* inc ref count */
		ws = &(*shared_websock_list)->ws;
		(void)pthread_mutex_lock(&(ws->ws_mutex));
		(*shared_websock_list)->ws.conn[(ws->references)++] = conn;
	}
	mg_unlock_context(conn->phys_ctx);

	/* call add */
	lua_getglobal(ws->state, "open");
	lua_newtable(ws->state);
	prepare_lua_request_info(conn, ws->state);
	lua_pushstring(ws->state, "client");
	lua_pushlightuserdata(ws->state, (void *)conn);
	lua_rawset(ws->state, -3);

	err = lua_pcall(ws->state, 1, 1, 0);
	if (err != 0) {
		lua_cry(conn, err, ws->state, script, "open handler");
	} else {
		if (lua_isboolean(ws->state, -1)) {
			ok = lua_toboolean(ws->state, -1);
		}
		lua_pop(ws->state, 1);
	}
	if (!ok) {
		/* Remove from ws connection list. */
		/* TODO (mid): Check if list entry and Lua state needs to be deleted
		 * (see websocket_close). */
		(*shared_websock_list)->ws.conn[--(ws->references)] = 0;
	}

	(void)pthread_mutex_unlock(&(ws->ws_mutex));

	return ok ? (void *)ws : NULL;
}


static int
lua_websocket_data(struct mg_connection *conn,
                   int bits,
                   char *data,
                   size_t data_len,
                   void *ws_arg)
{
	struct lua_websock_data *ws = (struct lua_websock_data *)(ws_arg);
	int err, ok = 0;

	DEBUG_ASSERT(ws != NULL);
	DEBUG_ASSERT(ws->state != NULL);

	(void)pthread_mutex_lock(&(ws->ws_mutex));

	lua_getglobal(ws->state, "data");
	lua_newtable(ws->state);
	lua_pushstring(ws->state, "client");
	lua_pushlightuserdata(ws->state, (void *)conn);
	lua_rawset(ws->state, -3);
	lua_pushstring(ws->state, "bits"); /* TODO: dont use "bits" but fields with
	                                      a meaning according to
	                                      http://tools.ietf.org/html/rfc6455,
	                                      section 5.2 */
	lua_pushnumber(ws->state, bits);
	lua_rawset(ws->state, -3);
	lua_pushstring(ws->state, "data");
	lua_pushlstring(ws->state, data, data_len);
	lua_rawset(ws->state, -3);

	err = lua_pcall(ws->state, 1, 1, 0);
	if (err != 0) {
		lua_cry(conn, err, ws->state, ws->script, "data handler");
	} else {
		if (lua_isboolean(ws->state, -1)) {
			ok = lua_toboolean(ws->state, -1);
		}
		lua_pop(ws->state, 1);
	}
	(void)pthread_mutex_unlock(&(ws->ws_mutex));

	return ok;
}


static int
lua_websocket_ready(struct mg_connection *conn, void *ws_arg)
{
	struct lua_websock_data *ws = (struct lua_websock_data *)(ws_arg);
	int err, ok = 0;

	DEBUG_ASSERT(ws != NULL);
	DEBUG_ASSERT(ws->state != NULL);

	(void)pthread_mutex_lock(&(ws->ws_mutex));

	lua_getglobal(ws->state, "ready");
	lua_newtable(ws->state);
	lua_pushstring(ws->state, "client");
	lua_pushlightuserdata(ws->state, (void *)conn);
	lua_rawset(ws->state, -3);
	err = lua_pcall(ws->state, 1, 1, 0);
	if (err != 0) {
		lua_cry(conn, err, ws->state, ws->script, "ready handler");
	} else {
		if (lua_isboolean(ws->state, -1)) {
			ok = lua_toboolean(ws->state, -1);
		}
		lua_pop(ws->state, 1);
	}

	(void)pthread_mutex_unlock(&(ws->ws_mutex));

	return ok;
}


static void
lua_websocket_close(struct mg_connection *conn, void *ws_arg)
{
	struct lua_websock_data *ws = (struct lua_websock_data *)(ws_arg);
	struct mg_shared_lua_websocket_list **shared_websock_list =
	    &(conn->dom_ctx->shared_lua_websockets);
	int err = 0;
	unsigned i;
	int delete_state = 0;

	DEBUG_ASSERT(ws != NULL);
	DEBUG_ASSERT(ws->state != NULL);

	(void)pthread_mutex_lock(&(ws->ws_mutex));

	lua_getglobal(ws->state, "close");
	lua_newtable(ws->state);
	lua_pushstring(ws->state, "client");
	lua_pushlightuserdata(ws->state, (void *)conn);
	lua_rawset(ws->state, -3);

	err = lua_pcall(ws->state, 1, 0, 0);
	if (err != 0) {
		lua_cry(conn, err, ws->state, ws->script, "close handler");
	}
	for (i = 0; i < ws->references; i++) {
		if (ws->conn[i] == conn) {
			ws->references--;
			if (ws->references == 0) {
				delete_state = 1;
				break;
			}
			ws->conn[i] = ws->conn[ws->references];
		}
	}
	/* TODO: Delete lua_websock_data and remove it from the websocket list.
	   This must only be done, when all connections are closed, and all
	   asynchronous operations and timers are completed/expired. */
	if (delete_state) {
		/* lock list (mg_context global) */
		mg_lock_context(conn->phys_ctx);
		while (*shared_websock_list) {
			/* find ws in list */
			if (0 == strcmp(ws->script, (*shared_websock_list)->ws.script)) {
				break;
			}
			shared_websock_list = &((*shared_websock_list)->next);
		}
		if (*shared_websock_list != NULL) {
			/* TODO: If we close the state here, timers must be stopped first */
			/* lua_close(ws->state); <-- other thread will crash, if there are
			 * still active timers */
		}
		mg_unlock_context(conn->phys_ctx);
	}

	(void)pthread_mutex_unlock(&(ws->ws_mutex));
}
#endif


static lua_State *
mg_lua_context_script_prepare(const char *file_name,
                              struct mg_context *ctx,
                              char *ebuf,
                              size_t ebuf_len)
{
	struct lua_State *L;
	int lua_ret;
	const char *lua_err_txt;

	L = luaL_newstate();
	if (L == NULL) {
		mg_snprintf(NULL,
		            NULL, /* No truncation check for ebuf */
		            ebuf,
		            ebuf_len,
		            "Error: %s",
		            "Cannot create Lua state");
		return 0;
	}

	/* Add all libraries */
	prepare_lua_environment(ctx,
	                        NULL /* conn */,
	                        NULL /* WS list*/,
	                        L,
	                        file_name,
	                        LUA_ENV_TYPE_BACKGROUND);

	/* Load lua script file */
	lua_ret = luaL_loadfile(L, file_name);
	if (lua_ret != LUA_OK) {
		/* Error when loading the file (e.g. file not found,
		 * out of memory, ...)
		 */
		lua_err_txt = lua_tostring(L, -1);
		mg_snprintf(NULL,
		            NULL, /* No truncation check for ebuf */
		            ebuf,
		            ebuf_len,
		            "Error loading file %s: %s\n",
		            file_name,
		            lua_err_txt);
		DEBUG_TRACE("Close Lua environment %p", L);
		lua_close(L);
		return 0;
	}
	/*	lua_close(L); must be done somewhere else */
	return L;
}


static lua_State *
mg_lua_context_script_run(lua_State *L,
                          const char *file_name,
                          struct mg_context *ctx,
                          char *ebuf,
                          size_t ebuf_len)
{
	int lua_ret;
	const char *lua_err_txt;

	(void)ctx;

	/* The script file is loaded, now call it */
	lua_ret = lua_pcall(L,
	                    /* no arguments */ 0,
	                    /* zero or one return value */ 1,
	                    /* errors as string return value */ 0);

	if (lua_ret != LUA_OK) {
		/* Error when executing the script */
		lua_err_txt = lua_tostring(L, -1);
		mg_snprintf(NULL,
		            NULL, /* No truncation check for ebuf */
		            ebuf,
		            ebuf_len,
		            "Error running file %s: %s\n",
		            file_name,
		            lua_err_txt);
		DEBUG_TRACE("Close Lua environment %p", L);
		lua_close(L);
		return 0;
	}

	/* Check optional return value */
	if (lua_isboolean(L, -1)) {
		/* A boolean return value false indicates failure */
		int ret = lua_toboolean(L, -1);
		if (ret == 0) {
			/* Script returned false */
			mg_snprintf(NULL,
			            NULL, /* No truncation check for ebuf */
			            ebuf,
			            ebuf_len,
			            "Script %s returned false\n",
			            file_name);
			DEBUG_TRACE("Close Lua environment %p", L);
			lua_close(L);
			return 0;
		}
	}

	/*	lua_close(L); must be done somewhere else */
	return L;
}


static void
lua_ctx_init(struct mg_context *ctx)
{
#if defined(USE_WEBSOCKET)
	ctx->dd.shared_lua_websockets = NULL;
#endif
}


static void
lua_ctx_exit(struct mg_context *ctx)
{
#if defined(USE_WEBSOCKET)
	struct mg_shared_lua_websocket_list **shared_websock_list =
	    &(ctx->dd.shared_lua_websockets);
	struct mg_shared_lua_websocket_list *next;

	mg_lock_context(ctx);
	while (*shared_websock_list) {
		DEBUG_TRACE("Close Lua environment %p",
		            (*shared_websock_list)->ws.state);
		lua_close((*shared_websock_list)->ws.state);
		mg_free((*shared_websock_list)->ws.script);

		/* Save "next" pointer before freeing list element */
		next = ((*shared_websock_list)->next);
		mg_free(*shared_websock_list);
		shared_websock_list = &next;
	}
	mg_unlock_context(ctx);
#endif
}


/* Execute Lua script from main */
int
run_lua(const char *file_name)
{
	int func_ret = EXIT_FAILURE;
	char ebuf[512] = {0};
	lua_State *L =
	    mg_lua_context_script_prepare(file_name, NULL, ebuf, sizeof(ebuf));

	if (L) {
		L = mg_lua_context_script_run(L, file_name, NULL, ebuf, sizeof(ebuf));
	}

	if (L) {
		/* Script executed */
		if (lua_type(L, -1) == LUA_TNUMBER) {
			func_ret = (int)lua_tonumber(L, -1);
		} else {
			func_ret = EXIT_SUCCESS;
		}
		DEBUG_TRACE("Close Lua environment %p", L);
		lua_close(L);
	} else {
		fprintf(stderr, "%s\n", ebuf);
	}
	return func_ret;
}


static void *lib_handle_uuid = NULL;

static void
lua_init_optional_libraries(void)
{
	/* Create logging mutex */
	pthread_mutex_init(&s_lua_traceMutex, &pthread_mutex_attr);

	/* shared Lua state */
	lua_shared_init();

/* UUID library */
#if !defined(_WIN32) && !defined(NO_DLOPEN)
	lib_handle_uuid = dlopen("libuuid.so", RTLD_LAZY);
	pf_uuid_generate.p =
	    (lib_handle_uuid ? dlsym(lib_handle_uuid, "uuid_generate") : 0);
#else
	pf_uuid_generate.p = 0;
#endif
}


static void
lua_exit_optional_libraries(void)
{
/* UUID library */
#if !defined(_WIN32) && !defined(NO_DLOPEN)
	if (lib_handle_uuid) {
		dlclose(lib_handle_uuid);
	}
#endif
	pf_uuid_generate.p = 0;
	lib_handle_uuid = NULL;

	/* shared Lua state */
	lua_shared_exit();

	/* Delete logging mutex */
	pthread_mutex_destroy(&s_lua_traceMutex);
}


/* End of mod_lua.inl */
