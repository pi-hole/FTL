set(ftl_sources
        ftl_lua.c
        ftl_lua.h
)

add_library(ftl_lua OBJECT ${ftl_sources})

set(lsqlite3_sources
        lsqlite3.c
)
add_library(lsqlite3 OBJECT ${lsqlite3_sources})
target_compile_definitions(lsqlite3 PRIVATE LSQLITE_VERSION="0.9.6")
target_include_directories(lsqlite3 PRIVATE ${PROJECT_SOURCE_DIR}/src)
# Add sqlite3.h to target's include path
target_include_directories(lsqlite3 PRIVATE ${PROJECT_SOURCE_DIR}/src/database)

set(sources
        lapi.c
        lapi.h
        lauxlib.c
        lauxlib.h
        lbaselib.c
        lcode.c
        lcode.h
        lcorolib.c
        lctype.c
        lctype.h
        ldblib.c
        ldebug.c
        ldebug.h
        ldo.c
        ldo.h
        ldump.c
        lfunc.c
        lfunc.h
        lgc.c
        lgc.h
        linit.c
        liolib.c
        ljumptab.h
        llex.c
        llex.h
        llimits.h
        lmathlib.c
        lmem.c
        lmem.h
        loadlib.c
        lobject.c
        lobject.h
        lopcodes.c
        lopcodes.h
        lopnames.h
        loslib.c
        lparser.c
        lparser.h
        lprefix.h
        lstate.c
        lstate.h
        lstring.c
        lstring.h
        lstrlib.c
        ltable.c
        ltable.h
        ltablib.c
        ltm.c
        ltm.h
        lua.c
        luac.c
        luaconf.h
        lua.h
        lualib.h
        lundump.c
        lundump.h
        lutf8lib.c
        lvm.c
        lvm.h
        lzio.c
        lzio.h
        )

add_library(lua OBJECT ${sources})
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(lua PRIVATE -Wno-maybe-uninitialized -Wno-unused-variable -Wno-unused-value)
    target_compile_options(ftl_lua PRIVATE -Wno-unused-value ${EXTRAWARN})
endif()

# LUA_USE_POSIX: ensures recommended POSIX functions are used instead of
#                (partially obsoleted) standard C functions
target_compile_definitions(lua PRIVATE LUA_USE_POSIX)

# Set the default path that Lua uses to look for Lua libraries.
target_compile_definitions(lua PRIVATE LUA_PATH_DEFAULT="/opt/pihole/libs/?.lua")

if(LUA_DL STREQUAL "true")
    target_compile_definitions(lua PRIVATE LUA_USE_DLOPEN)
endif()

target_include_directories(lua PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/src/lua)
target_include_directories(ftl_lua PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/src/lua)
