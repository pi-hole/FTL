set(sources
        ftl_lua.c
        ftl_lua.h
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
target_compile_options(lua PRIVATE -Wno-maybe-uninitialized -Wno-unused-variable -Wno-unused-value)

# LUA_USE_POSIX: ensures recommended POSIX functions are used instead of
#                (partially obsoleted) standard C functions
target_compile_definitions(lua PRIVATE LUA_USE_POSIX)

# Set the default path that Lua uses to look for Lua libraries.
target_compile_definitions(lua PRIVATE LUA_PATH_DEFAULT="/opt/pihole/libs/?.lua")

if(LUA_DL STREQUAL "true")
    target_compile_definitions(lua PRIVATE LUA_USE_DLOPEN)
endif()

if(LIBREADLINE AND LIBHISTORY AND LIBTERMCAP)
    message(STATUS "Embedded LUA will use readline for history: YES")
    target_compile_definitions(lua PRIVATE LUA_USE_READLINE)
else()
    message(STATUS "Embedded LUA will use readline for history: NO")
endif()

target_include_directories(lua PRIVATE ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/src/lua)
