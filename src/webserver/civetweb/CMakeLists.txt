# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/civetweb/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        civetweb.c
        civetweb.h
        handle_form.inl
        md5.inl
        sha1.inl
        timer.inl
        )

add_library(civetweb OBJECT ${sources})
target_compile_options(civetweb PRIVATE -Wno-unused-but-set-variable -Wno-unused-variable)
# NO_CGI = no CGI support (we don't need it)
# NO_SSL = no TLS in civetweb: the in-process front terminator terminates TLS
#          and civetweb only ever serves plain HTTP/1.1 on the loopback backend,
#          so civetweb's whole SSL layer is dead code and compiled out.
# USE_IPV6: add IPv6 support
# USE_LUA: add Lua support
# USE_STACK_SIZE: pin worker-thread stack to 1 MiB. Without it, threads inherit
#          the platform default (~8 MiB on glibc, but only ~128 KiB on musl/Alpine),
#          which is too tight for Lua pages, the recursive config API and Teleporter I/O.
# TIMER_RESOLUTION: set timer resolution to 1000ms (default is 10ms) in an attempt to reduce CPU load
target_compile_definitions(civetweb PRIVATE NO_CGI
                                            NO_DLOPEN
                                            NO_SSL
                                            USE_IPV6
                                            USE_LUA
                                            USE_STACK_SIZE=1048576
                                            TIMER_RESOLUTION=1000)

include_directories(${PROJECT_SOURCE_DIR}/src/lua)
target_include_directories(civetweb PRIVATE ${PROJECT_SOURCE_DIR}/src)
