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
# We can remove the NO_SSL later on. It adds additional constraints to the build system (availablity of libSSL-dev)
# NO_CGI = no CGI support (we don't need it)
# NO_SSL_DL NO_SSL = no SSL support (for now)
# USE_IPV6: add IPv6 support
# USE_LUA: add Lua support
# TIMER_RESOLUTION: set timer resolution to 1000ms (default is 10ms) in an attempt to reduce CPU load
# USE_X_DOM_SOCKET: allow the webserver to listen on a UNIX domain socket through the
#                   "x<path>" syntax in webserver.port, e.g. to run behind a reverse
#                   proxy without exposing any TCP port
target_compile_definitions(civetweb PRIVATE NO_CGI
                                            NO_DLOPEN
                                            NO_SSL_DL
                                            USE_IPV6
                                            USE_LUA
                                            USE_X_DOM_SOCKET
                                            TIMER_RESOLUTION=1000)

include_directories(${PROJECT_SOURCE_DIR}/src/lua)
target_include_directories(civetweb PRIVATE ${PROJECT_SOURCE_DIR}/src)
