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
target_compile_definitions(civetweb PRIVATE NO_CGI
                                            NO_DLOPEN
                                            NO_SSL_DL
                                            USE_IPV6
                                            USE_LUA
                                            TIMER_RESOLUTION=1000)

if(LIBMBEDCRYPTO AND LIBMBEDX509 AND LIBMBEDTLS)
    # Enable TLS support in civetweb if mbedTLS is available
    message(STATUS "Building FTL with TLS support: YES")
    target_compile_definitions(civetweb PRIVATE USE_MBEDTLS)
    target_compile_definitions(webserver PRIVATE HAVE_TLS)
else()
    # Disable TLS support in civetweb if mbedTLS is not available
    message(STATUS "Building FTL with TLS support: NO")
    target_compile_definitions(civetweb PRIVATE NO_SSL)
endif()

include_directories(${PROJECT_SOURCE_DIR}/src/lua /usr/local/include)
target_include_directories(civetweb PRIVATE ${PROJECT_SOURCE_DIR}/src)
