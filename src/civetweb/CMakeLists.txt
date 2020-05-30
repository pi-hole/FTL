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
        )

# We can remove the NO_SSL later on. It adds additional constraints to the build system (availablity of libSSL-dev)
# NO_CGI = no CGI support (we don't need it)
# NO_SSL_DL NO_SSL = no SSL support (for now)
# USE_SERVER_STATS = makes a few anonymous statistics available, such as
#   - Number of connections (currently and total)
#   - Amount of data read and written
# USE_IPV6: add IPv6 support
set(CIVETWEB_OPTS
        ""
        )


add_library(civetweb OBJECT ${sources})
target_compile_definitions(civetweb PRIVATE NO_CGI NO_SSL_DL NO_SSL USE_SERVER_STATS USE_IPV6)
target_include_directories(civetweb PRIVATE ${PROJECT_SOURCE_DIR}/src)
