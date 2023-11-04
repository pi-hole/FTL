# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/database/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

# This file has no dependencies on other code in the repo and takes a long time
# to build. It is placed in its own target so that it does not include any other
# headers in the build command and thus does not need to be rebuilt when headers
# are modified.
set(sqlite3_sources
        shell.c
        sqlite3.c
        )

add_library(sqlite3 OBJECT ${sqlite3_sources})
target_compile_options(sqlite3 PRIVATE -Wno-implicit-fallthrough -Wno-cast-function-type -Wno-sign-compare)

set(database_sources
        common.c
        common.h
        database-thread.c
        database-thread.h
        gravity-db.c
        gravity-db.h
        message-table.c
        message-table.h
        network-table.c
        network-table.h
        query-table.c
        query-table.h
        session-table.c
        session-table.h
        sqlite3.h
        sqlite3-ext.c
        sqlite3-ext.h
        aliasclients.c
        aliasclients.h
        )

add_library(database OBJECT ${database_sources})
target_compile_options(database PRIVATE "${EXTRAWARN}")
target_include_directories(database PRIVATE ${PROJECT_SOURCE_DIR}/src)
