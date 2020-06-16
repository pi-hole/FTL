# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/api/CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

set(sources
        ph7.c
        )

add_library(ph7 OBJECT ${sources})
target_compile_definitions(ph7 PRIVATE PH7_ENABLE_THREADS)

# Accept known warnings in the PH7 engine
target_compile_options(ph7 PRIVATE -Wno-unused-but-set-parameter
                                   -Wno-unused-but-set-variable
                                   -Wno-unused-const-variable
                                   -Wno-array-bounds
                                   -Wno-misleading-indentation
                                   -Wno-sign-compare)

target_include_directories(ph7 PRIVATE ${PROJECT_SOURCE_DIR}/src)
