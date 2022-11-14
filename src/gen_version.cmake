# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /src/gen_version.cmake
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

if(DEFINED ENV{GIT_BRANCH})
    set(GIT_BRANCH "$ENV{GIT_BRANCH}")
else()
    execute_process(
            COMMAND           bash -c "git branch | sed -n 's/^\\* //p'"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE   GIT_BRANCH
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if(DEFINED ENV{GIT_HASH})
    set(GIT_HASH "$ENV{GIT_HASH}")
else()
    execute_process(
            COMMAND           git --no-pager describe --always --abbrev=8 --dirty
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE   GIT_HASH
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if(DEFINED ENV{GIT_VERSION})
    set(GIT_VERSION "$ENV{GIT_VERSION}")
else()
    execute_process(
            COMMAND           git --no-pager describe --tags --always --abbrev=8 --dirty
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE   GIT_VERSION
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if(DEFINED ENV{GIT_DATE})
    set(GIT_DATE "$ENV{GIT_DATE}")
else()
    execute_process(
            COMMAND           bash -c "git --no-pager show --date=short --format=\"%ai\" --name-only | head -n 1"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE   GIT_DATE
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if(DEFINED ENV{GIT_TAG})
    set(GIT_TAG "$ENV{GIT_TAG}")
else()
    execute_process(
            COMMAND           git describe --tags --abbrev=0
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            OUTPUT_VARIABLE   GIT_TAG
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

# If CI_ARCH is unset (local compilation), ask uname -m and add locally compiled comment
if(DEFINED ENV{CI_ARCH})
    set(FTL_ARCH "$ENV{CI_ARCH} (compiled on CI)")
else()
    execute_process(
            COMMAND           uname -m
            OUTPUT_VARIABLE   UNAME
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(FTL_ARCH "${UNAME} (compiled locally)")
endif()

# Get compiler version
execute_process(
        COMMAND           bash -c "${CMAKE_C_COMPILER} --version | head -n 1"
        OUTPUT_VARIABLE   FTL_CC
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

message("Building Pi-hole FTL daemon")
message("   - Branch: ${GIT_BRANCH}")
message("   - Architecture: ${FTL_ARCH}")
message("   - Version: ${GIT_VERSION}")
message("   - Tag: ${GIT_TAG}")
message("   - Hash: ${GIT_HASH}")
message("   - Commit date: ${GIT_DATE}")

# configure the version file, but output to a temporary location
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/version~
        @ONLY
)

# compare with the real version file
execute_process(
        COMMAND
        ${CMAKE_COMMAND} -E compare_files
        ${CMAKE_CURRENT_BINARY_DIR}/version~
        ${CMAKE_CURRENT_BINARY_DIR}/version.h
        RESULT_VARIABLE
        VERSION_NEEDS_UPDATING

        OUTPUT_QUIET
        ERROR_QUIET
)

# update the real version file if necessary
if(VERSION_NEEDS_UPDATING)
    execute_process(
            COMMAND
            ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_BINARY_DIR}/version~
            ${CMAKE_CURRENT_BINARY_DIR}/version.h
    )
endif()
