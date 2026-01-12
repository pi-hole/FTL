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
                COMMAND bash -c "git branch | sed -n 's/^\\* //p'"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE GIT_BRANCH
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
endif()

if(DEFINED ENV{GIT_HASH})
        set(GIT_HASH "$ENV{GIT_HASH}")
else()
        execute_process(
                COMMAND git --no-pager describe --always --abbrev=8 --dirty
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE GIT_HASH
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
endif()

# Find the latest matching tag using improved logic (prefers tags from current branch)
# This uses git tag --sort=creatordate --merged HEAD to find tags on the current branch
if(NOT DEFINED ENV{GIT_TAG})
        execute_process(
                COMMAND
                        sh -c
                        "git tag -l --sort=creatordate --merged HEAD | grep -E '^v?[0-9]+\\.[0-9]+\\.[0-9]+' | sort -V | tail -1"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE LATEST_TAG
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
else()
        set(LATEST_TAG "$ENV{GIT_TAG}")
endif()

# Set GIT_TAG and GIT_VERSION based on the found tag
if(DEFINED ENV{GIT_VERSION})
        set(GIT_VERSION "$ENV{GIT_VERSION}")
elseif(LATEST_TAG)
        # Use the found tag for git describe
        execute_process(
                COMMAND git --no-pager describe --tags --always --abbrev=8 --dirty --match=${LATEST_TAG}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE GIT_VERSION
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
else()
        # Fallback if no matching tag found
        execute_process(
                COMMAND git --no-pager describe --tags --always --abbrev=8 --dirty
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE GIT_VERSION
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
endif()

if(DEFINED ENV{GIT_DATE})
        set(GIT_DATE "$ENV{GIT_DATE}")
else()
        execute_process(
                COMMAND bash -c "git --no-pager show --date=short --format=\"%ai\" --name-only | head -n 1"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE GIT_DATE
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE
        )
endif()

if(DEFINED ENV{GIT_TAG})
        set(GIT_TAG "$ENV{GIT_TAG}")
else()
        # Use LATEST_TAG if found, otherwise fallback to git describe
        if(LATEST_TAG)
                set(GIT_TAG "${LATEST_TAG}")
        else()
                execute_process(
                        COMMAND git describe --tags --abbrev=0
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        OUTPUT_VARIABLE GIT_TAG
                        ERROR_QUIET
                        OUTPUT_STRIP_TRAILING_WHITESPACE
                )
        endif()
endif()

# Extract version components from GIT_TAG for CMake project version
# Default values if extraction fails
set(GIT_DEFAULT_VERSION "0")
set(GIT_VERSION_MAJOR ${GIT_DEFAULT_VERSION})
set(GIT_VERSION_MINOR ${GIT_DEFAULT_VERSION})
set(GIT_VERSION_PATCH ${GIT_DEFAULT_VERSION})

if(GIT_TAG)
        # Parse the version information from tag (e.g., v5.21 or v5.21.1)
        string(REGEX REPLACE "^v?([0-9]+)\\..*" "\\1" GIT_VERSION_MAJOR "${GIT_TAG}")
        string(REGEX REPLACE "^v?[0-9]+\\.([0-9]+).*" "\\1" GIT_VERSION_MINOR "${GIT_TAG}")
        string(REGEX REPLACE "^v?[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" GIT_VERSION_PATCH "${GIT_TAG}")

        # If PATCH extraction failed (e.g., tag is v5.21), set to 0
        if(GIT_VERSION_PATCH STREQUAL GIT_TAG)
                set(GIT_VERSION_PATCH "0")
        endif()
endif()

# Set version variables for use in CMakeLists.txt
# When included during configure phase, these become available as PROJECT_VERSION_*
set(PROJECT_VERSION_MAJOR "${GIT_VERSION_MAJOR}")
set(PROJECT_VERSION_MINOR "${GIT_VERSION_MINOR}")
set(PROJECT_VERSION_PATCH "${GIT_VERSION_PATCH}")

# If called from CMakeLists.txt during configure phase, we're done here
# The version.c generation below is only needed during build phase
if(GEN_VERSION_CONFIGURE_MODE)
        return()
endif()

# If CI_ARCH is unset (local compilation), ask uname -m and add locally compiled comment
if(DEFINED ENV{CI_ARCH})
        set(FTL_ARCH "$ENV{CI_ARCH} (compiled on CI)")
else()
        execute_process(COMMAND uname -m OUTPUT_VARIABLE UNAME ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(FTL_ARCH "${UNAME} (compiled locally)")
endif()

# Get compiler version
execute_process(
        COMMAND bash -c "${CMAKE_C_COMPILER} --version | head -n 1"
        OUTPUT_VARIABLE FTL_CC
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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.c.in ${CMAKE_CURRENT_BINARY_DIR}/version~ @ONLY)

# compare with the real version file
execute_process(
        COMMAND
                ${CMAKE_COMMAND} -E compare_files ${CMAKE_CURRENT_BINARY_DIR}/version~
                ${CMAKE_CURRENT_BINARY_DIR}/version.c
        RESULT_VARIABLE VERSION_NEEDS_UPDATING
        OUTPUT_QUIET
        ERROR_QUIET
)

# update the real version file if necessary
if(VERSION_NEEDS_UPDATING)
        execute_process(
                COMMAND
                        ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/version~
                        ${CMAKE_CURRENT_BINARY_DIR}/version.c
        )
endif()
