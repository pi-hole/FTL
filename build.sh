#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Build script for FTL
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

# Abort script if one command returns a non-zero value
set -e

# Set builddir
builddir="cmake/"

# Parse arguments
for var in "$@"
do
    case "${var}" in
        "-c" | "clean"   ) clean=1;;
        "-C" | "CLEAN"   ) clean=1 && nobuild=1;;
        "-i" | "install" ) install=1;;
        "-t" | "test"    ) test=1;;
        "ci"             ) builddir="cmake_ci/";;
    esac
done

# Prepare build environment
if [[ -n "${clean}" ]]; then
    echo "Cleaning build environment"
    # Remove build directory
    rm -rf "${builddir}"
    if [[ -n ${nobuild} ]]; then
        exit 0
    fi
fi

# Remove possibly outdated api/docs elements
for filename in src/api/docs/hex/* src/api/docs/hex/**/*; do
    # Skip if not a file
    if [ ! -f "${filename}" ]; then
        continue
    fi

    # Get the original filename
    original_filename="${filename/"src/api/docs/hex/"/"src/api/docs/content/"}"

    # Remove the file if it is outdated
    if [ "${filename}" -ot "${original_filename}" ]; then
        rm "${filename}"
    fi
done

# Remove compiled LUA scripts if older than the plain ones
for scriptname in src/lua/scripts/*.lua; do
    if [ -f "${scriptname}.hex" ] && [ "${scriptname}.hex" -ot "${scriptname}" ]; then
        rm "${scriptname}.hex"
    fi
done

# Configure build, pass CMake CACHE entries if present
# Wrap multiple options in "" as first argument to ./build.sh:
#     ./build.sh "-DA=1 -DB=2" install
mkdir -p "${builddir}"
cd "${builddir}"
if [[ "${1}" == "-D"* ]]; then
    cmake "${1}" ..
else
    cmake ..
fi

# Build the sources with the number of available cores
cmake --build . -- -j $(nproc)

# If we are asked to install, we do this here (requires root privileges)
# Otherwise, we simply copy the binary one level up
if [[ -n "${install}" ]]; then
    echo "Installing pihole-FTL"
    SUDO=$(command -v sudo)
    ${SUDO} cmake --install .
else
    echo "Copying compiled pihole-FTL binary to repository root"
    cp pihole-FTL ../
fi

# If we are asked to run tests, we do this here
if [[ -n "${test}" ]]; then
    cd ..
    ./test/run.sh
fi
