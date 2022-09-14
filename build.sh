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

for var in "$@"
do
    case "${var}" in
        "-c" | "clean"   ) clean=1;;
        "-C" | "CLEAN"   ) clean=1 && nobuild=1;;
        "-i" | "install" ) install=1;;
        "-t" | "test"    ) test=1;;
    esac
done

# Prepare build environment
if [[ -n "${clean}" ]]; then
    echo "Cleaning build environment"
    rm -rf cmake/
    if [[ -n ${nobuild} ]]; then
        exit 0
    fi
fi

# Configure build, pass CMake CACHE entries if present
# Wrap multiple options in "" as first argument to ./build.sh:
#     ./build.sh "-DA=1 -DB=2" install
mkdir -p cmake
cd cmake
if [[ "${1}" == "-D"* ]]; then
    cmake "${1}" ..
else
    cmake ..
fi

# Build the sources
cmake --build . -- -j $(nproc)

# If we are asked to install, we do this here
# Otherwise, we simply copy the binary one level up
if [[ -n "${install}" ]]; then
    echo "Installing pihole-FTL"
    SUDO=$(command -v sudo)
    ${SUDO} cmake --install .
else
    echo "Copying compiled pihole-FTL binary to repository root"
    cp pihole-FTL ../
fi

if [[ -n "${test}" ]]; then
    cd ..
    ./test/run.sh
fi
