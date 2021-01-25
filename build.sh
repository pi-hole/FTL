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

# Prepare build environment
if [[ "${1}" == "clean" ]]; then
    rm -rf cmake/
    exit 0
fi

# Remove possibly generated api/docs elements
rm -rf src/api/docs/hex

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

# If we are asked to install, we do this here
# Otherwise, we simply build the sources and copy the binary one level up
if [[ "${1}" == "install" || "${2}" == "install" ]]; then
    sudo make install -j $(nproc)
else
    # Build the sources
    make -j $(nproc)
    cp pihole-FTL ../
fi
