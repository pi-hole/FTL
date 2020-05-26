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

rm -rf cmake/ && \
mkdir cmake && \
cd cmake && \
cmake .. && \
cmake --build . -- -j $(nproc) && \
cp pihole-FTL ../
