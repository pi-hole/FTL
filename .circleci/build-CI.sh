#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Build script for Circle CI
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

rm -rf cmake/ && \
mkdir cmake && \
cd cmake && \
cmake -DSTATIC="${1}" .. && \
cmake --build . -- GIT_BRANCH="${2}" GIT_TAG="${3}" CIRCLE_JOB="${4}" -j 4 && \
mv pihole-FTL ../
