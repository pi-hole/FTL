#!/bin/bash

rm -rf cmake/ && \
mkdir cmake && \
cd cmake && \
cmake -DSTATIC="${1}" .. && \
cmake --build . -- GIT_BRANCH="${2}" GIT_TAG="${3}" CIRCLE_JOB="${4}" -j 4