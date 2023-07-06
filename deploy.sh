#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2022 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Deploy script for FTL
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.


# Transfer Builds to Pi-hole server for pihole checkout
# We use sftp for secure transfer and use the branch name as dir on the server.
# The branch name could contain slashes, creating hierarchical dirs. However,
# this is not supported by sftp's `mkdir` (option -p) is not available. Therefore,
# we need to loop over each dir level and create them one by one.


# Safeguard: do not deploy if TARGET_DIR is empty
if [[ -z ${TARGET_DIR} ]]; then
    echo "Error: Empty target dir."
    exit 1
fi

IFS='/'
read -r -a path <<<"${TARGET_DIR}"

# Safeguard: do not deploy if more than one subdir (eg. /tweak/feature/subfeature) needs to be created
if [[ "${#path[@]}" -gt 2 ]]; then
    echo "Error: Your branch name contains more then one subdir. We won't deploy that."
    exit 1
fi

unset IFS

old_path="."

for dir in "${path[@]}"; do
    mapfile -t dir_content <<< "$(
        sftp -b - "${USER}"@"${HOST}" <<< "cd ${old_path}
        ls -1"
    )"

    # Loop over the dir content and check if this exact dir already exists
    path_exists=0
    for content in "${dir_content[@]}"; do
        if [[ "${content}" == "${dir}" ]]; then
            echo "Dir: ${old_path}/${dir} already exists"
            path_exists=1
        fi
    done

    # If the dir does not exist, create it
    if [[ "${path_exists}" -eq 0 ]]; then
        echo "Dir: ${old_path}/${dir} does not exist. Creating it."
        sftp -b - "${USER}"@"${HOST}" <<< "cd ${old_path}
        -mkdir ${dir}"
    fi

    old_path="${old_path}/${dir}"
done

sftp -r -b - "${USER}"@"${HOST}" <<< "cd ${old_path}
-mkdir ./docs
-mkdir ./docs/external
-mkdir ./docs/images
-mkdir ./docs/specs
put ${SOURCE_DIR}/* ./"
