#!/bin/sh
set -e

patch -p1 < patch/lua/0001-add-pihole-library.patch

echo "ALL PATCHES APPLIED OKAY"
