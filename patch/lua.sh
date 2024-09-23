#!/bin/sh
set -e

patch -p1 < patch/lua/0001-add-pihole-library.patch
patch -p1 < patch/lua/0001-Increase-LUA_IDSIZE-so-that-long-script-filenames-as.patch

echo "ALL PATCHES APPLIED OKAY"
