#!/bin/sh
set -e

patch -p1 < patch/lua/0001-add-pihole-library.patch
patch -p1 < patch/lua/0001-Increase-LUA_IDSIZE-so-that-long-script-filenames-as.patch
patch -p1 < patch/lua/0001-Add-bundled-script-loading-into-luaL_openlibs-to-mak.patch

echo "ALL PATCHES APPLIED OKAY"
