#!/bin/sh
set -e

patch -p1 < patch/civetweb/0001-add-pihole-mods.patch
patch -p1 < patch/civetweb/0001-Add-NO_DLOPEN-option-to-civetweb-s-LUA-routines.patch

echo "ALL PATCHES APPLIED OKAY"
