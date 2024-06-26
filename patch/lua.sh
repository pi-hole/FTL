#!/bin/sh
set -e

patch -p1 < patch/lua/0001-add-pihole-library.patch
patch -p1 < patch/lua/0002-Make-lsqlite3-globally-available-in-LUA.patch
patch -p1 < patch/lua/0003-Make-Pi-hole-bundled-scripts-e.g.-inspect-also-avail.patch

echo "ALL PATCHES APPLIED OKAY"
