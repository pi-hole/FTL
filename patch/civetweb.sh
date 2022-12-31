#!/bin/sh
set -e

patch -p1 < patch/civetweb/0001-add-pihole-mods.patch
