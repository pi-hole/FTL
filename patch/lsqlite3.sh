#!/bin/sh
set -e

patch -p1 < patch/lsqlite3/0001-Remove-deprecated-functions-from-lsqlite3-codebase.patch

echo "ALL PATCHES APPLIED OKAY"
