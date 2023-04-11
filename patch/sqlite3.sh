#!/bin/sh
set -e

patch -p1 < patch/sqlite3/0001-print-FTL-version-in-interactive-shell.patch
patch -p1 < patch/sqlite3/0002-make-sqlite3ErrName-public.patch

echo "ALL PATCHES APPLIED OKAY"
