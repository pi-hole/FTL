#!/bin/sh
set -e

patch src/database/shell.c patches/sqlite3/0001-print-FTL-version-in-interactive-shell.patch
patch src/database/sqlite3.c patches/sqlite3/0002-make-sqlite3ErrName-public.patch
