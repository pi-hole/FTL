#!/bin/sh
set -e

echo "Applying patches for civetweb"
echo "Applying patch 0001-add-pihole-mods.patch"
patch -p1 < patch/civetweb/0001-add-pihole-mods.patch

echo "Applying patch 0001-Always-Kepler-syntax-for-Lua-server-pages.patch"
patch -p1 < patch/civetweb/0001-Always-Kepler-syntax-for-Lua-server-pages.patch

echo "Applying patch 0001-Add-FTL-URI-rewriting-changes-to-CivetWeb.patch"
patch -p1 < patch/civetweb/0001-Add-FTL-URI-rewriting-changes-to-CivetWeb.patch

echo "Applying patch 0001-Add-mbedTLS-debug-logging-hook.patch"
patch -p1 < patch/civetweb/0001-Add-mbedTLS-debug-logging-hook.patch

echo "Applying patch 0001-Add-Register-CSRF-token-in-conn-request_info.patch"
patch -p1 < patch/civetweb/0001-Register-CSRF-token-in-conn-request_info.patch

echo "Applying patch 0001-Log-debug-messages-to-webserver.log-when-debug.webse.patch"
patch -p1 < patch/civetweb/0001-Log-debug-messages-to-webserver.log-when-debug.webse.patch

echo "Applying patch 0001-Expose-bound-to-addresses-from-CivetWeb-to-the-front.patch"
patch -p1 < patch/civetweb/0001-Expose-bound-to-addresses-from-CivetWeb-to-the-front.patch

echo "Applying patch 0001-Increase-niceness-of-all-civetweb-threads-as-DNS-ope.patch"
patch -p1 < patch/civetweb/0001-Increase-niceness-of-all-civetweb-threads-as-DNS-ope.patch

echo "ALL PATCHES APPLIED OKAY"
