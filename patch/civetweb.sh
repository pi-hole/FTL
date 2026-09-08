#!/bin/sh
# Re-apply the Pi-hole modifications on top of a fresh CivetWeb drop.
#
# The sources are copied in by hand from a checkout of
# https://github.com/DL6ER/civetweb (branch `pi-hole`), which tracks CivetWeb
# master plus the fixes we have pending upstream. Everything Pi-hole specific
# lives here rather than on that branch, so it stays close to master.
#
# We use `git apply --3way` rather than `patch`. `patch` matches hunks by
# surrounding context and, when that context has drifted, silently applies them
# somewhere else: three of these patches were quietly lost that way while
# `patch` still reported success. A three-way merge uses the blob the patch was
# generated against, so it either merges correctly or leaves a real conflict.
# It also tolerates code moving around, which is the normal case after a bump.
#
# The drop has to be committed (or at least staged) before running this, since
# the three-way merge needs the index to hold the unpatched sources.
set -e

fail=0

for patch in \
    0001-add-pihole-mods.patch \
    0001-Always-Kepler-syntax-for-Lua-server-pages.patch \
    0001-Add-FTL-URI-rewriting-changes-to-CivetWeb.patch \
    0001-Register-CSRF-token-in-conn-request_info.patch \
    0001-Log-debug-messages-to-webserver.log-when-debug.webse.patch \
    0001-Expose-bound-to-addresses-from-CivetWeb-to-the-front.patch \
    0001-Increase-niceness-of-all-civetweb-threads-as-DNS-ope.patch \
    0001-Demote-server-side-TLS-handshake-alerts-to-debug.patch
do
    printf 'Applying %s ... ' "$patch"
    if git apply --3way --index "patch/civetweb/$patch"; then
        echo "ok"
    else
        echo "FAILED"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "One or more patches did not apply - resolve the conflicts before building." >&2
    exit 1
fi

echo "ALL PATCHES APPLIED OKAY"
