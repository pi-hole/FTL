/* Pi-hole: A black hole for Internet advertisements
*  (c) 2022 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Embedded LUA scripts processor
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LUA_SCRIPTS_H
#define LUA_SCRIPTS_H

static const char inspect_lua[] = {
#include "inspect.lua.hex"
};

#endif // LUA_SCRIPTS_H