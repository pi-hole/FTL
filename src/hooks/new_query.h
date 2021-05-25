/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_NEW_QUERY_H
#define FTL_NEW_QUERY_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

#include <stdbool.h>
// struct ednsData
#include "../edns0.h"
// enum protocol
#include "../enums.h"

#define FTL_new_query(flags, name, blockingreason, addr, types, qtype, id, edns, proto) _FTL_new_query(flags, name, blockingreason, addr, types, qtype, id, edns, proto, __FILE__, __LINE__)
bool _FTL_new_query(const unsigned int flags, const char *name, const char** blockingreason, union mysockaddr *addr, const char *types, const unsigned short qtype, const int id, const ednsData *edns, enum protocol proto, const char* file, const int line);

#endif // FTL_NEW_QUERY_H
