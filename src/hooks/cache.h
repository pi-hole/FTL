/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_CACHE_H
#define FTL_CACHE_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

#define FTL_cache(flags, name, addr, arg, id, ttl) _FTL_cache(flags, name, addr, arg, id, ttl, __FILE__, __LINE__)
void _FTL_cache(const unsigned int flags, const char *name, const union all_addr *addr, const char * arg, const int id, const unsigned long ttl, const char* file, const int line);

#endif // FTL_CACHE_H
