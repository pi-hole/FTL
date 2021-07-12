/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_SET_REPLY_H
#define FTL_SET_REPLY_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif

  #include "../datastructure.h"
#endif // FTL_PRIVATE

#define query_set_reply(flags, addr, query, now) _query_set_reply(flags, addr, query, now, __FILE__, __LINE__)
void _query_set_reply(const unsigned int flags, const union all_addr *addr,
                      queriesData *query, const double now,
                      const char *file, const int line);

#endif // FTL_SET_REPLY_H
