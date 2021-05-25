/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_DETECT_BLOCKED_IP_H
#define FTL_DETECT_BLOCKED_IP_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif

  #include "../datastructure.h"
  enum query_status detect_blocked_IP(const unsigned short flags,
                                      const union all_addr *addr,
                                      const queriesData *query,
                                      const domainsData *domain);
#endif // FTL_PRIVATE

#endif // FTL_DETECT_BLOCKED_IP_H
