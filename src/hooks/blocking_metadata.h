/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_BLOCKING_METADATA_H
#define FTL_BLOCKING_METADATA_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

#define FTL_get_blocking_metadata(addrp, flags) _FTL_get_blocking_metadata(addrp, flags, __FILE__, __LINE__)
void _FTL_get_blocking_metadata(union all_addr **addrp, unsigned int *flags, const char *file, const int line);

extern unsigned char force_next_DNS_reply;

#endif // FTL_BLOCKING_METADATA_H
