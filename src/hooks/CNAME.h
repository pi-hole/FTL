/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_CNAME_H
#define FTL_CNAME_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

#define FTL_CNAME(domain, cpp, id) _FTL_CNAME(domain, cpp, id, __FILE__, __LINE__)
bool _FTL_CNAME(const char *domain, const struct crec *cpp, const int id, const char* file, const int line);

#endif // FTL_CNAME_H
