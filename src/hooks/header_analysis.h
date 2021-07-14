/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_HEADER_ANALYSIS_H
#define FTL_HEADER_ANALYSIS_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

extern union mysockaddr last_server;

#define FTL_header_analysis(header4, rcode, server, id) _FTL_header_analysis(header4, rcode, server, id, __FILE__, __LINE__)
void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const struct server *server,
                          const int id, const char* file, const int line);

#endif // FTL_HEADER_ANALYSIS_H
