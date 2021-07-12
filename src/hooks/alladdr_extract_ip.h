/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_ALLADDR_EXTRACT_IP_H
#define FTL_ALLADDR_EXTRACT_IP_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

void alladdr_extract_ip(union all_addr *addr, const sa_family_t family, char ip[ADDRSTRLEN+1]);
void mysockaddr_extract_ip_port(union mysockaddr *server, char ip[ADDRSTRLEN+1], in_port_t *port);

#endif // FTL_ALLADDR_EXTRACT_IP_H
