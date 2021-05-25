/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_IFACE_H
#define FTL_IFACE_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

// IFNAMSIZ
#include <net/if.h>

void FTL_iface(const int ifidx, const struct irec *ifaces);

struct nxtiface {
	char name[IFNAMSIZ];
	union all_addr addr4;
	union all_addr addr6;
};

extern struct nxtiface next_iface;

#endif // FTL_IFACE_H
