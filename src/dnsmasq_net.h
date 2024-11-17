/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Private network detection
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DNSMASQ_NET_H
#define DNSMASQ_NET_H

#include <arpa/inet.h>

// defined in src/dnsmasq/rfc1035.c
extern int private_net(struct in_addr addr, int ban_localhost);
extern int private_net6(struct in6_addr *a, int ban_localhost);

#endif
