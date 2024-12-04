/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DHCPv6 / ICMPv6 discovery prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DHCPV6_DISCOVER_H
#define DHCPV6_DISCOVER_H

int dhcpv6_discover_iface(const char *ifname, const unsigned int timeout);

#endif // DHCPV6_DISCOVER_H
