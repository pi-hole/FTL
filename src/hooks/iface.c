/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "iface.h"
#include "../config.h"
#include "../log.h"

// Fork-private copy of the interface name the most recent query came from
struct nxtiface next_iface = {"", {{0}}, {{0}}};

void FTL_iface(const int ifidx, const struct irec *ifaces)
{
	// Invalidate data we have from the last interface/query
	// Set addresses to 0.0.0.0 and ::, respectively
	memset(&next_iface.addr4, 0, sizeof(next_iface.addr4));
	memset(&next_iface.addr6, 0, sizeof(next_iface.addr6));

	// Copy overwrite addresses if configured via REPLY_ADDR4 and/or REPLY_ADDR6 settings
	if(config.reply_addr.overwrite_v4)
		memcpy(&next_iface.addr4, &config.reply_addr.v4, sizeof(config.reply_addr.v4));
	if(config.reply_addr.overwrite_v6)
		memcpy(&next_iface.addr6, &config.reply_addr.v6, sizeof(config.reply_addr.v6));

	// Use dummy when interface record is not available
	next_iface.name[0] = '-';
	next_iface.name[1] = '\0';

	// Return early when there is no interface available at this point
	if(ifidx == -1 || ifaces == NULL)
		return;

	// Determine addresses of this interface
	const struct irec *iface;
	bool haveIPv4 = false, haveGUAv6 = false, haveULAv6 = false;
	for (iface = ifaces; iface != NULL; iface = iface->next)
	{
		// If this interface has no name, we skip it
		if(iface->name == NULL)
			continue;

		// Check if this is the interface we want
		if(iface->index != ifidx)
			continue;

		// Copy interface name
		strncpy(next_iface.name, iface->name, sizeof(next_iface.name)-1);
		next_iface.name[sizeof(next_iface.name)-1] = '\0';

		// Check if this family type is overwritten by config settings
		const int family = iface->addr.sa.sa_family;
		if((config.reply_addr.overwrite_v4 && family == AF_INET) ||
		   (config.reply_addr.overwrite_v6 && family == AF_INET6))
			continue;

		bool isULA = false, isGUA = false;
		// Check if this address is different from 0000:0000:0000:0000:0000:0000:0000:0000
		if(family == AF_INET6 && memcmp(&next_iface.addr6.addr6, &iface->addr.in6.sin6_addr, sizeof(iface->addr.in6.sin6_addr)) != 0)
		{
			// Extract first byte
			// We do not directly access the underlying union as
			// MUSL defines it differently than GNU C
			uint8_t firstbyte;
			memcpy(&firstbyte, &iface->addr.in6.sin6_addr, 1);
		        // Global Unicast Address (2000::/3, RFC 4291)
			isGUA = (firstbyte & 0x70) == 0x20;
			// Unique Local Address   (fc00::/7, RFC 4193)
			isULA = (firstbyte & 0xfe) == 0xfc;
			// Store IPv6 address only if we don't already have a GUA or ULA address
			// This makes the preference:
			//  1. ULA
			//  2. GUA
			//  3. Link-local
			if((!haveGUAv6 && !haveULAv6) || (haveGUAv6 && isULA))
			{
				memcpy(&next_iface.addr6.addr6, &iface->addr.in6.sin6_addr, sizeof(iface->addr.in6.sin6_addr));
				if(isGUA)
					haveGUAv6 = true;
				else if(isULA)
					haveULAv6 = true;
			}
		}
		// Check if this address is different from 0.0.0.0
		else if(family == AF_INET && memcmp(&next_iface.addr4.addr4, &iface->addr.in.sin_addr, sizeof(iface->addr.in.sin_addr)) != 0)
		{
			haveIPv4 = true;
			// Store IPv4 address
			memcpy(&next_iface.addr4.addr4, &iface->addr.in.sin_addr, sizeof(iface->addr.in.sin_addr));
		}

		// Debug logging
		if(config.debug & DEBUG_NETWORKING)
		{
			char buffer[ADDRSTRLEN+1] = { 0 };
			if(family == AF_INET)
				inet_ntop(AF_INET, &iface->addr.in.sin_addr, buffer, ADDRSTRLEN);
			else if(family == AF_INET6)
				inet_ntop(AF_INET6, &iface->addr.in6.sin6_addr, buffer, ADDRSTRLEN);
			log_debug(DEBUG_NETWORKING, "Interface (%d) %s has IPv%i address %s %s", ifidx, next_iface.name,
			          family == AF_INET ? 4 : 6, buffer, isGUA ? "(GUA)" : isULA ? "(ULA)" : "(other)");
		}


		// Exit loop early if we already have everything we need
		// (a valid IPv4 address + a valid ULA IPv6 address)
		if(haveIPv4 && haveULAv6)
			break;
	}
}
