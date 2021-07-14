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
#include "mysockaddr_extract_ip_port.h"

void mysockaddr_extract_ip_port(union mysockaddr *server, char ip[ADDRSTRLEN+1], in_port_t *port)
{
	// Extract IP address
	inet_ntop(server->sa.sa_family,
	          server->sa.sa_family == AF_INET ?
	            (void*)&server->in.sin_addr :
	            (void*)&server->in6.sin6_addr,
	          ip, ADDRSTRLEN);

	// Extract port (only if requested)
	if(port != NULL)
	{
		*port = ntohs(server->sa.sa_family == AF_INET ?
		                server->in.sin_port :
		                server->in6.sin6_port);
	}
}
