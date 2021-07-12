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
#include "pihole_PTR.h"
// struct config
#include "../config/config.h"

static struct ptr_record *pihole_ptr = NULL;

void pihole_PTR(char *domain)
{
	// Convert PTR request into numeric form
	union all_addr addr = {{ 0 }};
	const int flags = in_arpa_name_2_addr(domain, &addr);

	// Check if this is a valid in-addr.arpa (IPv4) or ip6.[int|arpa] (IPv6)
	// specifier. If not, nothing is to be done here and we return early
	if(flags == 0 || pihole_ptr == NULL)
		return;

	// We do not want to reply with "pi.hole" to loopback PTRs
	if((flags == F_IPV4 && addr.addr4.s_addr == htonl(INADDR_LOOPBACK)) ||
	   (flags == F_IPV6 && IN6_IS_ADDR_LOOPBACK(&addr.addr6)))
		return;

	// If we reached this point, addr contains the address the client requested
	// a name for. We compare this address against all addresses of the local
	// interfaces to see if we should reply with "pi.hole"
	for (struct irec *iface = daemon->interfaces; iface != NULL; iface = iface->next)
	{
		const sa_family_t family = iface->addr.sa.sa_family;
		if((family == AF_INET && flags == F_IPV4 && iface->addr.in.sin_addr.s_addr == addr.addr4.s_addr) ||
		   (family == AF_INET6 && flags == F_IPV6 && IN6_ARE_ADDR_EQUAL(&iface->addr.in6.sin6_addr, &addr.addr6)))
		{
			// The last PTR record in daemon->ptr is reserved for Pi-hole
			free(pihole_ptr->name);
			pihole_ptr->name = strdup(domain);
			return;
		}
	}
}

void init_pihole_PTR(void)
{
	// Obtain PTR record used for Pi-hole PTR injection (if enabled)
	if(!config.pihole_ptr)
		return;

    // Add PTR record for pi.hole, the address will be injected later
    pihole_ptr = calloc(1, sizeof(struct ptr_record));
    pihole_ptr->name = strdup("x.x.x.x.in-addr.arpa");
    pihole_ptr->ptr = (char*)"pi.hole";
    pihole_ptr->next = NULL;
    // Add our PTR record to the end of the linked list
    if(daemon->ptr != NULL)
    {
        // Interate to the last PTR entry in dnsmasq's structure
        struct ptr_record *ptr;
        for(ptr = daemon->ptr; ptr && ptr->next; ptr = ptr->next);

        // Add our record after the last existing ptr-record
        ptr->next = pihole_ptr;
    }
    else
    {
        // Ours is the only record for daemon->ptr
        daemon->ptr = pihole_ptr;
    }
}
