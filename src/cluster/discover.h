/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster discovery prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CLUSTER_DISCOVER_H
#define CLUSTER_DISCOVER_H

#include "FTL.h"
#include <netinet/in.h>
#include <net/if.h>

// Fixed, because both sides have to agree on it without being told
#define CLUSTER_BEACON_PORT 4712

// What a node that answered says about itself: where it is, and on which port
// it speaks HTTPS. Nothing else - a cluster does not advertise its name
struct cluster_found {
	// Room for a link-local address and the interface it is on, which is
	// part of the address as far as anything connecting to it is concerned
	char address[INET6_ADDRSTRLEN + IF_NAMESIZE + 1];
	in_port_t port;
};

// Answering side, run from the cluster thread
bool cluster_beacon_open(void);
void cluster_beacon_poll(void);
void cluster_beacon_close(void);

// Asking side, run from an API request
unsigned int cluster_discover(struct cluster_found *found, unsigned int max,
                              const double timeout);

#endif // CLUSTER_DISCOVER_H
