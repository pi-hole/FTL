/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster DHCP failover prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CLUSTER_DHCP_H
#define CLUSTER_DHCP_H

#include "FTL.h"
#include "cluster/cluster.h"

// Is any node of the cluster able to serve DHCP at all?
bool cluster_dhcp_available(struct cluster_peer *peers, const unsigned int num_peers) __attribute__ ((pure));

// Decide who serves DHCP and act on the outcome. Fills owner with the name of
// the node that should be serving - which may well be a peer - and returns
// whether that node is this one
bool cluster_dhcp_round(struct cluster_peer *peers, const unsigned int num_peers,
                        char owner[CLUSTER_STRLEN]);

// Did the last round ask FTL to restart? Nothing else should happen then: the
// configuration has just been replaced and the daemon is on its way out
bool cluster_dhcp_restarting(void) __attribute__ ((pure));

// Claim or release the virtual IP address depending on whether this node is
// the one clients should be talking to
void cluster_vip_round(const bool mine);

// Give the virtual IP address up when FTL stops
void cluster_vip_shutdown(void);

#endif // CLUSTER_DHCP_H
