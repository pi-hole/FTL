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

// Decide who serves DHCP and act on the outcome. Fills owner with the name of
// the node that should be serving - which may well be a peer - and returns
// whether that node is this one
// What a round decided: who serves DHCP, whether this node has to change what
// it is doing, and where the address the clients use belongs
// How many consecutive rounds a decision has to hold before DHCP - and the
// address that follows it - moves. One missed answer must not move either, and
// a number of rounds is not something anybody has ever needed to tune
#define CLUSTER_DHCP_ACTIVATE_ROUNDS 2u
#define CLUSTER_DHCP_DEACTIVATE_ROUNDS 3u

struct cluster_intent {
	char owner[CLUSTER_STRLEN];
	bool serve;        // this node should be handing out leases
	bool change_dhcp;  // ...and that differs from what it is doing now
	bool hold_vip;     // the virtual IP address belongs here
};

void cluster_dhcp_round(struct cluster_peer *peers, const unsigned int num_peers,
                        const bool member, const bool leader_is_us,
                        struct cluster_intent *intent);
bool cluster_dhcp_apply(const struct cluster_intent *intent);

// Did the last round ask FTL to restart? Nothing else should happen then: the
// configuration has just been replaced and the daemon is on its way out
bool cluster_dhcp_capable(void);
bool cluster_dhcp_configured(void);
bool cluster_dhcp_restarting(void) __attribute__ ((pure));

// Claim or release the virtual IP address depending on whether this node is
// the one clients should be talking to
void cluster_vip_round(bool mine);

// Give the virtual IP address up when FTL stops
void cluster_vip_shutdown(void);

#endif // CLUSTER_DHCP_H
