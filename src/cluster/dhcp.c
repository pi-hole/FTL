/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster DHCP failover
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "config/config.h"
#include "config/dnsmasq_config.h"
#include "config/toml_writer.h"
#include "cluster/cluster.h"
#include "cluster/dhcp.h"
#include "cluster/vip.h"
// restart_ftl()
#include "signals.h"
// lock_shm()
#include "shmem.h"

// Consecutive rounds the outcome of the election has been the same. A single
// missed answer must not move DHCP: a takeover costs a restart on two nodes
static unsigned int rounds_wanting = 0;
static unsigned int rounds_yielding = 0;

// The last cluster.dhcp.master we complained about, so we complain once
static char warned_master[CLUSTER_STRLEN] = "";

// Set once we asked for a restart. The configuration has been replaced at that
// point and FTL is shutting down, so the round has to end right here
static bool restarting = false;

bool cluster_dhcp_restarting(void)
{
	return restarting;
}

// Can this node serve DHCP at all? A node without a lease range has nothing to
// take over with, and claiming DHCP would leave the network without a server
static bool dhcp_capable(void)
{
	return config.dhcp.start.v.in_addr.s_addr != 0 && config.dhcp.end.v.in_addr.s_addr != 0;
}

// Does this name refer to the given peer? A node is pinned by its name: its URL
// is known to its peers but not to itself, so matching on that would have every
// peer yield to a node that does not recognize itself as the one pinned
static bool peer_matches(const struct cluster_peer *peer, const char *needle)
{
	return strlen(needle) > 0 && strlen(peer->name) > 0 && strcmp(peer->name, needle) == 0;
}

// A peer only counts in the election if it is reachable, takes part in the
// failover itself, and could actually serve DHCP. A peer that has failover
// switched off keeps whatever DHCP state its administrator gave it and is none
// of our business
static bool peer_competes(const struct cluster_peer *peer)
{
	return peer->reachable && peer->failover && peer->dhcp_capable;
}

// Is any node of the cluster in a position to serve DHCP?
bool cluster_dhcp_available(struct cluster_peer *peers, const unsigned int num_peers)
{
	if(dhcp_capable())
		return true;

	for(unsigned int i = 0; i < num_peers; i++)
		if(peer_competes(&peers[i]))
			return true;

	return false;
}

// Who should be serving DHCP? Priority decides, ties are broken by name so
// every node comes to the same conclusion. Returns whether that node is us
static bool elect_dhcp(struct cluster_peer *peers, const unsigned int num_peers,
                       char owner[CLUSTER_STRLEN])
{
	char myname[CLUSTER_STRLEN] = "";
	cluster_name(myname);

	// Copied out of the configuration: another thread may replace it while
	// we are working with it
	char master[CLUSTER_STRLEN] = "";
	lock_shm();
	strncpy(master, config.cluster.dhcp.master.v.s, sizeof(master) - 1);
	unlock_shm();
	master[sizeof(master) - 1] = '\0';

	// A pinned node short-circuits the priority order - unless it is not in
	// a position to serve, in which case the others fall back to it
	if(strlen(master) > 0)
	{
		if(strcmp(master, myname) == 0)
		{
			strncpy(owner, myname, CLUSTER_STRLEN - 1);
			return true;
		}

		bool known = false;
		for(unsigned int i = 0; i < num_peers; i++)
		{
			if(!peer_matches(&peers[i], master))
				continue;

			known = true;
			if(peer_competes(&peers[i]))
			{
				strncpy(owner, peers[i].name, CLUSTER_STRLEN - 1);
				return false;
			}
		}

		// A pin naming a node nobody knows is a typo, not an instruction.
		// Ignoring it here and everywhere else keeps the nodes in
		// agreement rather than having them yield to a ghost
		if(!known && strcmp(warned_master, master) != 0)
		{
			log_warn("Cluster: cluster.dhcp.master names \"%s\", which is not a node of this cluster - using the priority order",
			         master);
			strncpy(warned_master, master, sizeof(warned_master) - 1);
		}
	}

	const char *best_name = myname;
	unsigned int best_priority = config.cluster.priority.v.ui;
	bool best_is_me = true;

	for(unsigned int i = 0; i < num_peers; i++)
	{
		const struct cluster_peer *peer = &peers[i];
		if(!peer_competes(peer))
			continue;

		// The pinned node is out of the running here: it already had its
		// chance above and was not able to take it
		if(peer_matches(peer, master))
			continue;

		if(peer->priority < best_priority ||
		   (peer->priority == best_priority && strcmp(peer->name, best_name) < 0))
		{
			best_priority = peer->priority;
			best_name = peer->name;
			best_is_me = false;
		}
	}

	strncpy(owner, best_name, CLUSTER_STRLEN - 1);

	return best_is_me;
}

// Switch the local DHCP server on or off. This is the same path a user takes
// through the API, down to the restart the changed dnsmasq configuration needs
static void set_dhcp_active(const bool active, const char *reason)
{
	// A read-only node is managed from the outside, so taking DHCP over
	// would be undone at the next restart
	if(config.misc.readOnly.v.b)
	{
		log_warn("Cluster: Cannot %s DHCP, the configuration is read-only",
		         active ? "take over" : "hand over");
		return;
	}

	// The same goes for dhcp.active pinned through the environment: the
	// restart below would bring the pinned value straight back, and the next
	// round would decide the same thing again - once every few seconds
	if(config.dhcp.active.f & FLAG_ENV_VAR)
	{
		log_warn("Cluster: Cannot %s DHCP, dhcp.active is pinned through the environment",
		         active ? "take over" : "hand over");
		return;
	}

	struct config newconf;
	duplicate_config(&newconf, &config);
	newconf.dhcp.active.v.b = active;

	char errbuf[ERRBUF_SIZE] = { 0 };
	if(!write_dnsmasq_config(&newconf, true, errbuf))
	{
		log_err("Cluster: Unable to %s DHCP: %s", active ? "enable" : "disable", errbuf);
		free_config(&newconf, false);
		return;
	}

	replace_config(&newconf);
	writeFTLtoml(true, NULL);

	log_info("Cluster: %s DHCP (%s)", active ? "Taking over" : "Handing over", reason);

	restarting = true;
	restart_ftl(active ? "Cluster: taking over DHCP" : "Cluster: handing over DHCP");
}

bool cluster_dhcp_round(struct cluster_peer *peers, const unsigned int num_peers,
                        char owner[CLUSTER_STRLEN])
{
	owner[0] = '\0';

	// Without failover, DHCP is whatever the administrator configured, and
	// the virtual IP address follows the configuration instead
	if(!config.cluster.dhcp.failover.v.b)
		return false;

	if(!dhcp_capable())
	{
		if(rounds_wanting == 0)
			log_warn("Cluster: DHCP failover is enabled but no lease range is configured, "
			         "this node cannot serve DHCP");
		rounds_wanting = 1;
		return false;
	}

	const bool mine = elect_dhcp(peers, num_peers, owner);
	owner[CLUSTER_STRLEN - 1] = '\0';

	const bool serving = config.dhcp.active.v.b;

	// Somebody else is still handing out leases. Waiting for them to stop
	// keeps two DHCP servers with separate lease databases off the network,
	// which is worse than a few seconds without one
	bool peer_serving = false;
	for(unsigned int i = 0; i < num_peers; i++)
		if(peers[i].reachable && peers[i].dhcp_active)
			peer_serving = true;

	if(mine && !serving && peer_serving)
	{
		log_debug(DEBUG_CLUSTER, "Cluster: Waiting for %s to stop serving DHCP", owner);
		return serving;
	}

	if(mine && !serving)
	{
		rounds_yielding = 0;
		rounds_wanting++;
		if(rounds_wanting < config.cluster.dhcp.activateAfter.v.ui)
		{
			log_debug(DEBUG_CLUSTER, "Cluster: Would take DHCP over (%u/%u rounds)",
			          rounds_wanting, config.cluster.dhcp.activateAfter.v.ui);
			// Not ours yet: the virtual IP address follows the DHCP
			// server, and that is still the other node
			return serving;
		}

		set_dhcp_active(true, "no higher-priority node is serving");
		rounds_wanting = 0;
		return mine;
	}

	if(!mine && serving)
	{
		rounds_wanting = 0;
		rounds_yielding++;
		if(rounds_yielding < config.cluster.dhcp.deactivateAfter.v.ui)
		{
			log_debug(DEBUG_CLUSTER, "Cluster: Would hand DHCP over to %s (%u/%u rounds)",
			          owner, rounds_yielding, config.cluster.dhcp.deactivateAfter.v.ui);
			// Still ours until we actually hand it over
			return serving;
		}

		set_dhcp_active(false, owner);
		rounds_yielding = 0;
		return mine;
	}

	rounds_wanting = 0;
	rounds_yielding = 0;

	return mine;
}

void cluster_vip_round(const bool mine)
{
	char address[CLUSTER_STRLEN] = "";
	cluster_vip_address(address);
	if(strlen(address) == 0)
		return;

	if(mine)
		vip_claim(address);
	else
		vip_release(address);
}

void cluster_vip_shutdown(void)
{
	char address[CLUSTER_STRLEN] = "";
	cluster_vip_address(address);
	if(strlen(address) == 0)
		return;

	// Leaving the address behind would keep clients talking to a Pi-hole
	// that is no longer answering
	vip_release(address);
}
