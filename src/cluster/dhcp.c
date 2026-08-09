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
// CLUSTER_SECRET_FILE
#include "config/password.h"
#include "config/dnsmasq_config.h"
#include "config/toml_writer.h"
#include "cluster/cluster.h"
#include "cluster/dhcp.h"
// gravity_running
#include "daemon.h"
#include "cluster/vip.h"
// cluster_node_id()
#include "cluster/sync.h"
#include <math.h>
// restart_ftl()
#include "signals.h"
// lock_shm()
#include "shmem.h"

// Consecutive rounds the outcome of the election has been the same. A single
// missed answer must not move DHCP: a takeover costs a restart on two nodes
static unsigned int rounds_wanting = 0;
static unsigned int rounds_yielding = 0;


// Said once rather than once per round while the condition lasts
static bool warned_incapable = false;
static bool warned_refused = false;

// ...and the same for peers that run DHCP failover while this node does not
static bool warned_failover = false;

// Set once we asked for a restart. The configuration has been replaced at that
// point and FTL is shutting down, so the round has to end right here
static bool restarting = false;

bool cluster_dhcp_restarting(void)
{
	return restarting;
}

// Set once a take-over failed for a reason the next round will hit again, so
// this node stops telling its peers it could serve
// When a failed take-over stops counting against this node. The reasons are
// mostly passing - a fork that failed, a disk that was full - and a node that
// took itself out of the running for good could leave the network with nobody
// serving at all
static double takeover_failed_until = 0.0;
static unsigned int takeover_failures = 0;
#define CLUSTER_TAKEOVER_BACKOFF 300.0
#define CLUSTER_TAKEOVER_BACKOFF_MAX 3600.0

// Doubling with every failure. A fault that is not going to clear - a static
// lease dnsmasq refuses, a full disk - would otherwise put this node back into
// the election every five minutes, and each attempt restarts the node that is
// currently serving
static void takeover_failed(void)
{
	double wait = CLUSTER_TAKEOVER_BACKOFF;
	for(unsigned int i = 0; i < takeover_failures && wait < CLUSTER_TAKEOVER_BACKOFF_MAX; i++)
		wait *= 2.0;

	takeover_failures++;
	takeover_failed_until = double_time() + fmin(wait, CLUSTER_TAKEOVER_BACKOFF_MAX);
}

// Can this node serve DHCP at all? Not "has it a lease range" but the whole
// question dnsmasq is asked when the configuration is written - a node that
// answers yes here and then cannot write its configuration leaves the network
// without a server, because the node that handed over has already stopped
// Is this node set up to serve DHCP at all - a range it could hand out, a
// configuration it may write, no environment pinning dhcp.active where the
// cluster cannot move it?
//
// Asked apart from cluster_dhcp_capable() because the two answer different
// questions. A node that failed a takeover is not capable for the next few
// minutes and then is again; a node with no lease range never will be. Both say
// "no" to capability, and a peer that has to decide whether anybody will pick
// DHCP up needs to tell them apart
bool cluster_dhcp_configured(void)
{
	if(config.misc.readOnly.v.b || (config.dhcp.active.f & FLAG_ENV_VAR))
		return false;

	char errbuf[ERRBUF_SIZE] = { 0 };
	lock_shm();
	const bool okay = dhcp_config_valid(&config, errbuf);
	unlock_shm();

	return okay;
}

bool cluster_dhcp_capable(void)
{
	// ...and this one is that, minus the two things that make a node unable to
	// take DHCP over just now: the wait a failed takeover leaves behind, and a
	// gravity run, which holds back the restart that would apply the change.
	//
	// Both belong here rather than in cluster_dhcp_configured(). A peer
	// deciding whether to hand DHCP over asks whether anybody is set up to
	// serve; the node it hands to has to be able to start serving. Saying yes
	// here while set_dhcp_active() would decline is how the node that was
	// serving stops and nobody takes its place
	if(cluster_waiting(takeover_failed_until, double_time(), CLUSTER_TAKEOVER_BACKOFF_MAX) ||
	   gravity_running)
		return false;

	return cluster_dhcp_configured();
}

// A peer only counts in the election if it is reachable, takes part in the
// failover itself, and could actually serve DHCP. A peer that has failover
// switched off keeps whatever DHCP state its administrator gave it and is none
// of our business
static bool peer_competes(const struct cluster_peer *peer)
{
	return peer->reachable && peer->failover && peer->dhcp_capable && !peer->is_self;
}

// Who should be serving DHCP? The reachable node with the lowest identity.
// Arbitrary but stable, and every node reaches the same answer without asking
// anybody - which is what matters: two nodes disagreeing is two DHCP servers.
// Returns whether that node is us, and names the winner
static bool elect_dhcp(struct cluster_peer *peers, const unsigned int num_peers,
                       char owner[CLUSTER_STRLEN], char owner_id[CLUSTER_HASHLEN])
{
	char myname[CLUSTER_STRLEN] = "";
	cluster_name(myname);

	const char *best_name = myname;
	const char *best_id = cluster_node_id();
	bool best_is_me = true;

	for(unsigned int i = 0; i < num_peers; i++)
	{
		const struct cluster_peer *peer = &peers[i];
		if(!peer_competes(peer))
			continue;

		// By identity, never by name: two Pi-holes imaged from the same
		// card are both "raspberrypi", and a comparison neither of them
		// wins is two DHCP servers on one network
		if(strcmp(peer->id, best_id) < 0)
		{
			best_name = peer->name;
			best_id = peer->id;
			best_is_me = false;
		}
	}

	strncpy(owner, best_name, CLUSTER_STRLEN - 1);
	owner[CLUSTER_STRLEN - 1] = '\0';
	strncpy(owner_id, best_id, CLUSTER_HASHLEN - 1);
	owner_id[CLUSTER_HASHLEN - 1] = '\0';

	return best_is_me;
}

// Switch the local DHCP server on or off. This is the same path a user takes
// through the API, down to the restart the changed dnsmasq configuration needs
static void set_dhcp_active(const bool active, const char *reason)
{
	// The switch and the restart that applies it are one act. A gravity run
	// holds the restart back until it finishes - minutes, and this node runs
	// one itself whenever it takes a peer's lists - and flipping the switch
	// meanwhile would have this node telling its peers it serves DHCP while
	// its dnsmasq does not, or the other way round. The election is decided
	// again every round, so this is a wait rather than a decision
	if(gravity_running)
	{
		log_debug(DEBUG_CLUSTER, "cluster: not changing DHCP while gravity runs");
		return;
	}

	// A read-only node is managed from the outside, so taking DHCP over
	// would be undone at the next restart
	if(config.misc.readOnly.v.b)
	{
		log_warn("cluster: cannot %s DHCP, config is read-only",
		         active ? "take over" : "hand over");
		takeover_failed();
		return;
	}

	// The same goes for dhcp.active pinned through the environment: the
	// restart below would bring the pinned value straight back, and the next
	// round would decide the same thing again - once every few seconds
	if(config.dhcp.active.f & FLAG_ENV_VAR)
	{
		log_warn("cluster: cannot %s DHCP, dhcp.active is pinned through the environment",
		         active ? "take over" : "hand over");
		takeover_failed();
		return;
	}

	// The same lock the two API writers take. This copies the configuration,
	// tests it - which forks a dnsmasq, taking hundreds of milliseconds -
	// and installs the copy, and a save arriving in that window would be
	// answered 200 and then reverted both in memory and in pihole.toml
	cluster_sync_lock();

	struct config newconf;
	duplicate_config(&newconf, &config);
	newconf.dhcp.active.v.b = active;

	char errbuf[ERRBUF_SIZE] = { 0 };
	if(!write_dnsmasq_config(&newconf, true, errbuf))
	{
		log_err("cluster: cannot %s DHCP: %s", active ? "enable" : "disable",
		        strlen(errbuf) > 0 ? errbuf : "the configuration was refused");
		free_config(&newconf, false);
		cluster_sync_unlock();

		// Told to the peers rather than only to the log: they elected
		// this node because it said it could serve, and they have to
		// elect somebody else now
		takeover_failed();
		return;
	}

	takeover_failed_until = 0.0;
	takeover_failures = 0;

	replace_config(&newconf);
	writeFTLtoml(true, NULL);
	cluster_sync_unlock();

	log_info("cluster: %s DHCP (%s)", active ? "taking over" : "handing over", reason);

	restarting = true;
	restart_ftl(active ? "cluster: taking over DHCP" : "cluster: handing over DHCP");
}

// One decision per round, taken in one pass and then applied. The rules used to
// be spread over early returns that each answered part of the question, and
// every one of them had to remember the other half: who serves DHCP, and where
// the address the clients use belongs. Anything that left one of the two
// unanswered put the address on two machines, or on none
void cluster_dhcp_round(struct cluster_peer *peers, const unsigned int num_peers,
                        const bool member, const bool leader_is_us,
                        struct cluster_intent *intent)
{
	memset(intent, 0, sizeof(*intent));

	const bool serving = config.dhcp.active.v.b;

	// A node the cluster no longer lists is on its own. It gives the address
	// back and stops handing out leases: the remaining nodes have elected
	// somebody else by now, and two servers on one range is the worst of the
	// outcomes available here
	if(!member)
	{
		intent->owner[0] = '\0';
		intent->hold_vip = false;

		// Only what the cluster switched on does the cluster switch off.
		// Without failover, dhcp.active is the administrator's setting
		// and leaving the member list is no reason to touch it
		intent->serve = config.cluster.dhcp.failover.v.b ? false : serving;
		intent->change_dhcp = intent->serve != serving;
		return;
	}

	// Whether failover runs is a per-node setting, and a node that does not
	// run it decides the address differently - so nodes disagreeing about it
	// would place the address twice, or not at all. One node running it is
	// enough for the DHCP server to anchor the address everywhere
	bool failover_anywhere = config.cluster.dhcp.failover.v.b;
	bool peer_serving = false, owner_serving = false, peer_capable = false;

	// A peer that answers and then refuses us is a peer that is running - so
	// if none of them will talk to us and at least one of them is up, the
	// fault is here rather than out there
	bool any_reachable = false, refusing = false;
	for(unsigned int i = 0; i < num_peers; i++)
	{
		if(peers[i].is_self)
			continue;
		if(peers[i].reachable)
			any_reachable = true;
		else if(peers[i].answered)
			refusing = true;
	}

	for(unsigned int i = 0; i < num_peers; i++)
	{
		if(peers[i].is_self || !peers[i].reachable)
			continue;
		if(peers[i].failover)
			failover_anywhere = true;
		// A peer that still sees somebody serving is reason enough to
		// wait, even when we cannot see that node ourselves
		if(peers[i].dhcp_active || peers[i].sees_dhcp)
			peer_serving = true;
		if(peer_competes(&peers[i]))
			peer_capable = true;
	}

	if(failover_anywhere && !config.cluster.dhcp.failover.v.b && !warned_failover)
	{
		log_warn("cluster: cluster.dhcp.failover is off here but on elsewhere, following the DHCP server");
		warned_failover = true;
	}

	// Nobody will talk to this node and somebody out there is up: a secret
	// that does not match, an identity the others reject. The network has a
	// working DHCP server and a node that cannot ask anybody is in no
	// position to add a second one or to move an address - so it changes
	// nothing at all until somebody fixes it.
	// Not a quorum: a node that still reaches one peer is not the odd one
	// out and carries on as usual, and a peer that is simply switched off
	// answers nothing and does not hold failover back
	if(refusing && !any_reachable)
	{
		if(!warned_refused)
			log_warn("cluster: the other nodes answer but do not accept this one, so DHCP and the virtual IP are left as they are - check %s",
			         CLUSTER_SECRET_FILE);
		warned_refused = true;

		intent->serve = serving;
		intent->hold_vip = vip_claimed();
		return;
	}
	warned_refused = false;

	// Without failover here, DHCP stays exactly as the administrator set it.
	// The address still follows whoever hands out leases, and falls back to
	// the leader when nobody does - the same rule the failover branch below
	// uses, so two nodes cannot answer it differently and place it twice or
	// not at all
	if(!config.cluster.dhcp.failover.v.b)
	{
		intent->serve = serving;
		intent->hold_vip = failover_anywhere ?
		                   (serving && !peer_serving) ||
		                   (!serving && !peer_serving && !peer_capable && leader_is_us) :
		                   leader_is_us;
		return;
	}

	if(!cluster_dhcp_capable())
	{
		if(!warned_incapable)
			log_warn("cluster: DHCP failover is on but this node cannot serve DHCP");
		warned_incapable = true;

		// Not being able to *change* dhcp.active is not the same as not
		// serving: a node handing out leases still anchors the address.
		// With nobody serving and nobody able to, the address follows the
		// leader instead, or it sits on no node at all
		intent->serve = serving;
		intent->hold_vip = serving || (!peer_serving && !peer_capable && leader_is_us);
		return;
	}
	warned_incapable = false;

	char owner_id[CLUSTER_HASHLEN] = "";
	const bool mine = elect_dhcp(peers, num_peers, intent->owner, owner_id);

	// By identity rather than by name: names collide, and a node that reads
	// "somebody called raspberrypi is already serving" would hand DHCP to
	// whichever of them answered first
	for(unsigned int i = 0; i < num_peers; i++)
		if(!peers[i].is_self && peers[i].dhcp_active &&
		   strcmp(peers[i].id, owner_id) == 0)
			owner_serving = true;

	// The address follows whoever is actually handing out leases. Where that
	// is nobody - during a hand-over, or with no node able to serve - it
	// follows the node that is about to, so it is never on nothing
	intent->serve = serving;
	intent->hold_vip = serving || (mine && !peer_serving) ||
	                   (!peer_serving && !peer_capable && leader_is_us);

	if(mine == serving)
	{
		// Already where it belongs
		rounds_wanting = 0;
		rounds_yielding = 0;
		return;
	}

	if(mine)
	{
		rounds_yielding = 0;

		// Somebody else is still handing out leases from the same range
		// with a lease database of its own. Their renewals and ours
		// would fight; waiting is better than that
		if(peer_serving)
		{
			// intent->owner is this node here - the one still handing out
			// leases is somebody else, and naming ourselves reads as a
			// node waiting for itself
			log_debug(DEBUG_CLUSTER, "cluster: waiting for the node still serving DHCP to stop");
			rounds_wanting = 0;
			return;
		}

		if(++rounds_wanting < CLUSTER_DHCP_ACTIVATE_ROUNDS)
		{
			log_debug(DEBUG_CLUSTER, "cluster: would take DHCP over (%u/%u rounds)",
			          rounds_wanting, CLUSTER_DHCP_ACTIVATE_ROUNDS);
			return;
		}

		rounds_wanting = 0;
		intent->change_dhcp = true;
		intent->serve = true;
		intent->hold_vip = true;
		return;
	}

	// Ours to give up. Immediately if the node taking over is already
	// serving - the wait exists so one missed answer does not move DHCP,
	// not to keep two servers on the network
	rounds_wanting = 0;
	if(!owner_serving && ++rounds_yielding < CLUSTER_DHCP_DEACTIVATE_ROUNDS)
	{
		log_debug(DEBUG_CLUSTER, "cluster: would hand DHCP over to %s (%u/%u rounds)",
		          intent->owner, rounds_yielding, CLUSTER_DHCP_DEACTIVATE_ROUNDS);
		return;
	}

	rounds_yielding = 0;
	intent->change_dhcp = true;
	intent->serve = false;

	// Held until the node taking over says it is serving, so the address is
	// never on nobody in the middle of a planned hand-over
	intent->hold_vip = !owner_serving;
}

// Apply what the round decided. Split from the decision so that a hand-over
// which cannot be carried out does not leave the address where it would have
// gone if it had
bool cluster_dhcp_apply(const struct cluster_intent *intent)
{
	// A change that cannot be carried out is attempted once per backoff
	// rather than once per round: set_dhcp_active() says why, and the
	// condition it complains about does not clear on its own
	if(intent->change_dhcp && cluster_dhcp_capable())
		set_dhcp_active(intent->serve, strlen(intent->owner) > 0 ? intent->owner :
		                (intent->serve ? "no other node is serving" : "no longer a member"));

	// What this node does, not what the election said: a change that was
	// refused leaves DHCP where it was
	return config.dhcp.active.v.b;
}

void cluster_vip_round(bool mine)
{
	char address[CLUSTER_STRLEN] = "";
	cluster_vip_address(address);
	if(strlen(address) == 0)
		return;

	// Taking the address over is damped the way taking DHCP over is: one
	// missed answer makes a node the leader for a round, and placing the
	// address on that would have two machines answering for it. Giving it up
	// is not damped - that direction ends with nobody holding it, which is
	// the better of the two - and neither is a node that is handing out
	// leases, where the address belongs without asking anybody
	static unsigned int rounds_wanting_vip = 0;
	if(mine && !vip_claimed() && !config.dhcp.active.v.b)
	{
		if(++rounds_wanting_vip < CLUSTER_DHCP_ACTIVATE_ROUNDS)
		{
			// Waiting, which is not the same as giving it up. Falling
			// through with mine=false would call the release, and the
			// release now takes away an address a previous run of this
			// node left behind - the very one this node is a round away
			// from claiming. Nothing to do but wait
			log_debug(DEBUG_CLUSTER, "cluster: would take %s over (%u/%u rounds)",
			          address, rounds_wanting_vip, CLUSTER_DHCP_ACTIVATE_ROUNDS);
			return;
		}
	}
	else
		rounds_wanting_vip = 0;

	// An address this node holds without having placed it is one an earlier
	// FTL left behind when it was killed - or one somebody assigned by hand.
	// It is not removed, because telling those two apart is not possible
	// from here, but it is said out loud: the node that took over has the
	// same address, and two machines answering for it is not obvious from
	// either of them
	static bool warned_stray = false;
	if(!mine && !vip_claimed() && vip_present(address))
	{
		if(!warned_stray)
			log_warn("cluster: %s is on this machine but belongs to another node now",
			         address);
		warned_stray = true;
	}
	else
		warned_stray = false;

	// A mistyped interface, or an address somebody else holds in a way we
	// may not touch, fails the same way every round. Saying so once per
	// round is thousands of lines a day onto the card this runs from
	static bool last_ok = true;
	static bool last_mine = false;
	const bool okay = mine ? vip_claim(address) : vip_release(address);

	if(okay != last_ok || mine != last_mine)
	{
		if(!okay)
			log_warn("cluster: cannot %s %s", mine ? "claim" : "release", address);
		last_ok = okay;
		last_mine = mine;
	}
}

void cluster_vip_shutdown(void)
{
	// Whatever this process placed goes back, whether FTL is stopping or
	// clustering was switched off under it. Nothing else is touched: FTL
	// stops for many reasons on machines that are not in a cluster at all,
	// and cluster.vip.address may be filled in on one of them
	char address[CLUSTER_STRLEN] = "";
	if(!vip_claimed_address(address, sizeof(address)))
		return;

	// Leaving the address behind would keep clients talking to a Pi-hole
	// that is no longer answering
	vip_release(address);
}
