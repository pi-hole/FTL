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
// check_capability()
#include "capabilities.h"
// if_nametoindex()
#include <net/if.h>
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
// Shorter than the DHCP one on purpose. Taking DHCP over restarts FTL, so
// trying again every few minutes is right; placing an address costs a netlink
// message, and the usual reason it failed - an interface that flapped, no
// default route for a moment, a typo somebody has since corrected - is over in
// seconds. Five minutes of the address on nobody is a long outage to sit out
#define CLUSTER_VIP_BACKOFF 30.0
#define CLUSTER_TAKEOVER_BACKOFF_MAX 3600.0

// Doubling with every failure. A fault that is not going to clear - a static
// lease dnsmasq refuses, a full disk - would otherwise put this node back into
// the election every five minutes, and each attempt restarts the node that is
// currently serving
// When placing the address failed, and until when this node stops offering to.
// A deadline rather than a flag: a claim fails for reasons that pass - no
// default-route interface during a network blip, an interface that has just
// flapped, a netlink call that timed out - and a node that answered "no" to
// them once must still be able to answer "yes" later.
//
// The first version of this was a plain latch, and the flag gated the only code
// that could clear it: one transient failure sidelined the node until FTL was
// restarted, which on the last node standing means the address is on nobody for
// good. This mirrors takeover_failed() instead, which DHCP has used all along
static double vip_failed_until = 0.0;
static unsigned int vip_failures = 0;

// Whether placing the address has ever failed here. Read by the election: a
// node that has failed once should not take the address off a node that is
// holding it, however the identities compare
bool cluster_vip_failed_before(void)
{
	return vip_failures > 0;
}

static void vip_claim_failed(void)
{
	double wait = CLUSTER_VIP_BACKOFF;
	for(unsigned int i = 0; i < vip_failures && wait < CLUSTER_TAKEOVER_BACKOFF_MAX; i++)
		wait *= 2.0;

	vip_failures++;
	vip_failed_until = double_time() + fmin(wait, CLUSTER_TAKEOVER_BACKOFF_MAX);
}

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
// Can this node answer on an address the cluster puts on it? Not the same
// question as "does DNS work here": in BIND mode dnsmasq binds the addresses it
// finds at start-up, so one that arrives afterwards is not one it answers on -
// the node resolves perfectly well on its own address and not at all on the
// cluster's. Holding it there is the same outage as holding it with no dnsmasq
bool cluster_vip_capable(void)
{
	// Placing an address needs CAP_NET_ADMIN, which a container does not have
	// unless somebody asked for it - the Docker default is without. FTL has
	// checked for it since before this branch, and said so only under
	// debug.caps
	if(!check_capability(CAP_NET_ADMIN))
		return false;

	// An interface that is not there is the commonest reason a claim fails,
	// and it is a question that can be answered rather than waited out. Asked
	// here so a typo makes this node stop offering for as long as it lasts -
	// and stop offering again the moment it is corrected, without a restart
	// and without the retry below re-offering on a promise it cannot keep
	char configured[CLUSTER_STRLEN] = "";
	lock_shm();
	strncpy(configured, config.cluster.vip.interface.v.s, sizeof(configured) - 1);
	unlock_shm();
	configured[sizeof(configured) - 1] = '\0';
	if(strlen(configured) > 0 && if_nametoindex(configured) == 0)
		return false;

	// ...and a claim that has been failing for a reason nothing here can see.
	// Only while the wait lasts, so whatever it was can pass
	if(cluster_waiting(vip_failed_until, double_time(), CLUSTER_TAKEOVER_BACKOFF_MAX))
		return false;

	return !dnsmasq_failed &&
	       config.dns.listeningMode.v.listeningMode != LISTEN_BIND;
}

bool cluster_dhcp_configured(void)
{
	// A node whose dnsmasq did not start is not a node that will serve DHCP,
	// however good its lease range looks: FTL is up and this thread is running,
	// so nothing else here would notice
	if(dnsmasq_failed)
		return false;

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
	const bool written = writeFTLtoml(true, NULL);
	cluster_sync_unlock();

	// The restart is two statements away and it reads this file, so a write
	// that did not land is a node about to come back on the value it just
	// changed - still serving after handing over, which is the second DHCP
	// server this whole file exists to prevent, or not serving after taking
	// over and elected again next round with nothing to break the loop.
	// The guards above already refuse to make a change that will not persist;
	// this is the same refusal, one signal later
	if(!written)
	{
		// ...and the value goes back where it was. `replace_config()` has
		// already installed it, and it is what this node publishes and
		// what the next round reads to decide whether it is where it
		// belongs - left standing, the node advertises a DHCP state its
		// dnsmasq is not in and never tries again, because it believes it
		// has already arrived
		cluster_sync_lock();
		config.dhcp.active.v.b = !active;
		cluster_sync_unlock();

		log_err("cluster: cannot %s DHCP: the configuration could not be written, so a restart would come back on the old value",
		        active ? "take over" : "hand over");
		takeover_failed();
		return;
	}

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

	// A node whose dnsmasq did not start answers no DNS and hands out no
	// leases, whatever its configuration says it is doing. Holding the address
	// the clients were told to resolve at is then the worst thing it can do -
	// worse than the per-node addresses the virtual one replaced, because
	// those at least stop answering when the node does. It gives the address
	// back and takes no part in DHCP; the election skips it too, so a peer
	// that can answer takes both over
	if(dnsmasq_failed)
	{
		intent->owner[0] = '\0';
		intent->serve = false;
		intent->hold_vip = false;

		// ...and where the cluster is what switched DHCP on, it stops saying
		// so in its own configuration and not only to the peers: on the way
		// back up a node starts serving from that file before any round has
		// run, beside whichever node took DHCP over meanwhile. Written here
		// rather than through cluster_dhcp_apply(), which asks
		// cluster_dhcp_capable() first and gets "no" for exactly the reason
		// we are in this branch.
		//
		// Only where the cluster switched it on. Without failover
		// `dhcp.active` is the administrator's setting, nobody else is going
		// to take DHCP over, and nothing would ever switch it back - so a
		// resolver that is down for a minute would cost them their DHCP
		// server for good.
		//
		// The dnsmasq configuration is deliberately left alone: there is no
		// dnsmasq to write it for, and testing it is what fails on a node
		// whose interface is the problem
		if(serving && config.cluster.dhcp.failover.v.b)
		{
			cluster_sync_lock();
			struct config newconf;
			duplicate_config(&newconf, &config);
			newconf.dhcp.active.v.b = false;
			struct config_apply applied = { 0 };
			applied.changed = true;
			char errbuf[ERRBUF_SIZE] = "";
			// The result is not checked because it cannot be false here:
			// `config_install()` only fails where it writes the dnsmasq
			// configuration, which this deliberately does not. A write
			// that does not land says so itself, in config_write()
			config_install(&newconf, &applied, false, 0.0, errbuf);
			cluster_sync_unlock();

			log_warn("cluster: dnsmasq is not running here, so this node stops serving DHCP - another node takes it over");
		}
		return;
	}

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
		bool somebody_takes_over = false;
		for(unsigned int i = 0; i < num_peers; i++)
		{
			if(peers[i].is_self || !peers[i].reachable || !peers[i].failover)
				continue;

			// Capable now, or merely waiting out a failed takeover:
			// both pick DHCP up. This is the same question do_leave()
			// asks, and for the same reason - stopping is only right
			// if stopping leaves somebody serving
			if(peers[i].dhcp_capable || peers[i].dhcp_configured)
			{
				somebody_takes_over = true;
				break;
			}
		}

		// Nobody to hand it to. Being dropped from a member list is a
		// reason to stop competing, not a reason to leave the network
		// without a DHCP server - and this node is the one that has it
		if(!somebody_takes_over && serving)
		{
			intent->serve = serving;
			intent->change_dhcp = false;
			return;
		}

		intent->serve = config.cluster.dhcp.failover.v.b ? false : serving;
		intent->change_dhcp = intent->serve != serving;
		return;
	}

	// Whether failover runs is a per-node setting, and a node that does not
	// run it decides the address differently - so nodes disagreeing about it
	// would place the address twice, or not at all. One node running it is
	// enough for the DHCP server to anchor the address everywhere
	bool failover_anywhere = config.cluster.dhcp.failover.v.b;
	// ...and, separately, whether the peer that is serving would answer on the
	// virtual address. The address follows whoever hands out leases, which is
	// right while that node can answer on it and leaves the address on nobody
	// when it cannot - this node declines to hold what it would not answer on,
	// and the serving peer's claim is what keeps everybody else from taking it
	bool peer_serving = false, owner_serving = false;
	// Whether any peer that is about to serve DHCP could also hold the
	// address. The rule below defers to such a peer rather than taking the
	// address from under it - and asking only whether one exists waits forever
	// when it would not answer on the address either, which leaves the address
	// on nobody
	bool peer_capable_anchors = false;
	bool serving_peer_anchors = false;

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

		// Asked of the node that is actually handing out leases, not of one
		// that merely sees it: a healthy bystander's ability to hold the
		// address said nothing about the server's, and credited it with one
		// it did not have. In a cluster of two there is no bystander, which
		// is why this worked when it was written
		if(peers[i].dhcp_active && peers[i].resolving && peers[i].vip_capable)
			serving_peer_anchors = true;
		if(peer_competes(&peers[i]) && peers[i].resolving && peers[i].vip_capable)
			peer_capable_anchors = true;
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
			log_warn("cluster: the other nodes answer but do not accept this one, so DHCP and the virtual IP are left as they are - check that clustering is on there and that %s matches",
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
		                   (!serving && !serving_peer_anchors && !peer_capable_anchors && leader_is_us) :
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
		intent->hold_vip = serving || (!serving_peer_anchors && !peer_capable_anchors && leader_is_us);
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
	                   (!serving_peer_anchors && !peer_capable_anchors && leader_is_us);

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
	// Not while this node is on its way out. `cleanup()` gives the address
	// back before the threads are stopped - it has to, because a node whose
	// resolver never came up has no other chance to - and this thread only
	// looks at `killed` at the top of its loop, so a round already in flight
	// would put the address straight back on an interface nobody is left to
	// answer on, while the surviving node claims it too
	if(killed)
		return;

	char address[CLUSTER_STRLEN] = "";
	cluster_vip_address(address);
	if(strlen(address) == 0)
		return;

	// ...and not onto a node that would not answer on it. The election prefers
	// a node that can, so this only bites when none of them can - and then the
	// address being absent is the truth rather than a second failure
	if(!cluster_vip_capable())
		mine = false;

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

	// ...and a claim that failed is remembered rather than only logged. The
	// election has no other way to learn it: this node keeps winning on
	// identity, keeps failing to place the address, and the node that could
	// place it never gets a turn - so the address the clients resolve at sits
	// on nobody. DHCP has had this feedback since the beginning, in
	// takeover_failed(); this is the same thing for the address.
	//
	// Cleared as soon as one succeeds, so a claim that failed because
	// somebody else still held the address does not sideline this node for good
	if(mine)
	{
		if(okay)
		{
			vip_failed_until = 0.0;
			vip_failures = 0;
		}
		else
			vip_claim_failed();
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
