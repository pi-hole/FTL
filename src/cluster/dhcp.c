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

// ...and which node those yielding rounds were counted against. Three rounds of
// the same successor is evidence that it is ready; three rounds of a different
// successor each time is an election that has not settled, and DHCP used to be
// handed over having never seen one candidate twice
static char yielding_to[CLUSTER_HASHLEN] = "";

// Consecutive means what it says. A round this node spends standing down, off
// the member list, refused by its peers or held back by a gravity run reaches
// no election at all, and counting the rounds either side of it as consecutive
// splices two unrelated missed answers into the two in a row that move DHCP
static void forget_rounds(void)
{
	rounds_wanting = 0;
	rounds_yielding = 0;
	yielding_to[0] = '\0';
}


// Said once rather than once per round while the condition lasts
static bool warned_incapable = false;
static bool warned_refused = false;

// ...and the same for peers that run DHCP failover while this node does not
static bool warned_failover = false;

// ...and for a hand-over held up by a member that answers and refuses us, which
// is a state the network notices long before the log does
static bool warned_refused_holds = false;

// ...and for the other half of the same guard, where nobody is serving at all
static bool warned_refused_takes = false;

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

// Set once per round: this node has failed to place the address and somebody
// else is holding it, so it stands aside. Kept here rather than in the election
// because cluster_vip_capable() is what the peers are told - an abstention only
// this node knows about has every peer electing it and deferring to it while it
// declines, which is the outage it was added to prevent, upside down
static bool vip_stand_aside = false;

void cluster_vip_note_holder(const bool somebody_else_holds_it)
{
	vip_stand_aside = somebody_else_holds_it && vip_failures > 0;
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

	// ...and standing aside for a node that is holding the address, which is
	// published with the rest so every node elects the same way
	if(vip_stand_aside)
		return false;

	// ...and for a twin, for the same reason as DHCP: both would take it
	if(duplicate_identity)
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
	// Two machines carrying one identity read each other as themselves and
	// would both serve. Neither can tell which is the original, so neither does
	if(duplicate_identity)
		return false;

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
	if(peer->is_self)
		return false;

	// ...and only where there is an identity to rank it by
	if(strlen(peer_identity(peer)) == 0)
		return false;

	if(peer->reachable)
		return peer->failover && peer->dhcp_capable;

	// Through a member that still reaches it. A node with one broken polling
	// direction otherwise ranks over a smaller cluster than everybody else,
	// elects a different winner, and starts a second DHCP server beside the one
	// it cannot see
	return peer->relayed_seen && peer->relayed_failover && peer->relayed_capable;
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

	// ...and this node only stands where it competes, which is the same
	// question peer_competes() asks of the others. It used to be assumed,
	// soundly, because the one caller sat behind the two guards that make it
	// true - and then a second caller was added in front of them, where a node
	// that takes no part in DHCP failover elected itself if it held the lowest
	// identity, and stopped deferring to the peer that was about to serve
	const bool i_compete = config.cluster.dhcp.failover.v.b && cluster_dhcp_capable();

	const char *best_name = myname;
	const char *best_id = cluster_node_id();
	bool best_is_me = i_compete;
	bool have_best = i_compete;

	for(unsigned int i = 0; i < num_peers; i++)
	{
		const struct cluster_peer *peer = &peers[i];
		if(!peer_competes(peer))
			continue;

		// By identity, never by name: two Pi-holes imaged from the same
		// card are both "raspberrypi", and a comparison neither of them
		// wins is two DHCP servers on one network
		if(!have_best || strcmp(peer_identity(peer), best_id) < 0)
		{
			// A member known only through a bystander has never told
			// this node its name, and an empty one reads as "nobody
			// owns DHCP" on the page - during a hand-over, which is
			// the one moment somebody is watching it
			best_name = strlen(peer->name) > 0 ? peer->name :
			            (peer->url != NULL ? peer->url : "");
			best_id = peer_identity(peer);
			best_is_me = false;
			have_best = true;
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
// test_config is false on one path only: a node whose dnsmasq did not start.
// Testing the configuration forks a dnsmasq over it, and on that node it fails
// for the reason the node is standing down in the first place - so the test
// answers a question already asked, and refusing on it leaves DHCP switched on
static void set_dhcp_active(const bool active, const char *reason, const bool test_config)
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
	if(!write_dnsmasq_config(&newconf, test_config, errbuf))
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
	// A machine sharing this node's identity is a different case from a dead
	// dnsmasq, and folding the two together left the worse half undone. Here
	// dnsmasq is healthy and *running*: writing `dhcp.active = false` without
	// rewriting its configuration and restarting stops the node saying it
	// serves without stopping it serving. The pair then hands out leases from
	// two databases while the cluster reports one server - a broadcast on that
	// range answers twice, which is exactly what standing down is for.
	//
	// set_dhcp_active() is the ordinary way to stop, and it does both. It is
	// reached directly rather than through cluster_dhcp_apply(), which asks
	// cluster_dhcp_capable() first and gets "no" for the reason we are here
	if(duplicate_identity)
	{
		intent->owner[0] = '\0';
		intent->serve = false;
		intent->hold_vip = false;
		forget_rounds();

		if(serving && config.cluster.dhcp.failover.v.b)
			set_dhcp_active(false, "another machine is using this node's identity", true);

		return;
	}

	// A node that answers no DNS has to stop rather than merely not start too.
	// `dnsmasq_failed` says the resolver did not come up, not that the daemon
	// is absent: it can be running with its DHCP socket open, so writing the
	// setting by hand stopped this node saying it served without stopping it
	// serving, and the pair handed out leases from two databases while the
	// cluster reported one server. Measured, on a node whose listening
	// interface does not exist: dhcp.active false, and a socket on :67.
	if(dnsmasq_failed)
	{
		intent->owner[0] = '\0';
		intent->serve = false;
		intent->hold_vip = false;
		forget_rounds();

		// Only where the cluster switched it on. Without failover
		// `dhcp.active` is the administrator's setting, nobody else is going
		// to take DHCP over, and nothing would ever switch it back - so a
		// resolver that is down for a minute would cost them their DHCP
		// server for good.
		//
		// Reached directly rather than through cluster_dhcp_apply(), which
		// asks cluster_dhcp_capable() first and gets "no" for exactly the
		// reason we are in this branch - and without the configuration test,
		// which forks a dnsmasq that fails here for the same reason again
		if(serving && config.cluster.dhcp.failover.v.b)
		{
			log_warn("cluster: dnsmasq is not running here, so this node stops serving DHCP - another node takes it over");
			set_dhcp_active(false, "this node's resolver did not start", false);
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
		forget_rounds();

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
			// ...and it is still the node handing out leases, which is
			// what this field says. Left empty it reported that nobody
			// serves DHCP while this node did, for as long as it stayed
			// off the member list
			cluster_name(intent->owner);
			return;
		}

		intent->serve = config.cluster.dhcp.failover.v.b ? false : serving;
		intent->change_dhcp = intent->serve != serving;
		if(intent->serve)
			cluster_name(intent->owner);
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

	// Whether another node is handing out leases, could hold the address too,
	// and has the lower identity. A node serving DHCP holds the address without
	// asking anybody, which is right while it is the only one - and two at once
	// is the administrator's doing wherever the cluster may not touch
	// `dhcp.active`: pinned through the environment, which is how the Docker
	// image switches DHCP on, or a read-only configuration. The address is
	// still the cluster's to place on exactly one machine, and comparing
	// identities is how every node reaches the same answer without asking
	bool beaten_by_anchor = false;

	// Who would take DHCP, asked once and before anything reads it.
	// elect_dhcp() only ranks what it is given, so it costs nothing to ask
	// early - and tracking "the lowest-identity competing peer" separately got
	// it wrong whenever the answer was this node, because a loop over peers
	// cannot elect the node running it
	char elected_owner[CLUSTER_STRLEN] = "", elected_id[CLUSTER_HASHLEN] = "";
	const bool elected_is_me = elect_dhcp(peers, num_peers, elected_owner, elected_id);
	bool elected_serving = false;
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

	// Whether anybody runs failover is asked of every member that answers
	// somebody, not only of the ones this node polls itself. It decides which
	// rule the address follows, so two nodes answering it differently place the
	// address twice - and one broken polling direction was enough to make them
	// differ, which is the fault the relay below was built to remove
	for(unsigned int i = 0; i < num_peers; i++)
	{
		if(peers[i].is_self || !peer_answers(&peers[i]))
			continue;
		if(peers[i].reachable ? peers[i].failover : peers[i].relayed_failover)
			failover_anywhere = true;
		if(!peers[i].reachable)
			continue;
		// A peer that still sees somebody serving is reason enough to
		// wait, even when we cannot see that node ourselves
		if(peers[i].dhcp_active || peers[i].sees_dhcp)
			peer_serving = true;

		// Asked of the node that is actually handing out leases, not of one
		// that merely sees it: a healthy bystander's ability to hold the
		// address said nothing about the server's, and credited it with one
		// it did not have. In a cluster of two there is no bystander, which
		// is why this worked when it was written.
		//
		// Through a bystander where this node cannot reach the server itself,
		// the same way `sees_dhcp` carries "somebody is serving" one line up.
		// One broken direction - a pin that no longer matches, a firewall rule,
		// a poll that times out on one path and not another - left this node
		// deferring to nobody while the server went on holding the address, and
		// it claimed the address as well
		if(strlen(peers[i].sees_anchor_id) > 0)
		{
			serving_peer_anchors = true;
			// ...and by identity, relayed along with it. Comparing only the
			// peers this node polls itself meant a node that knew - through a
			// bystander - that a lower identity was anchoring kept the address
			// anyway, and the node it should have yielded to kept it too
			if(strcmp(peers[i].sees_anchor_id, cluster_node_id()) < 0)
				beaten_by_anchor = true;
		}
		// The peer that would actually be elected, and only that one
		if(!elected_is_me && strcmp(peers[i].id, elected_id) == 0)
		{
			if(peers[i].resolving && peers[i].vip_capable)
				peer_capable_anchors = true;
			if(peers[i].dhcp_active)
				elected_serving = true;
		}
	}

	// ...and only while that node is in a position to act on it. It takes the
	// address by taking DHCP, and it cannot take DHCP while somebody else is
	// still handing out leases - so a server that no candidate will ever
	// displace (its own failover switched off, its dhcp.active pinned through
	// the environment, or simply unreachable from here) leaves every other
	// node deferring to one that is waiting for it, and the address on nobody
	if(peer_serving && !elected_serving)
		peer_capable_anchors = false;

	// Losing sight of the anchor is damped like every other take-over. One
	// missed poll of the node holding the address otherwise had a second
	// serving node place it and announce it in that same round, then give it
	// back a round later - and the holder announces nothing, so the clients
	// kept the wrong machine for as long as their caches lasted. A node that
	// already holds it, or has never been beaten in this process, is not made
	// to wait
	static unsigned int rounds_unbeaten = CLUSTER_DHCP_ACTIVATE_ROUNDS;
	if(beaten_by_anchor)
		rounds_unbeaten = 0;
	else if(rounds_unbeaten < CLUSTER_DHCP_ACTIVATE_ROUNDS)
		rounds_unbeaten++;
	const bool mine_to_hold = serving && !beaten_by_anchor &&
	                          (vip_claimed() || rounds_unbeaten >= CLUSTER_DHCP_ACTIVATE_ROUNDS);

	// Who is actually handing out leases. The election's answer is the same
	// thing only where the cluster is arbitrating, and the branches below that
	// do not arbitrate - failover switched off here, a gravity run or a failed
	// takeover holding this node back, nobody accepting this node - left the
	// field empty. A node serving DHCP then published "nobody serves DHCP" about
	// itself, every gravity run and for as long as a backoff lasted. The
	// failover branch elects over this and overwrites it
	if(serving)
		cluster_name(intent->owner);
	else
		for(unsigned int i = 0; i < num_peers; i++)
			if(!peers[i].is_self && peers[i].reachable && peers[i].dhcp_active)
			{
				strncpy(intent->owner, peers[i].name, CLUSTER_STRLEN - 1);
				intent->owner[CLUSTER_STRLEN - 1] = '\0';
				break;
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
		forget_rounds();
		return;
	}
	warned_refused = false;

	// Without failover here, DHCP stays exactly as the administrator set it.
	// The address still follows whoever hands out leases, and falls back to
	// the leader when nobody does - the same rule the failover branch below
	// uses, so two nodes cannot answer it differently and place it twice or
	// not at all.
	//
	// A node serving DHCP stands aside for a peer that is serving *and* could
	// hold the address, which is the question every other branch asks. Standing
	// aside for any peer that serves gives the address to a node that cannot
	// place it, and this node - which can - declines it as well
	if(!config.cluster.dhcp.failover.v.b)
	{
		intent->serve = serving;
		intent->hold_vip = failover_anywhere ?
		                   mine_to_hold ||
		                   (!serving && !serving_peer_anchors && !peer_capable_anchors && leader_is_us) :
		                   leader_is_us;
		forget_rounds();
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
		intent->hold_vip = mine_to_hold || (!serving_peer_anchors && !peer_capable_anchors && leader_is_us);
		forget_rounds();
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
	intent->hold_vip = mine_to_hold || (mine && !peer_serving) ||
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
		// would fight; waiting is better than that.
		//
		// ...and the same for a member that answers and refuses us, which is
		// a Pi-hole too old for clustering or one with clustering switched
		// off - precisely a Pi-hole that may be handing out leases under its
		// own settings, and one that publishes nothing to say whether it is.
		// The freeze further up covers the case where no member accepts this
		// node at all; halfway through a rolling upgrade some do, and starting
		// a second server beside the old one is what that left open
		if(peer_serving || refusing)
		{
			// intent->owner is this node here - the one still handing out
			// leases is somebody else, and naming ourselves reads as a
			// node waiting for itself
			log_debug(DEBUG_CLUSTER, "cluster: waiting for the node still serving DHCP to stop");

			// ...and where nobody is actually serving, the wait is not for a
			// hand-over but for a member that answers and refuses this node -
			// a mistyped member URL, or an address something else has taken.
			// The network has no DHCP server for as long as that entry stands
			// and the line above is debug-only, so nothing at default
			// verbosity connected the two
			if(refusing && !peer_serving)
			{
				if(!warned_refused_takes)
					log_warn("cluster: no node is serving DHCP and a member answers but does not accept this one - check cluster.members, that clustering is on there, and that %s matches",
					         CLUSTER_SECRET_FILE);
				warned_refused_takes = true;
			}
			else
				warned_refused_takes = false;

			rounds_wanting = 0;
			return;
		}
		warned_refused_takes = false;

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

	// Ours to give up - but not while a member is refusing us. The node that
	// would take it over is held back by that same member for as long as it
	// refuses, so giving up here leaves the network with no DHCP server at
	// all. Blocking only the taking-over half, which is what the guard did at
	// first, turned a rolling upgrade from "a second server for a while" into
	// "no server, permanently"
	rounds_wanting = 0;
	if(refusing && !owner_serving)
	{
		// Said out loud, once. A member that answers and refuses this node
		// holds DHCP where it is in both directions, so a mistyped member URL
		// - or a machine that answers on one - leaves the network without a
		// DHCP server, and at debug level nothing connected the two
		if(!warned_refused_holds)
			log_warn("cluster: not moving DHCP while a member answers but does not accept this node - check that clustering is on there and that %s matches",
			         CLUSTER_SECRET_FILE);
		warned_refused_holds = true;

		rounds_yielding = 0;
		return;
	}
	warned_refused_holds = false;

	// Immediately if the node taking over is already serving - the wait exists
	// so one missed answer does not move DHCP, not to keep two servers running
	if(strcmp(yielding_to, owner_id) != 0)
	{
		strncpy(yielding_to, owner_id, sizeof(yielding_to) - 1);
		yielding_to[sizeof(yielding_to) - 1] = '\0';
		rounds_yielding = 0;
	}
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
		                (intent->serve ? "no other node is serving" : "no longer a member"), true);

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
