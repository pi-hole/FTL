/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CLUSTER_H
#define CLUSTER_H

#include "FTL.h"
#include "webserver/cJSON/cJSON.h"
#include <pthread.h>

// More than a handful of Pi-holes in one cluster is not a scenario we design
// for: every node talks to every other one, so the number of requests per round
// grows quadratically with the cluster size
#define CLUSTER_MAX_PEERS 8

// Bigger than any real DHCP lease file - a /16 handed out in full is about
// 5 MB - and small enough that neither reading our own nor taking a peer's
// makes this node hold a lot of memory or write an unbounded file
#define CLUSTER_MAX_LEASES_SIZE (8u*1024u*1024u)
#define CLUSTER_STRLEN 128
#define CLUSTER_URLLEN 256
#define CLUSTER_HASHLEN 65

// What a node stamps when it declares its own configuration or lists as the one
// the cluster should start from, rather than because somebody changed something.
//
// Not the current time. A declaration has to lose to every real change, whenever
// that change was made: a member holding one can be out of touch for a single
// round while the others decide nobody has a version, and stamping the
// declaration `now` would make it outrank the very thing it should defer to -
// the node returns, finds itself older, and its lists and settings are replaced.
// A value below every real timestamp says "this is a starting point" in the one
// field every comparison already reads, and it travels with the version through
// a pull without anything having to carry it separately. Two declarations tie
// and are settled by identity, as any two equal stamps are
#define CLUSTER_BASELINE_STAMP 1.0

// ...and what tells the two apart afterwards. Any real change is a Unix
// timestamp, so anything below this is a declaration and not a moment
#define CLUSTER_BASELINE_MAX 1000000000.0
// Base64 of a SHA-256, plus room for the "sha256//" curl wants in front of it
#define CLUSTER_PINLEN 64
// Long enough for any address in text form, brackets and zone id included
#define CLUSTER_ADDRLEN 64

// The longest any of the waits below grows to, which is also the longest one of
// them can legitimately sit in the future
#define CLUSTER_BACKOFF_MAX 3600.0
#define CLUSTER_PUSH_BACKOFF_MAX 600.0

// A deadline this node parked in the future, and the longest it can legitimately
// be away. Anything beyond that is the wall clock having moved backwards under
// us rather than a wait somebody asked for - and waiting it out would hold a
// retry for as long as the step was
static inline bool cluster_waiting(const double deadline, const double now, const double longest)
{
	return deadline > 0.0 && now < deadline && deadline - now <= longest;
}

// How often a peer may publish a key it does not serve before this node stops
// trying it, and how long that lasts. Both matter: without the first, somebody
// on the wire turns one interception into a permanent downgrade; without the
// second, a proxy in front of a peer costs two TLS handshakes every round
#define CLUSTER_PIN_FAILURES 5
// An address offered by another node that did not work is not tried again every
// round - a peer moves back as easily as it moved away, so it is not for good
#define CLUSTER_HINT_REARM 300.0
// How long a node goes on standing down after the machine that shares its
// identity stops answering. Clearing it the moment the twin goes quiet put both
// of them back to serving DHCP and claiming the address after one missed poll -
// the split brain the detection exists to prevent, brought on by a hiccup
// between them rather than by anybody fixing anything. Long enough that no
// interruption clears it, short enough that a twin somebody switched off does
// not hold this node out of the cluster for the rest of the day
#define CLUSTER_TWIN_MEMORY 300.0
// How old a relayed fact may be and still decide anything. A relayed entry says
// when the peer last reached the subject, and nothing bounded that: a member
// polling on a long interval kept a node that had died most of an interval ago
// in both elections, and the address stayed on nobody until it noticed.
//
// Three of the publishing node's own rounds, with this as the floor. Not the
// reading node's interval - two readers then disagreed about the same fact and
// a member near the boundary joined and left the elections round after round -
// and not a constant on its own, which stopped the relay entirely on any
// cluster polling slower than it, and `cluster.interval` goes to an hour
#define CLUSTER_RELAY_MAX_AGE 120.0
#define CLUSTER_PIN_REARM 3600.0

// Two nodes deciding which change is newer need clocks that agree. This is how
// far apart they may be before this node refuses to synchronize with that peer
#define CLUSTER_MAX_CLOCK_OFFSET 2.0

// The longest a round may be scheduled ahead. Anything beyond this is a clock
// that moved, not an interval somebody configured
#define CLUSTER_MAX_INTERVAL 3600.0

struct cluster_peer {
	char *url;                       // "http(s)://host[:port]"
	void *curl;                      // CURL handle, kept for connection reuse
	char name[CLUSTER_STRLEN];       // node name as reported by the peer
	char version[CLUSTER_STRLEN];    // FTL version of the peer
	char branch[CLUSTER_STRLEN];     // ...and its branch, when that is not master
	char id[CLUSTER_HASHLEN];          // the peer's identity, which cannot collide
	char address[CLUSTER_ADDRLEN];     // where this peer answered, so its name is only resolved once
	char hint[CLUSTER_ADDRLEN];        // ...or where another node reached it, when we cannot resolve it
	char hint_failed[CLUSTER_ADDRLEN]; // ...and one such address that did not work
	double hint_rearm_at;              // ...which is tried again after a while, not never
	char run[CLUSTER_HASHLEN];         // the token its running FTL made up, which no copied file carries
	bool identity_shared;              // ...and whether it says another machine is using its identity
	char pin[CLUSTER_PINLEN];          // what its certificate's public key hashes to
	char pin_refused[CLUSTER_PINLEN];  // ...and one that turned out not to be served
	unsigned int pin_failures;         // how often in a row, so a relay cannot latch it
	double pin_rearm_at;               // when to try that key again anyway
	bool pin_warned;                   // ...which is said once, not every round
	bool push_warned;                  // ...and the same for one we will not push to
	bool read_warned;                  // ...and for one we will not take lists or leases from
	double asked_at;                   // when the last request went out...
	double answered_at;                // ...and when its answer was in hand
	double clock_offset;               // how far the peer's clock is from ours [s]
	double header_skew;                // the same, from the HTTP date of any answer, refusals included [s]
	bool gravity_owed;                 // it took lists from somebody and has not rebuilt over them yet
	char pinned[256];                  // settings it hashes but pins through the environment, so no push moves them
	char pinned_credentials[256];      // the same, for the credential fingerprint
	bool wants_credentials;            // it is set to synchronize credentials, whether or not that is happening
	bool clock_agrees;                 // ...and whether that is close enough to synchronize
	bool clock_warned;                 // ...which is said when it changes, not when a poll is missed
	bool is_self;                      // this member turned out to be this node
	bool answered_as_other;            // ...or answered as another node at some point, so it is not
	char confhash[CLUSTER_HASHLEN];    // fingerprint of the peer's synchronized config
	char credhash[CLUSTER_HASHLEN];    // ...and of its credentials, which travel only
	bool accepts_credentials;          // ...between two nodes that both accept them
	double config_changed;             // ...and when somebody last configured it
	char gravityhash[CLUSTER_HASHLEN]; // fingerprint of the peer's lists
	double gravity_changed;            // when the peer's lists last changed
	unsigned long pushed_generation;   // configuration we last handed to this peer
	char pushed_confhash[CLUSTER_HASHLEN]; // what the peer held when we last caught it up
	char pushed_ourhash[CLUSTER_HASHLEN];  // ...and what we held ourselves at the time
	char pushed_credhash[CLUSTER_HASHLEN]; // ...and our credentials, which neither of those covers
	bool stuck_valid;                  // ...and the same for its lists
	double stuck_changed;
	double retry_leases_at;            // when to try a failed lease download again
	double leases_backoff;             // ...and how long that wait has grown to
	double retry_lists_at;             // when to try a failed list download again
	double retry_backoff;              // ...and how long the wait has grown to
	double retry_push_at;              // when to hand this peer the configuration again
	double push_backoff;               // ...and how long that wait has grown to
	unsigned int id_changed_rounds;    // rounds this peer answered as somebody else
	bool id_warned;                    // ...which is said once, not every round
	bool knows_us;                     // the peer lists this node among its own members
	uint8_t sees;                      // ...and which of the members it reaches, a bit per entry
	unsigned int unknown_rounds;       // ...rounds in a row it did not
	bool unknown_warned;               // ...which is said once, not every round
	char error[CLUSTER_STRLEN];      // why the last round failed ("" if it did not)
	unsigned int rounds_down;        // consecutive rounds this peer was not
	double last_seen;
	bool reachable;
	// Whether the last request got an answer of any kind. A peer that
	// refuses us is a peer that is running: it says the fault is here
	bool answered;
	bool failover;                   // peer participates in DHCP failover
	bool dhcp_capable;               // peer has a lease range and could serve
	bool resolving;                  // peer's dnsmasq came up and answers DNS
	bool vip_capable;                // ...and would answer on an address placed later
	bool dhcp_configured;            // ...and whether that is "not now" or "not ever"
	bool dhcp_active;                // peer is currently serving DHCP
	char leaseshash[CLUSTER_HASHLEN];// ...and what its DHCP lease file hashes to
	bool sees_dhcp;                  // ...or can see a node that is
	char sees_anchor_id[CLUSTER_HASHLEN]; // the lowest identity it sees serving that could hold the address too
	// What the other members say about this one, for a round in which this
	// node cannot poll it itself. Both elections rank on these, so a node with
	// one broken polling direction otherwise ranks over a smaller cluster than
	// everybody else and reaches a different answer - which is two DHCP servers
	bool relayed_seen;                 // somebody who answers us still reaches it
	char relayed_id[CLUSTER_HASHLEN];  // ...and the identity it answered with, which both elections rank on
	bool relayed_failover;             // ...and says it runs DHCP failover
	bool relayed_capable;              // ...and that it could serve DHCP
	bool relayed_resolving;            // ...and that it answers DNS
	bool relayed_vip_capable;          // ...and that it could hold the address
	bool relayed_vip_held;             // ...and that it is holding it now
	bool vip_held;                   // peer currently holds the virtual IP
};

// What the cluster thread publishes after every round. This is a plain value
// type on purpose: the API threads read it under the state lock while the
// cluster thread keeps working on its own peer structs, which own memory and
// libcurl handles the API must never see
struct cluster_peer_status {
	char url[CLUSTER_URLLEN];
	char name[CLUSTER_STRLEN];
	char version[CLUSTER_STRLEN];
	char branch[CLUSTER_STRLEN];
	char error[CLUSTER_STRLEN];
	char id[CLUSTER_HASHLEN];
	char run[CLUSTER_HASHLEN];       // ...and the token its running FTL made up, so a
	                                 // third node can tell one member listed twice from two
	bool identity_shared;            // ...and whether it says another machine is using its identity
	double clock_offset;
	bool clock_agrees;
	bool is_self;
	bool knows_us;
	uint8_t sees;
	char address[CLUSTER_ADDRLEN];
	char confhash[CLUSTER_HASHLEN];
	char credhash[CLUSTER_HASHLEN];
	bool accepts_credentials;
	bool wants_credentials;
	char pinned[256];
	char pinned_credentials[256];
	double config_changed;
	char gravityhash[CLUSTER_HASHLEN];
	double gravity_changed;
	bool gravity_owed;
	double last_seen;
	bool reachable;
	bool failover;
	bool dhcp_capable;
	bool resolving;                  // ...and whether it answers DNS at all
	bool vip_capable;                // ...and would answer on an address placed later
	bool dhcp_configured;
	bool dhcp_active;
	bool vip_held;
};

struct cluster_state {
	unsigned int num_peers;
	struct cluster_peer_status peers[CLUSTER_MAX_PEERS];
	char leader[CLUSTER_STRLEN];     // reachable node with the lowest identity
	char dhcp_owner[CLUSTER_STRLEN]; // node serving DHCP ("" if none)
	bool vip_held;                   // this node holds the virtual IP
	double last_round;
};

bool cluster_start_thread(pthread_attr_t *attr);

// Ask the cluster thread to synchronize during its next round

// The cluster thread writes the state, the API threads read it
void cluster_lock(void);
void cluster_unlock(void);
struct cluster_state *cluster_state(void) __attribute__ ((const));

// Name of this node: cluster.name if set, the hostname otherwise. Copied out
// of the configuration under the lock, as the configuration is replaced by
// other threads while we work with it
void cluster_name(char buf[CLUSTER_STRLEN]);
bool peer_answers(const struct cluster_peer *peer) __attribute__ ((pure));
const char *peer_identity(const struct cluster_peer *peer) __attribute__ ((pure));
bool peer_anchors(const struct cluster_peer *peer) __attribute__ ((pure));

// The configured virtual IP address, copied out of the configuration under the
// lock. Everything else works with the copy: the string itself is freed the
// moment another thread replaces the configuration
void cluster_vip_address(char buf[CLUSTER_STRLEN]);

// Host part of a peer URL, if it is a plain IPv4 address. Used to tell DHCP
// clients about every node of the cluster
bool cluster_peer_ipv4(const char *entry, char *buf, const size_t buflen);

// The name of the node with this identity, for saying where a value came from.
// Returns NULL when no member of the cluster answers to it
// A configuration a peer handed us asked FTL to restart. Not done there and
// then: the nodes would all go down together
void cluster_restart_later(const char *reason);

// Take this node out of the cluster: the others are told, then clustering
// stops here. Acted on by the cluster thread at its next round
void cluster_leave(void);
bool cluster_leave_now(char *errbuf, bool *peers_told);

// Whether the cluster thread is actually there. `cluster.enabled` says what the
// administrator asked for, this says what happened
bool cluster_running(void);

// Set when more than one member answers with this node's identity - two machines
// carrying the same cluster.state. Read where a node decides whether to serve
extern bool duplicate_identity;

// Say that the lists of this node were last touched now, but only if this node
// never knew. Called when somebody joins, so the cluster can hand them over
void cluster_stamp_lists(void);


// Add this node's own status to the given JSON object
void cluster_local_status(cJSON *node);

#endif // CLUSTER_H
