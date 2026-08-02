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
#define CLUSTER_STRLEN 128
#define CLUSTER_URLLEN 256
#define CLUSTER_HASHLEN 65

struct cluster_peer {
	char *url;                       // "http(s)://host[:port]"
	char *sid;                       // cached session ID (NULL if not authenticated)
	void *curl;                      // CURL handle, kept for connection reuse
	char name[CLUSTER_STRLEN];       // node name as reported by the peer
	char version[CLUSTER_STRLEN];    // FTL version of the peer
	char id[CLUSTER_HASHLEN];          // the peer's identity, which cannot collide
	char error[CLUSTER_STRLEN];      // why the last round failed ("" if it did not)
	unsigned int priority;
	unsigned int rounds_up;          // consecutive rounds this peer was reachable
	unsigned int rounds_down;        // consecutive rounds this peer was not
	double last_seen;
	bool reachable;
	bool failover;                   // peer participates in DHCP failover
	bool dhcp_capable;               // peer has a lease range and could serve
	bool dhcp_active;                // peer is currently serving DHCP
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
	char error[CLUSTER_STRLEN];
	char id[CLUSTER_HASHLEN];
	unsigned int priority;
	double last_seen;
	bool reachable;
	bool failover;
	bool dhcp_capable;
	bool dhcp_active;
	bool vip_held;
};

struct cluster_state {
	bool enabled;
	unsigned int num_peers;
	struct cluster_peer_status peers[CLUSTER_MAX_PEERS];
	char leader[CLUSTER_STRLEN];     // highest-priority reachable node
	char dhcp_owner[CLUSTER_STRLEN]; // node serving DHCP ("" if none)
	bool vip_held;                   // this node holds the virtual IP
	double last_round;
};

bool cluster_start_thread(pthread_attr_t *attr);

// This node's identity inside the cluster. Names can collide - two Pi-holes
// imaged from the same card are both "raspberrypi" - so everything that has to
// pick one of two nodes without asking picks by this
const char *cluster_node_id(void) __attribute__ ((const));

// The cluster thread writes the state, the API threads read it
void cluster_lock(void);
void cluster_unlock(void);
struct cluster_state *cluster_state(void) __attribute__ ((const));

// Name of this node: cluster.name if set, the hostname otherwise. Copied out
// of the configuration under the lock, as the configuration is replaced by
// other threads while we work with it
void cluster_name(char buf[CLUSTER_STRLEN]);

// The configured virtual IP address, copied out of the configuration under the
// lock. Everything else works with the copy: the string itself is freed the
// moment another thread replaces the configuration
void cluster_vip_address(char buf[CLUSTER_STRLEN]);

// Host part of a peer URL, if it is a plain IPv4 address. Used to tell DHCP
// clients about every node of the cluster
bool cluster_peer_ipv4(const char *entry, char *buf, const size_t buflen);

// Add this node's own status to the given JSON object
void cluster_local_status(cJSON *node);

#endif // CLUSTER_H
