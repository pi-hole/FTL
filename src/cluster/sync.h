/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster configuration synchronization prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CLUSTER_SYNC_H
#define CLUSTER_SYNC_H

#include "FTL.h"
#include "cluster/cluster.h"

// Where the item versions and this node's identity live
#define CLUSTER_STATE_FILE_NAME "/etc/pihole/cluster.state"

// What this node knows about its own list tables. The configuration is not in
// here: when it was last changed lives in config_changed, which the whole of
// FTL writes to and this file only persists
struct cluster_sync_state {
	double gravity_changed;
	char gravity_hash[CLUSTER_HASHLEN];

	// A pull that was still settling when FTL stopped. Without this a
	// restart cannot tell a peer's tables awaiting a rebuild from a list
	// somebody edited here moments before, and publishes the second as the
	// first - under a timestamp that loses the edit to any peer
	double pending_changed;
	char pending_id[CLUSTER_HASHLEN];
	// ...and the fingerprint of what was imported. The peer moves on while
	// the rebuild runs, so its own fingerprint answers a different question
	char pending_hash[CLUSTER_HASHLEN];
};

// Fingerprints of everything we synchronize
// False when the list fingerprint could not be read - the caller keeps whatever
// it had rather than taking a read error for a change
bool cluster_sync_hashes(char confhash[CLUSTER_HASHLEN], char gravityhash[CLUSTER_HASHLEN]);
void cluster_config_hash(char out[CLUSTER_HASHLEN]);

// The DHCP leases of whichever node is handing out addresses, so the node that
// takes over from it knows which client holds which address
bool cluster_leases_read(uint8_t **data, size_t *size);
bool cluster_leases_hash(char out[CLUSTER_HASHLEN]);
void cluster_leases_hash_bytes(const uint8_t *data, const size_t size, char out[CLUSTER_HASHLEN]);
bool cluster_leases_write(const uint8_t *data, const size_t size);
void cluster_credentials_hash(char out[CLUSTER_HASHLEN]);

// Whether the last configuration change touched anything that is synchronized,
// which is what decides whether it counts as this node being configured
bool cluster_config_moved(void);

// Fingerprint of the adlist table alone. Only a change here makes the blocking
// database stale, and only then is a gravity run needed
bool cluster_adlist_hash(char hash[CLUSTER_HASHLEN]);

// Persisted across restarts: FTL restarts itself whenever a synchronized item
// asks for it, so keeping this in memory only would reset it constantly
void cluster_state_load(struct cluster_sync_state *state);
bool cluster_state_known(void) __attribute__ ((pure));
void cluster_state_save(const struct cluster_sync_state *state);
void cluster_state_forget(void);

// What this node hands to a peer: exactly what GET /api/config answers, minus
// the items that never leave a node
// encrypted says whether the peer this document is for is reached over TLS.
// The credentials are left out when it is not
cJSON *cluster_config_document(double *changed, const bool encrypted);

// ...and handing it over, which is a PATCH of the peer's configuration - the
// request the web interface makes when somebody hits Save. The peer decides for
// itself which of the items it does not hold yet
bool cluster_push_config(struct cluster_peer *peer, const char *body, const double changed);

// Can this document reach a peer at all, or is it larger than one can read?
bool cluster_push_possible(const char *body) __attribute__ ((pure));

// Held around the gravity tables: the cluster thread importing them and a
// webserver thread exporting them both reach the same database
void cluster_sync_lock(void);
void cluster_sync_unlock(void);

// This node's identity inside the cluster. Names can collide - two Pi-holes
// imaged from the same card are both "raspberrypi" - so everything that has to
// pick one of two nodes without asking picks by this
const char *cluster_node_id(void) __attribute__ ((const));

// Take the lists of a peer. These are replaced as a whole rather than merged:
// the archive carries whole tables, not the changes made to them
// held is what this node's tables hashed to when the round decided to pull; an
// edit made here since then is kept rather than replaced
bool cluster_pull_gravity(struct cluster_peer *peer, const char *held, bool *rebuilding);

// Start a rebuild of the blocking database. False when one is already running,
// in which case the caller asks again next round
bool cluster_run_gravity(void);

// A rebuild the cluster started, and how the last one ended. The lists are only
// this node's once they were actually built: the blocking database is not part
// of the fingerprint, so a node whose rebuild never ran would otherwise report
// the newest lists while blocking nothing
bool cluster_state_same_build(void) __attribute__ ((pure));
bool cluster_gravity_pending(void) __attribute__ ((pure));
bool cluster_gravity_succeeded(void) __attribute__ ((pure));

// Has the gravity run this node started finished? Looked at once per tick
void cluster_gravity_check(void);

#endif // CLUSTER_SYNC_H
