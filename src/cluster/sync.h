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
// here: when each item was last changed is kept per item below
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
	char pre_pull_hash[CLUSTER_HASHLEN]; // what this node held before it asked for the peer's lists
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
// Merge the serving node's lease file into this node's copy, newest expiry per
// address winning, so an outage does not drop the leases granted meanwhile
bool cluster_leases_merge(const uint8_t *incoming, const size_t insize,
                          uint8_t **out, size_t *outsize);
void cluster_credentials_hash(char out[CLUSTER_HASHLEN]);

// Which items the last configuration change touched that are synchronized,
// which is what decides which of them count as configured here
bool cluster_config_moved(bool moved[CONFIG_ELEMENTS]);

// When each item was last changed, here or on the peer it came from. Zero for
// an item nobody changed and for every item that never leaves a node
int cluster_item_index(const char *key) __attribute__ ((pure));
double cluster_item_changed(const unsigned int i);
void cluster_item_stamps(double out[CONFIG_ELEMENTS]);
void cluster_stamp_items(const bool which[CONFIG_ELEMENTS], const double when[CONFIG_ELEMENTS]);
double cluster_newest_change(void);

// What this node kept its own value of in the last push it was handed
void cluster_note_refused(const char *items);
void cluster_refused_items(char *out, const size_t outlen);

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
// the items that never leave a node and the ones include leaves out, with when
// each item was changed under "changed"
// encrypted says whether the peer this document is for is reached over TLS.
// The credentials are left out when it is not
cJSON *cluster_config_document(const bool include[CONFIG_ELEMENTS], const bool encrypted);

// ...and handing it over, which is a PATCH of the peer's configuration - the
// request the web interface makes when somebody hits Save. The peer decides for
// itself which of the items it does not hold yet. *taken (if not NULL) is false
// when the peer answered but holds newer versions of everything it was sent
bool cluster_push_config(struct cluster_peer *peer, const char *body, bool *taken);

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
// the archive carries whole tables, not the changes made to them. held is what
// this node's tables hashed to when the round decided to pull; an edit made here
// since then is kept rather than replaced
// imported is what the tables hash to right after the import, "" if unreadable
bool cluster_pull_gravity(struct cluster_peer *peer, const char *held, bool *rebuilding,
                          char imported[CLUSTER_HASHLEN]);

// Start a rebuild of the blocking database. False when one is already running,
// in which case the caller asks again next round
bool cluster_run_gravity(void);
// Is a gravity run going on that this node's cluster did not start?
bool cluster_gravity_elsewhere(void);

// An edit of the list tables made through the API. What moved the tables
// without one is not an edit made on this node
void cluster_note_list_write(void);
// The time of such an edit not accounted for yet (0 when there is none), and
// whether gravity.db is another file than when last accounted for, holding
// tables (hash) other than the ones that edit left
void cluster_lists_explain(const char *hash, double *written, bool *replaced);
void cluster_lists_accounted(const double written);

// A rebuild the cluster started, and how the last one ended. The lists are only
// this node's once they were actually built: the blocking database is not part
// of the fingerprint, so a node whose rebuild never ran would otherwise report
// the newest lists while blocking nothing
bool cluster_state_same_build(void) __attribute__ ((pure));
void cluster_state_build_settled(void);
bool cluster_gravity_pending(void) __attribute__ ((pure));
bool cluster_gravity_succeeded(void) __attribute__ ((pure));

// Has the gravity run this node started finished? Looked at once per tick. True
// when it ended and its outcome is to be settled, followed by the release
bool cluster_gravity_check(void);
void cluster_gravity_release(void);
// End that run, as a stop is pending
void cluster_gravity_stop(void);

#endif // CLUSTER_SYNC_H
