/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster engine
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "daemon.h"
#include "config/config.h"
#include "cluster/cluster.h"
#include "cluster/http.h"
#include "cluster/sync.h"
// cluster_plain_id()
#include "cluster/auth.h"
#include "cluster/dhcp.h"
#include "cluster/vip.h"
// cluster_beacon_open()
#include "cluster/discover.h"
// certificate_pin()
#include "webserver/x509.h"
// PATH_MAX
#include <limits.h>
#include "version.h"
#include "config/dnsmasq_config.h"
// create_cluster_secret()
#include "config/password.h"
// thread_names, thread_sleepms
#include "signals.h"
// prctl()
#include <sys/prctl.h>

// How often the thread looks at whether something changed [ms]
#define CLUSTER_TICK_MS 100

// How many rounds a peer may answer with an identity other than the one it was
// pinned to before we accept that it was rebuilt rather than impersonated
#define CLUSTER_ID_CHANGE_ROUNDS 3

// A peer that has just been given this node's address has not polled it yet, so
// it does not know its identity for a round or two. Only a peer that keeps not
// knowing us is one whose member list we are missing from
#define CLUSTER_UNKNOWN_ROUNDS 3

// How far apart the nodes restart when a synchronized change asks them to. They
// are the household's DNS servers, and taking them all down in the same second
// is the outage a cluster exists to prevent
#define CLUSTER_RESTART_STAGGER 10.0
// isprint()
#include <ctype.h>
#include <math.h>
// lock_shm()
#include "shmem.h"

// The peers the cluster thread works with. They own memory and a libcurl
// handle and are touched by that thread only, which is why no lock is taken
// while talking to a peer: holding one across network I/O would stall every
// peer polling us in return
static struct cluster_peer peers[CLUSTER_MAX_PEERS] = { 0 };
static unsigned int num_peers = 0;

// The snapshot the API threads read
static struct cluster_state state = { 0 };
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;

void cluster_lock(void)
{
	pthread_mutex_lock(&state_lock);
}

void cluster_unlock(void)
{
	pthread_mutex_unlock(&state_lock);
}

struct cluster_state *cluster_state(void)
{
	return &state;
}

void cluster_vip_address(char buf[CLUSTER_STRLEN])
{
	lock_shm();
	strncpy(buf, config.cluster.vip.address.v.s, CLUSTER_STRLEN - 1);
	unlock_shm();

	buf[CLUSTER_STRLEN - 1] = '\0';
}

void cluster_name(char buf[CLUSTER_STRLEN])
{
	lock_shm();
	const bool named = config.cluster.name.v.s != NULL && strlen(config.cluster.name.v.s) > 0;
	strncpy(buf, named ? config.cluster.name.v.s : hostname(), CLUSTER_STRLEN - 1);
	unlock_shm();

	buf[CLUSTER_STRLEN - 1] = '\0';
}

bool cluster_peer_ipv4(const char *entry, char *buf, const size_t buflen)
{
	// Skip the scheme
	const char *host = strstr(entry, "://");
	if(host == NULL)
		return false;
	host += 3;

	// The host ends at the port or the path
	size_t len = strcspn(host, ":/");
	if(len == 0 || len >= buflen)
		return false;

	char candidate[INET_ADDRSTRLEN] = "";
	if(len >= sizeof(candidate))
		return false;
	memcpy(candidate, host, len);

	struct in_addr addr = { 0 };
	if(inet_pton(AF_INET, candidate, &addr) != 1)
		return false;

	strcpy(buf, candidate);

	return true;
}

static void free_peer(struct cluster_peer *peer)
{
	cluster_http_free(peer);
	if(peer->url != NULL)
		free(peer->url);
	memset(peer, 0, sizeof(*peer));
}

// Rebuild the peer array from the configuration. Called before every round so
// changes to cluster.members take effect without restarting FTL. Peers that did
// not change keep their session and connection
static void update_peers(void)
{
	// The configured list is walked under the lock and copied out: another
	// thread replacing the configuration frees these cJSON nodes, and
	// everything below this point does I/O we must not hold a lock across
	char urls[CLUSTER_MAX_PEERS][CLUSTER_URLLEN] = { { 0 } };
	unsigned int num_urls = 0, num = 0;

	lock_shm();
	cJSON *conf_peers = config.cluster.members.v.json;
	num = conf_peers != NULL ? (unsigned int)cJSON_GetArraySize(conf_peers) : 0;
	for(cJSON *item = conf_peers != NULL ? conf_peers->child : NULL;
	    item != NULL && num_urls < CLUSTER_MAX_PEERS; item = item->next)
	{
		if(!cJSON_IsString(item))
			continue;

		strncpy(urls[num_urls], item->valuestring, CLUSTER_URLLEN - 1);
		urls[num_urls][CLUSTER_URLLEN - 1] = '\0';
		num_urls++;
	}
	unlock_shm();

	unsigned int i = 0;
	for(; i < num_urls; i++)
	{
		struct cluster_peer *peer = &peers[i];

		// Keep the existing peer, and its session, if it did not change
		if(peer->url != NULL && strcmp(peer->url, urls[i]) == 0)
			continue;

		free_peer(peer);
		peer->url = strdup(urls[i]);
	}

	// Release peers that are no longer configured
	for(unsigned int j = i; j < CLUSTER_MAX_PEERS; j++)
		if(peers[j].url != NULL)
			free_peer(&peers[j]);

	num_peers = i;

	// Once per list, not once per round: this is a configuration value, so
	// the condition lasts until somebody changes it
	static unsigned int warned_num = 0;
	if(num > CLUSTER_MAX_PEERS && warned_num != num)
	{
		log_warn("cluster: only the first %d of %u members are used",
		         CLUSTER_MAX_PEERS, num);
		warned_num = num;
	}
	else if(num <= CLUSTER_MAX_PEERS)
		warned_num = 0;
}

// Read one string/number/bool out of a nested status document
static const cJSON *status_item(const cJSON *json, const char *object, const char *key)
{
	const cJSON *obj = cJSON_GetObjectItem(json, object);
	if(obj == NULL)
		return NULL;

	return cJSON_GetObjectItem(obj, key);
}

// {"version": <n>, "hash": "<...>"} as it appears twice in a peer's answer
static void read_domain(const cJSON *domain, char hash[CLUSTER_HASHLEN], double *changed)
{
	if(domain == NULL)
		return;

	const cJSON *json_hash = cJSON_GetObjectItem(domain, "hash");
	if(cJSON_IsString(json_hash))
	{
		strncpy(hash, json_hash->valuestring, CLUSTER_HASHLEN - 1);
		hash[CLUSTER_HASHLEN - 1] = '\0';
	}

	// A clock that far ahead is broken rather than ahead, and taking it would
	// pin the lists to that node for good
	const cJSON *json_changed = cJSON_GetObjectItem(domain, "changed");
	if(cJSON_IsNumber(json_changed) && isfinite(json_changed->valuedouble) &&
	   json_changed->valuedouble >= 0.0 &&
	   json_changed->valuedouble <= double_time() + CLUSTER_MAX_CLOCK_OFFSET)
		*changed = json_changed->valuedouble;
}

static void mark_unreachable(struct cluster_peer *peer, const char *err)
{
	if(peer->reachable || peer->rounds_down == 0)
		log_info("cluster: %s unreachable (%s)", peer->url, err);

	peer->reachable = false;
	peer->rounds_down++;

	// A peer we have pinned to an identity refuses everything we send if it
	// was rebuilt and minted a new one, and the answer that would tell us so
	// is the answer it refuses. After a few rounds the pin goes and the next
	// request asks whoever is there
	if(peer->rounds_down >= CLUSTER_ID_CHANGE_ROUNDS && strlen(peer->id) > 0)
	{
		log_info("cluster: %s has not answered as %s, asking again without it",
		         peer->url, peer->id);
		peer->id[0] = '\0';
		peer->is_self = false;
	}

	peer->dhcp_active = false;
	peer->dhcp_capable = false;
	peer->resolving = true;
	peer->vip_capable = true;
	peer->sees_dhcp = false;
	peer->vip_held = false;
	peer->clock_agrees = false;
	strncpy(peer->error, err, sizeof(peer->error) - 1);
	peer->error[sizeof(peer->error) - 1] = '\0';
}

// Ask one peer how it is doing. This is the only request made per peer and
// round: everything we need to know is in the answer
static void poll_peer(struct cluster_peer *peer)
{
	cJSON *json = NULL;
	char err[CLUSTER_STRLEN] = "";

	char signer[CLUSTER_HASHLEN] = "";
	if(!cluster_http_json(peer, "/api/cluster/status", &json, err, sizeof(err),
	                      signer, sizeof(signer)))
	{
		mark_unreachable(peer, err);
		return;
	}

	const cJSON *node = cJSON_GetObjectItem(cJSON_GetObjectItem(json, "cluster"), "node");
	if(node == NULL)
	{
		cJSON_Delete(json);
		mark_unreachable(peer, "Answer contains no node status");
		return;
	}

	const cJSON *name = cJSON_GetObjectItem(node, "name");
	if(cJSON_IsString(name))
	{
		// The peer chooses this string and we log it, so anything that
		// could forge a log line is dropped rather than passed on
		size_t len = 0;
		for(const char *p = name->valuestring; *p != '\0' && len < sizeof(peer->name) - 1; p++)
			if(isprint((unsigned char)*p))
				peer->name[len++] = *p;
		peer->name[len] = '\0';
	}

	// Only ever out of an answer whose signature checked out, which is what
	// makes this safe: somebody in the middle can break the connection but
	// cannot say what the certificate on the other end should look like
	const cJSON *pin = cJSON_GetObjectItem(node, "pin");
	if(cJSON_IsString(pin) && strlen(pin->valuestring) < sizeof(peer->pin))
	{
		// A key this peer published before and then did not serve is not
		// taken again: pinning it would fail the same way every round.
		// The connection stays unpinned - still signed, so nobody can
		// change what travels, but readable to whoever sits on it
		const bool refused = strcmp(pin->valuestring, peer->pin_refused) == 0 &&
		                     peer->pin_failures >= CLUSTER_PIN_FAILURES &&
		                     cluster_waiting(peer->pin_rearm_at, double_time(), CLUSTER_PIN_REARM);

		if(refused)
		{
			if(!peer->pin_warned)
				log_warn("cluster: %s does not serve the certificate it publishes, connections to it are not identified",
				         peer->url);
			peer->pin_warned = true;
		}
		else
		{
			if(strlen(peer->pin) == 0 && strncmp(peer->url, "https://", 8) == 0)
				log_info("cluster: %s identifies itself with certificate %.16s...",
				         peer->url, pin->valuestring);
			strncpy(peer->pin, pin->valuestring, sizeof(peer->pin) - 1);
			peer->pin[sizeof(peer->pin) - 1] = '\0';
			peer->pin_warned = false;

			// A key that just failed often enough is left alone for a
			// while rather than tried again immediately
			if(strcmp(pin->valuestring, peer->pin_refused) == 0 &&
			   peer->pin_failures >= CLUSTER_PIN_FAILURES)
				peer->pin_rearm_at = double_time() + CLUSTER_PIN_REARM;
			else if(strcmp(pin->valuestring, peer->pin_refused) != 0)
			{
				peer->pin_refused[0] = '\0';
				peer->pin_failures = 0;
				peer->pin_rearm_at = 0.0;
			}
		}
	}

	const cJSON *version = cJSON_GetObjectItem(node, "version");
	if(cJSON_IsString(version))
	{
		strncpy(peer->version, version->valuestring, sizeof(peer->version) - 1);
		peer->version[sizeof(peer->version) - 1] = '\0';
	}

	const cJSON *branch = cJSON_GetObjectItem(node, "branch");
	strncpy(peer->branch, cJSON_IsString(branch) ? branch->valuestring : "",
	        sizeof(peer->branch) - 1);
	peer->branch[sizeof(peer->branch) - 1] = '\0';

	const cJSON *id = cJSON_GetObjectItem(node, "id");
	// Everything this node decides about a peer is decided by identity - who
	// leads, who serves DHCP, whose lists are newer. An answer that carries
	// none leaves that identity empty, and an empty one sorts before every
	// real one, so the node that said the least would win every election
	if(!cJSON_IsString(id) || strlen(id->valuestring) == 0)
	{
		mark_unreachable(peer, "no identity in the answer");
		cJSON_Delete(json);
		return;
	}

	{
		// A node keeps the identity it first answered with. Every node of
		// a cluster signs with the same secret, so an answer is proof
		// that somebody in the cluster wrote it, not proof of which node
		// did - and an answer of ours handed back to us would otherwise
		// be enough to take a working peer out of the cluster
		// A peer keeps the identity it first answered with, so an answer
		// of ours handed back to us cannot take a working peer out of the
		// cluster. But a node rebuilt at the same address mints a new
		// identity, and it must not be locked out for good: after a few
		// rounds of disagreeing, the new one is taken
		if(!cJSON_IsString(id) || !cluster_plain_id(id->valuestring))
		{
			// Said once: the text comes from the peer and the
			// condition lasts, so one line per round is thousands a
			// day onto the card this runs from
			if(!peer->id_warned)
				log_warn("cluster: %s answers with an unusable identity", peer->url);
			peer->id_warned = true;
			mark_unreachable(peer, "bad identity");
			cJSON_Delete(json);
			return;
		}

		// The identity in the document has to be the one the answer was
		// signed under. They are separate fields, and an answer of one
		// node handed to us as another node's would otherwise be adopted
		if(strcmp(id->valuestring, signer) != 0)
		{
			if(!peer->id_warned)
				log_warn("cluster: %s answers as %s but signed as %s",
				         peer->url, id->valuestring, signer);
			peer->id_warned = true;
			mark_unreachable(peer, "identity does not match the signature");
			cJSON_Delete(json);
			return;
		}

		peer->id_warned = false;

		if(strlen(peer->id) > 0 && strcmp(peer->id, id->valuestring) != 0)
		{
			if(++peer->id_changed_rounds < CLUSTER_ID_CHANGE_ROUNDS)
			{
				log_warn("cluster: %s answers as a different node, ignoring it",
				         peer->url);
				mark_unreachable(peer, "identity changed");
				cJSON_Delete(json);
				return;
			}

			log_info("cluster: %s was replaced, taking its new identity", peer->url);
			peer->is_self = false;
		}
		peer->id_changed_rounds = 0;

		strncpy(peer->id, id->valuestring, sizeof(peer->id) - 1);
		peer->id[sizeof(peer->id) - 1] = '\0';

		// The member list is the same on every node, so one of its entries
		// is this node. It answers with our own identity, which is how we
		// recognize it - decided again every round, never latched
		const bool self = strcmp(peer->id, cluster_node_id()) == 0;
		if(self && !peer->is_self)
			log_info("cluster: %s is this node, skipped", peer->url);
		peer->is_self = self;
		if(!self)
			peer->answered_as_other = true;
	}

	// How far apart the two clocks are. The peer stamped its answer somewhere
	// between this node sending the request and having the answer in hand, so
	// the middle of those two is when it stamped it by this node's clock -
	// which leaves the difference between the clocks rather than the time the
	// answer spent travelling. Only the asymmetry between the two directions
	// is left over, and on a local network that is microseconds
	const cJSON *peer_time = cJSON_GetObjectItem(node, "time");
	if(cJSON_IsNumber(peer_time) && isfinite(peer_time->valuedouble))
	{
		const double here = peer->asked_at > 0.0 && peer->answered_at >= peer->asked_at ?
		                    (peer->asked_at + peer->answered_at) / 2.0 : double_time();
		peer->clock_offset = peer_time->valuedouble - here;
		const bool agrees = fabs(peer->clock_offset) <= CLUSTER_MAX_CLOCK_OFFSET;

		// Latched rather than compared against the flag: an unreachable
		// peer has no reading at all, and clearing the flag for that
		// would have every missed poll answered by "agrees again"
		if(!agrees && !peer->clock_warned)
			log_warn("cluster: clock of %s is %.1f s off, not synchronizing with it",
			         peer->url, peer->clock_offset);
		else if(agrees && peer->clock_warned)
			log_info("cluster: clock of %s agrees again (%.1f s off)",
			         peer->url, peer->clock_offset);

		peer->clock_warned = !agrees;
		peer->clock_agrees = agrees;
	}
	else
		peer->clock_agrees = false;


	const cJSON *dhcp_active = status_item(node, "dhcp", "active");
	peer->dhcp_active = cJSON_IsTrue(dhcp_active);
	const cJSON *leases = status_item(node, "dhcp", "leases");
	strncpy(peer->leaseshash, cJSON_IsString(leases) ? leases->valuestring : "",
	        sizeof(peer->leaseshash) - 1);
	peer->leaseshash[sizeof(peer->leaseshash) - 1] = '\0';
	const cJSON *failover = status_item(node, "dhcp", "failover");
	peer->failover = cJSON_IsTrue(failover);
	const cJSON *capable = status_item(node, "dhcp", "capable");
	peer->dhcp_capable = cJSON_IsTrue(capable);
	// A node too old to say falls back to its capability, which is what this
	// node would have had to assume anyway
	const cJSON *configured = status_item(node, "dhcp", "configured");
	peer->dhcp_configured = cJSON_IsBool(configured) ? cJSON_IsTrue(configured)
	                                                 : peer->dhcp_capable;
	// A node too old to say is assumed to resolve: that is what this node had
	// to assume before the field existed, and refusing to lead to it would
	// split a mixed-version cluster over a question it cannot answer
	const cJSON *resolving = cJSON_GetObjectItem(node, "resolving");
	peer->resolving = cJSON_IsBool(resolving) ? cJSON_IsTrue(resolving) : true;
	const cJSON *vip_capable = cJSON_GetObjectItem(node, "vip_capable");
	peer->vip_capable = cJSON_IsBool(vip_capable) ? cJSON_IsTrue(vip_capable)
	                                              : peer->resolving;

	const cJSON *vip_held = status_item(node, "vip", "held");
	peer->vip_held = cJSON_IsTrue(vip_held);

	// What this peer can see that we cannot. A node whose link to the DHCP
	// server is broken while everybody else still reaches it would otherwise
	// take DHCP over on its own view alone, and the network would have two
	const cJSON *their_peers = cJSON_GetObjectItem(json, "cluster");
	their_peers = their_peers != NULL ? cJSON_GetObjectItem(their_peers, "peers") : NULL;
	peer->sees_dhcp = peer->dhcp_active;
	bool knows_us = peer->is_self;
	uint8_t sees = 0;

	// How this node appears in the member list, which is the same list the
	// peer publishes back to us
	const char *self_url = NULL;
	for(unsigned int i = 0; i < num_peers; i++)
		if(peers[i].is_self)
			self_url = peers[i].url;
	for(const cJSON *p = cJSON_IsArray(their_peers) ? their_peers->child : NULL;
	    p != NULL; p = p->next)
	{
		// Their view of us is not news about anybody else. Counting it
		// would make "somebody other than me is serving" true whenever
		// this node serves, and the node handing out the leases would
		// then decline the address that belongs with them
		const cJSON *pid = cJSON_GetObjectItem(p, "id");
		const cJSON *reachable = cJSON_GetObjectItem(p, "reachable");

		// A member this peer has not managed to poll yet is published with
		// an empty identity. That entry may be the one for this node, so it
		// is not evidence of a missing membership - but neither is every
		// other unidentified entry, and treating them all as ours would
		// silence the warning for good on a cluster with one long-dead
		// node. The address decides: the member list is the same document
		// on every node, so our own entry in it is our entry in theirs
		const cJSON *purl = cJSON_GetObjectItem(p, "url");
		if((!cJSON_IsString(pid) || strlen(pid->valuestring) == 0) &&
		   cJSON_IsString(purl) && self_url != NULL &&
		   strcmp(purl->valuestring, self_url) == 0)
			knows_us = true;

		// Which members this one can reach, as a bit per entry of our own
		// list. The list is the same on every node, so a bit means the
		// same thing on both sides - and every node polls every other,
		// so this is what says a partition apart from an outage
		if(cJSON_IsString(pid) && cJSON_IsTrue(reachable))
			for(unsigned int k = 0; k < num_peers && k < CLUSTER_MAX_PEERS; k++)
				if(strcmp(peers[k].id, pid->valuestring) == 0)
				{
					sees |= (uint8_t)(1U << k);
					break;
				}

		if(cJSON_IsString(pid) && strcmp(pid->valuestring, cluster_node_id()) == 0)
		{
			knows_us = true;
			continue;
		}

		const cJSON *active = status_item(p, "dhcp", "active");
		if(cJSON_IsTrue(reachable) && cJSON_IsTrue(active))
			peer->sees_dhcp = true;

		// Where this node reached somebody whose name we cannot resolve.
		// The member list is the same everywhere, so the entry it belongs
		// to is the one with the same URL. Only an offer: the connection
		// still has to succeed, and the certificate is still checked
		// against the name rather than against the address
		const cJSON *paddr = cJSON_GetObjectItem(p, "address");
		if(!cJSON_IsTrue(reachable) || !cJSON_IsString(purl) ||
		   !cJSON_IsString(paddr) || strlen(paddr->valuestring) == 0)
			continue;

		for(unsigned int k = 0; k < num_peers; k++)
		{
			struct cluster_peer *other = &peers[k];
			if(other->reachable || other->is_self ||
			   other->url == NULL || strcmp(other->url, purl->valuestring) != 0)
				continue;

			if(strlen(other->address) > 0)
				break;

			if(strcmp(other->hint_failed, paddr->valuestring) == 0)
			{
				if(cluster_waiting(other->hint_rearm_at, double_time(), CLUSTER_HINT_REARM))
					break;
				other->hint_failed[0] = '\0';
			}

			if(strcmp(other->hint, paddr->valuestring) != 0)
			{
				// A peer that is merely restarting gets an offer too,
				// and its own name would have done - so this is only
				// worth a line when somebody goes looking
				log_debug(DEBUG_CLUSTER, "cluster: %s says %s answers at %s, trying that",
				          peer->url, other->url, paddr->valuestring);
				strncpy(other->hint, paddr->valuestring, sizeof(other->hint) - 1);
				other->hint[sizeof(other->hint) - 1] = '\0';
			}
			break;
		}
	}

	// Synchronization travels from the node holding the newer document to the
	// ones behind it, so a peer this node is missing from never sends it
	// anything. It answers every poll and looks perfectly healthy while doing
	// nothing at all, which is worth one line rather than silence
	peer->sees = sees;
	peer->knows_us = knows_us;
	if(knows_us)
	{
		if(peer->unknown_warned)
			log_info("cluster: %s lists this node again", peer->url);
		peer->unknown_warned = false;
		peer->unknown_rounds = 0;
	}
	else if(++peer->unknown_rounds >= CLUSTER_UNKNOWN_ROUNDS && !peer->unknown_warned)
	{
		log_warn("cluster: %s does not list this node among its members, so it never sends anything here - add this node to cluster.members there",
		         peer->url);
		peer->unknown_warned = true;
	}

	const cJSON *sync = cJSON_GetObjectItem(node, "sync");
	const cJSON *theirconf = cJSON_GetObjectItem(sync, "config");
	read_domain(theirconf, peer->confhash, &peer->config_changed);
	const cJSON *theircreds = cJSON_GetObjectItem(theirconf, "credentials");
	strncpy(peer->credhash, cJSON_IsString(theircreds) ? theircreds->valuestring : "",
	        sizeof(peer->credhash) - 1);
	peer->credhash[sizeof(peer->credhash) - 1] = '\0';
	peer->accepts_credentials = cJSON_IsTrue(cJSON_GetObjectItem(theirconf, "accepts_credentials"));
	peer->wants_credentials = cJSON_IsTrue(cJSON_GetObjectItem(theirconf, "wants_credentials"));
	const cJSON *theirpinned = cJSON_GetObjectItem(theirconf, "pinned");
	strncpy(peer->pinned, cJSON_IsString(theirpinned) ? theirpinned->valuestring : "",
	        sizeof(peer->pinned) - 1);
	peer->pinned[sizeof(peer->pinned) - 1] = '\0';
	const cJSON *theirpinnedcreds = cJSON_GetObjectItem(theirconf, "pinned_credentials");
	strncpy(peer->pinned_credentials,
	        cJSON_IsString(theirpinnedcreds) ? theirpinnedcreds->valuestring : "",
	        sizeof(peer->pinned_credentials) - 1);
	peer->pinned_credentials[sizeof(peer->pinned_credentials) - 1] = '\0';
	const cJSON *theirlists = cJSON_GetObjectItem(sync, "gravity");
	read_domain(theirlists, peer->gravityhash, &peer->gravity_changed);
	peer->gravity_owed = cJSON_IsTrue(cJSON_GetObjectItem(theirlists, "owed"));

	cJSON_Delete(json);

	if(!peer->reachable)
		log_info("cluster: %s reachable (%s)", peer->url,
		         strlen(peer->name) > 0 ? peer->name : "unnamed");

	peer->reachable = true;
	peer->rounds_down = 0;
	peer->last_seen = double_time();
	peer->error[0] = '\0';
}

// The reachable node every node picks, by identity rather than by name - names
// collide, identities cannot
static char leader[CLUSTER_STRLEN] = "";
// Index of that node, or -1 if it is this one
static int leader_idx = -1;
static char dhcp_owner[CLUSTER_STRLEN] = "";

// How often FTL had replaced its configuration when we last handed it around
static unsigned long pushed_generation = 0;

// What this node's own certificate hashes to
static char own_pin[CLUSTER_PINLEN] = "";

// Read again whenever the certificate file is replaced. FTL renews its own
// certificate before it expires and restarts the web server rather than the
// daemon, so a pin read once at start-up would go stale under us - and a node
// publishing a key it no longer serves is one its peers refuse for good
static bool refresh_own_pin(void)
{
	static ino_t inode = 0;
	static time_t modified = 0;
	static off_t size = 0;

	// Copied out: another thread replaces the configuration, and frees the
	// string this points at, while we are still reading through it
	char certfile[PATH_MAX] = "";
	lock_shm();
	strncpy(certfile, config.webserver.tls.cert.v.s, sizeof(certfile) - 1);
	unlock_shm();
	certfile[sizeof(certfile) - 1] = '\0';

	struct stat st = { 0 };
	if(stat(certfile, &st) != 0)
		return strlen(own_pin) > 0;

	if(st.st_ino == inode && st.st_mtime == modified && st.st_size == size)
		return strlen(own_pin) > 0;

	inode = st.st_ino;
	modified = st.st_mtime;
	size = st.st_size;

	char pin[CLUSTER_PINLEN] = "";
	if(!certificate_pin(certfile, pin, sizeof(pin)))
		return false;

	if(strlen(own_pin) > 0 && strcmp(pin, own_pin) != 0)
		log_info("cluster: this node's certificate was replaced, telling the peers");

	strncpy(own_pin, pin, sizeof(own_pin) - 1);
	own_pin[sizeof(own_pin) - 1] = '\0';

	return true;
}

// What this node holds, and how often it was changed here
static struct cluster_sync_state sync_state = { 0 };
// Fingerprint of the synchronized configuration items, as the peers see it
static char published_confhash[CLUSTER_HASHLEN] = "";
// Set by POST /api/cluster/sync, consumed by the next round

static void catch_up(void);
static bool a_member(void);
static bool we_are_newer(const struct cluster_peer *peer);

// Is this peer reached over a connection nobody on the way can read? The
// credentials travel only where that is true, so the document is built twice
// when a cluster mixes the two
// Whether a CA of the administrator's own is configured. Read once per round
// under the lock: another thread replaces the configuration and frees that
// string, and this is asked once per peer on a path that runs every tick
static bool have_ca = false;

// ...and whether the credentials are part of what this node keeps in step,
// which walks the member list - a cJSON array another thread replaces and frees
static bool credentials_travel = false;

static void refresh_config_facts(void)
{
	lock_shm();
	have_ca = strlen(config.cluster.tls.ca.v.s) > 0;
	credentials_travel = cluster_credentials_syncable();
	unlock_shm();
}

// Whether this peer is the node we think it is. An https:// URL says the
// connection cannot be read, not who is on the other end of it: with no CA
// configured the certificate is checked against nothing, so what identifies the
// far end is the pin it published in an answer signed with the shared secret
static bool peer_identified(const struct cluster_peer *peer)
{
	if(peer->url == NULL || strncmp(peer->url, "https://", 8) != 0)
		return false;

	return strlen(peer->pin) > 0 || have_ca;
}

// A peer we cannot identify is one this node stops handing configuration to
// while that document has passwords in it. Not a narrower document - a document
// built to a narrower rule than the fingerprint the two nodes compare is one
// they can never agree they hold, and the difference is then reconciled in
// whichever direction the timestamps happen to fall. Said once per peer: it is
// a state somebody has to fix, not an event
static bool push_refused(struct cluster_peer *peer)
{
	if(!credentials_travel || peer_identified(peer))
	{
		peer->push_warned = false;
		return false;
	}

	if(!peer->push_warned)
		log_warn("cluster: not handing the configuration to %s - it cannot be identified and "
		         "the document carries this cluster's passwords. Set cluster.tls.ca, or switch "
		         "cluster.sync.credentials off", peer->url);
	peer->push_warned = true;

	return true;
}

// ...and the same for what this node reads from a peer in bulk - the list
// archive and the lease file. An https:// member whose published key is not the
// one it serves is left unpinned so the status poll can still learn a renewed
// key, and that is all the unpinned connection may carry: the archive names
// every domain, group and client, and the lease file every machine on the
// network. An http:// member is read as it always was - that is the
// administrator's choice, and the manual says what it costs
static bool read_refused(struct cluster_peer *peer)
{
	if(peer->url == NULL || strncmp(peer->url, "https://", 8) != 0 || peer_identified(peer))
	{
		peer->read_warned = false;
		return false;
	}

	if(!peer->read_warned)
		log_warn("cluster: not taking lists or leases from %s - it cannot be identified. Set cluster.tls.ca, or check the certificate it serves",
		         peer->url);
	peer->read_warned = true;

	return true;
}

// One document per round, built at most once. What it carries follows the same
// rule the published fingerprint does, so two nodes comparing fingerprints are
// comparing the same set of items
static char *document_for(char **body, double *changed)
{
	if(*body != NULL)
		return *body;

	double when = 0.0;
	cJSON *document = cluster_config_document(&when, credentials_travel);
	*body = document != NULL ? cJSON_PrintUnformatted(document) : NULL;
	cJSON_Delete(document);
	*changed = when;

	return *body;
}

static void owe_gravity(const double changed, const char *id, const char *hash);

// The adlists as of the last time this node decided what to do about them:
// when it started a rebuild, and when one finished. Comparing against it says
// whether the lists that feed the blocking database moved since
static char built_adlists[CLUSTER_HASHLEN] = "";

static void remember_adlists(void)
{
	char adlists[CLUSTER_HASHLEN] = "";
	if(!cluster_adlist_hash(adlists))
		return;

	memcpy(built_adlists, adlists, sizeof(built_adlists));
}

// Set once the member list stopped naming this node, so it is said once
static bool left_cluster = false;

// Somebody asked this node to leave. Done in the round rather than in the
// request: the other nodes have to be told before clustering stops here, and
// a node that switched itself off first would leave its entry behind on all
// of them
static volatile bool leaving = false;
// ...and set once it has happened. Everything this thread does from here on
// would talk about a cluster this node is no longer in - including the push
// that runs between rounds, which would otherwise hand the peers the empty
// member list this node keeps for itself, moments after telling them the
// right one
static bool left = false;

// Enabled and running are not the same thing: an empty member list, or a
// secret that cannot be read, leaves the switch on and the thread unstarted.
// Everything that reads the switch alone then reports a cluster that is not
// there - and waits for a thread that will never read what it was told
static volatile bool running = false;

bool cluster_running(void)
{
	return running;
}

void cluster_leave(void)
{
	leaving = true;
}

// Leaving on a node whose thread never started. No round has run, so there is
// no peer state and nobody to tell - what is left is the local half of
// do_leave(). DHCP is not touched here: what the cluster never took over,
// leaving it cannot hand back
bool cluster_leave_now(char *errbuf, bool *peers_told)
{
	cluster_sync_lock();

	// Read here rather than before the lock: `replace_config()` swaps the
	// whole tree and frees the old one, this array included
	const bool listed = config.cluster.members.v.json != NULL &&
	                    cJSON_GetArraySize(config.cluster.members.v.json) > 0;
	*peers_told = !listed;

	struct config newconf;
	duplicate_config(&newconf, &config);
	cJSON_Delete(newconf.cluster.members.v.json);
	newconf.cluster.members.v.json = cJSON_CreateArray();
	newconf.cluster.enabled.v.b = false;

	struct config_apply applied = { 0 };
	applied.changed = true;
	// The member list is what DHCP hands out as the resolvers to use
	applied.dnsmasq_changed = true;

	const bool written = config_install(&newconf, &applied, false, 0.0, errbuf);
	cluster_sync_unlock();

	if(!written)
	{
		log_err("cluster: cannot leave the cluster: %s", errbuf);
		return false;
	}

	// No restart: `restart_due()` is the cluster thread's, and there is none
	// here. Nothing needs one either - the thread that would have to be
	// stopped never started
	//
	// ...and the peers were not told, which is worth saying rather than
	// glossing. A thread that never started is not the same as a node with
	// no peers: an unreadable secret leaves the member list exactly where it
	// was, and every node on it still lists this one
	if(listed)
		log_warn("cluster: left the cluster - it was not running here, so the other nodes were not told: remove this node from their member lists");
	else
		log_info("cluster: left the cluster - it was never running here, so there was nobody to tell");

	return true;
}

// The member list without this node, which is what the others should hold
static char *without_us(void)
{
	cJSON *members = cJSON_CreateArray();
	for(unsigned int i = 0; i < num_peers; i++)
		if(!peers[i].is_self && peers[i].url != NULL)
			cJSON_AddItemToArray(members, cJSON_CreateString(peers[i].url));

	cJSON *cluster = cJSON_CreateObject();
	cJSON_AddItemToObject(cluster, "members", members);
	cJSON *conf = cJSON_CreateObject();
	cJSON_AddItemToObject(conf, "cluster", cluster);
	cJSON *document = cJSON_CreateObject();
	cJSON_AddItemToObject(document, "config", conf);

	char *body = cJSON_PrintUnformatted(document);
	cJSON_Delete(document);

	return body;
}

static void do_leave(void)
{
	// Only a node the others actually list has a removal to hand them, and
	// only such a node holds the list they hold - its own entry is in it.
	// A node that is not in its own list would be handing them whatever it
	// happens to have, which is not the cluster's list and not its business
	bool listed = false;
	for(unsigned int i = 0; i < num_peers; i++)
		if(peers[i].is_self)
			listed = true;

	char *body = listed ? without_us() : NULL;
	unsigned int told = 0;
	if(body != NULL)
	{
		const double changed = double_time();
		for(unsigned int i = 0; i < num_peers; i++)
			if(peers[i].reachable && !peers[i].is_self &&
			   cluster_push_config(&peers[i], body, changed))
				told++;
		free(body);
	}

	// Nothing to poll and nothing to answer any more. Written here rather
	// than in the request that asked for it, so the switch cannot be thrown
	// before the others were told
	cluster_sync_lock();
	struct config newconf;
	duplicate_config(&newconf, &config);
	cJSON_Delete(newconf.cluster.members.v.json);
	newconf.cluster.members.v.json = cJSON_CreateArray();
	newconf.cluster.enabled.v.b = false;

	// A node serving DHCP is serving it because the cluster elected it, and
	// the nodes it just handed the shorter member list to will elect somebody
	// else within a round or two. Leaving it switched on here is how one
	// network ends up with two DHCP servers - and this node would keep the
	// virtual IP address with it. Nothing switches it back off afterwards:
	// no round runs on a node that has left.
	//
	// ...but only where somebody can actually pick it up. The last node of a
	// cluster, or one whose remaining peers cannot serve, would otherwise
	// switch the network's only DHCP server off on its way out - and with
	// clustering switched off in the same breath, no round would ever turn it
	// back on. Two servers for a moment is a bad outcome; none at all, until
	// somebody notices by hand, is a worse one
	// Asked of the peers that could actually pick DHCP up, not of the ones
	// that merely take part in failover: a node with no lease range, a
	// read-only configuration or DHCP pinned through its environment says so
	// and is never elected, so handing DHCP to a cluster of those leaves the
	// network with none - and this node, having switched clustering off in
	// the same breath, runs no further round to notice.
	//
	// Of the two ways to be wrong, that one cannot be recovered from without
	// somebody logging in and turning DHCP back on by hand, while the other -
	// a peer that was briefly incapable picking DHCP up later, next to this
	// node still serving it - is visible on the network and says so below
	bool any_capable = false, any_backed_off = false;
	for(unsigned int i = 0; i < num_peers; i++)
	{
		if(peers[i].is_self || !peers[i].reachable || !peers[i].failover)
			continue;

		// Capable now, or merely waiting out a failed takeover: both pick
		// DHCP up. A peer that is not set up to serve at all never will,
		// so handing it DHCP hands it to nobody
		if(peers[i].dhcp_capable)
			any_capable = true;
		// Set up to serve, but waiting out a takeover it already tried
		// and failed. It will try again, so it counts - but if it is the
		// only one, there is a gap first
		else if(peers[i].dhcp_configured)
			any_backed_off = true;
	}

	const bool somebody_takes_over = any_capable || any_backed_off;
	const bool handing_dhcp_back = config.cluster.dhcp.failover.v.b &&
	                               config.dhcp.active.v.b && somebody_takes_over;

	if(config.cluster.dhcp.failover.v.b && config.dhcp.active.v.b && !somebody_takes_over)
	{
		log_warn("cluster: this node keeps serving DHCP - no other node in the cluster is set up to, so handing it over would leave the network without one");

		// The virtual address is the cluster's, and there is about to be
		// no cluster: it is given back when FTL stops, and nothing will
		// place it again. The clients this node hands leases to were told
		// to resolve there, so this is worth saying out loud rather than
		// leaving to be discovered
		char vip[CLUSTER_STRLEN] = "";
		cluster_vip_address(vip);
		if(strlen(vip) > 0 && vip_claimed())
			log_warn("cluster: %s goes with the cluster - the clients this node serves were told to resolve there, so give them another address or set %s on this machine for good",
			         vip, vip);
	}
	if(handing_dhcp_back)
		newconf.dhcp.active.v.b = false;

	if(handing_dhcp_back && !any_capable)
		log_warn("cluster: the node taking DHCP over is waiting out a takeover that already failed, so the network may be without a DHCP server for a while - check that it can serve");

	struct config_apply applied = { 0 };
	applied.changed = true;
	// The member list is what DHCP hands out as the resolvers to use
	applied.dnsmasq_changed = true;

	char errbuf[ERRBUF_SIZE] = "";
	const bool written = config_install(&newconf, &applied, false, 0.0, errbuf);
	cluster_sync_unlock();

	leaving = false;

	// A configuration that could not be written is a node that has not left:
	// it still holds the member list, still lists itself, and a restart here
	// would bring it back into a cluster that has just been told to drop it.
	// Staying is what repairs that - this node's own list names it, so the
	// next round hands the others their entry for it back
	if(!written)
	{
		log_err("cluster: cannot leave the cluster: %s", errbuf);
		return;
	}

	left = true;

	// What this node published about the cluster stops being true the moment
	// it leaves, and the restart that follows is seconds away - long enough
	// for the web interface to draw a cluster that is no longer there
	cluster_lock();
	state.num_peers = 0;
	state.leader[0] = '\0';
	state.dhcp_owner[0] = '\0';
	state.last_round = 0.0;
	cluster_unlock();

	if(listed)
		log_info("cluster: left the cluster, %u of %u nodes told", told,
		         num_peers > 0 ? num_peers - 1 : 0);
	else
		log_info("cluster: left the cluster - none of the members was this node, so there was nobody to tell");

	if(handing_dhcp_back)
		log_info("cluster: DHCP was handed back, another node takes it over");

	cluster_restart_later("cluster: left the cluster");
}


// When a restart a peer's configuration asked for is due, and what to call it
static double restart_at = 0.0;
static const char *restart_reason = NULL;

void cluster_restart_later(const char *reason)
{
	if(restart_at > 0.0)
		return; // one is already waiting

	// Read out of the published snapshot rather than out of the cluster
	// thread's own array: this runs on a webserver thread, and update_peers()
	// rebuilds those entries while it does
	unsigned int slot = 0, members = 1;
	bool holds_vip = false, know_slot = false;
	cluster_lock();
	for(unsigned int i = 0; i < state.num_peers; i++)
		if(state.peers[i].is_self)
		{
			slot = i;
			know_slot = true;
		}
	members = state.num_peers > 0 ? state.num_peers : 1;
	holds_vip = state.vip_held;
	cluster_unlock();

	// Each node takes its own place in the member list, so no two pick the
	// same moment - and whoever the clients are actually talking to goes
	// last, once the others are answering again.
	//
	// A node that has not recognized its own entry yet has no place to take.
	// Falling back on the first one would put it on top of whoever genuinely
	// holds it, and the two would restart together - which is the outage the
	// spacing is here to avoid. It waits behind everybody instead
	const double order = holds_vip ? members : know_slot ? slot : members + 1;
	const double delay = (order + 1) * CLUSTER_RESTART_STAGGER;

	restart_at = double_time() + delay;
	restart_reason = reason;

	log_info("cluster: restarting in %.0f s", delay);
}

// Is that restart due yet? Looked at once per tick
static void restart_due(void)
{
	if(restart_at <= 0.0)
		return;

	// Nothing schedules a restart further ahead than the whole cluster's
	// stagger, so anything beyond that is the wall clock having moved
	// backwards under us - and waiting it out would hold a restart the
	// configuration asked for for as long as the step was.
	//
	// The furthest is a node that has not recognized its own entry, which
	// waits behind every member and behind the one holding the virtual IP -
	// two places past the last slot, not one
	const double ahead = restart_at - double_time();
	if(ahead > (CLUSTER_MAX_PEERS + 2) * CLUSTER_RESTART_STAGGER + 1.0)
	{
		log_info("cluster: clock moved, restarting now");
		restart_at = 0.0;
		restart_ftl(restart_reason != NULL ? restart_reason : "cluster: config synchronized");
		return;
	}

	if(ahead > 0.0)
		return;

	restart_at = 0.0;
	restart_ftl(restart_reason != NULL ? restart_reason : "cluster: config synchronized");
}

// The reachable node with the lowest identity. It decides nothing about the
// content -
// with every node able to publish a change, there is no such thing as a
// configuration master - but the virtual IP address needs an anchor when DHCP
// failover is not what places it
static void elect_leader(void)
{
	char myname[CLUSTER_STRLEN] = "";
	cluster_name(myname);

	// The leader anchors the address the clients resolve at, so a node that
	// answers no DNS is the worst possible one to put it on - whatever its
	// identity says. Skipped only while somebody else can answer: if nobody
	// resolves there is nothing better to choose and the ordinary rule stands,
	// which also keeps a whole cluster restarting at once from having no
	// anchor at all
	bool anybody_resolves = cluster_vip_capable();
	for(unsigned int i = 0; i < num_peers && !anybody_resolves; i++)
		if(peers[i].reachable && !peers[i].is_self &&
		   peers[i].resolving && peers[i].vip_capable)
			anybody_resolves = true;

	// ...and a node that has failed to place the address does not take it off
	// one that is holding it. The capability check catches the reasons it can
	// see; for the rest, re-offering the moment a backoff expires costs the
	// working node the address for as long as it takes this one to fail again,
	// once per backoff, forever
	bool somebody_holds_it = false;
	for(unsigned int i = 0; i < num_peers && !somebody_holds_it; i++)
		if(peers[i].reachable && !peers[i].is_self && peers[i].vip_held)
			somebody_holds_it = true;

	const bool i_qualify = (!anybody_resolves || cluster_vip_capable()) &&
	                       !(somebody_holds_it && cluster_vip_failed_before());
	const char *best_name = myname;
	const char *best_id = cluster_node_id();
	bool have_best = i_qualify;

	int best_idx = -1;

	for(unsigned int i = 0; i < num_peers; i++)
	{
		const struct cluster_peer *peer = &peers[i];
		if(!peer->reachable || peer->is_self)
			continue;

		if(anybody_resolves && !(peer->resolving && peer->vip_capable))
			continue;

		const char *name = strlen(peer->name) > 0 ? peer->name : peer->url;
		if(!have_best || strcmp(peer->id, best_id) < 0)
		{
			best_name = name;
			best_id = peer->id;
			best_idx = (int)i;
			have_best = true;
		}
	}

	if(strcmp(leader, best_name) != 0)
		log_info("cluster: %s leads", best_name);

	strncpy(leader, best_name, CLUSTER_STRLEN - 1);
	leader[CLUSTER_STRLEN - 1] = '\0';
	leader_idx = best_idx;
}

// Whoever holds the newest content wins, no matter which node it was created
// on. Two nodes edited independently since they last agreed is a genuine
// conflict: it is settled by priority so every node settles it the same way,
// and the loser's changes are gone - there is no merging two edits of a
// configuration item that both claim to be the truth
static int elect_gravity_source(void)
{
	double best_changed = sync_state.gravity_changed;
	const char *best_id = cluster_node_id();
	int best_idx = -1;

	for(unsigned int i = 0; i < num_peers; i++)
	{
		struct cluster_peer *peer = &peers[i];
		if(!peer->reachable || !peer->clock_agrees || peer->is_self)
			continue;

		// A node that has not seen its lists change since it joined does
		// not know when they were last touched, and a node that never
		// knew must not win: importing lists replaces them all, so the
		// tie between two nodes that both know nothing has to end in
		// nobody taking anything. Only a node that can say when its
		// lists changed is taken from
		if(peer->gravity_changed <= 0.0)
			continue;

		// A peer we cannot currently pull from is not a candidate: the
		// round would be spent on it and abandoned, while a peer holding
		// the very same lists sits one entry further down
		if(cluster_waiting(peer->retry_lists_at, double_time(), CLUSTER_BACKOFF_MAX))
			continue;
		if(peer->stuck_valid && peer->gravity_changed <= peer->stuck_changed)
			continue;
		if(read_refused(peer))
			continue;

		if(peer->gravity_changed > best_changed ||
		   (!(peer->gravity_changed < best_changed) && best_changed > 0.0 &&
		    strcmp(peer->id, best_id) < 0))
		{
			best_changed = peer->gravity_changed;
			best_id = peer->id;
			best_idx = (int)i;
		}
	}

	return best_idx;
}

// Publish a new version and the content it describes together. The API reads
// both under the state lock, and a reader seeing a new version next to the old
// fingerprint would tell its peers this node holds something it does not
static void publish_gravity_state(const double changed, const char *hash)
{
	// Never dated later than now: a version from the future outranks every
	// list edit anybody makes until wall time reaches it, it is persisted,
	// and every peer copies it from us
	const double now = double_time();

	// Taken while the lock is still held: the writers hold it, and handing
	// cluster_state_save() the live struct would have it copy one somebody
	// is part way through changing - and write that to disk
	struct cluster_sync_state snapshot;
	cluster_lock();
	sync_state.gravity_changed = changed > now ? now : changed;
	strncpy(sync_state.gravity_hash, hash, sizeof(sync_state.gravity_hash) - 1);
	sync_state.gravity_hash[sizeof(sync_state.gravity_hash) - 1] = '\0';
	snapshot = sync_state;
	cluster_unlock();

	cluster_state_save(&snapshot);
}


// A pull that has not finished settling, kept with the rest of the state so a
// restart knows the tables on disk are a peer's rather than a local edit
static void publish_pending_gravity(const double changed, const char *id, const char *hash)
{
	struct cluster_sync_state snapshot;
	cluster_lock();
	sync_state.pending_changed = changed;
	strncpy(sync_state.pending_id, id, sizeof(sync_state.pending_id) - 1);
	sync_state.pending_id[sizeof(sync_state.pending_id) - 1] = '\0';
	strncpy(sync_state.pending_hash, hash, sizeof(sync_state.pending_hash) - 1);
	sync_state.pending_hash[sizeof(sync_state.pending_hash) - 1] = '\0';
	snapshot = sync_state;
	cluster_unlock();

	cluster_state_save(&snapshot);
}

// The fingerprint the peers compare against to decide whether they have to ask
// us for our configuration at all. Published once per round rather than
// computed per request, so a peer polling us never waits for it
static void publish_config_hash(const char *hash)
{
	cluster_lock();
	strncpy(published_confhash, hash, sizeof(published_confhash) - 1);
	published_confhash[sizeof(published_confhash) - 1] = '\0';
	cluster_unlock();
}

// Where this node stands with the lists. Everything about a pull that is not
// finished lives here, so there is one question to ask - "have we built what we
// are about to tell the cluster we hold?" - rather than four flags that can
// disagree with each other
// GRAVITY_PULLING covers the download and the import, which take seconds and
// during which the tables on disk are neither this node's nor yet recorded as
// the peer's. Anything asking what this node holds has to see that
enum gravity_state {
	GRAVITY_IDLE,     // what is on disk is what was built and what we publish
	GRAVITY_PULLING,  // a peer's tables are on their way in
	GRAVITY_OWED,     // a peer's tables are on disk, the rebuild has not started
	GRAVITY_RUNNING   // ...and now it has
};

static enum gravity_state gravity_state = GRAVITY_IDLE;

// A rebuild that failed is owed again rather than forgotten, with a wait that
// grows: an adlist that is down would otherwise mean a gravity run every round
static double gravity_retry_at = 0.0;
static double gravity_backoff = 0.0;

// The version to adopt once the rebuild succeeds, and who it came from
static double pending_gravity = 0.0;
static char pending_gravity_id[CLUSTER_HASHLEN] = "";
static char pending_gravity_hash[CLUSTER_HASHLEN] = "";

// What this node holds, never dated later than the present. A stamp taken while
// the clock was fast would otherwise outrank every change anybody makes until
// wall time catches up, and this node could push to nobody in the meantime
static double our_changed(void)
{
	const double now = double_time();

	// Repaired where it is kept rather than only where it is read: a clock
	// that stepped backwards leaves a stamp from the future behind, and a
	// node that reads it as now for every comparison looks newest for as
	// long as that lasts - taking nothing from anybody in the meantime
	if(config_changed > now)
		config_changed = now;

	return config_changed;
}

// Somebody changed this node: the content no longer matches what we recorded,
// and it was not a synchronization that changed it
static void note_local_changes(void)
{
	char confhash[CLUSTER_HASHLEN] = "", gravityhash[CLUSTER_HASHLEN] = "";
	const bool lists_read = cluster_sync_hashes(confhash, gravityhash);
	publish_config_hash(confhash);

	// A fingerprint we could not read says nothing about whether the lists
	// changed, and dating them to now would have this node outrank a peer
	// holding an edit it has not handed around yet
	// ...and not while a pull is settling: the tables on disk are already the
	// peer's, but the blocking database has not been built from them yet, so
	// calling that a change made here would advertise lists this node does
	// not block and cancel the wait for the rebuild
	const bool settling = gravity_state != GRAVITY_IDLE;

	if(lists_read && !settling && strcmp(gravityhash, sync_state.gravity_hash) != 0)
	{
		// A node that has never recorded anything is not "changed", it is
		// new - it starts at version zero and adopts what the cluster has.
		// Neither is a fingerprint that moved because the build did: a
		// schema migration moves it with nobody having touched a list, and
		// resume_gravity() returns before its own build guard when a rebuild
		// is still owed from before the upgrade. Asked before publishing,
		// which is what settles the question
		const bool first_time = strlen(sync_state.gravity_hash) == 0;
		const bool moved_by_build = !first_time && !cluster_state_same_build();
		const double now = double_time();
		if(moved_by_build)
			log_info("cluster: FTL was upgraded, keeping this node's list version");
		else if(!first_time)
			log_info("cluster: lists changed here");
		publish_gravity_state(first_time || moved_by_build ? sync_state.gravity_changed : now,
		                      gravityhash);

		// The blocking database is built from the adlists, so an allow or
		// deny entry, a group or a client needs nothing further - those
		// take effect as they are written. An adlist that moved does: the
		// domains behind it have to be fetched and written before this node
		// blocks them.
		//
		// A Pi-hole on its own leaves that to whoever runs gravity next.
		// A clustered one cannot: the nodes it just handed these lists to
		// rebuild from them by themselves, so the node the edit was made on
		// would be the only one in the cluster not blocking its own list
		char adlists[CLUSTER_HASHLEN] = "";
		if(!first_time && !moved_by_build && cluster_adlist_hash(adlists) &&
		   strlen(built_adlists) > 0 && strcmp(adlists, built_adlists) != 0)
		{
			remember_adlists();
			owe_gravity(now, cluster_node_id(), gravityhash);

			// ...and written down, like the rebuild a pull owes. A run
			// that fails waits and tries again, and a restart inside that
			// wait would otherwise find nothing owed - leaving this node
			// advertising lists it never built its blocking database from
			publish_pending_gravity(now, cluster_node_id(), gravityhash);
		}
	}

	// Nothing to compare against yet - a node that just started has built
	// whatever is on its disk, whoever put it there
	if(strlen(built_adlists) == 0)
		remember_adlists();
}

// A gravity version we pulled but could not end up matching. Remembered per
// peer so an unrelated node is not skipped along with it

// Take the lists from whichever node holds the newest of them. Unlike the
// configuration, these are not merged: the archive carries whole tables, so
// there is no telling which rows a node added and which ones it removed
// Did the rebuild we are waiting for finish, and did it work?
// The peer the outstanding pull came from, by identity rather than by position:
// cluster.members is synchronized, so an entry added anywhere reshuffles the
// array under us
static struct cluster_peer *pending_source(void)
{
	// Nobody is not somebody: a peer that has not identified itself yet
	// carries an empty identity too, and matching one against the other
	// would hand back an arbitrary stranger as the node these lists came
	// from
	if(strlen(pending_gravity_id) == 0)
		return NULL;

	for(unsigned int i = 0; i < num_peers; i++)
		if(strcmp(peers[i].id, pending_gravity_id) == 0)
			return &peers[i];

	return NULL;
}

// Move the lists on from wherever they are. Called once per round, and the only
// place that leaves GRAVITY_OWED or GRAVITY_RUNNING - so a rebuild that was
// owed cannot be forgotten, and a version cannot be published for tables
// nothing was built from
// A pull that ended. The version goes to disk before the record saying a pull
// is in flight is taken away: with the other order, a crash between the two
// fsyncs leaves the peer's tables on disk with nothing owed and the old version
// recorded, which the next start reads as a list somebody edited here
static void finish_pull(const double changed, const char *hash)
{
	publish_gravity_state(changed, hash);

	// What the run that just finished was built from, so the next round does
	// not read the tables it imported as an edit made here
	remember_adlists();

	cluster_lock();
	pending_gravity = 0.0;
	pending_gravity_id[0] = '\0';
	pending_gravity_hash[0] = '\0';
	cluster_unlock();

	publish_pending_gravity(0.0, "", "");
}

static void settle_gravity(void)
{
	if(gravity_state == GRAVITY_IDLE)
		return;

	// Imported but not yet building. The attempt is repeated every round:
	// what stops it is a rebuild that ran, not a round that passed
	if(gravity_state == GRAVITY_OWED)
	{
		if(cluster_waiting(gravity_retry_at, double_time(), CLUSTER_BACKOFF_MAX))
			return;

		if(!cluster_run_gravity())
			return;

		cluster_lock();
		gravity_state = GRAVITY_RUNNING;
		cluster_unlock();
		return;
	}

	if(cluster_gravity_pending())
		return; // still running

	char confhash[CLUSTER_HASHLEN] = "", gravityhash[CLUSTER_HASHLEN] = "";
	if(!cluster_sync_hashes(confhash, gravityhash))
		return; // decided next round, on a fingerprint we could read

	struct cluster_peer *source = pending_source();
	const double changed = pending_gravity;
	char pending_hash[CLUSTER_HASHLEN] = "";
	strncpy(pending_hash, pending_gravity_hash, sizeof(pending_hash) - 1);

	if(cluster_gravity_succeeded())
	{
		cluster_lock();
		gravity_state = GRAVITY_IDLE;
		cluster_unlock();
		gravity_retry_at = 0.0;
		gravity_backoff = 0.0;

		// Are these still the tables we imported? Compared against what
		// the peer held at the time rather than what it holds now: it
		// moves on while a rebuild runs, and reading that as "somebody
		// edited a list here" would publish its own tables back to it
		// under a newer stamp and undo the edit it just made
		const bool theirs = strlen(pending_hash) == 0 ||
		                    strcmp(gravityhash, pending_hash) == 0;

		// ...and neither the peer's nor different from what this node
		// held before it asked for them means the import never landed at
		// all. FTL stopped between recording the pull and committing it -
		// a crash, but an ordinary restart or upgrade inside that window
		// does it too - and the transaction took the tables back on the
		// way down. Nothing changed here, so nothing here is newer:
		// dating it now publishes this node's own pre-pull lists over the
		// edit it set out to fetch, and no retry recovers it because the
		// stale copy then wins every later comparison
		// ...and a fingerprint written by another build answers a
		// different question than the one being asked. The tables' columns
		// are part of it, so a gravity.db migration moves it with nobody
		// having touched a list - and `resume_gravity()` returns before
		// the build guard on exactly this path, so an interrupted pull
		// whose restart is an upgrade arrives here comparing across it.
		// Nothing here is newer in either case
		const bool unchanged = strcmp(gravityhash, sync_state.gravity_hash) == 0 ||
		                       !cluster_state_same_build();

		finish_pull(theirs ? changed :
		            unchanged ? sync_state.gravity_changed : double_time(),
		            gravityhash);
		if(source != NULL)
			source->stuck_valid = false;
		return;
	}

	// The tables are the peer's but nothing was built from them. The
	// fingerprint has to say what is on disk, under the version we already
	// had - otherwise the next round cannot explain the fingerprint, calls
	// it an edit made here, and dates lists this node never built to now
	publish_gravity_state(sync_state.gravity_changed, gravityhash);

	// Still owed. A blocking database built from lists this node no longer
	// holds is not a state to settle into, and settling into it silently is
	// worse: nothing afterwards can tell it from a node that is in step
	cluster_lock();
	gravity_state = GRAVITY_OWED;
	cluster_unlock();
	gravity_backoff = gravity_backoff > 0.0 ? fmin(gravity_backoff * 2.0, CLUSTER_BACKOFF_MAX) : 60.0;
	gravity_retry_at = double_time() + gravity_backoff;
	log_warn("cluster: lists were taken but not rebuilt, trying again in %.0f s", gravity_backoff);
}

// A rebuild this node has to run before it may say it holds these lists
// Takes the lock: gravity_state is read from the webserver thread as well
static void owe_gravity(const double changed, const char *id, const char *hash)
{
	cluster_lock();
	pending_gravity = changed;
	strncpy(pending_gravity_id, id, sizeof(pending_gravity_id) - 1);
	pending_gravity_id[sizeof(pending_gravity_id) - 1] = '\0';
	strncpy(pending_gravity_hash, hash, sizeof(pending_gravity_hash) - 1);
	pending_gravity_hash[sizeof(pending_gravity_hash) - 1] = '\0';
	gravity_state = GRAVITY_OWED;
	cluster_unlock();
}

// Keep a copy of the serving node's leases, so taking DHCP over does not mean
// starting from an empty file - every client would be offered an address it
// does not hold and every renewal refused
static void take_leases(void)
{
	// The node handing out addresses is the one writing this file; ours is
	// the copy. Reading a peer's over our own would hand our own clients
	// somebody else's addresses.
	//
	// ...and a node that will never take DHCP over has no use for a copy:
	// keeping one would leave a file full of another network's clients on a
	// machine that opted out of serving them
	if(config.dhcp.active.v.b || !config.cluster.dhcp.failover.v.b)
		return;

	char ours[CLUSTER_HASHLEN] = "";
	// A lease file we cannot read at all is one we have never written, and
	// an empty hash never matches - which is exactly the first pull
	cluster_leases_hash(ours);

	for(unsigned int i = 0; i < num_peers; i++)
	{
		struct cluster_peer *peer = &peers[i];
		// Only from the node actually serving: a standby holds a copy of
		// its own, and copying between copies would spread a stale one
		if(!peer->reachable || peer->is_self || !peer->dhcp_active ||
		   !peer->clock_agrees || strlen(peer->leaseshash) == 0 ||
		   strcmp(peer->leaseshash, ours) == 0)
			continue;

		if(read_refused(peer))
			continue;

		// The same wait a failed list download gets: a peer that cannot
		// hand these over is not asked again every round
		if(cluster_waiting(peer->retry_leases_at, double_time(), CLUSTER_BACKOFF_MAX))
			continue;

		uint8_t *data = NULL;
		size_t size = 0;
		char err[CLUSTER_STRLEN] = "";
		bool taken = cluster_http_raw(peer, "/api/cluster/leases", &data, &size,
		                             err, sizeof(err));
		if(taken && size > CLUSTER_MAX_LEASES_SIZE)
		{
			// More than this node would ever publish itself. A peer
			// holding the secret is not an attacker, but it is also not
			// a reason to write an unbounded file to this disk
			log_warn("cluster: leases of %s are %zu bytes, ignoring them",
			         peer->url, size);
			free(data);
			data = NULL;
			taken = false;
			snprintf(err, sizeof(err), "too large");
		}

		// It has to be the file the peer described when we polled it. The
		// fingerprint and the body are two separate reads on that node, so
		// a file caught mid-rewrite would have had to tear identically
		// twice to get this far.
		//
		// It also turns away a file that is merely newer - a lease handed
		// out between the poll and this request moves the file quite
		// legitimately - and that is the right trade either way: no wait is
		// armed here, so the next round asks again with a fresh
		// fingerprint and takes it then. What this node keeps in the
		// meantime is the copy it already had, which is a lease database
		// somebody once served rather than one that was never whole
		if(taken)
		{
			char arrived[CLUSTER_HASHLEN] = "";
			cluster_leases_hash_bytes(data, size, arrived);
			if(strcmp(arrived, peer->leaseshash) != 0)
			{
				log_debug(DEBUG_CLUSTER, "cluster: leases of %s arrived as %s, not the %s it published - asking again",
				          peer->url, arrived, peer->leaseshash);
				free(data);
				return;
			}
		}

		// A download that failed and a file that could not be written are
		// the same to this node: it does not hold the leases, and asking
		// again immediately would repeat whatever went wrong every round
		if(taken)
			taken = cluster_leases_write(data, size);
		free(data);

		if(!taken)
		{
			log_debug(DEBUG_CLUSTER, "cluster: cannot take the leases of %s: %s",
			          peer->url, err);
			peer->leases_backoff = peer->leases_backoff > 0.0 ?
			                       fmin(peer->leases_backoff * 2.0, CLUSTER_BACKOFF_MAX) : 60.0;
			peer->retry_leases_at = double_time() + peer->leases_backoff;
			return;
		}

		log_debug(DEBUG_CLUSTER, "cluster: took the DHCP leases of %s (%zu bytes)",
		          peer->url, size);
		peer->leases_backoff = 0.0;
		peer->retry_leases_at = 0.0;

		// One serving node, so one place to take them from
		return;
	}
}

static void take_gravity(const bool member)
{
	// An in-flight rebuild is finished either way, so this comes first
	settle_gravity();

	// A node the cluster no longer lists is on its own. Taking its lists
	// from the cluster anyway would replace what an administrator curated on
	// it after removing it, wholesale and every time the cluster changes
	if(!member)
		return;

	if(gravity_state != GRAVITY_IDLE)
		return; // last round's pull has not finished settling

	const int src = elect_gravity_source();
	if(src < 0)
		return;

	struct cluster_peer *peer = &peers[src];

	if(strcmp(peer->gravityhash, sync_state.gravity_hash) == 0)
	{
		// Same lists, different idea of when they last changed - take the
		// later one so this stops here. Not while a rebuild is owed: the
		// tables would be the peer's while the blocking database is not,
		// and taking its version makes that indistinguishable from a node
		// that is in step
		if(peer->gravity_changed > sync_state.gravity_changed &&
		   gravity_state == GRAVITY_IDLE)
			publish_gravity_state(peer->gravity_changed, sync_state.gravity_hash);
		return;
	}

	if(peer->stuck_valid && peer->gravity_changed <= peer->stuck_changed)
		return;

	// A download that failed on the way is retried, with a wait that grows
	// so a peer that is having a bad day is not asked ten times a minute.
	// Only a peer whose lists we imported and still do not match is given up
	// on until its version moves
	if(cluster_waiting(peer->retry_lists_at, double_time(), CLUSTER_BACKOFF_MAX))
		return;

	// A node that never knew when its lists changed has nothing to subtract,
	// and neither has one holding a declaration rather than a moment -
	// subtracting that from a real timestamp gives the age of the epoch
	if(sync_state.gravity_changed > CLUSTER_BASELINE_MAX &&
	   peer->gravity_changed > CLUSTER_BASELINE_MAX)
		log_info("cluster: taking lists of %s (%.0f s newer)",
		         peer->url, peer->gravity_changed - sync_state.gravity_changed);
	else
		log_info("cluster: taking lists of %s", peer->url);

	// Written down before the tables are touched, not after. The import
	// replaces and commits seven tables; an interruption between that commit
	// and the bookkeeping would leave a peer's lists on disk with nothing on
	// disk saying so, and the next start reads them as a list edited here -
	// publishes them as the newest in the cluster, and never runs the rebuild
	// they are owed
	cluster_lock();
	gravity_state = GRAVITY_PULLING;
	pending_gravity = peer->gravity_changed;
	strncpy(pending_gravity_id, peer->id, sizeof(pending_gravity_id) - 1);
	pending_gravity_id[sizeof(pending_gravity_id) - 1] = '\0';
	strncpy(pending_gravity_hash, peer->gravityhash, sizeof(pending_gravity_hash) - 1);
	pending_gravity_hash[sizeof(pending_gravity_hash) - 1] = '\0';
	cluster_unlock();
	publish_pending_gravity(pending_gravity, pending_gravity_id, pending_gravity_hash);

	bool rebuilding = false;
	if(!cluster_pull_gravity(peer, sync_state.gravity_hash, &rebuilding))
	{
		// Nothing landed. The import replaces the seven tables inside one
		// transaction, so a failure anywhere in it leaves the tables this
		// node already had - and the download failing never reaches them.
		//
		// Read out of a fingerprint before, which got it backwards exactly
		// when it mattered: a database that is locked or unreadable is what
		// made the import fail, and a fingerprint that cannot be read was
		// taken for a difference. The node then owed a rebuild it did not
		// need, ran gravity over its own untouched tables, found they were
		// not the peer's - and published its own pre-pull lists stamped
		// now, which outranks and undoes the edit it had set out to fetch
		cluster_lock();
		gravity_state = GRAVITY_IDLE;
		pending_gravity = 0.0;
		pending_gravity_id[0] = '\0';
		pending_gravity_hash[0] = '\0';
		cluster_unlock();
		publish_pending_gravity(0.0, "", "");

		// Doubling from one round to at most an hour
		peer->retry_backoff = peer->retry_backoff > 0.0 ?
		                      fmin(peer->retry_backoff * 2.0, CLUSTER_BACKOFF_MAX) : 10.0;
		peer->retry_lists_at = double_time() + peer->retry_backoff;
		return;
	}

	peer->retry_backoff = 0.0;
	peer->retry_lists_at = 0.0;

	// The adlists changed, so a rebuild is owed before this node may say it
	// holds the peer's lists. Whether it can start is settle_gravity()'s
	// business, so it is asked here rather than left to the next round: the
	// blocking database still holds domains under this node's own adlist ids,
	// and the table those ids lived in has just been replaced with the peer's.
	// Where the two do not overlap the node blocks nothing at all until the
	// rebuild lands, and waiting a whole cluster.interval before even starting
	// adds that interval to a gap nobody asked for
	if(rebuilding)
	{
		// Already recorded above, with the peer's fingerprint as it was
		// when we took the tables - it moves on while the rebuild runs,
		// and asking it afterwards answers a different question than
		// "is this still what I imported?"
		cluster_lock();
		gravity_state = GRAVITY_OWED;
		cluster_unlock();
		settle_gravity();
		return;
	}

	char confhash[CLUSTER_HASHLEN] = "", gravityhash[CLUSTER_HASHLEN] = "";
	if(!cluster_sync_hashes(confhash, gravityhash))
	{
		// The peer's tables are on disk and the record written above says
		// so, so this only has to keep the rebuild owed rather than let
		// the next round read them as a list somebody edited here
		cluster_lock();
		gravity_state = GRAVITY_OWED;
		cluster_unlock();
		return;
	}

	// Nothing further is owed, so what is on disk is this node's again
	cluster_lock();
	gravity_state = GRAVITY_IDLE;
	cluster_unlock();

	// Adopt the version we just took over - this content is now theirs, not
	// a change of ours - but only if we really did end up with it
	if(strcmp(gravityhash, peer->gravityhash) == 0)
	{
		finish_pull(peer->gravity_changed, gravityhash);
		peer->stuck_valid = false;
		return;
	}

	log_warn("cluster: lists still differ from %s after synchronizing", peer->url);
	peer->stuck_valid = true;
	peer->stuck_changed = peer->gravity_changed;
	finish_pull(sync_state.gravity_changed, gravityhash);
}

// A restart with a rebuild outstanding leaves the peer's tables on disk and the
// version we had in the state file. Without this the first round reads the
// difference as an edit made here, dates the peer's lists to now, and the
// rebuild that was owed is never run
// A node that joins takes what the cluster holds, its lists included. A cluster
// nobody has ever edited a list on cannot say when its lists were last touched,
// and a node that cannot say that is never taken from - so the moment somebody
// joins, now is when these lists were last touched
void cluster_stamp_lists(void)
{
	// A node in the middle of a pull holds the peer's tables with nothing
	// built from them yet - or nothing built from them at all. Stamping
	// those as this node's own, dated now, makes it the newest holder of
	// lists it never chose. Read under the lock: this runs on a webserver
	// thread while the cluster thread is moving through the states
	cluster_lock();
	const bool known = sync_state.gravity_changed > 0.0;
	const bool settling = gravity_state != GRAVITY_IDLE;
	cluster_unlock();

	if(known || settling)
		return;

	char confhash[CLUSTER_HASHLEN] = "", gravityhash[CLUSTER_HASHLEN] = "";
	if(!cluster_sync_hashes(confhash, gravityhash))
		return;

	// Deliberately not now - see CLUSTER_BASELINE_STAMP. This says "start
	// from these", and a node that comes back holding a real edit has to
	// win against it however long ago that edit was made
	publish_gravity_state(CLUSTER_BASELINE_STAMP, gravityhash);
}

static void resume_gravity(void)
{
	char confhash[CLUSTER_HASHLEN] = "", gravityhash[CLUSTER_HASHLEN] = "";
	if(!cluster_sync_hashes(confhash, gravityhash))
	{
		// A pull that had not finished settling is owed a rebuild
		// whatever the tables read as: forgetting it here would have this
		// node tell the cluster it holds lists it never built
		if(sync_state.pending_changed > 0.0)
		{
			log_warn("cluster: cannot read the lists, rebuilding the interrupted synchronization");
			owe_gravity(sync_state.pending_changed, sync_state.pending_id, sync_state.pending_hash);
		}
		return;
	}

	// Asked before the fingerprints are compared: a rebuild that failed
	// leaves the tables matching what was recorded, so a pull that never
	// finished would look like a node that is in step - and be published as
	// one, with a blocking database built from the lists before it
	if(sync_state.pending_changed > 0.0)
	{
		log_info("cluster: a list synchronization was interrupted, rebuilding");
		owe_gravity(sync_state.pending_changed, sync_state.pending_id, sync_state.pending_hash);
		return;
	}

	if(strlen(sync_state.gravity_hash) == 0 ||
	   strcmp(gravityhash, sync_state.gravity_hash) == 0)
		return;

	// The list fingerprint is taken over the whole of each table, so a
	// release that migrates the database moves it with nobody having touched
	// a list. What is on disk is recorded, under the version this node
	// already had - dating it to now would make an upgraded node the newest
	// holder of lists it was simply handed by its own schema
	if(!cluster_state_same_build())
	{
		log_info("cluster: FTL was upgraded, keeping this node's list version");
		publish_gravity_state(sync_state.gravity_changed, gravityhash);
		return;
	}

	// The tables on disk are not the ones this node last recorded, and no
	// pull was in flight - so somebody edited a list here and FTL stopped
	// before the round that would have recorded it. That is a change made on
	// this node, and dating it to the version we already had would have the
	// cluster hand the old lists back
	const double now = double_time();
	log_info("cluster: lists were changed while this node was down");
	publish_gravity_state(now, gravityhash);

	// ...and dating them to now makes this node the newest holder in the
	// cluster, which is a claim about its blocking database as much as about
	// its tables. Nothing built one from these lists - FTL was not running
	// when they changed - so the rebuild is owed here exactly as it is owed
	// after a pull. Which part of the tables moved cannot be told apart
	// across a restart, so the answer that cannot be wrong is taken
	owe_gravity(now, cluster_node_id(), gravityhash);
	publish_pending_gravity(now, cluster_node_id(), gravityhash);
}

// A node that has never recorded a list version is never taken from, and a
// cluster where that is true of everybody never synchronizes its lists at all -
// which is what a cluster assembled from the command line looks like, since
// nothing there goes through the enrolment that stamps them.
//
// So the moment this node can see that nobody else can say either, it says it
// for them: these lists, as of now. Only then - a node that joined a cluster
// which already holds a version has to keep its zero, or it would arrive as the
// newest holder of lists it was about to be given
static void baseline_lists(void)
{
	cluster_lock();
	const bool known = sync_state.gravity_changed > 0.0;
	cluster_unlock();

	if(known)
		return;

	bool somebody_answers = false;
	for(unsigned int i = 0; i < num_peers; i++)
	{
		if(peers[i].is_self || !peers[i].reachable)
			continue;

		// Somebody holds a version, so it is theirs we converge on
		if(peers[i].gravity_changed > 0.0)
			return;

		somebody_answers = true;
	}

	// On our own there is nothing to converge with, and stamping would only
	// decide a question nobody has asked yet
	if(!somebody_answers)
		return;

	log_info("cluster: no node holds a list version yet, offering this node's as the one to start from");
	cluster_stamp_lists();
}

// ...and the same for the configuration, which has the same hole: a cluster
// built from the command line moves nobody's configuration timestamp, because
// none of the settings that recipe touches is one the cluster hashes, and what
// FTL writes at startup is not a change anybody made. Every node then sits at
// zero, no node is newer than any other, and the settings never converge - the
// manual says they do
static void baseline_config(void)
{
	if(our_changed() > 0.0)
		return;

	bool somebody_answers = false;
	for(unsigned int i = 0; i < num_peers; i++)
	{
		if(peers[i].is_self || !peers[i].reachable)
			continue;

		// Somebody has a version, so it is theirs we converge on
		if(peers[i].config_changed > 0.0)
			return;

		somebody_answers = true;
	}

	if(!somebody_answers)
		return;

	log_info("cluster: no node holds a configuration version yet, offering this node's as the one to start from");
	config_stamp_baseline();
}

// Take the newest configuration and the newest lists, wherever they were made.
// The two travel independently: a configuration change on one node and a list
// change on another both survive
static void sync_round(void)
{
	note_local_changes();

	if(!a_member())
	{
		if(!left_cluster)
			log_warn("cluster: this node is not in the member list, not synchronizing - add the address the others reach it at to cluster.members");
		left_cluster = true;
		return;
	}
	if(left_cluster)
	{
		log_info("cluster: this node is a member again");
		left_cluster = false;
	}

	// After the membership gate, never before it: a node the others do not
	// list is a node whose lists are nobody's baseline, and stamping them
	// here would have it arrive as the newest holder the moment it is added
	baseline_lists();
	baseline_config();

	catch_up();
}

// Copy what the API is allowed to see out of the working peers. This is the
// only place the state lock is taken by the cluster thread, and it holds it
// for a few memcpy()s only
static void publish_state(void)
{
	// Asking the kernel for the address takes long enough that it does not
	// belong inside the lock the API waits on
	char address[CLUSTER_STRLEN] = "";
	cluster_vip_address(address);
	const bool vip_held = strlen(address) > 0 && vip_present(address);

	cluster_lock();

	state.num_peers = num_peers;
	memcpy(state.leader, leader, sizeof(state.leader));
	memcpy(state.dhcp_owner, dhcp_owner, sizeof(state.dhcp_owner));
	state.vip_held = vip_held;
	state.last_round = double_time();

	for(unsigned int i = 0; i < num_peers; i++)
	{
		const struct cluster_peer *peer = &peers[i];
		struct cluster_peer_status *status = &state.peers[i];

		strncpy(status->url, peer->url != NULL ? peer->url : "", sizeof(status->url) - 1);
		status->url[sizeof(status->url) - 1] = '\0';
		memcpy(status->name, peer->name, sizeof(status->name));
		memcpy(status->version, peer->version, sizeof(status->version));
		memcpy(status->branch, peer->branch, sizeof(status->branch));
		memcpy(status->error, peer->error, sizeof(status->error));
		memcpy(status->id, peer->id, sizeof(status->id));
		memcpy(status->confhash, peer->confhash, sizeof(status->confhash));
		memcpy(status->credhash, peer->credhash, sizeof(status->credhash));
		status->accepts_credentials = peer->accepts_credentials;
		status->config_changed = peer->config_changed;
		memcpy(status->gravityhash, peer->gravityhash, sizeof(status->gravityhash));
		status->gravity_owed = peer->gravity_owed;
		memcpy(status->pinned, peer->pinned, sizeof(status->pinned));
		memcpy(status->pinned_credentials, peer->pinned_credentials,
		       sizeof(status->pinned_credentials));
		status->wants_credentials = peer->wants_credentials;
		status->gravity_changed = peer->gravity_changed;
		status->clock_offset = peer->clock_offset;
		status->clock_agrees = peer->clock_agrees;
		status->is_self = peer->is_self;
		status->knows_us = peer->knows_us;
		status->sees = peer->sees;
		memcpy(status->address, peer->address, sizeof(status->address));
		status->last_seen = peer->last_seen;
		status->reachable = peer->reachable;
		status->failover = peer->failover;
		status->dhcp_capable = peer->dhcp_capable;
		status->resolving = peer->resolving;
		status->vip_capable = peer->vip_capable;
		status->dhcp_configured = peer->dhcp_configured;
		status->dhcp_active = peer->dhcp_active;
		status->vip_held = peer->vip_held;
	}

	cluster_unlock();
}

void cluster_local_status(cJSON *node)
{
	char myname[CLUSTER_STRLEN] = "";
	cluster_name(myname);
	cJSON_AddStringToObject(node, "name", myname);
	cJSON_AddStringToObject(node, "id", cluster_node_id());

	// What a peer's TLS connection to this node has to hash to. Published
	// rather than distributed: the answer carrying it is signed with the
	// shared secret, so a certificate is authenticated by what already
	// authenticates everything else - and nobody has a file to copy
	if(strlen(own_pin) > 0)
		cJSON_AddStringToObject(node, "pin", own_pin);
	cJSON_AddStringToObject(node, "version", git_version());
	// Only when it is not what a release is built from: a cluster of stock
	// Pi-holes has nothing to say here, one with a node built from a branch
	// has all the more
	if(strcmp(git_branch(), "master") != 0)
		cJSON_AddStringToObject(node, "branch", git_branch());
	// The nodes decide which of two changes is the newer one by the clock,
	// so they check that they agree on what time it is
	cJSON_AddNumberToObject(node, "time", double_time());

	// Whether this node answers DNS at all. A dnsmasq that did not start
	// leaves FTL up and the cluster thread running, so without this the peers
	// see a node that is reachable, healthy and eligible to anchor the address
	// its clients resolve at - and elect it
	cJSON_AddBoolToObject(node, "resolving", !dnsmasq_failed);
	// ...and whether it would answer on an address the cluster places on it,
	// which BIND mode makes a different question - see cluster_vip_capable()
	cJSON_AddBoolToObject(node, "vip_capable", cluster_vip_capable());

	cJSON *dhcp = cJSON_CreateObject();
	// ...and the same gate as its three neighbours below. A dead dnsmasq hands
	// out no leases whatever the setting says, and a peer reads this one field
	// as "somebody is still serving": it then refuses to take DHCP over and
	// leaves the virtual address on nobody, which for a client is the outage
	// this node giving the address back was supposed to end
	cJSON_AddBoolToObject(dhcp, "active", config.dhcp.active.v.b && !dnsmasq_failed);
	cJSON_AddBoolToObject(dhcp, "failover", config.cluster.dhcp.failover.v.b);
	// The same question this node asks itself before taking over, so a peer
	// never elects a node that would then fail to start a server
	cJSON_AddBoolToObject(dhcp, "capable", cluster_dhcp_capable());
	// ...and whether that is a "not just now" or a "not ever", which is what a
	// node leaving the cluster needs in order to know whether handing DHCP
	// over leaves anybody holding it
	cJSON_AddBoolToObject(dhcp, "configured", cluster_dhcp_configured());
	// What this node's lease file hashes to, so a standby can tell whether
	// its copy is still the one the serving node holds. Only the serving
	// node's is worth anything, which is why it sits inside "dhcp"
	char leaseshash[CLUSTER_HASHLEN] = "";
	if(cluster_leases_hash(leaseshash))
		cJSON_AddStringToObject(dhcp, "leases", leaseshash);
	cJSON_AddItemToObject(node, "dhcp", dhcp);

	// Read under the lock the cluster thread publishes them under, so a peer
	// never sees a version next to a fingerprint it does not belong to
	cluster_lock();
	const bool vip_held = state.vip_held;
	const struct cluster_sync_state published = sync_state;
	char confhash[CLUSTER_HASHLEN] = "";
	memcpy(confhash, published_confhash, sizeof(confhash));
	// Lists were taken from a peer and the rebuild over them has not run.
	// The fingerprint cannot say this: it names the tables on disk, and
	// after a failed rebuild those are exactly the peer's - so a node whose
	// `pihole -g` keeps failing would read as one in step.
	//
	// A rebuild that is running counts too: the tables are already the ones
	// this node published and the blocking database is not, so reporting it as
	// in step for the minutes the run takes says the opposite of the thing
	// this flag exists to say. A pull that has not imported yet does not - the
	// tables there are still this node's own, and consistent with them
	const bool gravity_owed = gravity_state == GRAVITY_OWED ||
	                          gravity_state == GRAVITY_RUNNING;
	cluster_unlock();

	char address[CLUSTER_STRLEN] = "";
	cluster_vip_address(address);

	cJSON *vip = cJSON_CreateObject();
	cJSON_AddStringToObject(vip, "address", address);
	cJSON_AddBoolToObject(vip, "held", vip_held);
	cJSON_AddItemToObject(node, "vip", vip);

	// What the peers compare against to find out who holds the newest
	// content, and whether theirs differs from it
	cJSON *sync = cJSON_CreateObject();
	// What always travels, and the credentials on their own. The second only
	// means anything between two nodes that both accept them, which is why
	// each node says whether it does
	char credhash[CLUSTER_HASHLEN] = "";
	cluster_credentials_hash(credhash);

	cJSON *conf = cJSON_CreateObject();
	cJSON_AddNumberToObject(conf, "changed", our_changed());
	cJSON_AddStringToObject(conf, "hash", confhash);
	cJSON_AddStringToObject(conf, "credentials", credhash);
	cJSON_AddBoolToObject(conf, "accepts_credentials", cluster_credentials_syncable());
	// What was asked for, next to what is happening. The two differ when a
	// member is reached over http, and the difference is the whole answer to
	// "why are the passwords not the same yet"
	cJSON_AddBoolToObject(conf, "wants_credentials", config.cluster.sync.credentials.v.b);
	// Hashed here but unmovable by any push, so a peer differing only in
	// these differs for good. Named so the difference can be acted on
	char pinned[256] = "";
	cluster_pinned_items(false, pinned, sizeof(pinned));
	cJSON_AddStringToObject(conf, "pinned", pinned);
	// ...and the ones in the credential fingerprint, which is compared apart
	// from the rest and so has to be explained apart from it
	char pinned_credentials[256] = "";
	cluster_pinned_items(true, pinned_credentials, sizeof(pinned_credentials));
	cJSON_AddStringToObject(conf, "pinned_credentials", pinned_credentials);
	cJSON_AddItemToObject(sync, "config", conf);
	cJSON *lists = cJSON_CreateObject();
	cJSON_AddNumberToObject(lists, "changed", published.gravity_changed);
	cJSON_AddStringToObject(lists, "hash", published.gravity_hash);
	cJSON_AddBoolToObject(lists, "owed", gravity_owed);
	cJSON_AddItemToObject(sync, "gravity", lists);
	cJSON_AddItemToObject(node, "sync", sync);
}

// Hand this node's configuration to the peers as soon as somebody changes it.
// Almost every tick answers "nothing changed" by comparing two numbers, so this
// costs nothing while the cluster is idle
// Which of two configurations is the one to keep. The node somebody configured
// more recently holds it; two nodes nobody ever configured, or configured in
// the same microsecond, are settled by identity, so both reach the same answer
// and exactly one of them sends
static bool we_are_newer(const struct cluster_peer *peer)
{
	// A node nobody has ever configured holds defaults, and defaults are
	// never worth handing to anybody. Without this a freshly imaged node
	// joining a cluster settles a tie of zero against zero by identity and
	// has an even chance of replacing years of configuration with nothing
	const double ours = our_changed();
	if(ours <= 0.0)
		return false;

	if(ours > peer->config_changed)
		return true;
	if(ours < peer->config_changed)
		return false;

	return strcmp(cluster_node_id(), peer->id) > 0;
}

// A node that was away missed the pushes made while it was gone. Nothing is
// waiting to be sent - neither side changed anything just now - so the
// fingerprints are what says the two are apart, and the time each was last
// configured says which way round it is
// The member list is the same on every node, so one of its entries is this one.
// If none of them turns out to be us - somebody took this node out of the
// cluster, and the removal reached us - we have nothing to say to the others
// any more and must not keep pushing our configuration at them
static bool a_member(void)
{
	// Latched: once every entry has answered and none of them was us, a peer
	// missing a single round afterwards does not put this node back in. It
	// would otherwise flap between member and not, and each flap moves DHCP
	static bool decided = false;

	// Whether this node has ever recognized itself in the member list. Kept
	// across rounds because it is the difference between two situations this
	// node cannot otherwise tell apart: one where the cluster has removed it,
	// and one where it simply cannot reach the address it is listed under
	static bool ever_identified = false;
	static bool warned_unreachable = false;

	bool reached_all = true;
	// ...and whether any entry that does not answer could still be this node:
	// one that has never answered as anybody else
	bool unknown_entry = false;
	unsigned int answered = 0, list_us = 0, sure_not = 0;
	for(unsigned int i = 0; i < num_peers; i++)
	{
		if(peers[i].is_self)
		{
			decided = false;
			ever_identified = true;
			warned_unreachable = false;
			return true;
		}
		if(!peers[i].reachable)
		{
			reached_all = false;
			if(!peers[i].answered_as_other)
				unknown_entry = true;
			continue;
		}

		answered++;
		if(peers[i].knows_us)
			list_us++;
		// ...and only a peer that has not listed this node for several
		// rounds running is evidence of anything. A peer still in its
		// first round publishes no members at all, and one that had this
		// node down for a while publishes its entry with the identity
		// blanked - both of which last a round or two and mean nothing
		else if(peers[i].unknown_warned)
			sure_not++;
	}

	// Every entry answered and none of them was us. Waiting for the one that
	// did not answer is the safe direction while there is still one to wait
	// for, because an entry nobody has polled may be this node under an
	// address it cannot dial just now - and deciding wrongly here switches
	// off a DHCP server the network may be the only one of
	if(reached_all)
		decided = true;

	// ...but the peers themselves say so too, and they say it whether or not
	// every entry answered. A node the cluster removed is absent from every
	// list its former peers publish; a node that simply cannot reach its own
	// entry is still in theirs. That is the difference between waiting and
	// waiting for good.
	//
	// Every answering peer has to have been saying it for several rounds, and
	// one peer listing this node again takes it back: this is the only
	// evidence that does not come from polling our own entry, so it must not
	// turn a node off on the strength of a single round
	if(list_us > 0)
		decided = false;
	else if(answered > 0 && sure_not == answered)
		decided = true;

	// A node that has never once recognized itself in the member list is not
	// entitled to this conclusion. From here the two cases look identical -
	// the cluster removed it, or its own entry names an address nothing can
	// reach - and only one of them is a reason to give DHCP away. Acting on
	// the wrong one costs a restart, and the restart clears the state that
	// would have damped it, so it happens again, and again.
	//
	// Its own address failing is a misconfiguration to be told about, not a
	// membership to resign.
	//
	// Only where an entry that could be this node exists: one that does not
	// answer and has never answered as somebody else. A list every entry of
	// which has answered as another node does not name this node, before and
	// after a restart alike - and the hand-over a removal triggers restarts
	// FTL, which would otherwise turn "removed" into "member" on the same
	// evidence the moment one of those nodes went quiet
	if(decided && !ever_identified && unknown_entry)
	{
		if(!warned_unreachable)
			log_warn("cluster: none of the member addresses answers as this node - check that one of them is this Pi-hole and that it is reachable there");
		warned_unreachable = true;
		return true;
	}

	// Until every entry has answered once, the one that is us may still be
	// among those that have not
	return !decided;
}

static void catch_up(void)
{
	char *body_for_all = NULL;
	double changed = 0.0;
	for(unsigned int i = 0; i < num_peers; i++)
	{
		struct cluster_peer *peer = &peers[i];
		if(!peer->reachable || !peer->clock_agrees || peer->is_self)
			continue;

		if(push_refused(peer))
			continue;

		// The credentials are not part of that fingerprint, because they
		// only converge between two nodes that both accept them - so a
		// peer that was away while the password changed is behind on
		// something the fingerprint cannot see, and is asked here instead
		char ourcreds[CLUSTER_HASHLEN] = "";
		cluster_credentials_hash(ourcreds);
		const bool creds_apart = cluster_credentials_syncable() &&
		                         peer->accepts_credentials &&
		                         strlen(peer->credhash) > 0 &&
		                         strcmp(peer->credhash, ourcreds) != 0;

		if(strcmp(peer->confhash, published_confhash) == 0 && !creds_apart)
			continue;

		// What we know about this peer was gathered before our own
		// configuration last moved - very likely by a push from this very
		// peer. Deciding it is behind on that would have the two hand the
		// same document back and forth once per change
		if(peer->last_seen < our_changed())
			continue;

		// The peer was configured more recently than we were, so it
		// catches us up rather than the other way around
		if(!we_are_newer(peer))
			continue;

		// Items the peer cannot take - one pinned through its
		// environment, one its validators reject - keep the two
		// fingerprints apart for good. Sending the same configuration
		// to the same answer again would repeat that every round,
		// forever. Both sides are remembered: once either of them moves
		// on there is something new to say
		//
		// The credentials are remembered with them. They are not in either
		// fingerprint - that is why creds_apart is computed at all - so
		// without this a password changed while the peer was away is
		// silenced by a latch that armed over an unrelated setting, and
		// nothing retries it: the two never converge and only an unrelated
		// change or a restart here would ever say anything again
		if(strcmp(peer->confhash, peer->pushed_confhash) == 0 &&
		   strcmp(published_confhash, peer->pushed_ourhash) == 0 &&
		   strcmp(ourcreds, peer->pushed_credhash) == 0)
		{
			// ...with one exception: a peer that refused the document
			// outright may not refuse it forever - a node is not
			// read-only for good - so this is a wait rather than a
			// decision, and one that grows
			if(peer->push_backoff <= 0.0 ||
			   cluster_waiting(peer->retry_push_at, double_time(), CLUSTER_PUSH_BACKOFF_MAX))
				continue;
		}
		else
		{
			// Something moved on one of the two sides, so whatever the
			// last attempt ran into is worth trying again at once
			peer->push_backoff = 0.0;
			peer->retry_push_at = 0.0;
		}

		// Built once per encryption class, and only if there is somebody
		// to send it to
		char *body = document_for(&body_for_all, &changed);
		if(body == NULL)
			break;

		if(!cluster_push_config(peer, body, changed))
		{
			// Remembered either way, so the next round can tell "this
			// peer refused what it holds now" from "there is something
			// new to say". A document this peer will never take - one
			// too large for it to read - stops here for good; anything
			// else is tried again after a wait that grows, as a peer
			// that is read-only today may not be tomorrow
			strncpy(peer->pushed_confhash, peer->confhash,
			        sizeof(peer->pushed_confhash) - 1);
			peer->pushed_confhash[sizeof(peer->pushed_confhash) - 1] = '\0';
			strncpy(peer->pushed_ourhash, published_confhash,
			        sizeof(peer->pushed_ourhash) - 1);
			peer->pushed_ourhash[sizeof(peer->pushed_ourhash) - 1] = '\0';
			strncpy(peer->pushed_credhash, ourcreds,
			        sizeof(peer->pushed_credhash) - 1);
			peer->pushed_credhash[sizeof(peer->pushed_credhash) - 1] = '\0';

			if(cluster_push_possible(body))
			{
				if(peer->push_backoff <= 0.0)
					log_info("cluster: %s did not take the configuration, trying again later",
					         strlen(peer->name) > 0 ? peer->name : peer->url);
				peer->push_backoff = peer->push_backoff > 0.0 ?
				                     fmin(peer->push_backoff * 2.0, CLUSTER_PUSH_BACKOFF_MAX) : 10.0;
				peer->retry_push_at = double_time() + peer->push_backoff;
			}
			continue;
		}

		// Remembered only after it worked: a push also fails for
		// passing reasons, and remembering those would stop us from
		// ever catching this peer up
		strncpy(peer->pushed_confhash, peer->confhash, sizeof(peer->pushed_confhash) - 1);
		peer->pushed_confhash[sizeof(peer->pushed_confhash) - 1] = '\0';
		strncpy(peer->pushed_ourhash, published_confhash, sizeof(peer->pushed_ourhash) - 1);
		peer->pushed_ourhash[sizeof(peer->pushed_ourhash) - 1] = '\0';
		strncpy(peer->pushed_credhash, ourcreds, sizeof(peer->pushed_credhash) - 1);
		peer->pushed_credhash[sizeof(peer->pushed_credhash) - 1] = '\0';
		peer->pushed_generation = config_generation;
		peer->push_backoff = 0.0;
		peer->retry_push_at = 0.0;

		log_info("cluster: caught %s up", strlen(peer->name) > 0 ? peer->name : peer->url);
	}

	if(body_for_all != NULL)
		free(body_for_all);
}

static void push_round(void)
{
	if(left)
		return;

	const unsigned long generation = config_generation;
	if(generation == pushed_generation)
		return;

	// What this node holds has just changed, so what it tells its peers it
	// holds changes with it. Published here rather than at the next round:
	// a peer polling us in between would be told the value from before, and
	// would set out to correct a node that is already ahead of it
	char nowhash[CLUSTER_HASHLEN] = "";
	cluster_config_hash(nowhash);
	publish_config_hash(nowhash);

	// Somebody took this node out of the cluster. Handing our configuration
	// to nodes that no longer list us would put us back in through the door
	// they closed
	if(!a_member())
	{
		pushed_generation = generation;
		return;
	}

	// One document for every peer, and one timestamp with it. Building it per
	// peer would let a change made while this loop runs reach the later ones
	// and not the earlier
	char *body_for_all = NULL;
	double changed = 0.0;

	unsigned int handed = 0;
	for(unsigned int i = 0; i < num_peers; i++)
	{
		struct cluster_peer *peer = &peers[i];
		if(!peer->reachable || !peer->clock_agrees || peer->is_self)
			continue;

		if(push_refused(peer))
			continue;

		// The peer we just took this from already has it
		if(peer->pushed_generation == generation)
			continue;

		// ...and a peer holding a configuration newer than ours is not
		// ours to correct. Without this a node that changed something the
		// cluster does not synchronize - or one that has never been
		// configured at all - hands its own values to everybody
		if(!we_are_newer(peer))
			continue;

		char *body = document_for(&body_for_all, &changed);
		if(body == NULL)
			break;

		if(cluster_push_config(peer, body, changed))
		{
			peer->pushed_generation = generation;
			handed++;
		}
		else if(!cluster_push_possible(body))
		{
			// Too large for this peer to read, and it will be just as
			// large next round. Counted as handed over so the tick
			// stops trying; the fingerprints stay apart and the catch-
			// up path reports it once per change
			peer->pushed_generation = generation;
		}
	}

	if(body_for_all != NULL)
		free(body_for_all);

	// Only when every peer has it: one that was unreachable has to be
	// handed the change when it comes back, and the round below does that
	// through the fingerprint comparison anyway
	pushed_generation = generation;

	if(handed > 0)
		log_debug(DEBUG_CLUSTER, "cluster: handed config to %u node%s",
		          handed, handed == 1 ? "" : "s");
}

static void cluster_round(void)
{
	// Nothing to poll, nobody to tell, and a restart on its way
	if(left)
		return;

	// Before anything is published: a renewed certificate has to reach the
	// peers in the same round the web server starts serving it
	refresh_own_pin();
	refresh_config_facts();

	update_peers();

	// Every entry, including the one that turned out to be this node: what
	// that costs is one request per round, and it means a single answer -
	// one of ours handed back to us by somebody on the path - cannot take a
	// live peer out of the cluster for good
	for(unsigned int i = 0; i < num_peers; i++)
		poll_peer(&peers[i]);

	elect_leader();

	// Asked while the peers were being polled, so their reachability is as
	// fresh as it gets - and nothing below matters to a node that is going
	if(leaving)
	{
		do_leave();
		return;
	}

	// The configuration first: it is a request and an answer, and it decides
	// nothing about who runs DHCP
	sync_round();

	// Who serves DHCP, and where the address the clients use belongs - one
	// decision, so the two can never contradict each other
	const bool member = a_member();

	// ...and the leases of whoever is handing out addresses, so this node
	// could take over from it right now. Only while it is a member: a node
	// the cluster removed is not going to be asked to serve, and taking a
	// cluster's leases after being told to go is how a machine ends up
	// holding a lease database it will never be allowed to hand out
	if(member)
		take_leases();

	struct cluster_intent intent = { { 0 }, false, false, false };
	cluster_dhcp_round(peers, num_peers, member, leader_idx < 0, &intent);

	// The address is placed before DHCP changes hands: handing over takes
	// FTL down with it, and the address would otherwise be left wherever it
	// happened to be until this node has restarted
	cluster_vip_round(intent.hold_vip);

	cluster_dhcp_apply(&intent);

	strncpy(dhcp_owner, intent.owner, sizeof(dhcp_owner) - 1);
	dhcp_owner[sizeof(dhcp_owner) - 1] = '\0';

	// Handing DHCP over replaces the configuration and takes FTL down with
	// it - anything below this would race that
	if(cluster_dhcp_restarting())
		return;

	publish_state();

	// Last, because it is a whole database rather than an answer to a
	// question: a peer taking its time over it would otherwise hold this
	// thread while a DHCP server was waiting to be handed over
	take_gravity(member);
}

static void *run_cluster_thread(void *val)
{
	(void)val;

	prctl(PR_SET_NAME, thread_names[CLUSTER], 0, 0, 0);

	if(!cluster_http_init())
		return NULL;

	cluster_state_load(&sync_state);
	resume_gravity();

	// A node that wants to join has no cluster to ask, so the members say
	// where they are themselves. Only bound while this thread runs
	cluster_beacon_open();

	char myname[CLUSTER_STRLEN] = "";
	cluster_name(myname);

	log_info("cluster: this node is \"%s\" (id %s)", myname, cluster_node_id());

	// Told to the peers so they can recognize this node's TLS connection.
	// Without one they cannot, and an https:// cluster falls back to the
	// signature alone - which keeps anybody from changing what travels, but
	// not from reading it
	if(!refresh_own_pin())
		log_info("cluster: no certificate in %s to identify this node with",
		         config.webserver.tls.cert.v.s);

	// dnsmasq binds the addresses it finds at start-up in this mode, so an
	// address that arrives later is not one it answers on
	if(strlen(config.cluster.vip.address.v.s) > 0 &&
	   config.dns.listeningMode.v.listeningMode == LISTEN_BIND)
		log_warn("cluster: dns.listeningMode is BIND, DNS will not answer on %s",
		         config.cluster.vip.address.v.s);

	// Two cadences: the tick looks at a counter and hands a change to the
	// peers the moment somebody makes one, the round polls them and cleans
	// up after whatever the pushes missed
	double next_round = 0.0;
	while(!killed)
	{
		// Clamped rather than trusted: pihole.toml is a file somebody can
		// edit, and a zero would spin
		const unsigned int interval =
			config.cluster.interval.v.ui < 1 ? 10 :
			config.cluster.interval.v.ui > CLUSTER_MAX_INTERVAL ?
			(unsigned int)CLUSTER_MAX_INTERVAL : config.cluster.interval.v.ui;

		if(double_time() >= next_round)
		{
			cluster_round();
			next_round = double_time() + interval;
		}
		else if(next_round - double_time() > (double)interval + 1.0)
		{
			// Nothing schedules a round further ahead than one interval,
			// so the clock moved backwards under us. Rounds would stop
			// for as long as the step was, taking DHCP failover with them
			log_info("cluster: clock moved, running the next round now");
			next_round = 0.0;
		}
		else
			push_round();

		// A gravity run started after a list synchronization takes
		// minutes, so it is watched from here rather than waited for
		cluster_gravity_check();

		restart_due();
		cluster_beacon_poll();

		thread_sleepms(CLUSTER, CLUSTER_TICK_MS);
	}


	cluster_beacon_close();

	for(unsigned int i = 0; i < CLUSTER_MAX_PEERS; i++)
		if(peers[i].url != NULL)
			free_peer(&peers[i]);
	num_peers = 0;

	cluster_lock();
	state.num_peers = 0;
	cluster_unlock();

	log_info("cluster: terminating");

	return NULL;
}

// Cleared where the thread ends rather than before each `return`: one of those
// returns is `cluster_http_init()` failing, and a flag left standing there says
// a cluster is running on a node that has none - and sends everything that asks
// to the thread that is not there
static void *cluster_thread(void *val)
{
	void *ret = run_cluster_thread(val);
	running = false;
	return ret;
}

bool cluster_start_thread(pthread_attr_t *attr)
{
	if(!config.cluster.enabled.v.b)
		return false;

	// All nodes share one secret. FTL creates it if this node does not have
	// one yet, the administrator copies that file to the other nodes. Done
	// before the member list is looked at: the file is what the
	// administrator needs in order to fill that list in
	if(!create_cluster_secret())
	{
		log_err("cluster: no secret in %s, not starting", CLUSTER_SECRET_FILE);
		return false;
	}

	if(config.cluster.members.v.json == NULL ||
	   cJSON_GetArraySize(config.cluster.members.v.json) == 0)
	{
		log_warn("cluster: enabled but no members configured, not starting");
		return false;
	}

	running = true;
	if(pthread_create(&threads[CLUSTER], attr, cluster_thread, NULL) != 0)
	{
		running = false;
		log_err("Unable to create cluster thread");
		return false;
	}

	return true;
}
