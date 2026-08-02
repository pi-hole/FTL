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
#include "cluster/dhcp.h"
#include "cluster/vip.h"
#include "version.h"
// create_cluster_secret()
#include "config/password.h"
// thread_names, thread_sleepms
#include "signals.h"
// prctl()
#include <sys/prctl.h>
// isprint(), isalnum()
#include <ctype.h>
// generate_password()
#include "config/password.h"
#include <fcntl.h>
#include <sys/stat.h>
// lock_shm()
#include "shmem.h"

// The peers the cluster thread works with. They own memory and a libcurl
// handle and are touched by that thread only, which is why no lock is taken
// while talking to a peer: holding one across network I/O would stall every
// peer polling us in return
static struct cluster_peer peers[CLUSTER_MAX_PEERS] = { 0 };
static unsigned int num_peers = 0;

// The snapshot the API threads read
// Where this node's identity lives. Names are what an administrator reads, and
// they collide - two Pi-holes imaged from the same card are both "raspberrypi" -
// so an election that has to pick one of two nodes picks by this instead
#define CLUSTER_STATE_FILE "/etc/pihole/cluster.state"
static char node_id[17] = "";

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

const char *cluster_node_id(void)
{
	return node_id;
}

// Read this node's identity, generating one if it does not have any yet
static void cluster_id_load(void)
{
	FILE *file = fopen(CLUSTER_STATE_FILE, "r");
	if(file != NULL)
	{
		char line[64] = "";
		while(fgets(line, sizeof(line), file) != NULL)
			if(sscanf(line, "node %16s", node_id) == 1)
				break;
		fclose(file);
	}

	if(strlen(node_id) > 0)
		return;

	// Random rather than derived from anything: two Pi-holes imaged from the
	// same card share their name, their MAC prefix and their machine ID, and
	// two nodes with one identity cannot elect
	char *generated = NULL;
	if(generate_password(&generated, NULL) && generated != NULL)
	{
		for(unsigned int i = 0; i < sizeof(node_id) - 1 && generated[i] != '\0'; i++)
			node_id[i] = isalnum((unsigned char)generated[i]) ? generated[i] : 'x';
		node_id[sizeof(node_id) - 1] = '\0';
	}
	if(generated != NULL)
		free(generated);

	if(strlen(node_id) == 0)
	{
		strncpy(node_id, "unidentified", sizeof(node_id) - 1);
		log_warn("Cluster: Unable to generate an identity for this node");
		return;
	}

	const int fd = open(CLUSTER_STATE_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
	                    S_IRUSR | S_IWUSR | S_IRGRP);
	if(fd < 0)
	{
		log_err("Cluster: Unable to write %s: %s", CLUSTER_STATE_FILE, strerror(errno));
		return;
	}

	FILE *out = fdopen(fd, "w");
	if(out == NULL)
	{
		log_err("Cluster: Unable to write %s: %s", CLUSTER_STATE_FILE, strerror(errno));
		close(fd);
		return;
	}

	fprintf(out, "node %s\n", node_id);
	if(fclose(out) != 0)
		log_err("Cluster: Unable to write %s: %s", CLUSTER_STATE_FILE, strerror(errno));

	log_info("Cluster: This node identifies itself as %s", node_id);
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
	if(peer->sid != NULL)
		free(peer->sid);
	memset(peer, 0, sizeof(*peer));
}

// Rebuild the peer array from the configuration. Called before every round so
// changes to cluster.peers take effect without restarting FTL. Peers that did
// not change keep their session and connection
static void update_peers(void)
{
	// The configured list is walked under the lock and copied out: another
	// thread replacing the configuration frees these cJSON nodes, and
	// everything below this point does I/O we must not hold a lock across
	char urls[CLUSTER_MAX_PEERS][CLUSTER_URLLEN] = { { 0 } };
	unsigned int num_urls = 0, num = 0;

	lock_shm();
	cJSON *conf_peers = config.cluster.peers.v.json;
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

	if(num > CLUSTER_MAX_PEERS)
		log_warn("Cluster: Only the first %d of %u configured peers are used",
		         CLUSTER_MAX_PEERS, num);
}

// Read one string/number/bool out of a nested status document
static const cJSON *status_item(const cJSON *json, const char *object, const char *key)
{
	const cJSON *obj = cJSON_GetObjectItem(json, object);
	if(obj == NULL)
		return NULL;

	return cJSON_GetObjectItem(obj, key);
}

static void mark_unreachable(struct cluster_peer *peer, const char *err)
{
	if(peer->reachable || peer->rounds_down == 0)
		log_info("Cluster: Peer %s is unreachable (%s)", peer->url, err);

	peer->reachable = false;
	peer->rounds_up = 0;
	peer->rounds_down++;
	peer->dhcp_active = false;
	peer->dhcp_capable = false;
	peer->vip_held = false;
	strncpy(peer->error, err, sizeof(peer->error) - 1);
	peer->error[sizeof(peer->error) - 1] = '\0';
}

// Ask one peer how it is doing. This is the only request made per peer and
// round: everything we need to know is in the answer
static void poll_peer(struct cluster_peer *peer)
{
	cJSON *json = NULL;
	char err[CLUSTER_STRLEN] = "";

	if(!cluster_http_json(peer, "/api/cluster/status", &json, err, sizeof(err)))
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

	const cJSON *version = cJSON_GetObjectItem(node, "version");
	if(cJSON_IsString(version))
	{
		strncpy(peer->version, version->valuestring, sizeof(peer->version) - 1);
		peer->version[sizeof(peer->version) - 1] = '\0';
	}

	const cJSON *id = cJSON_GetObjectItem(node, "id");
	if(cJSON_IsString(id))
	{
		strncpy(peer->id, id->valuestring, sizeof(peer->id) - 1);
		peer->id[sizeof(peer->id) - 1] = '\0';

		// One identity on two nodes means neither can win an election
		// against the other - they would both reach the same verdict
		if(strcmp(peer->id, cluster_node_id()) == 0)
			log_warn("Cluster: %s reports the same identity as this node - was %s copied between them?",
			         peer->url, CLUSTER_STATE_FILE);
	}

	const cJSON *priority = cJSON_GetObjectItem(node, "priority");
	if(cJSON_IsNumber(priority))
		peer->priority = (unsigned int)priority->valuedouble;

	const cJSON *dhcp_active = status_item(node, "dhcp", "active");
	peer->dhcp_active = cJSON_IsTrue(dhcp_active);
	const cJSON *failover = status_item(node, "dhcp", "failover");
	peer->failover = cJSON_IsTrue(failover);
	const cJSON *capable = status_item(node, "dhcp", "capable");
	peer->dhcp_capable = cJSON_IsTrue(capable);
	const cJSON *vip_held = status_item(node, "vip", "held");
	peer->vip_held = cJSON_IsTrue(vip_held);

	cJSON_Delete(json);

	if(!peer->reachable)
		log_info("Cluster: Peer %s (%s) is reachable", peer->url,
		         strlen(peer->name) > 0 ? peer->name : "unnamed");

	peer->reachable = true;
	peer->rounds_down = 0;
	peer->rounds_up++;
	peer->last_seen = double_time();
	peer->error[0] = '\0';
}

// The reachable node with the lowest priority. Ties are broken by name so every
// node picks the same one
static char leader[CLUSTER_STRLEN] = "";
// Index of that node, or -1 if it is this one
static int leader_idx = -1;
static char dhcp_owner[CLUSTER_STRLEN] = "";


// The highest-priority reachable node. It decides nothing about the content -
// with every node able to publish a change, there is no such thing as a
// configuration master - but the virtual IP address needs an anchor when DHCP
// failover is not what places it
static void elect_leader(void)
{
	char myname[CLUSTER_STRLEN] = "";
	cluster_name(myname);
	const char *best_name = myname;
	const char *best_id = cluster_node_id();
	unsigned int best_priority = config.cluster.priority.v.ui;
	int best_idx = -1;

	for(unsigned int i = 0; i < num_peers; i++)
	{
		const struct cluster_peer *peer = &peers[i];
		if(!peer->reachable)
			continue;

		const char *name = strlen(peer->name) > 0 ? peer->name : peer->url;
		if(peer->priority < best_priority ||
		   (peer->priority == best_priority && strcmp(peer->id, best_id) < 0))
		{
			best_priority = peer->priority;
			best_name = name;
			best_id = peer->id;
			best_idx = (int)i;
		}
	}

	if(strcmp(leader, best_name) != 0)
		log_info("Cluster: %s is the highest-priority reachable node", best_name);

	strncpy(leader, best_name, CLUSTER_STRLEN - 1);
	leader[CLUSTER_STRLEN - 1] = '\0';
	leader_idx = best_idx;
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

	state.enabled = true;
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
		memcpy(status->error, peer->error, sizeof(status->error));
		memcpy(status->id, peer->id, sizeof(status->id));
		status->priority = peer->priority;
		status->last_seen = peer->last_seen;
		status->reachable = peer->reachable;
		status->failover = peer->failover;
		status->dhcp_capable = peer->dhcp_capable;
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
	cJSON_AddNumberToObject(node, "priority", config.cluster.priority.v.ui);
	cJSON_AddStringToObject(node, "version", git_version());

	cJSON *dhcp = cJSON_CreateObject();
	cJSON_AddBoolToObject(dhcp, "active", config.dhcp.active.v.b);
	cJSON_AddBoolToObject(dhcp, "failover", config.cluster.dhcp.failover.v.b);
	// Without a lease range this node cannot take DHCP over, and a peer
	// electing it anyway would leave the network without a server
	cJSON_AddBoolToObject(dhcp, "capable", config.dhcp.start.v.in_addr.s_addr != 0 &&
	                                       config.dhcp.end.v.in_addr.s_addr != 0);
	cJSON_AddItemToObject(node, "dhcp", dhcp);

	char address[CLUSTER_STRLEN] = "";
	cluster_vip_address(address);

	cluster_lock();
	const bool vip_held = state.vip_held;
	cluster_unlock();

	cJSON *vip = cJSON_CreateObject();
	cJSON_AddStringToObject(vip, "address", address);
	cJSON_AddBoolToObject(vip, "held", vip_held);
	cJSON_AddItemToObject(node, "vip", vip);

}

static void cluster_round(void)
{
	update_peers();

	for(unsigned int i = 0; i < num_peers; i++)
		poll_peer(&peers[i]);

	elect_leader();

	// Who serves DHCP, and who do the clients talk to?
	char owner[CLUSTER_STRLEN] = "";
	const bool dhcp_mine = cluster_dhcp_round(peers, num_peers, owner);

	// Handing DHCP over replaces the configuration and takes FTL down with
	// it - reading the configuration again here would race that
	if(cluster_dhcp_restarting())
		return;

	// The virtual IP address follows the DHCP server where there is one, and
	// the highest-priority reachable node otherwise - including the case
	// where failover is enabled but no node has a lease range to serve from,
	// as nobody would hold the address then
	const bool dhcp_decides = config.cluster.dhcp.failover.v.b &&
	                          cluster_dhcp_available(peers, num_peers);
	const bool vip_mine = dhcp_decides ? dhcp_mine : leader_idx < 0;
	cluster_vip_round(vip_mine);

	strncpy(dhcp_owner, owner, sizeof(dhcp_owner) - 1);
	dhcp_owner[sizeof(dhcp_owner) - 1] = '\0';

	publish_state();
}

static void *cluster_thread(void *val)
{
	(void)val;

	prctl(PR_SET_NAME, thread_names[CLUSTER], 0, 0, 0);

	if(!cluster_http_init())
		return NULL;

	cluster_id_load();

	char myname[CLUSTER_STRLEN] = "";
	cluster_name(myname);

	log_info("Cluster: This node is \"%s\" with priority %u",
	         myname, config.cluster.priority.v.ui);

	if(config.cluster.timeout.v.ui == 0)
		log_warn("Cluster: cluster.timeout is zero, which lets a single unresponsive peer "
		         "stop the cluster - a request without a timeout never returns");

	if(!config.cluster.tls.verify.v.b)
		log_warn("Cluster: TLS certificates of the peers are not verified. Anybody able to "
		         "answer for a peer receives the cluster secret and can hand this node a "
		         "configuration of their choosing - see cluster.tls.ca");

	while(!killed)
	{
		cluster_round();

		// A zero interval would spin, so treat it as "use the default"
		const unsigned int interval = config.cluster.interval.v.ui > 0 ?
		                              config.cluster.interval.v.ui : 10;
		thread_sleepms(CLUSTER, 1000 * (int)interval);
	}


	for(unsigned int i = 0; i < CLUSTER_MAX_PEERS; i++)
		if(peers[i].url != NULL)
			free_peer(&peers[i]);
	num_peers = 0;

	cluster_lock();
	state.num_peers = 0;
	cluster_unlock();

	log_info("Cluster: Terminating");

	return NULL;
}

bool cluster_start_thread(pthread_attr_t *attr)
{
	if(!config.cluster.enabled.v.b)
		return false;

	if(config.cluster.peers.v.json == NULL ||
	   cJSON_GetArraySize(config.cluster.peers.v.json) == 0)
	{
		log_warn("Cluster is enabled but no peers are configured, not starting");
		return false;
	}

	// All nodes share one secret. FTL creates it if this node does not have
	// one yet, the administrator copies that file to the other nodes
	if(!create_cluster_secret())
	{
		log_err("Cluster: Unable to read or create the cluster secret, not starting");
		return false;
	}

	if(pthread_create(&threads[CLUSTER], attr, cluster_thread, NULL) != 0)
	{
		log_err("Unable to create cluster thread");
		return false;
	}

	return true;
}
