/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/cluster
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// config struct
#include "config/config.h"
// cluster state
#include "cluster/cluster.h"

int api_cluster_status(struct ftl_conn *api)
{
	// Copied out under the lock and rendered without it: every JSON_* macro
	// below returns from this function on an allocation failure, which would
	// leave the lock held and wedge the cluster thread with it
	struct cluster_state state = { 0 };
	cluster_lock();
	memcpy(&state, cluster_state(), sizeof(state));
	cluster_unlock();

	cJSON *node = JSON_NEW_OBJECT();
	cJSON *peers = JSON_NEW_ARRAY();

	// This node. Peers poll exactly this object, so it has to be complete
	// even when the cluster thread never ran (clustering disabled)
	cluster_local_status(node);

	for(unsigned int i = 0; i < state.num_peers; i++)
	{
		const struct cluster_peer_status *peer = &state.peers[i];
		cJSON *item = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(item, "url", peer->url);
		JSON_COPY_STR_TO_OBJECT(item, "name", peer->name);
		JSON_COPY_STR_TO_OBJECT(item, "id", peer->id);
		JSON_COPY_STR_TO_OBJECT(item, "version", peer->version);
		JSON_ADD_NUMBER_TO_OBJECT(item, "priority", peer->priority);
		JSON_ADD_BOOL_TO_OBJECT(item, "reachable", peer->reachable);
		if(peer->last_seen > 0.0)
			JSON_ADD_NUMBER_TO_OBJECT(item, "last_seen", peer->last_seen);
		else
			JSON_ADD_NULL_TO_OBJECT(item, "last_seen");
		if(strlen(peer->error) > 0)
			JSON_COPY_STR_TO_OBJECT(item, "error", peer->error);
		else
			JSON_ADD_NULL_TO_OBJECT(item, "error");

		cJSON *dhcp = JSON_NEW_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(dhcp, "active", peer->dhcp_active);
		JSON_ADD_BOOL_TO_OBJECT(dhcp, "failover", peer->failover);
		JSON_ADD_BOOL_TO_OBJECT(dhcp, "capable", peer->dhcp_capable);
		JSON_ADD_ITEM_TO_OBJECT(item, "dhcp", dhcp);

		cJSON *vip = JSON_NEW_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(vip, "held", peer->vip_held);
		JSON_ADD_ITEM_TO_OBJECT(item, "vip", vip);

		JSON_ADD_ITEM_TO_ARRAY(peers, item);
	}

	cJSON *cluster = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(cluster, "enabled", config.cluster.enabled.v.b);
	JSON_COPY_STR_TO_OBJECT(cluster, "leader", state.leader);
	JSON_COPY_STR_TO_OBJECT(cluster, "dhcp_owner", state.dhcp_owner);
	if(state.last_round > 0.0)
		JSON_ADD_NUMBER_TO_OBJECT(cluster, "last_round", state.last_round);
	else
		JSON_ADD_NULL_TO_OBJECT(cluster, "last_round");
	JSON_ADD_ITEM_TO_OBJECT(cluster, "node", node);
	JSON_ADD_ITEM_TO_OBJECT(cluster, "peers", peers);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "cluster", cluster);
	JSON_SEND_OBJECT(json);
}

