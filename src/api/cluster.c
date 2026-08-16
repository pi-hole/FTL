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
// cluster_config_document()
#include "cluster/sync.h"
// generate_cluster_zip()
#include "zip/teleporter.h"
// lock_shm()
#include "shmem.h"
// cluster_secret(), adopt_cluster_secret()
#include "config/password.h"
// cluster_http_bootstrap()
#include "cluster/http.h"
// cluster_discover()
#include "cluster/discover.h"
// ERRBUF_SIZE
#include "config/dnsmasq_config.h"

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
		JSON_COPY_STR_TO_OBJECT(item, "branch", peer->branch);
		JSON_ADD_BOOL_TO_OBJECT(item, "reachable", peer->reachable);
		// The member list is the same on every node, so one entry is this
		// node - it is listed for completeness and otherwise left alone
		JSON_ADD_BOOL_TO_OBJECT(item, "self", peer->is_self);
		JSON_ADD_BOOL_TO_OBJECT(item, "knows_us", peer->knows_us);
		JSON_COPY_STR_TO_OBJECT(item, "address", peer->address);
		// Every node polls every other one, so reachability is not one
		// list but a matrix. This is the row this member reports
		cJSON *sees = JSON_NEW_ARRAY();
		for(unsigned int k = 0; k < state.num_peers && k < CLUSTER_MAX_PEERS; k++)
			if(peer->sees & (1U << k))
				JSON_COPY_STR_TO_ARRAY(sees, state.peers[k].id);
		JSON_ADD_ITEM_TO_OBJECT(item, "sees", sees);
		cJSON *clock = JSON_NEW_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(clock, "agrees", peer->clock_agrees);
		JSON_ADD_NUMBER_TO_OBJECT(clock, "offset", peer->clock_offset);
		JSON_ADD_ITEM_TO_OBJECT(item, "clock", clock);
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
		JSON_ADD_BOOL_TO_OBJECT(dhcp, "configured", peer->dhcp_configured);
		JSON_ADD_ITEM_TO_OBJECT(item, "dhcp", dhcp);

		cJSON *vip = JSON_NEW_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(vip, "held", peer->vip_held);
		JSON_ADD_ITEM_TO_OBJECT(item, "vip", vip);

		cJSON *sync = JSON_NEW_OBJECT();
		cJSON *peerconf = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(peerconf, "changed", peer->config_changed);
		JSON_COPY_STR_TO_OBJECT(peerconf, "hash", peer->confhash);
		JSON_COPY_STR_TO_OBJECT(peerconf, "credentials", peer->credhash);
		JSON_ADD_BOOL_TO_OBJECT(peerconf, "accepts_credentials", peer->accepts_credentials);
		JSON_ADD_BOOL_TO_OBJECT(peerconf, "wants_credentials", peer->wants_credentials);
		JSON_COPY_STR_TO_OBJECT(peerconf, "pinned", peer->pinned);
		JSON_COPY_STR_TO_OBJECT(peerconf, "pinned_credentials", peer->pinned_credentials);
		JSON_ADD_ITEM_TO_OBJECT(sync, "config", peerconf);

		cJSON *peergravity = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(peergravity, "changed", peer->gravity_changed);
		JSON_COPY_STR_TO_OBJECT(peergravity, "hash", peer->gravityhash);
		JSON_ADD_BOOL_TO_OBJECT(peergravity, "owed", peer->gravity_owed);
		JSON_ADD_ITEM_TO_OBJECT(sync, "gravity", peergravity);
		JSON_ADD_ITEM_TO_OBJECT(item, "sync", sync);

		JSON_ADD_ITEM_TO_ARRAY(peers, item);
	}

	cJSON *cluster = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(cluster, "enabled", config.cluster.enabled.v.b);
	// Switched on and actually running are two different answers, and a page
	// that only ever sees the first one draws a healthy cluster for a node
	// where the thread never started
	JSON_ADD_BOOL_TO_OBJECT(cluster, "running", cluster_running());
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


// Ask the local segment which other Pi-holes are there. An administrator who
// wants to build a cluster should not have to go and look up addresses
int api_cluster_discover(struct ftl_conn *api)
{
	if(api->session.used && api->session.cluster)
		return send_json_error(api, 403, "forbidden",
		                       "A peer cannot ask this node to scan the network", NULL);

	struct cluster_found found[CLUSTER_MAX_PEERS * 2] = { 0 };
	const unsigned int num = cluster_discover(found, sizeof(found)/sizeof(found[0]), 1.5);

	cJSON *nodes = JSON_NEW_ARRAY();
	for(unsigned int i = 0; i < num; i++)
	{
		cJSON *node = JSON_NEW_OBJECT();
		JSON_COPY_STR_TO_OBJECT(node, "address", found[i].address);
		JSON_ADD_NUMBER_TO_OBJECT(node, "port", found[i].port);

		// The URL this node would be joined through. Without a port
		// there is no encrypted connection to it, and joining needs one
		if(found[i].port > 0)
		{
			// The zone behind a link-local address is separated by a
			// percent sign, which a URL spells %25
			char host[sizeof(found[i].address) + 2] = "";
			const char *zone = strchr(found[i].address, '%');
			if(zone != NULL)
				snprintf(host, sizeof(host), "%.*s%%25%s",
				         (int)(zone - found[i].address), found[i].address, zone + 1);
			else
				strncpy(host, found[i].address, sizeof(host) - 1);

			char url[CLUSTER_URLLEN] = "";
			const bool v6 = strchr(found[i].address, ':') != NULL;
			snprintf(url, sizeof(url), "https://%s%s%s:%u",
			         v6 ? "[" : "", host, v6 ? "]" : "",
			         (unsigned int)found[i].port);
			JSON_COPY_STR_TO_OBJECT(node, "url", url);
		}
		else
			JSON_ADD_NULL_TO_OBJECT(node, "url");

		JSON_ADD_ITEM_TO_ARRAY(nodes, node);
	}

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "nodes", nodes);
	JSON_SEND_OBJECT(json);
}

// Everything that has to be true before this node hands its cluster secret to
// somebody, or takes somebody else's. The secret is what lets a node change the
// configuration of every other one, so this is deliberately narrow
static const char *bootstrap_refusal(struct ftl_conn *api)
{
	// Over TLS only. The secret and the password both cross this connection,
	// and a signature would keep them from being changed, not from being read
	if(!api->request->is_ssl)
		return "This needs an encrypted connection";

	// As far as this Pi-hole authenticates anything at all. A node with no
	// password has an open API because somebody decided so, and this is part
	// of that API - demanding a session it cannot create would make a
	// password-less cluster impossible to build while protecting nothing:
	// whoever can reach such a node can already make it hand the others
	// whatever they like, secret or no secret
	lock_shm();
	const bool have_password = config.webserver.api.pwhash.v.s[0] != '\0';
	unlock_shm();

	if(have_password && !api->session.used)
		return "This needs a session created with the web interface password";

	// The real password, not an application password and not the CLI one:
	// those exist so a script can read data, not so it can take over a
	// cluster
	if(api->session.app || api->session.cli)
		return "This needs a session created with the web interface password";

	// ...and never a peer. A cluster identity may read what the cluster
	// publishes; the secret is what made it a peer in the first place
	if(api->session.cluster)
		return "A peer cannot ask for the cluster secret";

	return NULL;
}

// An item forced through the environment cannot be changed by anybody, so a
// member list written here would be back to the environment's at the next start
static const char *env_forced(const bool joining)
{
	if(config.cluster.members.f & FLAG_ENV_VAR)
		return "cluster.members is set through the environment, add the node there instead";

	if(joining && config.cluster.enabled.f & FLAG_ENV_VAR)
		return "cluster.enabled is set through the environment";

	return NULL;
}

// Whether the member list already names this node, so enrolling twice is not
// an error and does not grow the list
static bool member_listed(const cJSON *members, const char *url)
{
	for(const cJSON *item = members != NULL ? members->child : NULL; item != NULL; item = item->next)
		if(cJSON_IsString(item) && strcmp(item->valuestring, url) == 0)
			return true;

	return false;
}

// A list handed to us by another node is as unchecked as any other payload, and
// what installs it writes it straight out
static bool members_valid(cJSON *members, char *errbuf)
{
	char validation[VALIDATOR_ERRBUF_LEN] = { 0 };
	union conf_value check = { .json = members };
	if(config.cluster.members.c(&check, config.cluster.members.k, validation))
		return true;

	strncpy(errbuf, validation, ERRBUF_SIZE - 1);
	errbuf[ERRBUF_SIZE - 1] = '\0';

	return false;
}

// The list this node should hold, with add named in it. Takes over base; a NULL
// add leaves the list as it came, which is what a joining node wants when the
// node it joined worked out its address for it
static cJSON *members_with(cJSON *base, const char *add)
{
	cJSON *members = base;
	if(!cJSON_IsArray(members))
	{
		cJSON_Delete(members);
		members = JSON_NEW_ARRAY();
	}

	if(add != NULL && !member_listed(members, add))
		cJSON_AddItemToArray(members, cJSON_CreateString(add));

	return members;
}

// Install a member list the way any other configuration change is installed:
// under the lock the other writers take, and stamped so the rest of the cluster
// takes it from here. base is the list to install and is taken over by this
// function, or NULL to add to the list this node already holds
static bool install_members(cJSON *base, const char *add, const bool joining, char *errbuf)
{
	cluster_sync_lock();

	struct config newconf;
	duplicate_config(&newconf, &config);

	// Read inside the lock rather than before it: two administrators
	// enrolling two nodes at the same moment would otherwise each install
	// their list over the other's, and the node that lost is left holding a
	// secret nobody talks to
	cJSON *members = members_with(base != NULL ? base :
	                              cJSON_Duplicate(newconf.cluster.members.v.json, true), add);

	if(!members_valid(members, errbuf))
	{
		cJSON_Delete(members);
		free_config(&newconf, false);
		cluster_sync_unlock();
		return false;
	}

	cJSON_Delete(newconf.cluster.members.v.json);
	newconf.cluster.members.v.json = members;

	// A node that joins does so to be in step with the others, and this is
	// not synchronized - nobody else would ever set it
	if(joining)
		newconf.cluster.enabled.v.b = true;

	struct config_apply applied = { 0 };
	applied.changed = true;

	// The member list is what the DHCP server hands out as the resolvers to
	// use, so dnsmasq has to be told about it - it is FLAG_RESTART_FTL for
	// that reason
	applied.dnsmasq_changed = true;

	// A node that is joining arrives as one nobody has configured yet - the
	// epoch as the moment it was last changed - so the cluster hands it
	// everything rather than taking its settings. A node that enrolls
	// somebody else made an ordinary change, which travels from here
	const bool installed = config_install(&newconf, &applied, joining, 0.0, errbuf);
	if(installed && joining)
		cluster_state_forget();

	cluster_sync_unlock();

	return installed;
}

// Take a node into this cluster: add it to the member list, which is what
// carries it to the other nodes, and hand it the shared secret. The caller has
// proven it knows this node's password, which is the stronger credential
int api_cluster_enroll(struct ftl_conn *api)
{
	const char *refusal = bootstrap_refusal(api);
	if(refusal != NULL)
		return send_json_error(api, 403, "forbidden", refusal, NULL);

	if(config.misc.readOnly.v.b)
		return send_json_error(api, 403, "forbidden",
		                       "The config is currently in read-only mode", NULL);

	if(api->payload.json == NULL)
		return send_json_error(api, 400, "bad_request", "No valid JSON payload found",
		                       api->payload.json_error);

	// Where the joining node is, as seen from here. Asking it where it thinks
	// it is gets an answer from a machine that cannot know how anybody else
	// reaches it; the address this request arrived from is the one that
	// demonstrably works, because it just did. A caller that knows better -
	// a node behind a port forward - says so and that is used instead
	const cJSON *self = cJSON_GetObjectItem(api->payload.json, "self");
	const cJSON *port = cJSON_GetObjectItem(api->payload.json, "port");

	char joiner[CLUSTER_URLLEN] = "";
	if(cJSON_IsString(self) && strlen(self->valuestring) > 0)
	{
		if(strlen(self->valuestring) >= sizeof(joiner))
			return send_json_error(api, 400, "bad_request", "self is too long", NULL);

		if(strncmp(self->valuestring, "http://", 7) != 0 &&
		   strncmp(self->valuestring, "https://", 8) != 0)
			return send_json_error(api, 400, "bad_request",
			                       "self must start with http:// or https://", NULL);

		strncpy(joiner, self->valuestring, sizeof(joiner) - 1);
	}
	else
	{
		const char *from = api->request != NULL ? api->request->remote_addr : NULL;
		if(from == NULL || strlen(from) == 0)
			return send_json_error(api, 400, "bad_request",
			                       "Cannot tell where this request came from", NULL);

		// Its own port, which only it knows - this connection says nothing
		// about what it listens on
		if(!cJSON_IsNumber(port) || port->valuedouble < 1 || port->valuedouble > 65535)
			return send_json_error(api, 400, "bad_request",
			                       "Either self or port is needed", NULL);

		// A bare IPv6 address needs brackets before a port can follow it.
		// The default port is left off: written out it would be a second
		// spelling of an address the list may already hold, and the two
		// would be polled as two nodes
		const bool v6 = strchr(from, ':') != NULL;
		const unsigned int p = (unsigned int)port->valuedouble;
		if(p == 443)
			snprintf(joiner, sizeof(joiner), "https://%s%s%s",
			         v6 ? "[" : "", from, v6 ? "]" : "");
		else
			snprintf(joiner, sizeof(joiner), "https://%s%s%s:%u",
			         v6 ? "[" : "", from, v6 ? "]" : "", p);
	}

	const char *forced = env_forced(false);
	if(forced != NULL)
		return send_json_error(api, 400, "bad_request", forced, NULL);

	// A node that is not in a cluster itself has no cluster to take anybody
	// into: the list it would hand over would name the joining node and
	// nobody else, leaving both of them talking to a cluster of one
	lock_shm();
	const bool clustered = config.cluster.enabled.v.b &&
	                       cJSON_GetArraySize(config.cluster.members.v.json) > 0;
	unlock_shm();
	if(!clustered)
		return send_json_error(api, 400, "bad_request",
		                       "This Pi-hole is not part of a cluster",
		                       "Create one on its HA cluster page first, or set cluster.members to its own URL and switch cluster.enabled on");

	char secret[CLUSTER_SECRET_LEN] = "";
	if(!cluster_secret_copy(secret, sizeof(secret)))
		return send_json_error(api, 400, "bad_request",
		                       "This Pi-hole has no usable cluster secret", NULL);

	lock_shm();
	const bool listed = member_listed(config.cluster.members.v.json, joiner);
	unlock_shm();

	// Enrolling the same node twice is not an error - it is what an
	// administrator does after a join that did not finish
	if(!listed)
	{
		char errbuf[ERRBUF_SIZE] = { 0 };
		if(!install_members(NULL, joiner, false, errbuf))
			return send_json_error(api, 400, "bad_request",
			                       "Could not add that node to the member list", errbuf);

		// What the DHCP server hands out as the resolvers to use is
		// built from the member list, and that reaches dnsmasq at start
		api->ftl.restart_reason = "cluster: a node was enrolled";
		api->ftl.restart = true;
	}

	// The joining node arrives as one that never held anything, so this one
	// has to be able to say when its lists were last touched - a node that
	// cannot say is never taken from
	cluster_stamp_lists();

	// Worth a line in the log at any level: somebody just took the key to
	// this cluster, and the administrator should be able to see when
	log_info("cluster: enrolled %s, handing over the cluster secret", joiner);

	lock_shm();
	cJSON *members = cJSON_Duplicate(config.cluster.members.v.json, true);
	unlock_shm();

	cJSON *json = JSON_NEW_OBJECT();
	JSON_COPY_STR_TO_OBJECT(json, "secret", secret);
	JSON_ADD_ITEM_TO_OBJECT(json, "members", members != NULL ? members : JSON_NEW_ARRAY());
	JSON_SEND_OBJECT(json);
}

// Join a cluster: fetch the secret from a node that is already a member, take
// its member list, add ourselves to it and switch clustering on
int api_cluster_join(struct ftl_conn *api)
{
	const char *refusal = bootstrap_refusal(api);
	if(refusal != NULL)
		return send_json_error(api, 403, "forbidden", refusal, NULL);

	if(config.misc.readOnly.v.b)
		return send_json_error(api, 403, "forbidden",
		                       "The config is currently in read-only mode", NULL);

	if(api->payload.json == NULL)
		return send_json_error(api, 400, "bad_request", "No valid JSON payload found",
		                       api->payload.json_error);

	const cJSON *url = cJSON_GetObjectItem(api->payload.json, "url");
	const cJSON *password = cJSON_GetObjectItem(api->payload.json, "password");
	const cJSON *self = cJSON_GetObjectItem(api->payload.json, "self");
	const cJSON *pin = cJSON_GetObjectItem(api->payload.json, "pin");
	// Only where the node being joined has a second factor. Without it that
	// node answers the password alone with 400 and no session, and there is
	// no way through the web interface at all
	const cJSON *totp = cJSON_GetObjectItem(api->payload.json, "totp");
	if(!cJSON_IsString(url) || !cJSON_IsString(password))
		return send_json_error(api, 400, "bad_request",
		                       "url and password are required", NULL);

	if(strlen(url->valuestring) >= CLUSTER_URLLEN ||
	   (cJSON_IsString(self) && strlen(self->valuestring) >= CLUSTER_URLLEN))
		return send_json_error(api, 400, "bad_request", "URL is too long", NULL);

	// Left out in the ordinary case: the node being joined sees where this
	// request comes from, which is an address that demonstrably reaches this
	// node, and composes it with the port named below
	const char *me = cJSON_IsString(self) ? self->valuestring : NULL;

	const char *forced = env_forced(true);
	if(forced != NULL)
		return send_json_error(api, 400, "bad_request", forced, NULL);

	// A node already in a cluster is signing requests with the secret this
	// would replace. Leaving the old cluster is a separate decision, and one
	// nobody makes by accident
	if(config.cluster.enabled.v.b)
		return send_json_error(api, 400, "bad_request",
		                       "This Pi-hole is already part of a cluster",
		                       "Switch cluster.enabled off before joining another one");

	char secret[256] = "";
	char err[256] = "";
	cJSON *members = NULL;
	// Optional, and the only thing that makes this first connection something
	// a listener cannot read: the pin of the node being joined, copied out of
	// its web interface by somebody who cares
	const char *fingerprint = cJSON_IsString(pin) ? pin->valuestring : NULL;
	if(fingerprint != NULL && strlen(fingerprint) >= CLUSTER_PINLEN)
		return send_json_error(api, 400, "bad_request", "pin is not a certificate pin", NULL);

	const char *token = cJSON_IsString(totp) ? totp->valuestring : NULL;
	if(token != NULL && strlen(token) >= CLUSTER_STRLEN)
		return send_json_error(api, 400, "bad_request", "totp is not a token", NULL);

	if(!cluster_http_bootstrap(url->valuestring, password->valuestring, token, me,
	                           fingerprint, secret, sizeof(secret), &members, err, sizeof(err)))
	{
		return send_json_error_free(api, 400, "bad_request",
		                            "Could not join that cluster", strdup(err), true, true);
	}

	// The list the other node answered with already names this one, as it
	// enrolled us before handing the secret over. It is added anyway if it
	// does not: a node that is not in its own member list would never be
	// part of anything.
	// Checked here rather than only where it is installed, because the
	// secret is replaced in between: a join that is refused after that point
	// leaves this node holding a secret its own cluster knows nothing about
	members = members_with(members, me);


	char errbuf[ERRBUF_SIZE] = { 0 };
	if(!members_valid(members, errbuf))
	{
		cJSON_Delete(members);
		return send_json_error(api, 400, "bad_request",
		                       "That node sent a member list this one cannot use", errbuf);
	}

	if(!adopt_cluster_secret(secret))
	{
		cJSON_Delete(members);
		return send_json_error(api, 500, "internal_error",
		                       "Could not store the cluster secret", NULL);
	}

	if(!install_members(members, me, true, errbuf))
		return send_json_error(api, 500, "internal_error",
		                       "The cluster secret was taken but the member list could not be stored",
		                       errbuf);

	log_info("cluster: joined the cluster of %s", url->valuestring);

	// Clustering starts with the thread, which starts with FTL
	api->ftl.restart_reason = "cluster: joined";
	api->ftl.restart = true;

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(json, "joined", true);
	JSON_SEND_OBJECT(json);
}

// The list tables as a ZIP archive, in the same shape a Teleporter archive
// carries them - but without the configuration file the Teleporter also holds
// Leave the cluster. The work is the cluster thread's: the other nodes have to
// be told before clustering stops here, and only that thread may talk to them
int api_cluster_leave(struct ftl_conn *api)
{
	if(!config.cluster.enabled.v.b)
		return send_json_error(api, 400, "bad_request",
		                       "This Pi-hole is not part of a cluster", NULL);

	// The same credential this cluster is joined with. Leaving tells every
	// other node to drop this one and hands DHCP away, which is not
	// something an application password - handed to a script so it can read
	// data - or a peer's own cluster identity has any business doing
	if(api->session.app || api->session.cli)
		return send_json_error(api, 403, "forbidden",
		                       "This needs a session created with the web interface password", NULL);

	if(api->session.cluster)
		return send_json_error(api, 403, "forbidden",
		                       "A peer cannot make this node leave", NULL);

	// A node that cannot write its own configuration cannot leave: the other
	// nodes would be told to drop it and it would come back at the next
	// restart still holding the member list, in a cluster that no longer
	// lists it
	if(config.misc.readOnly.v.b)
		return send_json_error(api, 403, "forbidden",
		                       "The config is currently in read-only mode", NULL);

	if(config.cluster.enabled.f & FLAG_ENV_VAR)
		return send_json_error(api, 403, "forbidden",
		                       "cluster.enabled is set through the environment, so it cannot be switched off here", NULL);

	// Leaving is the cluster thread's work - the others have to be told
	// first. On a node where that thread never started nothing would ever
	// read the flag, and there is nobody to tell either, so the leave
	// happens right here instead of being reported and not done
	if(!cluster_running())
	{
		char errbuf[ERRBUF_SIZE] = "";
		bool peers_told = false;
		if(!cluster_leave_now(errbuf, &peers_told))
			return send_json_error(api, 500, "internal_error",
			                       "Could not write the configuration", errbuf);

		// ...and no restart follows it, so the page has to be told not
		// to wait for one - nor for peers that were never told, which is
		// something only the administrator can now put right
		cJSON *left = JSON_NEW_OBJECT();
		JSON_ADD_BOOL_TO_OBJECT(left, "leaving", true);
		JSON_ADD_BOOL_TO_OBJECT(left, "restarting", false);
		JSON_ADD_BOOL_TO_OBJECT(left, "peers_told", peers_told);
		JSON_SEND_OBJECT(left);
	}

	cluster_leave();

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_BOOL_TO_OBJECT(json, "leaving", true);
	JSON_ADD_BOOL_TO_OBJECT(json, "restarting", true);
	// No `peers_told` here: the cluster thread does the telling a round from
	// now, and how many of them it reached goes in the log. Answering `true`
	// before anything has been attempted said the opposite of what happens
	// when a peer is down - "0 of 1 nodes told"

	JSON_SEND_OBJECT(json);
}

// The lease file as it is on disk. Only the node handing out addresses has
// anything worth reading here, and only its peers ever ask
int api_cluster_leases(struct ftl_conn *api)
{
	uint8_t *data = NULL;
	size_t size = 0;
	if(!cluster_leases_read(&data, &size))
		return send_json_error(api, 404, "not_found",
		                       "This node has no DHCP leases", NULL);

	send_http_ok_signed(api, "application/octet-stream", (const char *)data, size);
	if(size > 0)
		mg_write(api->conn, data, size);
	free(data);

	return 200;
}

int api_cluster_lists(struct ftl_conn *api)
{
	mz_zip_archive zip = { 0 };
	void *ptr = NULL;
	size_t size = 0u;

	const char *error = generate_cluster_zip(&zip, &ptr, &size);
	if(error != NULL)
		return send_json_error(api, 500,
		                       "compression_error",
		                       error,
		                       NULL);

	send_http_ok_signed(api, "application/zip", ptr, size);
	mg_write(api->conn, ptr, size);

	// Finalizing the archive handed the buffer over to us
	free_teleporter_zip(&zip);
	free(ptr);

	return 200;
}
