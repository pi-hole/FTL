/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster request authentication
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// The nodes of a cluster authenticate every single request to each other with
// the shared cluster secret rather than with a session. A session is a bearer
// token: it travels in a header, it is as good as the secret for as long as it
// lives, and it says nothing about which request it was meant for. A signature
// says all of it - who sent this, to whom, which method and path, and with
// exactly this body - and it says it without the secret ever being on the wire.
//
// That matters because the realistic cluster is two Pi-holes with self-signed
// certificates, which is a setup where TLS verification is commonly turned off.
// Signing every request means an attacker sitting on that connection can read
// what is exchanged, but cannot change it and cannot make one up.

#include "FTL.h"
#include "log.h"
#include "config/config.h"
#include "cluster/auth.h"
#include "cluster/cluster.h"
#include "cluster/sync.h"
// cluster_secret()
#include "config/password.h"
// get_secure_randomness()
#include "api/auth.h"
// double_time()
#include "timers.h"

#include <math.h>
#include <nettle/hmac.h>
#include <nettle/sha2.h>

// The secret is never used as a key directly: one derived key signs requests,
// another signs the answers, so a signature can never be replayed as the other
#define CLUSTER_REQUEST_KEY "FTL cluster request v1"
#define CLUSTER_RESPONSE_KEY "FTL cluster response v1"

// What goes into a signature, so a future version can change it and be told
// apart rather than be misread
#define CLUSTER_SIG_VERSION "FTLCLUSTER1"

// The last sequence accepted from each peer. Anything not strictly above it is
// a replay, whoever sends it
struct sender {
	char id[CLUSTER_HASHLEN];
	long long seq;
	time_t last;
};
static struct sender senders[CLUSTER_MAX_PEERS];
static pthread_mutex_t senders_lock = PTHREAD_MUTEX_INITIALIZER;

// Our own sequence. Microseconds since the epoch, but never repeating and never
// going backwards: a clock set back would otherwise have our peers reject
// everything we send until it has caught up again
static long long last_seq = 0;
static pthread_mutex_t seq_lock = PTHREAD_MUTEX_INITIALIZER;

// Comparing signatures with strcmp() would answer in a time that depends on how
// much of it is right, which is enough to search for the rest byte by byte
static bool constant_time_equal(const char *a, const char *b, const size_t len)
{
	uint8_t diff = 0;
	for(size_t i = 0; i < len; i++)
		diff |= (uint8_t)a[i] ^ (uint8_t)b[i];

	return diff == 0;
}

static void sha256_hex(const char *data, const size_t len, char out[CLUSTER_SIGLEN])
{
	uint8_t digest[SHA256_DIGEST_SIZE];
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, len, (const uint8_t *)data);
#if NETTLE_VERSION_MAJOR >= 4
	sha256_digest(&ctx, digest);
#else
	sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
#endif
	sha256_raw_to_hex(digest, out);
}

static void hmac_hex(const char *key, const size_t keylen,
                     const char *data, const size_t len, char out[CLUSTER_SIGLEN])
{
	uint8_t digest[SHA256_DIGEST_SIZE];
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, keylen, (const uint8_t *)key);
	hmac_sha256_update(&ctx, len, (const uint8_t *)data);
#if NETTLE_VERSION_MAJOR >= 4
	hmac_sha256_digest(&ctx, digest);
#else
	hmac_sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
#endif
	sha256_raw_to_hex(digest, out);
}

// The key that signs requests, or the one that signs answers, derived from the
// cluster secret. False when this node has no usable secret, which is what
// makes an unconfigured node refuse to take part rather than fall back to
// something weaker
static bool derive_key(const char *purpose, uint8_t key[SHA256_DIGEST_SIZE])
{
	char secret[CLUSTER_SECRET_LEN] = "";
	if(!cluster_secret_copy(secret, sizeof(secret)))
		return false;

	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, strlen(secret), (const uint8_t *)secret);
	hmac_sha256_update(&ctx, strlen(purpose), (const uint8_t *)purpose);
#if NETTLE_VERSION_MAJOR >= 4
	hmac_sha256_digest(&ctx, key);
#else
	hmac_sha256_digest(&ctx, SHA256_DIGEST_SIZE, key);
#endif

	return true;
}

// Everything the signature covers, in one string. The parts are separated by
// newlines and none of them may contain one, so no combination of values can be
// made to look like a different combination
// False when the parts do not fit. The hash of the body is written last, so a
// URI long enough to fill this buffer would push it out and leave a signature
// that says nothing about the body - and two requests differing only there
// would sign identically. Nothing in this cluster builds a URI anywhere near
// that long, and forging one still needs the secret, so this is a refusal
// rather than a fix for a way in
static bool canonical_request(char *buf, const size_t buflen,
                              const char *method, const char *uri, const char *from,
                              const char *to, const long long seq, const char *bodyhash)
{
	const int len = snprintf(buf, buflen, "%s\n%s\n%s\n%s\n%s\n%lld\n%s",
	                         CLUSTER_SIG_VERSION, method, uri, from, to, seq, bodyhash);

	return len > 0 && (size_t)len < buflen;
}

static bool sign_request(const char *method, const char *uri, const char *from,
                         const char *to, const long long seq, const char *body,
                         char sig[CLUSTER_SIGLEN])
{
	uint8_t key[SHA256_DIGEST_SIZE];
	if(!derive_key(CLUSTER_REQUEST_KEY, key))
		return false;

	char bodyhash[CLUSTER_SIGLEN] = "";
	sha256_hex(body != NULL ? body : "", body != NULL ? strlen(body) : 0, bodyhash);

	char canonical[1024] = "";
	if(!canonical_request(canonical, sizeof(canonical), method, uri, from, to, seq, bodyhash))
	{
		log_warn("cluster: cannot sign a request for %s, it is too long", uri);
		return false;
	}

	hmac_hex((const char *)key, sizeof(key), canonical, strlen(canonical), sig);

	return true;
}

// The answer names who wrote it. Every node signs with the same key, so without
// this an answer of one node verifies as an answer of any other - including an
// answer of ours handed back to us, which is enough to make a node believe a
// live peer is itself and stop talking to it
static bool sign_response(const char *from, const long long seq,
                          const char *body, const size_t len, char sig[CLUSTER_SIGLEN])
{
	uint8_t key[SHA256_DIGEST_SIZE];
	if(!derive_key(CLUSTER_RESPONSE_KEY, key))
		return false;

	char bodyhash[CLUSTER_SIGLEN] = "";
	sha256_hex(body, len, bodyhash);

	char canonical[256] = "";
	snprintf(canonical, sizeof(canonical), "%s-R\n%s\n%lld\n%s",
	         CLUSTER_SIG_VERSION, from, seq, bodyhash);
	hmac_hex((const char *)key, sizeof(key), canonical, strlen(canonical), sig);

	return true;
}

bool cluster_sign_request(const char *method, const char *uri, const char *to,
                          const char *body, struct cluster_signature *out)
{
	// One microsecond apart is enough to tell two requests apart, and never
	// going backwards keeps that true across a clock that was set back a
	// little. A clock that was set back further than the window our peers
	// judge us by is a different matter: holding on to the old count would
	// have every peer refuse us as out of date until real time caught up
	// again, so the count follows the clock down
	const long long now = (long long)(double_time() * 1e6);
	const long long window = (long long)CLUSTER_SIG_WINDOW * 1000000;
	pthread_mutex_lock(&seq_lock);
	last_seq = now > last_seq || now < last_seq - window ? now : last_seq + 1;
	out->seq = last_seq;
	pthread_mutex_unlock(&seq_lock);

	return sign_request(method, uri, cluster_node_id(), to, out->seq, body, out->sig);
}

// A sequence we have already seen from this sender, or one from before the last
// we accepted, is a replay. The first request of a sender is judged by the time
// window alone
static bool sequence_fresh(const char *id, const long long seq)
{
	const time_t now = time(NULL);
	bool fresh = false;

	pthread_mutex_lock(&senders_lock);

	int slot = -1, oldest = 0;
	for(unsigned int i = 0; i < ArraySize(senders); i++)
	{
		if(strcmp(senders[i].id, id) == 0)
		{
			slot = (int)i;
			break;
		}
		if(senders[i].id[0] == '\0')
		{
			slot = (int)i;
			break;
		}
		if(senders[i].last < senders[oldest].last)
			oldest = (int)i;
	}

	if(slot < 0)
	{
		// More senders than a cluster can hold: the one we have not
		// heard from in the longest time makes room
		slot = oldest;
		senders[slot].id[0] = '\0';
	}

	if(senders[slot].id[0] == '\0')
	{
		strncpy(senders[slot].id, id, sizeof(senders[slot].id) - 1);
		senders[slot].id[sizeof(senders[slot].id) - 1] = '\0';
		senders[slot].seq = 0;
	}

	// An entry older than the window is aged out: the window check has
	// already bounded this request by time alone, which is all a sender's
	// first request ever gets. Without this a clock that was fast records a
	// mark no peer can beat until wall time reaches it - and the correction
	// that fixes the clock is exactly what triggers it
	if(llabs((long long)(now - senders[slot].last)) > CLUSTER_SIG_WINDOW)
		senders[slot].seq = 0;

	if(seq > senders[slot].seq)
	{
		senders[slot].seq = seq;
		senders[slot].last = now;
		fresh = true;
	}

	pthread_mutex_unlock(&senders_lock);

	return fresh;
}

// A node id is what we compare and what we print, so it may only be what a node
// id ever is
bool cluster_plain_id(const char *str)
{
	const size_t len = strlen(str);
	if(len == 0 || len >= CLUSTER_HASHLEN)
		return false;

	for(size_t i = 0; i < len; i++)
		if(!isalnum((unsigned char)str[i]))
			return false;

	return true;
}

bool cluster_verify_request(struct ftl_conn *api)
{
	const char *from = mg_get_header(api->conn, CLUSTER_HDR_FROM);
	const char *to = mg_get_header(api->conn, CLUSTER_HDR_TO);
	const char *seqstr = mg_get_header(api->conn, CLUSTER_HDR_SEQ);
	const char *sig = mg_get_header(api->conn, CLUSTER_HDR_SIG);

	// Not a cluster request at all, so not ours to judge
	if(sig == NULL)
		return false;

	// Everything below refuses at debug level: anyone can send these headers
	// without knowing anything, and a warning per attempt would let whoever
	// does it fill the log - and the disk. Only a request that carries a
	// valid signature, and is refused anyway, is worth saying out loud
	// Only that this node is part of a cluster at all. Whether it also
	// synchronizes its configuration is decided where a configuration is
	// taken, not here: DHCP failover and the virtual IP are separate
	// switches and they need these requests answered
	if(!config.cluster.enabled.v.b)
	{
		log_web_debug(DEBUG_API, "Cluster request refused: this node is not in a cluster");
		return false;
	}

	if(from == NULL || to == NULL || seqstr == NULL ||
	   !cluster_plain_id(from) || strlen(sig) != CLUSTER_SIGLEN - 1)
	{
		log_web_debug(DEBUG_API, "Cluster request refused: incomplete signature");
		return false;
	}

	// A request that names its recipient can only be used against that one.
	// Only a GET may leave it open, and only because reading a status
	// document somewhere else gains an attacker nothing
	if(strcmp(to, cluster_node_id()) != 0 &&
	   !(api->method == HTTP_GET && strcmp(to, CLUSTER_ANY_NODE) == 0))
	{
		log_web_debug(DEBUG_API, "Cluster request refused: addressed to another node");
		return false;
	}

	// A node reads its own status once to recognize its own entry in the
	// member list, so a GET under our own identity is expected. Taking a
	// configuration from ourselves over the network is not
	if(api->method != HTTP_GET && strcmp(from, cluster_node_id()) == 0)
	{
		log_web_debug(DEBUG_API, "Cluster request refused: sent under our own identity");
		return false;
	}

	char *end = NULL;
	const long long seq = strtoll(seqstr, &end, 10);
	if(end == seqstr || *end != '\0' || seq <= 0)
	{
		log_web_debug(DEBUG_API, "Cluster request refused: malformed sequence");
		return false;
	}

	const long long now = (long long)(double_time() * 1e6);
	if(llabs(now - seq) > (long long)CLUSTER_SIG_WINDOW * 1000000)
	{
		log_web_debug(DEBUG_API, "Cluster request refused: %.0f s out of date",
		              fabs((double)(now - seq)) / 1e6);
		return false;
	}

	// civetweb hands us the decoded path, so a request carrying an escape
	// would be signed over one string and judged against another. Nothing a
	// node sends needs one, and refusing them keeps the two ends from ever
	// disagreeing on what was signed
	if(strchr(api->request->local_uri_raw, '%') != NULL ||
	   (api->request->query_string != NULL && strchr(api->request->query_string, '%') != NULL))
	{
		log_web_debug(DEBUG_API, "Cluster request refused: escaped characters in the URI");
		return false;
	}

	// The URI as the peer signed it, query string and all
	char uri[512] = "";
	if(api->request->query_string != NULL && strlen(api->request->query_string) > 0)
		snprintf(uri, sizeof(uri), "%s?%s", api->request->local_uri_raw, api->request->query_string);
	else
		snprintf(uri, sizeof(uri), "%s", api->request->local_uri_raw);

	char expected[CLUSTER_SIGLEN] = "";
	if(!sign_request(api->request->request_method, uri, from, to, seq,
	                 api->payload.raw, expected))
	{
		log_web_debug(DEBUG_API, "Cluster request refused: no usable cluster secret here");
		return false;
	}

	if(!constant_time_equal(expected, sig, CLUSTER_SIGLEN - 1))
	{
		log_web_debug(DEBUG_API, "Cluster request refused: signature does not match");
		return false;
	}

	// Only now, with the sender proven, is it worth remembering anything
	// about it - otherwise anyone could push our peers out of the table
	if(!sequence_fresh(from, seq))
	{
		log_web_debug(DEBUG_API, "Cluster request refused: seen before");
		return false;
	}

	api->session.used = true;
	api->session.cluster = true;
	api->session.cluster_seq = seq;
	api->user_id = -1;

	return true;
}

bool cluster_response_signature(struct ftl_conn *api, const char *body, const size_t len,
                                char sig[CLUSTER_SIGLEN])
{
	if(!api->session.used || !api->session.cluster || api->session.cluster_seq == 0)
		return false;

	return sign_response(cluster_node_id(), api->session.cluster_seq, body, len, sig);
}

bool cluster_verify_response(const char *from, const long long seq, const char *sig,
                             const char *body, const size_t len)
{
	if(sig == NULL || strlen(sig) != CLUSTER_SIGLEN - 1 ||
	   from == NULL || !cluster_plain_id(from))
		return false;

	char expected[CLUSTER_SIGLEN] = "";
	if(!sign_response(from, seq, body, len, expected))
		return false;

	return constant_time_equal(expected, sig, CLUSTER_SIGLEN - 1);
}
