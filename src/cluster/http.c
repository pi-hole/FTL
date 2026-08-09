/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster HTTP client
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "config/config.h"
// get_bound_https_port()
#include "webserver/webserver.h"
// PATH_MAX
#include <limits.h>
#include "cluster/http.h"
#include "version.h"
// cluster_sign_request()
#include "cluster/auth.h"
// CLUSTER_SECRET_FILE
#include "config/password.h"
// cluster_node_id()
#include "cluster/sync.h"
// lock_shm()
#include "shmem.h"
#include <limits.h>

#ifdef HAVE_CURL

#include <curl/curl.h>
#include <arpa/inet.h>

// A peer's answer is a status document or a Teleporter archive, both of which
// are far below this. The limit exists so a broken (or hostile) peer cannot
// make us allocate until we are killed
#define MAX_RESPONSE_SIZE (32u*1024u*1024u)

// What an answer we parse may weigh. A status document is a few kilobytes and
// the configuration a few dozen; anything past this is not something to hand to
// a JSON parser, and the archive of lists - the one answer that is genuinely
// large - never goes through one
#define MAX_JSON_SIZE (1u*1024u*1024u)

struct buffer {
	char *data;
	size_t size;
	size_t max;
};

// How long a peer may take to answer, derived from the round it belongs to: a
// round cannot wait for its own peers longer than it lasts. Never zero, which
// libcurl reads as "wait forever" - one unresponsive peer away from a cluster
// that stops
static long connect_timeout(void)
{
	const long interval = config.cluster.interval.v.ui > 0 ?
	                      (long)config.cluster.interval.v.ui : 10;

	return interval / 5 < 1 ? 1 : interval / 5;
}

// A whole list database takes longer than an answer to a question - but the
// cluster thread is the one that decides DHCP failover, so the budget is a few
// rounds rather than two minutes
static long bulk_timeout(void)
{
	const long interval = config.cluster.interval.v.ui > 0 ?
	                      (long)config.cluster.interval.v.ui : 10;

	return interval * 3 < 30 ? 30 : interval * 3;
}

// A request that failed before the first chunk arrived leaves no buffer behind
static void free_buffer(struct buffer *buf)
{
	if(buf->data != NULL)
		free(buf->data);

	buf->data = NULL;
	buf->size = 0;
}

// What the peer put on its answer: the signature and the identity it signed
// with. Picked out of the header block as it arrives, so the answer can be
// checked before anything is read out of it
struct answer {
	char sig[CLUSTER_SIGLEN];
	char by[CLUSTER_SIGLEN];
};

static bool header_value(const char *buffer, const size_t len, const char *name,
                         char *out, const size_t outlen)
{
	const size_t namelen = strlen(name);
	if(len <= namelen + 1 || strncasecmp(buffer, name, namelen) != 0 || buffer[namelen] != ':')
		return false;

	const char *value = buffer + namelen + 1;
	size_t vlen = len - namelen - 1;
	while(vlen > 0 && (*value == ' ' || *value == '\t'))
	{
		value++;
		vlen--;
	}
	while(vlen > 0 && (value[vlen - 1] == '\r' || value[vlen - 1] == '\n'))
		vlen--;

	if(vlen == 0 || vlen >= outlen)
		return false;

	memcpy(out, value, vlen);
	out[vlen] = '\0';

	return true;
}

static size_t header_cb(char *buffer, size_t size, size_t nitems, void *userp)
{
	struct answer *answer = (struct answer *)userp;
	const size_t len = size * nitems;

	if(!header_value(buffer, len, CLUSTER_HDR_SIG, answer->sig, sizeof(answer->sig)))
		header_value(buffer, len, CLUSTER_HDR_BY, answer->by, sizeof(answer->by));

	return len;
}

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct buffer *buf = (struct buffer *)userp;
	const size_t chunk = size * nmemb;

	// Returning anything else than the chunk size aborts the transfer
	const size_t max = buf->max > 0 ? buf->max : MAX_RESPONSE_SIZE;
	if(buf->size + chunk + 1 > max)
		return 0;

	char *ptr = realloc(buf->data, buf->size + chunk + 1);
	if(ptr == NULL)
		return 0;

	buf->data = ptr;
	memcpy(buf->data + buf->size, contents, chunk);
	buf->size += chunk;
	buf->data[buf->size] = '\0';

	return chunk;
}

bool cluster_http_init(void)
{
	// Only the cluster thread uses libcurl, so a plain global init is enough
	const CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
	if(rc != CURLE_OK)
	{
		log_err("cluster: libcurl init failed: %s", curl_easy_strerror(rc));
		return false;
	}

	log_debug(DEBUG_CLUSTER, "cluster: using %s", curl_version());
	return true;
}

void cluster_http_free(struct cluster_peer *peer)
{
	if(peer->curl == NULL)
		return;

	curl_easy_cleanup((CURL *)peer->curl);
	peer->curl = NULL;
}

// Split "http(s)://host[:port]" into what curl would resolve and the port it
// would use. Both are needed verbatim for a resolve entry, which is matched
// against the request by host and port rather than by URL
static bool url_host_port(const char *url, char *host, size_t hostlen,
                          char *port, size_t portlen)
{
	const char *p = strstr(url, "://");
	if(p == NULL)
		return false;

	const bool tls = strncmp(url, "https://", 8) == 0;
	p += 3;

	const char *end = p + strcspn(p, "/");
	const char *colon = NULL;
	size_t len = 0;

	if(*p == '[')
	{
		// An address literal keeps its brackets in the URL and loses
		// them in the resolve entry
		const char *close = memchr(p, ']', (size_t)(end - p));
		if(close == NULL)
			return false;

		p++;
		len = (size_t)(close - p);
		colon = close + 1 < end && close[1] == ':' ? close + 1 : NULL;
	}
	else
	{
		colon = memchr(p, ':', (size_t)(end - p));
		len = (size_t)((colon != NULL ? colon : end) - p);
	}

	if(len == 0 || len >= hostlen)
		return false;
	memcpy(host, p, len);
	host[len] = '\0';

	if(colon == NULL)
		return snprintf(port, portlen, "%s", tls ? "443" : "80") > 0;

	len = (size_t)(end - colon - 1);
	if(len == 0 || len >= portlen)
		return false;
	memcpy(port, colon + 1, len);
	port[len] = '\0';

	return true;
}

// Whether the URL already names an address, in which case there is nothing to
// resolve and nothing to learn
static bool is_address(const char *host)
{
	struct in_addr v4;
	struct in6_addr v6;
	return inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1;
}

// Point curl at the address this peer last answered on instead of asking the
// resolver for its name every time the connection has to be re-established.
// The name still travels in SNI and is still what the certificate is checked
// against, so this changes where we connect and nothing about who we accept
static struct curl_slist *resolve_entry(struct cluster_peer *peer)
{
	char host[CLUSTER_URLLEN] = "", port[8] = "";
	if(!url_host_port(peer->url, host, sizeof(host), port, sizeof(port)) || is_address(host))
		return NULL;

	// Removal first: an entry curl already holds for this pair would
	// otherwise stand, and the point of dropping an address is to stop
	// using it
	char entry[CLUSTER_URLLEN + CLUSTER_ADDRLEN + 16] = "";
	snprintf(entry, sizeof(entry), "-%s:%s", host, port);
	struct curl_slist *list = curl_slist_append(NULL, entry);

	const char *use = strlen(peer->address) > 0 ? peer->address :
	                  strlen(peer->hint) > 0 ? peer->hint : NULL;
	if(use == NULL)
		return list;

	// An address with colons in it needs brackets here, or the entry cannot
	// be told apart from the host:port:address separators around it
	if(strchr(use, ':') != NULL)
		snprintf(entry, sizeof(entry), "%s:%s:[%s]", host, port, use);
	else
		snprintf(entry, sizeof(entry), "%s:%s:%s", host, port, use);

	return curl_slist_append(list, entry);
}

// Perform one request against a peer. postdata == NULL requests a GET
static bool request(struct cluster_peer *peer, const char *method, const char *path,
                    const char *postdata, struct buffer *buf, long *code,
                    char *err, const size_t errlen, const long timeout,
                    char *signer, const size_t signerlen)
{
	if(peer->curl == NULL)
	{
		peer->curl = curl_easy_init();
		if(peer->curl == NULL)
		{
			strncpy(err, "Unable to create a libcurl handle", errlen - 1);
			return false;
		}
	}

	CURL *curl = (CURL *)peer->curl;
	// Reset the options but keep the connection, DNS and TLS session caches
	curl_easy_reset(curl);

	peer->answered = false;

	struct answer answer = { { 0 }, { 0 } };

	char url[512] = "";
	snprintf(url, sizeof(url), "%s%s", peer->url, path);

	char agent[128] = "";
	snprintf(agent, sizeof(agent), "pihole-FTL/%s", git_version());

	// Who we are talking to. Until a peer has answered once we do not know
	// its identity, which is why a request that changes something is never
	// the first one we send it
	const char *to = strlen(peer->id) > 0 ? peer->id : CLUSTER_ANY_NODE;
	struct cluster_signature sign = { 0 };
	if(!cluster_sign_request(method, path, to, postdata, &sign))
	{
		strncpy(err, "This node has no usable cluster secret", errlen - 1);
		return false;
	}

	char hdr[4][160] = { { 0 } };
	snprintf(hdr[0], sizeof(hdr[0]), "%s: %s", CLUSTER_HDR_FROM, cluster_node_id());
	snprintf(hdr[1], sizeof(hdr[1]), "%s: %s", CLUSTER_HDR_TO, to);
	snprintf(hdr[2], sizeof(hdr[2]), "%s: %lld", CLUSTER_HDR_SEQ, sign.seq);
	snprintf(hdr[3], sizeof(hdr[3]), "%s: %s", CLUSTER_HDR_SIG, sign.sig);

	struct curl_slist *headers = NULL;
	for(unsigned int i = 0; i < ArraySize(hdr); i++)
		headers = curl_slist_append(headers, hdr[i]);
	if(postdata != NULL)
		headers = curl_slist_append(headers, "Content-Type: application/json");
	// We ask for identity encoding: the answers are small and this saves the
	// peer from compressing what we immediately decompress again
	headers = curl_slist_append(headers, "Accept-Encoding: identity");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)buf);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&answer);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	// A peer that answers at a trickle would otherwise hold this thread for
	// the whole budget, and the DHCP hand-over waits behind it
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 100L);
	curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 10L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout());
	// libcurl must not use signals for timeouts in a threaded program
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	// A peer redirecting us elsewhere is a misconfiguration, not something to follow
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	struct curl_slist *resolve = resolve_entry(peer);
	if(resolve != NULL)
		curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
	// Copied out: another thread replaces the configuration, and frees the
	// string this points at, while curl is still holding it
	char cafile[PATH_MAX] = "";
	lock_shm();
	strncpy(cafile, config.cluster.tls.ca.v.s, sizeof(cafile) - 1);
	unlock_shm();

	if(strlen(cafile) > 0)
	{
		// Somebody who runs their own CA said where it is
		curl_easy_setopt(curl, CURLOPT_CAINFO, cafile);
	}
	else
	{
		// Pi-hole's certificates are self-signed and name a machine
		// rather than the address a peer reaches it at, so neither the
		// chain nor the hostname says anything. What does is the pin
		// below: the peer told us what its public key hashes to, in an
		// answer signed with the shared secret
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	// Learned rather than configured, and only ever from a signed answer.
	// Until we have it, the signature on the answer is the only thing that
	// says who we are talking to - which is why a first contact carries
	// nothing but a status document
	char pin[CLUSTER_PINLEN + 16] = "";
	if(strlen(peer->pin) > 0)
	{
		snprintf(pin, sizeof(pin), "sha256//%s", peer->pin);
		curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pin);
	}
	if(postdata != NULL)
	{
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(postdata));
	}
	if(strcmp(method, "GET") != 0)
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);

	// Bracketing the request is what makes the peer's timestamp usable: on its
	// own it says when the peer stamped the answer, which is a moment already
	// past by the time this node reads it
	peer->asked_at = double_time();
	CURLcode rc = curl_easy_perform(curl);
	peer->answered_at = double_time();

	// A certificate that no longer hashes to what the peer last told us is
	// either one it renewed - FTL does that on its own, without restarting -
	// or somebody in the middle. Which of the two, the answer decides: it is
	// signed, and a signature is not something a listener can produce.
	//
	// Only a request that carries nothing is asked again without the pin.
	// Handing a configuration to whoever answers, before anything has said
	// who that is, would put this cluster's passwords on their socket - and
	// discarding their unsigned answer afterwards does not take them back.
	// A push waits for the poll to re-establish the pin instead
	// Nothing here decides anything until the answer has been verified: an
	// unpinned attempt is a question, not a conclusion. Whoever answers it
	// can be anybody, and only a signature says otherwise
	char previous_pin[CLUSTER_PINLEN] = "";
	bool asked_unpinned = false;
	if(rc == CURLE_SSL_PINNEDPUBKEYNOTMATCH && strlen(peer->pin) > 0 && postdata == NULL &&
	   strcmp(path, "/api/cluster/status") == 0)
	{
		log_info("cluster: certificate of %s changed, asking it again", peer->url);

		strncpy(previous_pin, peer->pin, sizeof(previous_pin) - 1);
		peer->pin[0] = '\0';
		curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, NULL);
		peer->asked_at = double_time();
		rc = curl_easy_perform(curl);
		peer->answered_at = double_time();
		asked_unpinned = true;
	}

	curl_slist_free_all(headers);
	curl_slist_free_all(resolve);

	if(rc != CURLE_OK)
	{
		// The address we had is not where this peer answers any more, so
		// the next attempt asks the resolver again rather than insisting
		if(strlen(peer->address) > 0)
			log_info("cluster: %s no longer answers on %s, resolving its name again",
			         peer->url, peer->address);
		peer->address[0] = '\0';
		if(strlen(peer->hint) > 0)
		{
			strncpy(peer->hint_failed, peer->hint, sizeof(peer->hint_failed) - 1);
			peer->hint_failed[sizeof(peer->hint_failed) - 1] = '\0';
			peer->hint_rearm_at = double_time() + CLUSTER_HINT_REARM;
			peer->hint[0] = '\0';
		}

		if(asked_unpinned)
			strncpy(peer->pin, previous_pin, sizeof(peer->pin) - 1);
		snprintf(err, errlen, "%s", curl_easy_strerror(rc));
		return false;
	}

	// Where that answer came from. Asked for once and kept, so the name in
	// the member list is resolved when this node starts and not every time
	// the connection has to be built again
	const char *ip = NULL;
	if(curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &ip) == CURLE_OK &&
	   ip != NULL && strlen(ip) > 0 && strcmp(ip, peer->address) != 0)
	{
		strncpy(peer->address, ip, sizeof(peer->address) - 1);
		peer->address[sizeof(peer->address) - 1] = '\0';
		peer->hint[0] = '\0';
		peer->hint_failed[0] = '\0';
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, code);
	log_debug(DEBUG_CLUSTER, "cluster: %s %s -> %ld (%zu bytes)",
	          method, url, *code, buf->size);

	// Whatever it says, something answered on that address
	peer->answered = true;

	// An answer that decides anything here has to come from the node we
	// asked. Only the answers we act on are signed, so a rejection - which
	// carries nothing we use - is let through as it is
	if(*code == 200 &&
	   !cluster_verify_response(answer.by, sign.seq, answer.sig,
	                            buf->data != NULL ? buf->data : "", buf->size))
	{
		if(asked_unpinned)
			strncpy(peer->pin, previous_pin, sizeof(peer->pin) - 1);
		strncpy(err, "Answer is not signed by the peer we asked", errlen - 1);
		return false;
	}

	// Anything but a signed answer leaves what we knew standing: a rejection
	// carries no signature, and somebody in the middle can produce one of
	// those at will
	if(asked_unpinned && *code != 200)
		strncpy(peer->pin, previous_pin, sizeof(peer->pin) - 1);

	// A signed answer proves the body came from the peer. It says nothing
	// about the certificate the TLS layer was handed - somebody relaying our
	// request to the real node produces exactly this - so the key we had is
	// counted as unserved rather than written off. Only a peer that keeps
	// publishing a key it does not serve reaches the count, and even then
	// the pin is re-armed after a while: a downgrade nobody can make
	// permanent is one an attacker has to hold the wire for
	if(asked_unpinned && *code == 200)
	{
		if(strcmp(peer->pin_refused, previous_pin) != 0)
		{
			strncpy(peer->pin_refused, previous_pin, sizeof(peer->pin_refused) - 1);
			peer->pin_refused[sizeof(peer->pin_refused) - 1] = '\0';
			peer->pin_failures = 0;
		}
		peer->pin_failures++;
	}

	if(*code == 200 && signer != NULL && signerlen > 0)
	{
		strncpy(signer, answer.by, signerlen - 1);
		signer[signerlen - 1] = '\0';
	}

	// ...and by the node we thought we were talking to. An answer of ours
	// reflected back would otherwise have us mark a live peer as ourselves
	if(*code == 200 && strlen(peer->id) > 0 && strcmp(answer.by, peer->id) != 0)
	{
		strncpy(err, "Answer comes from a different node than we asked", errlen - 1);
		return false;
	}
	if(*code == 200 && strlen(peer->id) == 0 && strcmp(answer.by, cluster_node_id()) == 0 &&
	   !peer->is_self)
	{
		// Our own answer on a peer's URL: either this member entry really
		// is us, which the status document says for itself, or somebody
		// sent our request back to us
		log_debug(DEBUG_CLUSTER, "cluster: %s answered with our own identity", peer->url);
	}

	return true;
}

// A request that carries no signature, for the one exchange that happens before
// this node has a cluster secret to sign with: fetching that secret from a node
// that is already a member, authenticated with that node's own password
static bool plain_request(const char *url, const char *method, const char *path,
                          const char *postdata, const char *extra, const char *pin,
                          struct buffer *buf, long *code, char *err, const size_t errlen)
{
	CURL *curl = curl_easy_init();
	if(curl == NULL)
	{
		strncpy(err, "Unable to create a libcurl handle", errlen - 1);
		return false;
	}

	char full[CLUSTER_URLLEN + 64] = "";
	snprintf(full, sizeof(full), "%s%s", url, path);

	char agent[128] = "";
	snprintf(agent, sizeof(agent), "pihole-FTL/%s", git_version());

	struct curl_slist *headers = NULL;
	if(extra != NULL)
		headers = curl_slist_append(headers, extra);
	if(postdata != NULL)
		headers = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, full);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)buf);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, connect_timeout() * 5);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout());
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	if(strcmp(method, "GET") != 0)
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	if(postdata != NULL)
	{
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(postdata));
	}

	// This is the one connection a cluster cannot authenticate for itself:
	// the node making it is not a member yet, so it holds neither the shared
	// secret nor a pin. An administrator who cares can pass the other node's
	// pin - the page shows it - with the join request, which closes the gap;
	// the password and the secret are only ever sent over a connection the
	// caller already required to be TLS either way
	char cafile[PATH_MAX] = "";
	lock_shm();
	strncpy(cafile, config.cluster.tls.ca.v.s, sizeof(cafile) - 1);
	unlock_shm();

	char pinned[CLUSTER_PINLEN + 16] = "";
	if(pin != NULL && strlen(pin) > 0)
	{
		snprintf(pinned, sizeof(pinned), "sha256//%s", pin);
		curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pinned);
	}

	if(strlen(cafile) > 0)
		curl_easy_setopt(curl, CURLOPT_CAINFO, cafile);
	else
	{
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	const CURLcode rc = curl_easy_perform(curl);
	curl_slist_free_all(headers);

	if(rc != CURLE_OK)
	{
		snprintf(err, errlen, "%s", curl_easy_strerror(rc));
		curl_easy_cleanup(curl);
		return false;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, code);
	curl_easy_cleanup(curl);

	return true;
}

// Fetch the cluster secret from a node that is already a member, using that
// node's own password. This is the whole of joining: everything else follows
// from holding the secret
bool cluster_http_bootstrap(const char *url, const char *password, const char *self,
                            const char *pin, char *secret, const size_t secretlen,
                            cJSON **membersout, char *err, const size_t errlen)
{
	*membersout = NULL;

	// The password and the secret both travel here, so this one refuses to
	// speak plaintext at all
	if(strncmp(url, "https://", 8) != 0)
	{
		strncpy(err, "Joining a cluster needs an https:// address", errlen - 1);
		return false;
	}

	cJSON *body = cJSON_CreateObject();
	cJSON_AddStringToObject(body, "password", password);
	char *postdata = cJSON_PrintUnformatted(body);
	cJSON_Delete(body);
	if(postdata == NULL)
	{
		strncpy(err, "Unable to build the login request", errlen - 1);
		return false;
	}

	// Capped: this answer is parsed, and it comes from a node that is not a
	// member yet - nothing about it has been authenticated at this point
	struct buffer buf = { .max = MAX_JSON_SIZE };
	long code = 0;
	const bool okay = plain_request(url, "POST", "/api/auth", postdata, NULL, pin,
	                                &buf, &code, err, errlen);
	free(postdata);

	cJSON *answer = okay && buf.data != NULL ? cJSON_Parse(buf.data) : NULL;
	free_buffer(&buf);

	const cJSON *session = answer != NULL ? cJSON_GetObjectItem(answer, "session") : NULL;
	const cJSON *sid = session != NULL ? cJSON_GetObjectItem(session, "sid") : NULL;
	const cJSON *valid = session != NULL ? cJSON_GetObjectItem(session, "valid") : NULL;

	// A node with no password answers a valid session with no identifier in
	// it: its API is open, so there is nothing to carry and nothing to end.
	// The requests below then go without one
	const bool open_api = cJSON_IsTrue(valid) && !cJSON_IsString(sid);

	if(!okay || code != 200 || (!cJSON_IsString(sid) && !open_api))
	{
		cJSON_Delete(answer);
		if(strlen(err) == 0)
			strncpy(err, code == 401 ? "The password was refused" :
			             "That node did not answer with a session", errlen - 1);
		return false;
	}

	char sidheader[256] = "";
	if(cJSON_IsString(sid))
		snprintf(sidheader, sizeof(sidheader), "X-FTL-SID: %s", sid->valuestring);
	const char *auth = strlen(sidheader) > 0 ? sidheader : NULL;
	cJSON_Delete(answer);

	// Enrolling rather than only asking for the secret: the node we are
	// joining adds us to its member list, and that list is what travels to
	// the rest of the cluster.
	// Without an address of our own to offer, we send the port we listen on
	// and let that node put it together with the address this request comes
	// from - it can see that, and we cannot
	cJSON *who = cJSON_CreateObject();
	if(self != NULL)
		cJSON_AddStringToObject(who, "self", self);
	else
		cJSON_AddNumberToObject(who, "port", get_bound_https_port());
	char *enroll = cJSON_PrintUnformatted(who);
	cJSON_Delete(who);

	const bool got = enroll != NULL &&
	                 plain_request(url, "POST", "/api/cluster/enroll", enroll, auth, pin,
	                               &buf, &code, err, errlen);
	free(enroll);
	cJSON *handover = got && buf.data != NULL ? cJSON_Parse(buf.data) : NULL;
	free_buffer(&buf);

	// The session goes away whether or not the handover worked
	struct buffer discard = { 0 };
	long ignored = 0;
	char ignorederr[128] = "";
	// Nothing to end where nothing was created
	if(auth != NULL)
		plain_request(url, "DELETE", "/api/auth", NULL, auth, pin, &discard, &ignored,
		              ignorederr, sizeof(ignorederr));
	free_buffer(&discard);

	const cJSON *value = handover != NULL ? cJSON_GetObjectItem(handover, "secret") : NULL;
	if(!got || code != 200 || !cJSON_IsString(value))
	{
		cJSON_Delete(handover);
		if(strlen(err) == 0)
			snprintf(err, errlen, "That node did not enroll this one (HTTP %ld)", code);
		return false;
	}

	strncpy(secret, value->valuestring, secretlen - 1);
	secret[secretlen - 1] = '\0';

	const cJSON *list = cJSON_GetObjectItem(handover, "members");
	if(cJSON_IsArray(list))
		*membersout = cJSON_Duplicate(list, true);

	cJSON_Delete(handover);

	return true;
}

// Ask a peer for something. Every request carries its own signature, so there
// is no session to establish, to keep alive or to lose
static bool cluster_get(struct cluster_peer *peer, const char *path,
                        struct buffer *buf, char *err, const size_t errlen,
                        const long timeout, char *signer, const size_t signerlen)
{
	long code = 0;
	if(!request(peer, "GET", path, NULL, buf, &code, err, errlen, timeout, signer, signerlen))
	{
		// The transfer may well have failed after the first chunk arrived
		free_buffer(buf);
		return false;
	}

	if(code != 200)
	{
		// A Pi-hole that does not know this endpoint answers 404 with
		// FTL's own error document, which is what tells an FTL without
		// clustering apart from a 404 out of anything else
		if(code == 404 && buf->data != NULL &&
		   strstr(buf->data, "\"not_found\"") != NULL)
			snprintf(err, errlen, "FTL is too old for clustering");
		// Nothing here is authenticated by a session: the peer refused
		// the signature, so the two do not hold the same secret
		else if(code == 401 || code == 403)
			snprintf(err, errlen, "not accepted - check %s on both nodes",
			         CLUSTER_SECRET_FILE);
		else
			snprintf(err, errlen, "HTTP %ld", code);
		free_buffer(buf);
		return false;
	}

	return true;
}

// Hand our configuration to a peer. This is a PATCH of its configuration, the
// very same request the web interface makes when somebody hits Save - the peer
// applies it through the same code and answers with what it holds afterwards
bool cluster_http_patch(struct cluster_peer *peer, const char *path, const char *body,
                        cJSON **json, char *err, const size_t errlen)
{
	*json = NULL;

	struct buffer buf = { .max = MAX_JSON_SIZE };
	long code = 0;
	if(!request(peer, "PATCH", path, body, &buf, &code, err, errlen, connect_timeout(), NULL, 0))
	{
		free_buffer(&buf);
		return false;
	}

	if(code != 200)
	{
		snprintf(err, errlen, "HTTP %ld", code);
		free_buffer(&buf);
		return false;
	}

	if(buf.data != NULL)
		*json = cJSON_Parse(buf.data);
	free_buffer(&buf);

	return true;
}

bool cluster_http_json(struct cluster_peer *peer, const char *path, cJSON **json,
                       char *err, const size_t errlen, char *signer, const size_t signerlen)
{
	// Capped where it arrives rather than where it is parsed: an answer that
	// cannot be a status document is not one to allocate room for first
	struct buffer buf = { .max = MAX_JSON_SIZE };
	if(!cluster_get(peer, path, &buf, err, errlen, connect_timeout(), signer, signerlen))
		return false;

	*json = buf.data != NULL ? cJSON_Parse(buf.data) : NULL;
	free_buffer(&buf);

	if(*json == NULL)
	{
		strncpy(err, "Answer is not valid JSON", errlen - 1);
		return false;
	}

	return true;
}

bool cluster_http_raw(struct cluster_peer *peer, const char *path, uint8_t **data,
                      size_t *size, char *err, const size_t errlen)
{
	struct buffer buf = { 0 };
	// A whole list database, not an answer to a question
	if(!cluster_get(peer, path, &buf, err, errlen, bulk_timeout(), NULL, 0))
		return false;

	*data = (uint8_t *)buf.data;
	*size = buf.size;

	return true;
}

#else // HAVE_CURL

bool cluster_http_init(void)
{
	log_warn("FTL was built without libcurl, clustering is not available");
	return false;
}

void cluster_http_free(struct cluster_peer *peer)
{
	(void)peer;
}

bool cluster_http_bootstrap(const char *url, const char *password, const char *self,
                            const char *pin, char *secret, const size_t secretlen,
                            cJSON **members, char *err, const size_t errlen)
{
	(void)url; (void)password; (void)self; (void)pin; (void)secret; (void)secretlen;
	*members = NULL;
	strncpy(err, "Built without libcurl", errlen - 1);
	return false;
}

bool cluster_http_patch(struct cluster_peer *peer, const char *path, const char *body,
                        cJSON **json, char *err, const size_t errlen)
{
	(void)peer; (void)path; (void)body;
	*json = NULL;
	strncpy(err, "Built without libcurl", errlen - 1);
	return false;
}

bool cluster_http_json(struct cluster_peer *peer, const char *path, cJSON **json,
                       char *err, const size_t errlen, char *signer, const size_t signerlen)
{
	(void)peer; (void)path; (void)json; (void)signer; (void)signerlen;
	strncpy(err, "Built without libcurl", errlen - 1);
	return false;
}

bool cluster_http_raw(struct cluster_peer *peer, const char *path, uint8_t **data,
                      size_t *size, char *err, const size_t errlen)
{
	(void)peer; (void)path; (void)data; (void)size;
	strncpy(err, "Built without libcurl", errlen - 1);
	return false;
}

#endif // HAVE_CURL
