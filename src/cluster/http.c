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
#include "cluster/http.h"
#include "version.h"
// cluster_secret()
#include "config/password.h"

#ifdef HAVE_CURL

#include <curl/curl.h>

// A peer's answer is a status document or a Teleporter archive, both of which
// are far below this. The limit exists so a broken (or hostile) peer cannot
// make us allocate until we are killed
#define MAX_RESPONSE_SIZE (32u*1024u*1024u)

struct buffer {
	char *data;
	size_t size;
};

// A request that failed before the first chunk arrived leaves no buffer behind
static void free_buffer(struct buffer *buf)
{
	if(buf->data != NULL)
		free(buf->data);

	buf->data = NULL;
	buf->size = 0;
}

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct buffer *buf = (struct buffer *)userp;
	const size_t chunk = size * nmemb;

	// Returning anything else than the chunk size aborts the transfer
	if(buf->size + chunk + 1 > MAX_RESPONSE_SIZE)
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
		log_err("Cluster: Unable to initialize libcurl: %s", curl_easy_strerror(rc));
		return false;
	}

	log_debug(DEBUG_CLUSTER, "Cluster: Using %s", curl_version());
	return true;
}

void cluster_http_free(struct cluster_peer *peer)
{
	if(peer->curl == NULL)
		return;

	curl_easy_cleanup((CURL *)peer->curl);
	peer->curl = NULL;
}

// Perform one request against a peer. postdata == NULL requests a GET
static bool request(struct cluster_peer *peer, const char *path, const char *postdata,
                    struct buffer *buf, long *code, char *err, const size_t errlen)
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

	char url[512] = "";
	snprintf(url, sizeof(url), "%s%s", peer->url, path);

	char agent[128] = "";
	snprintf(agent, sizeof(agent), "pihole-FTL/%s", git_version());

	struct curl_slist *headers = NULL;
	if(peer->sid != NULL)
	{
		char sidheader[128] = "";
		snprintf(sidheader, sizeof(sidheader), "X-FTL-SID: %s", peer->sid);
		headers = curl_slist_append(headers, sidheader);
	}
	if(postdata != NULL)
		headers = curl_slist_append(headers, "Content-Type: application/json");
	// We ask for identity encoding: the answers are small and this saves the
	// peer from compressing what we immediately decompress again
	headers = curl_slist_append(headers, "Accept-Encoding: identity");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)buf);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)config.cluster.timeout.v.ui);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)config.cluster.timeout.v.ui);
	// libcurl must not use signals for timeouts in a threaded program
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	// A peer redirecting us elsewhere is a misconfiguration, not something to follow
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	if(!config.cluster.tls.verify.v.b)
	{
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}
	else if(strlen(config.cluster.tls.ca.v.s) > 0)
	{
		// Pi-hole's certificates are self-signed, so the peers' own
		// certificates are the trust anchor for a cluster
		curl_easy_setopt(curl, CURLOPT_CAINFO, config.cluster.tls.ca.v.s);
	}
	if(postdata != NULL)
	{
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(postdata));
	}

	const CURLcode rc = curl_easy_perform(curl);
	curl_slist_free_all(headers);

	if(rc != CURLE_OK)
	{
		snprintf(err, errlen, "%s", curl_easy_strerror(rc));
		return false;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, code);
	log_debug(DEBUG_CLUSTER, "Cluster: %s %s -> %ld (%zu bytes)",
	          postdata != NULL ? "POST" : "GET", url, *code, buf->size);

	return true;
}

// Log into a peer using the shared cluster secret and remember the session ID. The
// session is reused for all subsequent requests: authenticating on every
// request would create a new session each time until the peer runs out of
// session seats
static bool authenticate(struct cluster_peer *peer, char *err, const size_t errlen)
{
	const char *secret = cluster_secret();
	if(secret == NULL || strlen(secret) == 0)
	{
		strncpy(err, "This node has no cluster secret", errlen - 1);
		return false;
	}

	// Build the request body through cJSON so a secret containing characters
	// with a meaning in JSON is escaped correctly
	cJSON *body = cJSON_CreateObject();
	cJSON_AddStringToObject(body, "password", secret);
	char *postdata = cJSON_PrintUnformatted(body);
	cJSON_Delete(body);
	if(postdata == NULL)
	{
		strncpy(err, "Unable to create the authentication request", errlen - 1);
		return false;
	}

	// Forget any previous session, it is either expired or was evicted
	if(peer->sid != NULL)
	{
		free(peer->sid);
		peer->sid = NULL;
	}

	struct buffer buf = { 0 };
	long code = 0;
	const bool success = request(peer, "/api/auth", postdata, &buf, &code, err, errlen);
	free(postdata);

	if(!success)
	{
		free_buffer(&buf);
		return false;
	}

	if(code != 200)
	{
		snprintf(err, errlen, "Authentication rejected (HTTP %ld)", code);
		free_buffer(&buf);
		return false;
	}

	cJSON *json = buf.data != NULL ? cJSON_Parse(buf.data) : NULL;
	free_buffer(&buf);
	if(json == NULL)
	{
		strncpy(err, "Authentication answer is not valid JSON", errlen - 1);
		return false;
	}

	const cJSON *session = cJSON_GetObjectItem(json, "session");
	const cJSON *sid = session != NULL ? cJSON_GetObjectItem(session, "sid") : NULL;
	if(!cJSON_IsString(sid))
	{
		strncpy(err, "Authentication answer contains no session ID", errlen - 1);
		cJSON_Delete(json);
		return false;
	}

	peer->sid = strdup(sid->valuestring);
	cJSON_Delete(json);

	log_debug(DEBUG_CLUSTER, "Cluster: Authenticated at %s", peer->url);

	return peer->sid != NULL;
}

// Perform a GET request, authenticating first if we have no session yet and
// re-authenticating once if the peer tells us our session is not valid
static bool authenticated_get(struct cluster_peer *peer, const char *path,
                              struct buffer *buf, char *err, const size_t errlen)
{
	if(peer->sid == NULL && !authenticate(peer, err, errlen))
		return false;

	long code = 0;
	if(!request(peer, path, NULL, buf, &code, err, errlen))
	{
		// The transfer may well have failed after the first chunk arrived
		free_buffer(buf);
		return false;
	}

	if(code == 401)
	{
		// Our session expired or was evicted, get a new one and retry once
		free_buffer(buf);

		if(!authenticate(peer, err, errlen))
			return false;

		if(!request(peer, path, NULL, buf, &code, err, errlen))
		{
			free_buffer(buf);
			return false;
		}
	}

	if(code != 200)
	{
		snprintf(err, errlen, "HTTP %ld", code);
		free_buffer(buf);
		return false;
	}

	return true;
}

bool cluster_http_json(struct cluster_peer *peer, const char *path, cJSON **json,
                       char *err, const size_t errlen)
{
	struct buffer buf = { 0 };
	if(!authenticated_get(peer, path, &buf, err, errlen))
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
	if(!authenticated_get(peer, path, &buf, err, errlen))
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

bool cluster_http_json(struct cluster_peer *peer, const char *path, cJSON **json,
                       char *err, const size_t errlen)
{
	(void)peer; (void)path; (void)json;
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
