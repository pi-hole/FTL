/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster HTTP client prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CLUSTER_HTTP_H
#define CLUSTER_HTTP_H

#include "FTL.h"
#include "cluster/cluster.h"

// Initialize/clean up the HTTP client. Both are called by the cluster thread
// only, which is the only thread using libcurl
bool cluster_http_init(void);
void cluster_http_free(struct cluster_peer *peer);

// Join a cluster: fetch the shared secret from a node that is already a member,
// authenticated with that node's own password. The caller owns *members
bool cluster_http_bootstrap(const char *url, const char *password, const char *totp,
                            const char *self, const char *pin, char *secret,
                            const size_t secretlen, cJSON **members, char *err,
                            const size_t errlen);

// Request a JSON document from a peer. The caller owns *json and has to free it
// with cJSON_Delete(). Returns false and fills err on any error
// signer, when not NULL, receives the identity the answer was signed under -
// which is not the same thing as the identity the document claims
bool cluster_http_json(struct cluster_peer *peer, const char *path, cJSON **json,
                       char *err, const size_t errlen, char *signer, const size_t signerlen);

// Hand a JSON document to a peer. The caller owns *json (which may be NULL if
// the peer answered with an empty body) and has to free it with cJSON_Delete()
bool cluster_http_patch(struct cluster_peer *peer, const char *path, const char *body,
                        cJSON **json, char *err, const size_t errlen);

// Request a binary document (e.g., a Teleporter archive) from a peer. The caller
// owns *data and has to free() it
bool cluster_http_raw(struct cluster_peer *peer, const char *path, uint8_t **data,
                      size_t *size, char *err, const size_t errlen);

#endif // CLUSTER_HTTP_H
