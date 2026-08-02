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

// Request a JSON document from a peer. The caller owns *json and has to free it
// with cJSON_Delete(). Returns false and fills err on any error
bool cluster_http_json(struct cluster_peer *peer, const char *path, cJSON **json,
                       char *err, const size_t errlen);

// Request a binary document (e.g., a Teleporter archive) from a peer. The caller
// owns *data and has to free() it
bool cluster_http_raw(struct cluster_peer *peer, const char *path, uint8_t **data,
                      size_t *size, char *err, const size_t errlen);

#endif // CLUSTER_HTTP_H
