/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster request authentication prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CLUSTER_AUTH_H
#define CLUSTER_AUTH_H

#include "FTL.h"
#include "webserver/http-common.h"

// A SHA256 digest in hex, plus the terminating NUL
#define CLUSTER_SIGLEN 65

// How far apart the clocks of two nodes may be for a request to be accepted.
// They have to agree within two seconds to synchronize at all, so this is
// generous, and it is what bounds how long a captured request stays usable
// against a node that has just restarted
#define CLUSTER_SIG_WINDOW 30

// What a signed request carries. The recipient is named so a request captured
// on the way to one node cannot be replayed at another, and the sequence is
// microseconds since the epoch, strictly increasing per sender
#define CLUSTER_HDR_FROM  "X-FTL-Cluster"
#define CLUSTER_HDR_TO    "X-FTL-Cluster-To"
#define CLUSTER_HDR_SEQ   "X-FTL-Cluster-Seq"
#define CLUSTER_HDR_SIG   "X-FTL-Cluster-Sig"
#define CLUSTER_HDR_BY    "X-FTL-Cluster-By"

// A GET carries no consequence, so it may be sent before we know who we are
// talking to - the first poll of a peer we have never reached
#define CLUSTER_ANY_NODE "*"

// Is this what a node identity looks like? A peer chooses the string and we
// compare it, store it and print it, so it may only be what an identity is
bool cluster_plain_id(const char *str) __attribute__ ((pure));

struct cluster_signature {
	long long seq;
	char sig[CLUSTER_SIGLEN];
};

// Sign a request to a peer. body may be NULL for a GET
bool cluster_sign_request(const char *method, const char *uri, const char *to,
                          const char *body, struct cluster_signature *out);

// Is this request a signed one from a peer of our cluster? Sets the session up
// as a cluster session if so. A request without our headers is left alone and
// takes the regular authentication path
bool cluster_verify_request(struct ftl_conn *api);

// The signature this node puts on its answer to a cluster request, so a peer
// cannot be lied to about who holds what. False if this is not one
bool cluster_response_signature(struct ftl_conn *api, const char *body, const size_t len,
                                char sig[CLUSTER_SIGLEN]);

// ...and the check the peer makes on it
bool cluster_verify_response(const char *from, const long long seq, const char *sig,
                             const char *body, const size_t len);

#endif // CLUSTER_AUTH_H
