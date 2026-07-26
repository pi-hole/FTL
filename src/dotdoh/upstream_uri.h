/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted upstream URI parser
*
*  Public interface of the dns.upstreams entry parser. Self-contained (standard
*  headers only, no FTL.h) so the standalone regression harness can use it.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_UPSTREAM_URI_H
#define DOTDOH_UPSTREAM_URI_H

#include <stdbool.h>

enum ustype { UST_PLAIN = 0, UST_DOT, UST_DOH };

#define UURI_HOST_MAX 256
#define UURI_PATH_MAX 256

struct upstream_uri {
	enum ustype type;
	char connect_host[UURI_HOST_MAX]; // TCP connect target: IP literal or hostname
	char verify_name[UURI_HOST_MAX]; // SNI + certificate verification name
	int  port; // 53 (plain) / 853 (DoT) / 443 (DoH) default
	char doh_path[UURI_PATH_MAX]; // DoH only, default "/dns-query"
};

// Parse one dns.upstreams entry.
bool parse_upstream_uri(const char *in, struct upstream_uri *out);

#endif /* DOTDOH_UPSTREAM_URI_H */
